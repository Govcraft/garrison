//! The install-token exchange, end to end, against a real plane.
//!
//! One PostgreSQL container, one `schemaforge serve` on the repository's own
//! schemas and policies, one `garrison-hooks` on free ports. Nothing is faked:
//! the Ed25519 keypair is generated here, its SPKI goes onto a real
//! `InstallCredential` row, the assertion is signed and posted over HTTP, and
//! the bearer that comes back is spent on the plane's ordinary REST API.
//!
//! What it proves:
//!
//! 1. A daemon holding the private half of a credential the plane recorded
//!    can exchange a signed assertion for a bearer, and that bearer reads the
//!    `AgentInstall` row it speaks for — which means the tenant chain the
//!    exchange minted is the one the plane's row-level scoping honours.
//! 2. Every refusal the design promises comes back with the status the daemon
//!    branches on: a forged signature 401, a replayed nonce 401, a revoked
//!    credential 403, a retired install 403.
//!
//! The negative cases matter more than the positive one. A 401 costs a daemon
//! one retry with a fresh assertion; a 403 is a decision somebody made, and a
//! daemon that retried it would turn a deliberate quarantine into a denial of
//! service against its own control plane.
//!
//! Skips, with a printed reason, when `schemaforge` is not on `PATH` or no
//! container runtime answers (`DOCKER_HOST=unix:///run/user/1000/podman/podman.sock`
//! for rootless podman).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::{Signer as _, SigningKey};
use garrison_wire::{signing_bytes, token_request, InstallAssertion, TokenRequest};
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "garrison-test-admin";
const ISSUER: &str = "garrison-control-plane";
const OPERATOR_UPN: &str = "exchange@example-agency.gov";

/// A child process that dies with the test, whichever way the test ends.
struct Reaped(Child, &'static str);

impl Drop for Reaped {
    fn drop(&mut self) {
        if self.0.kill().is_err() {
            eprintln!("{} had already exited", self.1);
        }
        let _ = self.0.wait();
    }
}

// =============================================================================
// The daemon's half, in miniature
// =============================================================================

/// An install key, as `agent/src/enrollment/key.rs` holds one.
struct Install {
    key: SigningKey,
    credential_row: String,
    install_row: String,
}

impl Install {
    /// A fresh keypair, so the exchange is never tested against the pinned
    /// vector's key by accident.
    fn generate(credential_row: String, install_row: String) -> Self {
        let mut seed = [0u8; 32];
        getrandom_seed(&mut seed);
        Self {
            key: SigningKey::from_bytes(&seed),
            credential_row,
            install_row,
        }
    }

    /// The public half as an `InstallCredential.public_key` holds it.
    fn spki_base64(&self) -> String {
        let der = self
            .key
            .verifying_key()
            .to_public_key_der()
            .expect("an Ed25519 key encodes to SPKI");
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    }

    /// An assertion signed the way the daemon signs one.
    fn assert_now(&self, nonce: &str) -> TokenRequest {
        let assertion = InstallAssertion {
            credential_id: self.credential_row.clone(),
            install_id: self.install_row.clone(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 60,
            nonce: nonce.to_string(),
        };
        let bytes = signing_bytes(&assertion).expect("an assertion serializes");
        let signature = self.key.sign(&bytes);
        token_request(&bytes, &signature.to_bytes(), &assertion.credential_id)
    }
}

/// Randomness without pulling a crate in for four lines.
fn getrandom_seed(seed: &mut [u8; 32]) {
    let mut file = std::fs::File::open("/dev/urandom").expect("urandom");
    use std::io::Read as _;
    file.read_exact(seed).expect("read urandom");
}

/// A nonce long enough for the exchange and never repeated.
fn nonce(tag: &str) -> String {
    format!(
        "{tag}-{:022}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

// =============================================================================
// Fixtures
// =============================================================================

struct Plane {
    http: reqwest::Client,
    base: String,
    admin: String,
    work: PathBuf,
}

impl Plane {
    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/forge/{path}", self.base)
    }

    async fn create(&self, schema: &str, fields: Value) -> String {
        let response = self
            .http
            .post(self.url(&format!("schemas/{schema}/entities")))
            .bearer_auth(&self.admin)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .expect("plane reachable");
        let status = response.status();
        let body: Value = response.json().await.expect("json body");
        assert!(status.is_success(), "create {schema}: {status} {body}");
        body["id"].as_str().expect("a new id").to_string()
    }

    async fn patch(&self, schema: &str, id: &str, fields: Value) {
        let response = self
            .http
            .patch(self.url(&format!("schemas/{schema}/entities/{id}")))
            .bearer_auth(&self.admin)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .expect("plane reachable");
        let status = response.status();
        let body: Value = response.json().await.expect("json body");
        assert!(status.is_success(), "patch {schema}/{id}: {status} {body}");
    }

    async fn get_as(&self, bearer: &str, schema: &str, id: &str) -> (u16, Value) {
        let response = self
            .http
            .get(self.url(&format!("schemas/{schema}/entities/{id}")))
            .bearer_auth(bearer)
            .send()
            .await
            .expect("plane reachable");
        let status = response.status().as_u16();
        (status, response.json().await.expect("json body"))
    }

    /// The tail of both logs, so a failure says why rather than only what.
    fn dump_logs(&self) {
        for log in ["plane.log", "hooks.log"] {
            let text = std::fs::read_to_string(self.work.join(log)).unwrap_or_default();
            let tail: Vec<&str> = text.lines().rev().take(30).collect();
            eprintln!("---- {log} (last lines, newest first) ----");
            for line in tail {
                eprintln!("{line}");
            }
        }
    }
}

/// Posts an assertion at the exchange and reports what came back.
async fn exchange(http: &reqwest::Client, base: &str, body: &TokenRequest) -> (u16, Value) {
    let response = http
        .post(format!("{base}/api/v1/install/token"))
        .json(body)
        .send()
        .await
        .expect("the exchange is reachable");
    let status = response.status().as_u16();
    (status, response.json().await.expect("json body"))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("hooks-service sits in the repository root")
        .to_path_buf()
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("readdir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}

fn schemaforge() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("schemaforge"))
        .find(|candidate| candidate.is_file())
}

fn mint(key: &Path, sub: &str, roles: &str, chain: &str) -> String {
    let output = Command::new("schemaforge")
        .args([
            "token",
            "generate",
            "--key",
            key.to_str().expect("utf8 path"),
            "--sub",
            sub,
            "--roles",
            roles,
            "--issuer",
            ISSUER,
            "--lifetime",
            "3600",
            "--tenant-chain",
            chain,
            "--format",
            "plain",
        ])
        .output()
        .expect("schemaforge token generate runs");
    assert!(
        output.status.success(),
        "token generate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 token")
        .trim()
        .to_string()
}

/// The plane's config. No hook bindings: this test exercises the HTTP route,
/// and a binding to a service that has not started yet would only add a way
/// for seeding to fail.
fn plane_config(db_url: &str, key: &Path) -> String {
    format!(
        r#"
[database]
url             = "{db_url}"
max_connections = 10
min_connections = 1

[token]
format   = "paseto"
version  = "v4"
purpose  = "local"
key_path = "{key}"
issuer   = "{ISSUER}"

[schema_forge.authz.principal_claims.entra_object_id]
type     = "string"
required = false
source   = {{ user_field = "entra_object_id" }}

[schema_forge.authz.principal_claims.org_slug]
type     = "string"
required = false
source   = {{ user_field = "org_slug" }}
"#,
        key = key.display(),
    )
}

fn hooks_config(port: u16, key: &Path, plane: &str) -> String {
    format!(
        r#"
[service]
name = "garrison-hooks-exchange-test"
bind = "127.0.0.1"
port = {port}

[grpc]
enabled = true
use_separate_port = false

[token]
format = "paseto"
key_path = "{key}"
public_paths = ["/api/v1/install/token"]

[garrison]
url      = "{plane}"
issuer   = "{ISSUER}"
lifetime = 900
"#,
        key = key.display(),
    )
}

fn run_apply(cwd: &Path, db_url: &str) -> bool {
    let output = Command::new("schemaforge")
        .current_dir(cwd)
        .env("ACTON_DATABASE_URL", db_url)
        .args([
            "apply",
            "schemas",
            "--with-policies",
            "--force",
            "-c",
            "config.toml",
        ])
        .output()
        .expect("schemaforge apply runs");
    if !output.status.success() {
        eprintln!("apply: {}", String::from_utf8_lossy(&output.stderr));
    }
    output.status.success()
}

// =============================================================================
// The test
// =============================================================================

#[tokio::test]
async fn a_signed_assertion_buys_a_bearer_that_reads_its_own_install() {
    if schemaforge().is_none() {
        eprintln!("skipping: schemaforge is not on PATH");
        return;
    }

    let image = GenericImage::new("postgres", "16")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "garrison")
        .with_env_var("POSTGRES_PASSWORD", "garrison")
        .with_env_var("POSTGRES_DB", "garrison_plane");
    let postgres = match image.start().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("skipping: no container runtime answered ({error})");
            return;
        }
    };
    let pg_port = postgres
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let db_url = format!("postgres://garrison:garrison@127.0.0.1:{pg_port}/garrison_plane");

    // A private copy of the repository's model, so nothing here can touch the
    // checkout or any plane an operator is running.
    let root = repo_root();
    let work = tempfile::tempdir().expect("tempdir");
    copy_tree(&root.join("schemas"), &work.path().join("schemas"));
    copy_tree(&root.join("policies"), &work.path().join("policies"));
    std::fs::create_dir_all(work.path().join("keys")).expect("keys dir");
    let key = work.path().join("keys/paseto.key");
    let status = Command::new("schemaforge")
        .args(["token", "init-key", "--output"])
        .arg(&key)
        .status()
        .expect("init-key runs");
    assert!(status.success(), "init-key");

    let plane_port = free_port();
    let hooks_port = free_port();
    std::fs::write(work.path().join("config.toml"), plane_config(&db_url, &key))
        .expect("plane config");

    // Postgres logs "ready" once during init and again after its restart;
    // an apply in the gap fails to connect and is simply tried again.
    let applied = (0..30).any(|_| {
        run_apply(work.path(), &db_url) || {
            std::thread::sleep(Duration::from_millis(500));
            false
        }
    });
    assert!(applied, "schemaforge apply never succeeded");

    let plane_base = format!("http://127.0.0.1:{plane_port}");
    let plane_log = std::fs::File::create(work.path().join("plane.log")).expect("log");
    let _plane = Reaped(
        Command::new("schemaforge")
            .current_dir(work.path())
            .env("ACTON_DATABASE_URL", &db_url)
            .env("FORGE_ADMIN_USER", ADMIN_USER)
            .env("FORGE_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .args([
                "serve",
                "--schemas",
                "schemas",
                "-H",
                "127.0.0.1",
                "-p",
                &plane_port.to_string(),
                "-c",
                "config.toml",
            ])
            .stdout(Stdio::from(plane_log.try_clone().expect("clone log")))
            .stderr(Stdio::from(plane_log))
            .spawn()
            .expect("schemaforge serve spawns"),
        "plane",
    );

    let http = reqwest::Client::new();
    let admin = {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let attempt = http
                .post(format!("{plane_base}/api/v1/forge/auth/login"))
                .json(&json!({ "username": ADMIN_USER, "password": ADMIN_PASSWORD }))
                .send()
                .await;
            if let Ok(response) = attempt {
                if let Ok(body) = response.json::<Value>().await {
                    if let Some(token) = body["token"].as_str() {
                        break token.to_string();
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "plane never answered a login; see {}",
                work.path().join("plane.log").display()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    let mut plane = Plane {
        http: http.clone(),
        base: plane_base.clone(),
        admin,
        work: work.path().to_path_buf(),
    };

    // The tenant chain is the point. A row written without one lands with a
    // null tenant and is invisible to every tenant-scoped bearer, including
    // the one this exchange is about to mint.
    let org_id = plane
        .create(
            "Organization",
            json!({
                "name": "Example Agency",
                "slug": "example-agency",
                "entra_tenant_id": "tenant-example",
                "entra_group_id": "group-garrison",
                "seats_licensed": 5,
                "owner_id": ADMIN_USER
            }),
        )
        .await;
    let chain = json!([{ "schema": "Organization", "entity_id": org_id }]).to_string();
    plane.admin = mint(&key, "seed-admin", "platform_admin", &chain);

    let operator_id = plane
        .create(
            "Operator",
            json!({
                "upn": OPERATOR_UPN,
                "display_name": "Exchange Operator",
                "email": OPERATOR_UPN,
                "organization": org_id,
                "status": "active"
            }),
        )
        .await;

    let install_row = plane
        .create(
            "AgentInstall",
            json!({
                "install_id": "install_exchange_1",
                "hostname": "ws-exchange",
                "operator": operator_id,
                "organization": org_id,
                "platform": "linux",
                "agent_version": "0.1.0",
                "sandbox_hardening": "best_effort",
                "isolation_active": true,
                "status": "active"
            }),
        )
        .await;

    // The keypair the daemon would have generated at enrollment. Only the
    // public half reaches the plane.
    let mut install = Install::generate(String::new(), install_row.clone());
    let credential_row = plane
        .create(
            "InstallCredential",
            json!({
                "credential_id": "cred_exchange_1",
                "install": install_row,
                "organization": org_id,
                "credential_kind": "ed25519",
                "public_key": install.spki_base64(),
                "status": "active"
            }),
        )
        .await;
    install.credential_row = credential_row.clone();

    // A second install, retired, to prove the install's own status is checked
    // and not only the credential's. It is created active and retired
    // afterwards, because the schema's own `@require` forbids an active
    // credential on an already-retired install — which is exactly the
    // sequence a real decommissioning follows.
    let retired_row = plane
        .create(
            "AgentInstall",
            json!({
                "install_id": "install_exchange_retired",
                "hostname": "ws-retired",
                "operator": operator_id,
                "organization": org_id,
                "platform": "linux",
                "agent_version": "0.1.0",
                "sandbox_hardening": "unavailable",
                "status": "active"
            }),
        )
        .await;
    let mut retired = Install::generate(String::new(), retired_row.clone());
    retired.credential_row = plane
        .create(
            "InstallCredential",
            json!({
                "credential_id": "cred_exchange_retired",
                "install": retired_row,
                "organization": org_id,
                "credential_kind": "ed25519",
                "public_key": retired.spki_base64(),
                "status": "active"
            }),
        )
        .await;
    plane
        .patch("AgentInstall", &retired_row, json!({ "status": "retired" }))
        .await;

    let hook_token = mint(
        &key,
        "garrison-hooks",
        "enrollment_service,audit_service",
        &chain,
    );

    let hooks_dir = work.path().join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("hooks dir");
    std::fs::write(
        hooks_dir.join("config.toml"),
        hooks_config(hooks_port, &key, &plane_base),
    )
    .expect("hooks config");
    let hooks_log = std::fs::File::create(work.path().join("hooks.log")).expect("log");
    let _hooks = Reaped(
        Command::new(env!("CARGO_BIN_EXE_garrison-hooks"))
            .current_dir(&hooks_dir)
            .env("ACTON_GARRISON_TOKEN", &hook_token)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(hooks_log.try_clone().expect("clone log")))
            .stderr(Stdio::from(hooks_log))
            .spawn()
            .expect("garrison-hooks spawns"),
        "hooks",
    );
    let hooks_base = format!("http://127.0.0.1:{hooks_port}");

    // Wait for the route rather than for the process: a service that booted
    // and then refused its config would otherwise look like a slow start.
    {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let reached = http
                .post(format!("{hooks_base}/api/v1/install/token"))
                .json(&json!({}))
                .send()
                .await
                .map(|response| response.status().as_u16());
            // Anything but a transport error means the route is mounted and
            // is not being intercepted by the token middleware.
            if matches!(reached, Ok(status) if status != 401) {
                break;
            }
            if Instant::now() >= deadline {
                plane.dump_logs();
                panic!("the exchange never answered on {hooks_base}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    // ---------------------------------------------------------------------
    // 1. The happy path, and the bearer spent on the plane.
    // ---------------------------------------------------------------------
    let good = install.assert_now(&nonce("ok"));
    let (status, body) = exchange(&http, &hooks_base, &good).await;
    if status != 200 {
        plane.dump_logs();
    }
    assert_eq!(status, 200, "exchange: {body}");
    let bearer = body["token"].as_str().expect("a token").to_string();
    assert_eq!(body["install"], json!(install_row));
    assert_eq!(body["organization"], json!(org_id));
    assert!(body["expires_at"]
        .as_str()
        .is_some_and(|at| at.ends_with('Z')));

    let (status, row) = plane.get_as(&bearer, "AgentInstall", &install_row).await;
    assert_eq!(
        status, 200,
        "the minted bearer must read its own install: {row}"
    );
    assert_eq!(row["fields"]["install_id"], json!("install_exchange_1"));

    // ---------------------------------------------------------------------
    // 2. A replayed assertion. Same bytes, same nonce, already spent.
    // ---------------------------------------------------------------------
    let (status, body) = exchange(&http, &hooks_base, &good).await;
    assert_eq!(status, 401, "a replay must not buy a second bearer: {body}");
    assert_eq!(body["error"], json!("assertion_replayed"));

    // ---------------------------------------------------------------------
    // 3. A forged signature.
    // ---------------------------------------------------------------------
    let impostor = Install::generate(credential_row.clone(), install_row.clone());
    let (status, body) = exchange(&http, &hooks_base, &impostor.assert_now(&nonce("forged"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], json!("assertion_rejected"));

    // ---------------------------------------------------------------------
    // 4. A retired install, with a perfectly good credential.
    // ---------------------------------------------------------------------
    let (status, body) = exchange(&http, &hooks_base, &retired.assert_now(&nonce("retired"))).await;
    assert_eq!(
        status, 403,
        "a retired install is a decision, not a retryable failure: {body}"
    );
    assert_eq!(body["error"], json!("install_not_active"));

    // ---------------------------------------------------------------------
    // 5. A revoked credential. Revoking needs a reason, per the schema.
    // ---------------------------------------------------------------------
    plane
        .patch(
            "InstallCredential",
            &credential_row,
            json!({
                "status": "revoked",
                "revocation_reason": "the exchange integration test revoked it"
            }),
        )
        .await;
    let (status, body) = exchange(&http, &hooks_base, &install.assert_now(&nonce("revoked"))).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], json!("credential_rejected"));

    // ---------------------------------------------------------------------
    // 6. An unknown credential discloses nothing about whether it exists.
    // ---------------------------------------------------------------------
    let ghost = Install::generate(
        "installcredential_00000000000000000000000".to_string(),
        install_row.clone(),
    );
    let (status, body) = exchange(&http, &hooks_base, &ghost.assert_now(&nonce("ghost"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], json!("unknown_credential"));
}

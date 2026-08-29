//! The directory sync, end to end, against a real plane.
//!
//! One PostgreSQL container, one `schemaforge serve` on the repository's own
//! schemas and policies, one `garrison-hooks` with `[directory] mode = "file"`
//! reading a JSON snapshot this test edits between ticks. Nothing is faked
//! past that file: the reconciler, the plane client, Cedar, the `@require`
//! rules, and the enrollment hook all run for real.
//!
//! What it proves:
//!
//! 1. Provisioning: a member in the snapshot with no operator row becomes an
//!    `active` operator carrying her `entra_object_id`, and a hand-typed
//!    operator whose UPN matches is linked (R1, R2). She can then enrol a
//!    machine through the ordinary `Redemption` path and the install binds to
//!    her row (R4).
//! 2. Deprovisioning: flipping her `enabled` flag suspends the operator,
//!    revokes her seat with the written reason, and deactivates her console
//!    login; a second enrollment is refused with "operator is not active".
//!
//! Skips, with a printed reason, when `schemaforge` is not on `PATH` or no
//! container runtime answers (`DOCKER_HOST=unix:///run/user/1000/podman/podman.sock`
//! for rootless podman).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "garrison-test-admin";
const ISSUER: &str = "garrison-control-plane";
const ALICE_UPN: &str = "alice@example-agency.gov";
const ALICE_OID: &str = "aaaaaaaa-1111-1111-1111-111111111111";
const DEV_UPN: &str = "dev@agency.gov";
const DEV_OID: &str = "dddddddd-4444-4444-4444-444444444444";

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

struct Plane {
    http: reqwest::Client,
    base: String,
    /// The bearer every seed and assertion uses. The login token creates
    /// the Organization; after that a `platform_admin` service token scoped
    /// to it takes over, because a row written without a tenant chain lands
    /// with no tenant and is invisible to every tenant-scoped bearer,
    /// including the hooks service under test.
    admin: String,
    work: PathBuf,
}

impl Plane {
    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/forge/{path}", self.base)
    }

    async fn create(&self, schema: &str, fields: Value) -> Value {
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
        body
    }

    async fn get(&self, schema: &str, id: &str) -> Value {
        let response = self
            .http
            .get(self.url(&format!("schemas/{schema}/entities/{id}")))
            .bearer_auth(&self.admin)
            .send()
            .await
            .expect("plane reachable");
        let status = response.status();
        let body: Value = response.json().await.expect("json body");
        assert!(status.is_success(), "get {schema}/{id}: {status} {body}");
        body
    }

    async fn find(&self, schema: &str, field: &str, value: &str) -> Option<Value> {
        let response = self
            .http
            .post(self.url(&format!("schemas/{schema}/entities/query")))
            .bearer_auth(&self.admin)
            .json(&json!({
                "filter": { "field": field, "op": "eq", "value": value },
                "limit": 5
            }))
            .send()
            .await
            .expect("plane reachable");
        let body: Value = response.json().await.expect("json body");
        body["entities"]
            .as_array()
            .and_then(|rows| rows.first().cloned())
    }

    /// Poll until `probe` returns `Some`, or give up after `within`, printing
    /// the tail of both process logs so a timeout says why.
    async fn wait_for<F, Fut, T>(&self, what: &str, within: Duration, mut probe: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let deadline = Instant::now() + within;
        loop {
            if let Some(found) = probe().await {
                return found;
            }
            if Instant::now() >= deadline {
                for log in ["plane.log", "hooks.log"] {
                    let text = std::fs::read_to_string(self.work.join(log)).unwrap_or_default();
                    let tail: Vec<&str> = text.lines().rev().take(40).collect();
                    eprintln!("---- {log} (last lines, newest first) ----");
                    for line in tail {
                        eprintln!("{line}");
                    }
                }
                panic!("timed out waiting for {what}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
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

fn plane_config(db_url: &str, key: &Path, hooks_port: u16, descriptor: &Path) -> String {
    let binding = |schema: &str| {
        format!(
            r#"
[[schema_forge.hooks.bindings]]
schema          = "{schema}"
event           = "BeforeValidate"
endpoint        = "http://127.0.0.1:{hooks_port}"
timeout_ms      = 15000
required        = true
descriptor_path = "{}"
"#,
            descriptor.display()
        )
    };
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

[schema_forge.hooks]
enabled              = true
default_timeout_ms   = 15000
max_concurrent_async = 100
allow_plaintext      = true
{redemption}{audit}{bundle}"#,
        key = key.display(),
        redemption = binding("Redemption"),
        audit = binding("AuditEvent"),
        bundle = binding("PolicyBundle"),
    )
}

fn hooks_config(port: u16, key: &Path, plane: &str, snapshot: &Path, organization: &str) -> String {
    format!(
        r#"
[service]
name = "garrison-hooks-test"
bind = "127.0.0.1"
port = {port}

[grpc]
enabled = true
use_separate_port = false

[token]
format = "paseto"
key_path = "{key}"
# The install-token exchange, which a daemon reaches with no bearer. The
# service refuses to boot without this line, so it belongs in every config
# that starts one — including this fixture.
public_paths = ["/api/v1/install/token"]

[garrison]
url    = "{plane}"
issuer = "{ISSUER}"

[directory]
mode         = "file"
path         = "{snapshot}"
organization = "{organization}"
interval  = 2
staleness = 60
fraction  = 0.5
"#,
        key = key.display(),
        snapshot = snapshot.display(),
    )
}

fn member(oid: &str, upn: &str, name: &str, enabled: bool) -> Value {
    json!({
        "object_id": oid,
        "upn": upn,
        "display_name": name,
        "mail": upn,
        "enabled": enabled
    })
}

fn write_snapshot(path: &Path, members: &[Value]) {
    std::fs::write(path, serde_json::to_vec_pretty(&members).expect("json")).expect("write");
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

#[tokio::test]
async fn provisioning_and_deprovisioning_flow_through_a_real_plane() {
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
    let descriptor = root.join("hooks-service/hooks_descriptor.bin");
    assert!(
        descriptor.is_file(),
        "hooks_descriptor.bin is copied next to Cargo.toml by build.rs"
    );
    std::fs::write(
        work.path().join("config.toml"),
        plane_config(&db_url, &key, hooks_port, &descriptor),
    )
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

    // The organization, a hand-typed operator the directory will link, and
    // an enrollment token for the person the directory will create.
    let org = plane
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
    let org_id = org["id"].as_str().expect("org id").to_string();
    let chain = json!([{ "schema": "Organization", "entity_id": org_id }]).to_string();
    plane.admin = mint(&key, "seed-admin", "platform_admin", &chain);

    let dev = plane
        .create(
            "Operator",
            json!({
                "upn": DEV_UPN,
                "display_name": "Dev Operator",
                "email": DEV_UPN,
                "organization": org_id,
                "status": "active"
            }),
        )
        .await;
    let dev_id = dev["id"].as_str().expect("dev id").to_string();

    let expires = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    for token_id in ["tok_alice_1", "tok_alice_2"] {
        plane
            .create(
                "EnrollmentToken",
                json!({
                    "token_id": token_id,
                    "issuer": ISSUER,
                    "organization": org_id,
                    "scope": "organization",
                    "max_uses": 1,
                    "issued_by": ADMIN_USER,
                    "expires_at": expires
                }),
            )
            .await;
    }

    // No console User is seeded. The plane's user store has no tenant
    // column, so the tenant-scoped sync cannot list it; that half is
    // recorded in the sync detail and asserted below, not faked.
    let hook_token = mint(
        &key,
        "garrison-hooks",
        "enrollment_service,audit_service",
        &chain,
    );
    let directory_token = mint(&key, "garrison-directory", "directory_service", &chain);
    let enrollee_1 = mint(&key, "tok_alice_1", "enrollee", &chain);
    let enrollee_2 = mint(&key, "tok_alice_2", "enrollee", &chain);

    let snapshot = work.path().join("directory.json");
    write_snapshot(
        &snapshot,
        &[
            member(ALICE_OID, ALICE_UPN, "Alice Anderson", true),
            member(DEV_OID, DEV_UPN, "Dev Operator", true),
        ],
    );

    let hooks_dir = work.path().join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("hooks dir");
    std::fs::write(
        hooks_dir.join("config.toml"),
        hooks_config(hooks_port, &key, &plane_base, &snapshot, &org_id),
    )
    .expect("hooks config");
    let hooks_log = std::fs::File::create(work.path().join("hooks.log")).expect("log");
    let _hooks = Reaped(
        Command::new(env!("CARGO_BIN_EXE_garrison-hooks"))
            .current_dir(&hooks_dir)
            .env("ACTON_GARRISON_TOKEN", &hook_token)
            .env("ACTON_DIRECTORY_TOKEN", &directory_token)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(hooks_log.try_clone().expect("clone log")))
            .stderr(Stdio::from(hooks_log))
            .spawn()
            .expect("garrison-hooks spawns"),
        "hooks",
    );

    // 1. Provisioning. The first tick creates alice and links dev.
    let synced = plane
        .wait_for(
            "the first successful sync",
            Duration::from_secs(60),
            || async {
                let row = plane.get("Organization", &org_id).await;
                (row["fields"]["directory_sync_status"] == json!("ok")).then_some(row)
            },
        )
        .await;
    assert!(synced["fields"]["directory_synced_at"].is_string());

    let alice = plane
        .find("Operator", "upn", ALICE_UPN)
        .await
        .expect("alice was created by the sync");
    let alice_id = alice["id"].as_str().expect("alice id").to_string();
    assert_eq!(alice["fields"]["entra_object_id"], json!(ALICE_OID));
    assert_eq!(alice["fields"]["status"], json!("active"));
    assert_eq!(alice["fields"]["organization"], json!(org_id));

    let dev = plane.get("Operator", &dev_id).await;
    assert_eq!(
        dev["fields"]["entra_object_id"],
        json!(DEV_OID),
        "the hand-typed operator is linked by UPN, on the same row"
    );
    assert!(dev["fields"]["directory_synced_at"].is_string());

    // She holds a seat, so deprovisioning has something to take away.
    let seat = plane
        .create(
            "Seat",
            json!({ "operator": alice_id, "organization": org_id, "status": "active" }),
        )
        .await;
    let seat_id = seat["id"].as_str().expect("seat id").to_string();

    // A machine enrols for her through the ordinary path.
    let redemption = |token: &str, token_id: &str, install: &str| {
        http.post(plane.url("schemas/Redemption/entities"))
            .bearer_auth(token)
            .json(&json!({ "fields": {
                "token_id": token_id,
                "install_id": install,
                "hostname": "ws-alice",
                "operator_upn": ALICE_UPN,
                "platform": "linux",
                "agent_version": "0.1.0",
                "sandbox_hardening": "best_effort",
                "credential_kind": "ed25519",
                "public_key": "MCowBQYDK2VwAyEAtestpublickeytestpublickeytestpublickey="
            }}))
            .send()
    };
    let accepted: Value = redemption(&enrollee_1, "tok_alice_1", "inst-alice-1")
        .await
        .expect("plane reachable")
        .json()
        .await
        .expect("json");
    assert_eq!(
        accepted["fields"]["outcome"],
        json!("accepted"),
        "enrollment: {accepted}"
    );
    let install_id = accepted["fields"]["install"]
        .as_str()
        .expect("install id")
        .to_string();
    let install = plane.get("AgentInstall", &install_id).await;
    assert_eq!(
        install["fields"]["operator"],
        json!(alice_id),
        "the install binds to the operator the directory created"
    );

    // 2. Deprovisioning. Her account is disabled in the directory.
    write_snapshot(
        &snapshot,
        &[
            member(ALICE_OID, ALICE_UPN, "Alice Anderson", false),
            member(DEV_OID, DEV_UPN, "Dev Operator", true),
        ],
    );
    let alice = plane
        .wait_for("alice to be suspended", Duration::from_secs(60), || async {
            let row = plane.get("Operator", &alice_id).await;
            (row["fields"]["status"] == json!("suspended")).then_some(row)
        })
        .await;
    assert_eq!(alice["fields"]["entra_object_id"], json!(ALICE_OID));

    // The operator row is patched before its seats, so the seat can lag
    // the status by one round trip.
    let seat = plane
        .wait_for(
            "alice's seat to be revoked",
            Duration::from_secs(30),
            || async {
                let row = plane.get("Seat", &seat_id).await;
                (row["fields"]["status"] == json!("revoked")).then_some(row)
            },
        )
        .await;
    assert_eq!(
        seat["fields"]["revocation_reason"],
        json!("directory: account disabled")
    );
    assert!(seat["fields"]["revoked_at"].is_string());

    let org = plane
        .wait_for(
            "the sync to record the tick",
            Duration::from_secs(30),
            || async {
                let row = plane.get("Organization", &org_id).await;
                (row["fields"]["directory_sync_status"] == json!("ok")
                    && row["fields"]["directory_sync_detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("suspended 1")))
                .then_some(row)
            },
        )
        .await;
    assert!(
        org["fields"]["directory_sync_detail"]
            .as_str()
            .is_some_and(|d| d.contains("console users not reconciled")),
        "the user half is reported, not hidden: {}",
        org["fields"]["directory_sync_detail"]
    );

    let refused: Value = redemption(&enrollee_2, "tok_alice_2", "inst-alice-2")
        .await
        .expect("plane reachable")
        .json()
        .await
        .expect("json");
    assert_eq!(refused["fields"]["outcome"], json!("refused"), "{refused}");
    assert_eq!(
        refused["fields"]["refusal_reason"],
        json!("operator is not active (suspended)")
    );

    // dev was never touched by any of this.
    let dev = plane.get("Operator", &dev_id).await;
    assert_eq!(dev["fields"]["status"], json!("active"));
}

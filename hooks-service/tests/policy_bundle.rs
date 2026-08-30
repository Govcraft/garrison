//! The publish gate, end to end, against a real plane.
//!
//! One PostgreSQL container, one `schemaforge serve` on the repository's own
//! schemas and policies, one `garrison-hooks` bound to
//! `PolicyBundle.before_validate`. Nothing is faked past the process
//! boundary: the plane's `@require` on `checksum`, the hook's read-back of
//! the bundle's rules with its own bearer, `garrison_policy::validate`, and
//! `garrison_policy::checksum` all run for real.
//!
//! What it proves:
//!
//! 1. A draft that flips to `published` comes back carrying a 64-character
//!    BLAKE3 the submitter never sent, and that value is exactly what
//!    `garrison_policy::checksum` computes over the same rows read back from
//!    the plane. That is the whole basis of "the machine is running the
//!    policy we published": if the two ends disagreed, every install would
//!    report drift.
//! 2. A bundle holding a command rule that does not match its own
//!    `match_examples` cannot be published at all, and the refusal names the
//!    rule and the example. A rule nobody can check is a rule nobody should
//!    distribute.
//!
//! Skips, with a printed reason, when `schemaforge` is not on `PATH` or no
//! container runtime answers (`DOCKER_HOST=unix:///run/user/1000/podman/podman.sock`
//! for rootless podman).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use garrison_policy::{Bundle, BundleHeader, CommandRule, ModelEndpoint, ToolRule};
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "garrison-test-admin";
const ISSUER: &str = "garrison-control-plane";

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
    /// The bearer every seed and assertion uses. The login token creates the
    /// Organization; after that a `platform_admin` service token scoped to it
    /// takes over, because a row written without a tenant chain lands with no
    /// tenant and is invisible to every tenant-scoped bearer, including the
    /// hooks service under test.
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

    /// Every row of `schema` whose `field` equals `value`.
    ///
    /// One condition, because the query grammar takes exactly one; anything
    /// compound is filtered in Rust, here as everywhere else.
    async fn query(&self, schema: &str, field: &str, value: &str) -> Vec<Value> {
        let response = self
            .http
            .post(self.url(&format!("schemas/{schema}/entities/query")))
            .bearer_auth(&self.admin)
            .json(&json!({
                "filter": { "field": field, "op": "eq", "value": value },
                "limit": 100
            }))
            .send()
            .await
            .expect("plane reachable");
        let body: Value = response.json().await.expect("json body");
        body["entities"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .to_vec()
    }

    /// Attempts an update and hands back whatever the plane said, refusal
    /// included. The publish gate's whole job is to refuse, so a helper that
    /// asserted success could not test it.
    async fn patch(&self, schema: &str, id: &str, fields: Value) -> (reqwest::StatusCode, Value) {
        let response = self
            .http
            .patch(self.url(&format!("schemas/{schema}/entities/{id}")))
            .bearer_auth(&self.admin)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .expect("plane reachable");
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        (status, body)
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

/// A SchemaForge row as the policy crate reads one: `{id, …fields}`.
///
/// The plane answers `{"id": …, "fields": {…}}` and the shared types
/// deserialize from the flattened shape, because that is what both the hook
/// and the daemon hold. Flattening here rather than writing a second set of
/// serde attributes is the point of the shared crate.
fn flatten(row: &Value) -> Value {
    let mut fields = row["fields"].clone();
    if let Some(object) = fields.as_object_mut() {
        object.insert("id".to_string(), row["id"].clone());
    }
    fields
}

fn read_row<T: serde::de::DeserializeOwned>(row: &Value, what: &str) -> T {
    serde_json::from_value(flatten(row)).unwrap_or_else(|error| panic!("{what} parses: {error}"))
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

[[schema_forge.hooks.bindings]]
schema          = "PolicyBundle"
event           = "BeforeValidate"
endpoint        = "http://127.0.0.1:{hooks_port}"
timeout_ms      = 15000
required        = true
descriptor_path = "{descriptor}"
"#,
        key = key.display(),
        descriptor = descriptor.display(),
    )
}

fn hooks_config(port: u16, key: &Path, plane: &str) -> String {
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

#[tokio::test]
async fn publishing_a_bundle_stamps_the_checksum_the_daemon_will_verify() {
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

    // The hook reads the bundle's rules back with its own bearer. The policy
    // schemas grant `enrollment_service` read and nothing else, which is
    // exactly what a gate that only answers a question needs.
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

    // The endpoint this organization approved, cited by the bundle below.
    let endpoint = plane
        .create(
            "ModelEndpoint",
            json!({
                "name": "Agency Ollama",
                "organization": org_id,
                "provider_type": "ollama",
                "model": "qwen3-coder",
                "base_url": "http://127.0.0.1:11434/v1/",
                "hosting": "on_prem",
                "authorization": "ato",
                "approved_at": chrono::Utc::now().to_rfc3339(),
                "approved_by": "ciso@example-agency.gov",
                "status": "approved"
            }),
        )
        .await;
    let endpoint_id = endpoint["id"].as_str().expect("endpoint id").to_string();

    // A draft. `status` defaults to `draft`, so nothing is gated yet.
    let bundle = plane
        .create(
            "PolicyBundle",
            json!({
                "name": "Baseline",
                "version": 1,
                "organization": org_id,
                "description": "the rules every workstation runs under",
                "default_approval_mode": "on_request",
                "network_egress": "deny",
                "allow_unsandboxed_escalation": false,
                "allowed_endpoints": [endpoint_id]
            }),
        )
        .await;
    let bundle_id = bundle["id"].as_str().expect("bundle id").to_string();
    assert_eq!(bundle["fields"]["status"], json!("draft"));
    assert_eq!(
        bundle["fields"]["checksum"],
        json!(""),
        "a draft has nothing to checksum"
    );

    for rule in [
        json!({
            "name": "git read-only",
            "bundle": bundle_id,
            "organization": org_id,
            "program": "git",
            "argv_pattern": ["status"],
            "decision": "allow",
            "justification": "reading the working tree changes nothing",
            "match_examples": ["git status", "bash -lc 'git status'"],
            "not_match_examples": ["git push origin main"],
            "priority": 10
        }),
        json!({
            "name": "no recursive force removal",
            "bundle": bundle_id,
            "organization": org_id,
            "program": "rm",
            "argv_pattern": ["-rf", "**"],
            "decision": "forbid",
            "justification": "an unrecoverable delete is never worth the round trip",
            "match_examples": ["rm -rf /tmp/build"],
            "not_match_examples": ["rm one-file.txt"],
            "priority": 5
        }),
    ] {
        plane.create("CommandRule", rule).await;
    }

    plane
        .create(
            "ToolRule",
            json!({
                "tool_name": "read_file",
                "bundle": bundle_id,
                "organization": org_id,
                "decision": "auto_approve",
                "justification": "reading a file the operator already opened is not a change",
                "sandbox_required": false
            }),
        )
        .await;

    // The hook service may still be starting; a `required` binding the plane
    // cannot reach refuses the publish, which is the correct behaviour and a
    // useless thing to assert on. Retry until it answers.
    let published = plane
        .wait_for(
            "the publish gate to answer",
            Duration::from_secs(60),
            || async {
                let (status, body) = plane
                    .patch("PolicyBundle", &bundle_id, json!({ "status": "published" }))
                    .await;
                if !status.is_success() {
                    eprintln!("the publish gate has not answered yet: {status} {body}");
                }
                status.is_success().then_some(body)
            },
        )
        .await;
    assert_eq!(published["fields"]["status"], json!("published"));

    let row = plane.get("PolicyBundle", &bundle_id).await;
    let stamped = row["fields"]["checksum"]
        .as_str()
        .expect("a published bundle carries a checksum")
        .to_string();
    assert_eq!(stamped.len(), 64, "BLAKE3 in lowercase hex: {stamped}");
    assert!(
        stamped
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "BLAKE3 in lowercase hex: {stamped}"
    );
    assert!(
        row["fields"]["published_at"].is_string(),
        "the gate records when: {row}"
    );
    assert_eq!(
        row["fields"]["published_by"],
        json!("seed-admin"),
        "the gate records who, from the token rather than the submission: {row}"
    );

    // The daemon's half of the same question: pull the rows, hash them with
    // the shared crate, and see the plane's answer.
    let mut header: BundleHeader = read_row(&row, "the bundle header");
    header.checksum = String::new();
    let pulled = Bundle {
        header,
        command_rules: plane
            .query("CommandRule", "bundle", &bundle_id)
            .await
            .iter()
            .map(|row| read_row::<CommandRule>(row, "a command rule"))
            .collect(),
        tool_rules: plane
            .query("ToolRule", "bundle", &bundle_id)
            .await
            .iter()
            .map(|row| read_row::<ToolRule>(row, "a tool rule"))
            .collect(),
        endpoints: vec![read_row::<ModelEndpoint>(
            &plane.get("ModelEndpoint", &endpoint_id).await,
            "the endpoint",
        )],
    };
    assert_eq!(pulled.command_rules.len(), 2, "both rules came back");
    assert_eq!(pulled.tool_rules.len(), 1);
    assert_eq!(
        garrison_policy::checksum(&pulled),
        stamped,
        "the plane stamped a checksum the daemon cannot reproduce, which would ground the fleet"
    );

    // And the same rows, with the plane's own record of the checksum, verify.
    let mut in_force = pulled.clone();
    in_force.header.checksum = stamped.clone();
    assert!(
        garrison_policy::verify(&in_force).is_ok(),
        "the bundle an install would put in force does not verify"
    );

    // 2. A rule that does not agree with its own examples.
    let bad = plane
        .create(
            "PolicyBundle",
            json!({
                "name": "Unreviewable",
                "version": 1,
                "organization": org_id,
                "allowed_endpoints": [endpoint_id]
            }),
        )
        .await;
    let bad_id = bad["id"].as_str().expect("bundle id").to_string();
    plane
        .create(
            "CommandRule",
            json!({
                "name": "npm ci only",
                "bundle": bad_id,
                "organization": org_id,
                "program": "npm",
                "argv_pattern": ["ci"],
                "decision": "allow",
                "justification": "a lockfile install is reproducible",
                // The author meant this rule to cover `npm install`. It does
                // not, and this is the last moment anybody would notice.
                "match_examples": ["npm install express"],
                "not_match_examples": []
            }),
        )
        .await;

    let (status, body) = plane
        .patch("PolicyBundle", &bad_id, json!({ "status": "published" }))
        .await;
    assert!(
        !status.is_success(),
        "a bundle whose rule fails its own examples was published anyway: {status} {body}"
    );
    let said = body.to_string();
    assert!(
        said.contains("npm ci only"),
        "the refusal must name the rule so one attempt reveals the problem: {said}"
    );
    assert!(
        said.contains("npm install express"),
        "the refusal must name the example that disagreed: {said}"
    );

    let unchanged = plane.get("PolicyBundle", &bad_id).await;
    assert_eq!(
        unchanged["fields"]["status"],
        json!("draft"),
        "a refused publish leaves the draft a draft"
    );
    assert_eq!(
        unchanged["fields"]["checksum"],
        json!(""),
        "and stamps nothing on it"
    );
}

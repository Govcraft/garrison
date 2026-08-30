//! The seat rule, end to end, against a real control plane.
//!
//! One PostgreSQL container, one `schemaforge serve` on the repository's own
//! schemas and policies, and the daemon's own reader
//! (`garrison_agent::entitlement::fetch::fetch`) spending an `operator`
//! bearer against it. Nothing about the rows is faked: the three reads, the
//! Cedar `@access` fences, the `@require` on a revocation reason, and the
//! adjudication all run for real.
//!
//! What it proves:
//!
//! 1. An `assigned` seat is not an entitlement. Only a live `active` seat
//!    lets a turn run.
//! 2. Activated, that seat entitles the install, and the standing names the
//!    seat and the tier the console set.
//! 3. The plane will not let a seat be revoked silently. A PATCH that moves
//!    `status` to `revoked` with no reason is rejected, so the explanation an
//!    operator reads is a fact the schema enforces rather than a convention.
//! 4. Revoked with a reason, the very next check refuses and carries that
//!    reason, and the refusal carries no grace: a cached refusal never ages
//!    into permission.
//! 5. A retired install is refused whatever its operator's seats say.
//!
//! Skips, with a printed reason, when `schemaforge` is not on `PATH` or no
//! container runtime answers (`DOCKER_HOST=unix:///run/user/1000/podman/podman.sock`
//! for rootless podman).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use garrison_agent::entitlement::fetch::fetch;
use garrison_agent::entitlement::verdict::{admit, Refusal, SeatAdmission, Tier, Verdict};
use garrison_agent::plane::api::Api;
use garrison_agent::plane::session::Session;

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "garrison-test-admin";
const ISSUER: &str = "garrison-control-plane";
const OPERATOR_UPN: &str = "seat-holder@example-agency.gov";

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

/// The console's view of the plane: a `platform_admin` bearer, used to seed
/// rows and to play the part of an administrator revoking a seat.
struct Console {
    http: reqwest::Client,
    base: String,
    admin: String,
}

impl Console {
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

    /// Patches a row and hands back the status, so a caller can assert on a
    /// refusal as easily as on a success.
    async fn patch(&self, schema: &str, id: &str, fields: Value) -> (u16, Value) {
        let response = self
            .http
            .patch(self.url(&format!("schemas/{schema}/entities/{id}")))
            .bearer_auth(&self.admin)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .expect("plane reachable");
        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        (status, body)
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
        .expect("the agent crate sits in the repository root")
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
async fn a_seat_is_only_an_entitlement_while_the_plane_says_it_is() {
    if schemaforge().is_none() {
        garrison_wire::skip_live("schemaforge is not on PATH");
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
            garrison_wire::skip_live(&format!("no container runtime answered ({error})"));
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
    let mut console = Console {
        http: http.clone(),
        base: plane_base.clone(),
        admin,
    };

    let org = console
        .create(
            "Organization",
            json!({
                "name": "Example Agency",
                "slug": "example-agency",
                "impact_level": "commercial",
                "seats_licensed": 5,
                "owner_id": ADMIN_USER
            }),
        )
        .await;
    let org_id = org["id"].as_str().expect("org id").to_string();

    // Every row from here on is written with a tenant chain. A row written
    // without one lands with no tenant and is invisible to the very bearer
    // the daemon holds, which would make this test prove nothing.
    let chain = json!([{ "schema": "Organization", "entity_id": org_id }]).to_string();
    console.admin = mint(&key, "seed-admin", "platform_admin", &chain);

    let operator = console
        .create(
            "Operator",
            json!({
                "upn": OPERATOR_UPN,
                "display_name": "Seat Holder",
                "email": OPERATOR_UPN,
                "organization": org_id,
                "status": "active"
            }),
        )
        .await;
    let operator_id = operator["id"].as_str().expect("operator id").to_string();

    let install = console
        .create(
            "AgentInstall",
            json!({
                "install_id": "inst-seat-1",
                "hostname": "ws-seat",
                "operator": operator_id,
                "organization": org_id,
                "platform": "linux",
                "agent_version": "0.1.0",
                "sandbox_hardening": "best_effort",
                "lifecycle": "durable",
                "status": "active"
            }),
        )
        .await;
    let install_id = install["id"].as_str().expect("install id").to_string();

    // The seat starts `assigned`, which is exactly what an unactivated seat
    // looks like, so the first check proves the daemon does not spend one.
    let seat = console
        .create(
            "Seat",
            json!({
                "operator": operator_id,
                "organization": org_id,
                "tier": "elevated",
                "status": "assigned"
            }),
        )
        .await;
    let seat_id = seat["id"].as_str().expect("seat id").to_string();

    // The daemon's own credential: the role the install-token exchange hands
    // a running agent, no wider.
    let bearer = mint(&key, "inst-seat-1", "operator", &chain);
    let session = Session {
        api: Api::new(&plane_base, &bearer).expect("an api over the test plane"),
        install: install_id.clone(),
        organization: org_id.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    };

    // 1. An assigned seat is not an entitlement.
    let standing = fetch(&session, None, Utc::now())
        .await
        .expect("the plane answered");
    assert_eq!(
        standing.verdict,
        Verdict::Refused(Refusal::SeatNotActive {
            status: "assigned".to_string()
        }),
        "an assigned seat does not let a turn run"
    );

    // 2. Activated, it does, and the standing names it.
    let (status, body) = console
        .patch(
            "Seat",
            &seat_id,
            json!({ "status": "active", "activated_at": Utc::now().to_rfc3339() }),
        )
        .await;
    assert!((200..300).contains(&status), "activate: {status} {body}");

    let standing = fetch(&session, None, Utc::now())
        .await
        .expect("the plane answered");
    assert_eq!(
        standing.verdict,
        Verdict::Entitled {
            seat: seat_id.clone(),
            tier: Tier::Elevated
        },
        "an active seat entitles this install, at the tier the console set"
    );
    assert_eq!(
        standing.grace_secs,
        24 * 60 * 60,
        "commercial and elevated is a 24-hour offline window"
    );

    // 3. The plane will not let a seat be revoked silently.
    let (status, body) = console
        .patch("Seat", &seat_id, json!({ "status": "revoked" }))
        .await;
    assert!(
        (400..500).contains(&status),
        "a revocation with no reason must be refused, got {status} {body}"
    );
    let standing = fetch(&session, None, Utc::now())
        .await
        .expect("the plane answered");
    assert!(
        matches!(standing.verdict, Verdict::Entitled { .. }),
        "a refused revocation changes nothing: {:?}",
        standing.verdict
    );

    // 4. Revoked with a reason, the next check refuses and says why.
    let (status, body) = console
        .patch(
            "Seat",
            &seat_id,
            json!({
                "status": "revoked",
                "revoked_at": Utc::now().to_rfc3339(),
                "revocation_reason": "offboarded by the security officer"
            }),
        )
        .await;
    assert!((200..300).contains(&status), "revoke: {status} {body}");

    let standing = fetch(&session, None, Utc::now())
        .await
        .expect("the plane answered");
    match &standing.verdict {
        Verdict::Refused(Refusal::SeatRevoked { reason, .. }) => assert_eq!(
            reason, "offboarded by the security officer",
            "the refusal carries the reason the console recorded"
        ),
        other => panic!("a revoked seat must refuse the next turn, got {other:?}"),
    }

    // A refusal is a verdict, not an outage: it carries no window to ride
    // out. This is the property that keeps a revoked install from running for
    // the rest of what would have been its grace period.
    let far_future = Utc::now() + chrono::Duration::days(30);
    let admission = admit(Some(&standing), None, far_future);
    assert!(
        matches!(admission, SeatAdmission::Refuse(_)),
        "a cached refusal never ages into permission: {admission:?}"
    );

    // 5. A retired install is refused whatever its operator's seats say.
    let (status, body) = console
        .patch(
            "Seat",
            &seat_id,
            json!({ "status": "active", "revocation_reason": "" }),
        )
        .await;
    assert!((200..300).contains(&status), "reinstate: {status} {body}");
    let (status, body) = console
        .patch("AgentInstall", &install_id, json!({ "status": "retired" }))
        .await;
    assert!((200..300).contains(&status), "retire: {status} {body}");

    let standing = fetch(&session, None, Utc::now())
        .await
        .expect("the plane answered");
    assert_eq!(
        standing.verdict,
        Verdict::Refused(Refusal::InstallNotActive {
            status: "retired".to_string()
        }),
        "a retired machine does not run on a live seat"
    );
}

//! Scaffolded once by `schema-forge hooks generate` — edit freely.
//!
//! Subsequent runs are additive: new `@hook`-annotated schemas get
//! spliced into `mod pb { ... }` and the `GrpcServicesBuilder` chain
//! between the `SCHEMAFORGE_HOOKS_*` marker comments below. Keep
//! those markers in place and your custom module imports, env-var
//! validation, and per-service constructor wiring will survive
//! every regen. Use `--regenerate` to opt out and rewrite this
//! file from scratch.
//!
//! # Who is allowed to call this
//!
//! A hook invocation carries a snapshot of the entity's fields and the
//! subject claim of the user whose request triggered it, so this process
//! must not answer to anyone who can reach its port. Serving through
//! `ServiceBuilder` is what prevents that: when `config.toml` has a
//! `[token]` section, acton-service applies token authentication to
//! every registered gRPC service automatically, and the forge presents
//! a short-lived PASETO minted from the same key. Add `[caller_auth]`
//! on top to require a specific mutual-TLS SAN.
//!
//! Replacing this with a bare `tonic::transport::Server` removes all of
//! that silently — the RPCs keep working, they just stop being
//! authenticated.

mod adjudicate;
mod config;
mod directory;
mod hooks;
mod install_token;
mod plane;
mod reconcile;
mod silence;
mod sync;

mod pb {
    // SCHEMAFORGE_HOOKS_PB_BEGIN — DO NOT REMOVE (additive insertion marker)
    pub mod audit_event {
        tonic::include_proto!("schema_forge_hooks.audit_event");
    }
    pub mod redemption {
        tonic::include_proto!("schema_forge_hooks.redemption");
    }
    pub mod policy_bundle {
        tonic::include_proto!("schema_forge_hooks.policy_bundle");
    }
    // SCHEMAFORGE_HOOKS_PB_END
}

use std::sync::Arc;
use std::time::Duration;

use acton_service::error::Error;
use acton_service::grpc::server::GrpcServicesBuilder;
use acton_service::prelude::*;

use crate::config::{DirectoryMode, HooksConfig};
use crate::directory::Directory;
use crate::hooks::redemption::DirectoryGate;
use crate::install_token::{Exchange, NonceLedger};
use crate::plane::Plane;
use crate::reconcile::Policy;
use crate::silence::{SilenceSettings, SilenceSweep};
use crate::sync::{DirectorySync, SyncSettings};

#[tokio::main]
async fn main() -> Result<()> {
    // Reads ./config.toml, then $XDG_CONFIG_HOME and /etc; `ACTON_*`
    // environment variables override the file. The `[grpc]` section must
    // set `enabled = true` or the build below is refused rather than
    // silently serving no RPCs.
    let config: Config = Config::load()?;

    // The same file, read a second time through our own extension type. Two
    // loads rather than one because `GrpcServicesBuilder::build` takes an
    // untyped `AppState`, so the framework path has to stay `Config<()>`;
    // threading `HooksConfig` through it would mean giving up the health
    // service's dependency probing to keep one call.
    let custom = Config::<HooksConfig>::load()?.custom;
    let garrison = custom.garrison;
    let directory = custom.directory;

    // Refuse to boot on a half-configured plane rather than discover it on the
    // night of the first enrollment. Every missing field is named at once.
    let mut missing = garrison.missing();
    missing.extend(directory.missing());
    if !missing.is_empty() {
        return Err(Error::ValidationError(format!(
            "missing required configuration: {}",
            missing.join(", ")
        )));
    }
    let invalid = directory.invalid();
    if !invalid.is_empty() {
        return Err(Error::ValidationError(format!(
            "invalid configuration: {}",
            invalid.join("; ")
        )));
    }

    // One client for the enrollment hook. It holds the `enrollment_service`
    // bearer, which is authorized for a handful of operations and nothing else.
    let plane = Plane::new(&garrison.url, &garrison.token)
        .map_err(|e| Error::ValidationError(e.to_string()))?;

    // A second client for the audit ingest and the liveness sweep. Same
    // bearer, which therefore has to carry `audit_service` beside
    // `enrollment_service`; a separate `Plane` value rather than a shared one
    // so the two paths cannot come to depend on each other's state.
    let audit_plane = Plane::new(&garrison.url, &garrison.token)
        .map_err(|e| Error::ValidationError(e.to_string()))?;

    // The sweep that notices an install which stopped shipping. Parked where
    // the supervised actor's `after_start` finds it on every incarnation. Both
    // intervals are floored at a second: a zero would arm no schedule at all
    // and the liveness signal would be silently absent.
    silence::install(Arc::new(SilenceSettings {
        plane: Plane::new(&garrison.url, &garrison.token)
            .map_err(|e| Error::ValidationError(e.to_string()))?,
        silence: Duration::from_secs(garrison.silence.max(1)),
        sweep: Duration::from_secs(garrison.sweep.max(1)),
    }));

    // The install-token exchange: the one authenticated path from a daemon to
    // the plane. It mints with the same `[token]` key this service verifies
    // inbound hook calls against, so the bearer it hands out is
    // indistinguishable from one the forge's own CLI produced. A missing or
    // unusable key is a refusal to boot, not a 500 on the first enrollment.
    let key_path = install_token_key(&config)?;
    let exchange = Arc::new(Exchange::new(
        Plane::new(&garrison.url, &garrison.token)
            .map_err(|e| Error::ValidationError(e.to_string()))?,
        key_path,
        garrison.issuer.clone(),
        garrison.lifetime,
    )?);

    // The directory sync, when enabled, holds its own bearer for the
    // `directory_service` role. Settings are parked where the supervised
    // actor's `after_start` can find them on every incarnation.
    let gate = DirectoryGate {
        enabled: directory.enabled(),
        staleness: Duration::from_secs(directory.staleness),
    };
    if directory.enabled() {
        let source: Arc<dyn Directory> = match directory.mode {
            DirectoryMode::File => Arc::new(directory::file::FileDirectory::new(&directory.path)),
            DirectoryMode::Graph => Arc::new(
                directory::graph::GraphDirectory::new(
                    &directory.authority,
                    &directory.graph,
                    &directory.client,
                    &directory.secret,
                )
                .map_err(|e| Error::ValidationError(e.to_string()))?,
            ),
            DirectoryMode::Off => unreachable!("enabled() is false for Off"),
        };
        let sync_plane = Plane::new(&garrison.url, &directory.token)
            .map_err(|e| Error::ValidationError(e.to_string()))?;
        sync::install(Arc::new(SyncSettings {
            directory: source,
            organization: directory.organization.clone(),
            plane: sync_plane,
            interval: Duration::from_secs(directory.interval),
            policy: Policy {
                max_offboard_fraction: directory.fraction,
            },
        }));
    } else {
        tracing::warn!(
            "[directory] mode is off: operators are hand-typed and nothing deprovisions them"
        );
    }

    // The health service probes whatever dependencies the config declares.
    let state = AppState::builder().config(config.clone()).build().await?;

    // Reflection is deliberately not enabled: it would publish every
    // hook message definition, and therefore your entity field names, to
    // unauthenticated callers — reflection and health are exempt from the
    // token layer. Turn it on with `.with_reflection()` plus
    // `.add_file_descriptor_set(..)` only where that exposure is fine.
    let grpc_services = GrpcServicesBuilder::new()
        .with_health()
        // SCHEMAFORGE_HOOKS_SERVICES_BEGIN — DO NOT REMOVE (additive insertion marker)
        .add_service(
            pb::audit_event::audit_event_hooks_server::AuditEventHooksServer::new(
                hooks::audit_event::Service::new(audit_plane),
            ),
        )
        .add_service(
            pb::redemption::redemption_hooks_server::RedemptionHooksServer::new(
                hooks::redemption::Service::new(plane, garrison.issuer).with_directory(gate),
            ),
        )
        .add_service(
            pb::policy_bundle::policy_bundle_hooks_server::PolicyBundleHooksServer::new(
                hooks::policy_bundle::Service,
            ),
        )
        // SCHEMAFORGE_HOOKS_SERVICES_END
        .build(Some(state));

    // One HTTP route beside the gRPC hooks, on the same listener and the same
    // port. `.with_base_path("/api")` is not decoration: without it the
    // versioned router mounts at `/v1/...`, the path `[token] public_paths`
    // exempts never matches, and every exchange 401s.
    let routes = VersionedApiBuilder::new()
        .with_base_path("/api")
        .add_version(ApiVersion::V1, |router| {
            router.merge(install_token::routes(exchange))
        })
        .build_routes();

    let mut builder = ServiceBuilder::new()
        .with_config(config)
        .with_actor::<NonceLedger>()
        .with_actor::<SilenceSweep>()
        .with_routes(routes)
        .with_grpc_services(grpc_services);
    if directory.enabled() {
        builder = builder.with_actor::<DirectorySync>();
    }
    builder.try_build()?.serve().await?;
    Ok(())
}

/// The PASETO key this service both verifies and mints with, once the
/// exchange's own route is known to be reachable.
///
/// The key is read from the framework's own `[token]` section rather than a
/// second setting, because two paths that must name the same file are two
/// paths that will one day differ.
///
/// The `public_paths` check is not pedantry. A daemon arriving at the
/// exchange has no bearer by definition, so without that exemption every
/// exchange answers 401 from middleware the route never sees, and the symptom
/// points at the daemon's credentials rather than at this file. Refusing to
/// boot names the missing line instead.
fn install_token_key(config: &Config) -> Result<std::path::PathBuf> {
    let Some(acton_service::config::TokenConfig::Paseto(paseto)) = config.token.as_ref() else {
        return Err(Error::ValidationError(
            "the install-token exchange mints with the plane's PASETO key; \
             add a [token] section with format = \"paseto\" and key_path"
                .to_string(),
        ));
    };
    if !paseto
        .public_paths
        .iter()
        .any(|prefix| install_token::PUBLIC_PATH.starts_with(prefix.as_str()))
    {
        return Err(Error::ValidationError(format!(
            "[token] public_paths does not exempt {}; a daemon exchanging an \
             assertion carries no bearer and would be refused before the route \
             is reached",
            install_token::PUBLIC_PATH
        )));
    }
    Ok(paseto.key_path.clone())
}

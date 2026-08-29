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
mod hooks;
mod plane;

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

use acton_service::error::Error;
use acton_service::grpc::server::GrpcServicesBuilder;
use acton_service::prelude::*;

use crate::config::HooksConfig;
use crate::plane::Plane;

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
    let garrison = Config::<HooksConfig>::load()?.custom.garrison;

    // Refuse to boot on a half-configured plane rather than discover it on the
    // night of the first enrollment. Every missing field is named at once.
    let missing = garrison.missing();
    if !missing.is_empty() {
        return Err(Error::ValidationError(format!(
            "missing required configuration: {}",
            missing.join(", ")
        )));
    }

    // One client for the process. It holds the `enrollment_service` bearer,
    // which is authorized for four operations and nothing else.
    let plane = Plane::new(&garrison.url, &garrison.token)
        .map_err(|e| Error::ValidationError(e.to_string()))?;

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
                hooks::audit_event::Service,
            ),
        )
        .add_service(
            pb::redemption::redemption_hooks_server::RedemptionHooksServer::new(
                hooks::redemption::Service::new(plane, garrison.issuer),
            ),
        )
        .add_service(
            pb::policy_bundle::policy_bundle_hooks_server::PolicyBundleHooksServer::new(
                hooks::policy_bundle::Service,
            ),
        )
        // SCHEMAFORGE_HOOKS_SERVICES_END
        .build(Some(state));

    ServiceBuilder::new()
        .with_config(config)
        .with_grpc_services(grpc_services)
        .try_build()?
        .serve()
        .await?;
    Ok(())
}

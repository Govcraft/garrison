//! Per-schema hook service implementations.
//!
//! Module declarations for annotated schemas are managed additively
//! between the `SCHEMAFORGE_HOOKS_MODS_*` markers below — keep those
//! comments in place. Add your own `pub mod` lines outside the
//! markers if you want them to survive every regen.

// SCHEMAFORGE_HOOKS_MODS_BEGIN — DO NOT REMOVE (additive insertion marker)
pub mod audit_event;
pub mod policy_bundle;
pub mod redemption;
// SCHEMAFORGE_HOOKS_MODS_END

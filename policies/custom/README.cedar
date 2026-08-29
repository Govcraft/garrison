// Hand-written Cedar policies for the Garrison control plane.
//
// Everything the .schema files declare — @access, @field_access, @tenant,
// @owner — is lowered into generated policies automatically; nothing here
// needs to restate it. This directory is for the decisions the DSL cannot
// express, for example scoping a resource by an Entra claim carried on the
// token rather than by role.
//
// Two rules apply to anything added here:
//
//   1. The whole bundle is validated in strict mode on every load, so a
//      policy referencing an unknown attribute, action, or entity type fails
//      the build rather than silently never matching. `task plane:policies`
//      runs exactly what the runtime runs.
//
//   2. Reading an optional principal attribute must be guarded —
//      `principal has entra_object_id && principal.entra_object_id == ...` —
//      and the attribute must first be declared under
//      `[schema_forge.authz.principal_claims]` in config.toml.
//
// This file is comments only and contributes no policies.

// Audit export requires a directory identity.
//
// A console login whose User row carries `entra_object_id` gets that value
// projected onto `Forge::Principal` at login (see
// `[schema_forge.authz.principal_claims]` in config.toml). Service bearers
// minted by `schemaforge token generate` carry no such claim. Bulk export of
// the audit trail is the one action that must be attributable to a person
// the directory knows, so it is forbidden to any principal without one. The
// read grants are untouched; this narrows the copy, not the view.
//
// The attribute is optional on the principal, so it is tested with `has`
// rather than read directly; an unguarded read fails strict validation.
@id("garrison.auditevent.export_requires_directory_identity")
forbid (
    principal is Forge::Principal,
    action == Action::"ExportAuditEvent",
    resource is AuditEvent
) unless {
    principal has entra_object_id
};

// The audit trail is append-only, and export is a separate grant.
//
// Two things the .schema files cannot say, written here because Cedar can:
//
//   1. A `forbid` beats every `permit`, including the ones generated from
//      @access and including platform_admin's bypass. That is what makes
//      "nobody deletes" true rather than aspirational. Writing `delete: []`
//      in the schema does NOT do this — an empty list generates a permit for
//      any authenticated principal.
//
//   2. @export enables the export *endpoint* but grants nobody the distinct
//      Export{Entity} action. Without a permit here, export is denied to
//      everyone, which is the correct fail-closed default and also useless.

// An entry, once written, is what happened. It is not editable and not
// removable through the API by anyone.
//
// Records-retention deletion, when it comes, is a deliberate change to this
// file plus a documented disposition schedule — not a permission somebody
// already quietly holds.
@id("garrison.auditevent.append_only")
forbid (
    principal is Forge::Principal,
    action in [Action::"UpdateAuditEvent", Action::"DeleteAuditEvent"],
    resource is AuditEvent
);

// Chain state is maintained by the plane as entries arrive, so it updates.
// It still never disappears.
@id("garrison.auditchain.no_delete")
forbid (
    principal is Forge::Principal,
    action == Action::"DeleteAuditChain",
    resource is AuditChain
);

// Bulk export is the compliance-reporting path: the roles that already read
// the trail may take a copy of it. Operators, who append and cannot read,
// are absent here on purpose.
@id("garrison.auditevent.export")
permit (
    principal in Forge::Group::"auditor",
    action == Action::"ExportAuditEvent",
    resource is AuditEvent
);

@id("garrison.auditevent.export_security_officer")
permit (
    principal in Forge::Group::"security_officer",
    action == Action::"ExportAuditEvent",
    resource is AuditEvent
);

@id("garrison.auditevent.export_org_admin")
permit (
    principal in Forge::Group::"org_admin",
    action == Action::"ExportAuditEvent",
    resource is AuditEvent
);

@id("garrison.auditchain.export")
permit (
    principal in Forge::Group::"auditor",
    action == Action::"ExportAuditChain",
    resource is AuditChain
);

@id("garrison.auditchain.export_security_officer")
permit (
    principal in Forge::Group::"security_officer",
    action == Action::"ExportAuditChain",
    resource is AuditChain
);

@id("garrison.auditchain.export_org_admin")
permit (
    principal in Forge::Group::"org_admin",
    action == Action::"ExportAuditChain",
    resource is AuditChain
);

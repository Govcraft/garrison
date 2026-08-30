// Credentials are revoked, not deleted.
//
// The generated permits from @access already narrow deletion to org_admin.
// This narrows it to nobody, for the same reason the audit trail is
// append-only: the record that a key existed, was used from these addresses,
// and was revoked on this date for this reason is the only evidence that the
// revocation happened at all. Deleting the row deletes the incident.
//
// Rotation does not need deletion. A superseded credential moves to
// 'rotating' and then 'revoked', and the `supersedes` chain stays walkable
// back to enrollment.
@id("garrison.installcredential.no_delete")
forbid (
    principal is Forge::Principal,
    action == Action::"DeleteInstallCredential",
    resource is InstallCredential
);

// A spent enrollment token is the provenance of every install that redeemed
// it. Same reasoning, and the row is small.
@id("garrison.enrollmenttoken.no_delete")
forbid (
    principal is Forge::Principal,
    action == Action::"DeleteEnrollmentToken",
    resource is EnrollmentToken
);

// A redemption is a decided verdict, not a mutable row.
//
// The hook resolves `token_id` from the authenticated principal, and it runs
// on creates alone — an update to a decided redemption must not mint a second
// credential for the same install. That leaves update unattended: `@access`
// grants `write` to `enrollee`, and `write` covers update, so without this a
// same-organization enrollee could reach another install's row and rewrite the
// token it was decided under.
//
// The row is also the evidence a security officer reads when an unknown
// machine presents a revoked grant at 03:00. Same reasoning as
// `garrison.auditevent.append_only`: a record that can be edited afterwards is
// not a record.
@id("garrison.redemption.append_only")
forbid (
    principal is Forge::Principal,
    action == Action::"UpdateRedemption",
    resource is Redemption
);

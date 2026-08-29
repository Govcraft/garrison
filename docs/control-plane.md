# Garrison control plane

The control plane is the administrative half of Garrison: the place an
organization says who may run the agent, what the agent is allowed to do, and
what it actually did. It is a [SchemaForge](https://github.com/Govcraft/schemaforge)
application, which means the entity model in `schemas/` is the source of truth
for its tables, REST API, migrations, Cedar policies, and OpenAPI spec — there
is no hand-written CRUD layer to drift from it.

This is a roadmap document with one implemented part. Statements prefixed
**Implemented** describe this checkout; **Planned** describes intended work.

## Status

**Implemented:** the entity model (`schemas/`), the role hierarchy
(`policies/role_ranks.toml`), the service configuration (`config.toml`), and
the two gates that run without a database:

```sh
task plane:check      # parse the schemas, then strict-mode validate the Cedar bundle
```

18 schemas lower into a Cedar bundle of 231 policies, 12 of them hand-written
in `policies/custom/`, all strict-mode validated. The model has also been
applied end to end against a throwaway PostgreSQL 16 instance: 31 migration
steps, 18 tables, every `unique` constraint and every CEL rule type-checked at
apply time, and the three hook bindings validated against the generated
descriptor at startup. The server was then run against it and the
authorization and write-time rules exercised over HTTP — both delete
`forbid`s against a control case that succeeds, issuer separation between
enrollment artifacts and console bearers, and every `@require` on both its
passing and its failing branch. That database was discarded.

Tooling: `schemaforge` 0.37.2, PostgreSQL flavor.

The agent enrolls itself on first run (`agent/src/enrollment/`), against the
same endpoint and the same hook.

Entra ID is the authority for operators: `hooks-service/` runs a directory
sync that creates, links, renames, suspends, and offboards `Operator` rows
from a Microsoft Graph listing (or a JSON file), and the enrollment hook
refuses anyone the directory has not vouched for. See "Directory" below for
the rules and for what has and has not been proved against a real tenant.

**Planned:** everything else that moves bytes. The agent does not yet pull
policy from this plane or push audit to it, no database has been provisioned,
and there is no administration site. The
model landing first is deliberate — the wire contract between agent and plane is
the entity model, so it is the thing worth being wrong about early and cheaply.

## What SchemaForge owns, and what it does not

SchemaForge is itself an application on `acton-service`, and `acton-service`
owns the platform layer: token issuance and validation, account lifecycle,
sessions, TLS and mutual TLS, rate limiting, health probes, metrics, and the
Cedar *engine*. None of that is built here. What is built here is the part that
is true only because Garrison is Garrison: the entities, their access
annotations, and the role ranks that order them.

The same line runs through the identity model. SchemaForge's system `User`
schema is the login store for this administrative console — the humans who
open the admin UI. `Operator` is a different thing: the Entra ID principal a
running `garrison-agent` acts *for*. One person can be both, and in a small
deployment usually is, but conflating them would mean every developer who runs
the agent needs a console account.

## The model

Eight files, eighteen schemas, one tenancy root. Seventeen are Garrison's; the
eighteenth, `schemas/user.schema`, is the deployment's override of
SchemaForge's system `User` schema, redeclared verbatim plus the two columns
that carry directory identity into a console token.

### Tenancy — `schemas/organization.schema`

`Organization` is `@tenant(root)`: one boundary, one agency or program office.
Every other schema is `@tenant(parent: "Organization")`, so SchemaForge
generates a `forbid` policy per schema that rejects any access where the
principal is not a member of the record's tenant. Cross-tenant leakage is a
record-level Cedar decision, not a `WHERE` clause somebody has to remember.

`Team` groups operators so policy can be assigned to a squad rather than to
every developer by name.

`Organization.entra_group_id` names the Entra ID group whose members are the
organization's operators, and the three `directory_*` fields are the
reconciler's report: when it last ran, whether it succeeded, and what it
found. The `directory_service` role may write those three fields and no
others. Every field that says what the organization is (`name`, `slug`,
`entra_tenant_id`, `entra_group_id`, `impact_level`, `seats_licensed`,
`active`) carries `@field_access(write: ["org_admin"])`, so the sync can
report on the boundary but never move it. `directory_sync_status` starts at
`never`; a stale or `failed` view refuses new enrollments and changes no
operator.

The system `User` gains `entra_object_id` and `org_slug`. Both are projected
onto `Forge::Principal` at every console login and refresh through
`[schema_forge.authz.principal_claims]` in `config.toml`, which is what lets a
Cedar policy ask whether the person behind a bearer is someone the directory
knows. `roles`, `role_rank`, and `metadata` are fenced to `platform_admin`, so
the `directory_service` bearer can deactivate a login when the directory
disables a person but cannot promote one.

### Identity and entitlement — `schemas/identity.schema`

| Schema | What it answers |
|---|---|
| `Operator` | Which Entra principal is this, what team, what status |
| `Seat` | Is that principal entitled to prompt a model right now |

`Operator.entra_object_id` is the stable join key; `upn` is the natural key an
agent presents and can change. `Seat` carries the offboarding lever, and a
`@require` rule makes revocation state what it is for — a revoked seat with no
recorded reason is rejected at write time, in-process, before any hook.

The `directory_service` role reads and writes `Operator`: a rename in the
directory patches `upn`, `email`, and `display_name` on the same row and
nothing else changes, because every relation to an operator is by id. A
disabled account becomes `suspended`, a removed member becomes `offboarded`,
and `directory_synced_at` on the row is per-person proof the reconciler saw
them. On `Seat` the same role may write, but `@field_access` fences `operator`,
`organization`, `tier`, `activated_at`, and `expires_at` to `org_admin`. What
is left is `status`, `revoked_at`, and `revocation_reason`: the sync can take
a seat away and say why, and cannot grant, move, or extend one.

### Machine identity — `schemas/credential.schema`

| Schema | What it answers |
|---|---|
| `EnrollmentToken` | Who authorized this machine to join, and is that grant spent |
| `InstallCredential` | What key does this daemon sign with, and is it still good |

An `Operator` is a human with an Entra token. A daemon heartbeats at 03:00 with
nobody logged in, so it cannot borrow that token and needs an identity of its
own. The split is along the only line that matters: what is secret and what is
not.

`InstallCredential` stores **public verification material only** — a base64
SPKI public key, and for the mTLS variant the certificate fingerprint
acton-service pins against. The daemon generates its keypair at enrollment and
never transmits the private half. A shared bearer secret was considered and
rejected: it would put a replayable credential in the database, on the wire at
every heartbeat, and in a file on every workstation, which is three copies of
something that only needs to exist in one place.

`EnrollmentToken` stores no secret either, which took a second pass to get
right. Modeled as a password — a random secret with its argon2 hash in the row
— it was unmintable. The hash has to be `@hidden`; SchemaForge rejects any
request body naming a hidden field; and a `required` field nobody may send
cannot be created by anyone, `platform_admin` included. A `before_validate`
hook could have filled it, but that solves the wrong half: the plaintext still
could never reach the human doing the provisioning, because a create response
carries only persisted fields.

So the artifact is not stored at all. It is a PASETO v4 token minted with
`schemaforge token generate` against the key the plane already holds, carrying
the token id as `sub` and the grant as claims:

```sh
schemaforge token generate --sub tok_7f3a --lifetime 172800 \
  --issuer garrison-enrollment --roles '' \
  --custom-claim-string org=$ORG --custom-claim-string scope=organization \
  --custom-claim-long max_uses=25

schemaforge entity create EnrollmentToken \
  --set token_id=tok_7f3a --set issuer=garrison-enrollment \
  --set organization=$ORG --set scope=organization --set max_uses=25 \
  --set issued_by=so@agency.gov --set expires_at=2026-08-31T04:00:00Z
```

Authenticity comes from the signature; the row supplies what a signature
cannot — revocation, use counting, and who issued it. The row is an ordinary
entity, so provisioning is scriptable with the CLI like everything else.

The two token families are kept apart structurally, not by convention. An
enrollment artifact is minted under its own `issuer`, and acton-service
validates `iss` on every bearer, so presenting one as a session token fails
before authorization runs:

```
GET /schemas/Organization/entities   (enrollment artifact as bearer)
  401  Invalid PASETO token: the claim 'iss' failed validation
GET /schemas/Organization/entities   (console bearer, same route)
  200
```

The corollary is that the redemption route must verify the artifact itself,
since the standard bearer middleware will refuse it. That is correct: a daemon
redeeming a token has no other credential to present.

The trade to write down: a database compromise still yields nothing, but a
compromise of the signing key lets an attacker mint enrollment tokens. That key
already protects every session token, so it concentrates no new trust.

Neither schema is deletable. `policies/custom/credential-lifecycle.cedar`
carries a `forbid` on both delete actions for the same reason the audit trail
has one — the record that a key existed, was used from these addresses, and was
revoked on this date for this reason is the only evidence the revocation
happened. Rotation does not need deletion: a superseded credential moves to
`rotating` then `revoked`, and the self-referencing `supersedes` field keeps the
chain walkable back to enrollment.

`InstallCredential.status` carries a cross-entity `@require` — a retired install
cannot hold an active credential — resolved through the `related.install.status`
single-hop read, with the caller's tenant scope applied.

The credential triplet is named the same on both sides of enrollment:
`credential_kind`, `public_key`, `cert_fingerprint` on `Redemption` and on
`InstallCredential`. The hook copies the fields across without translating,
and a reader of either wire shape sees one vocabulary. (The field was `kind`
on `InstallCredential` before 1.0; the rename is a column migration, and the
one live row is recreated by re-enrolling.)

### Enrollment — `schemas/enrollment.schema`

| Schema | What it answers |
|---|---|
| `Redemption` | Which machine presented which grant, and what was decided |

Redemption is not a bespoke route. It is a schema, so SchemaForge generates the
endpoint, the Cedar policies, and the audit for it the same way it does for
every other entity, and creating a `Redemption` is the act of enrolling.

Two mechanisms carry the security, and neither is code:

```
token_id @require("has(principal.sub) && token_id == principal.sub")
```

binds the write to the caller's own artifact. A daemon holding `tok_A` cannot
redeem `tok_B`; the rule runs in-process before any hook, and the mismatch is a
422 naming the rule. The `enrollee` role is scoped to exactly one action — it
holds no read grant on `Redemption` itself, so the create response is the only
thing a daemon ever sees of this schema.

Everything that has to look at another row happens in a `before_validate` hook,
in `hooks-service/`:

| Step | Why it is there |
|---|---|
| Adjudicate the token | issuer, status, expiry, use count, tenant — in that order |
| Resolve the operator | an operator-scoped grant wins over the machine's claim |
| Admit the operator | `status` must be `active`; with the directory on, the row must carry an `entra_object_id` and the organization's directory view must be fresh (R4 below) |
| Create the `AgentInstall` | `status = enrolled`, not `active`: joining the fleet is not entitlement |
| Create the `InstallCredential` | public material only, `status = active` |
| Spend the token | one patch carrying both the new count and the status it implies |

`before_validate` rather than `before_change` because it is the last phase at
which a field the client never sent can still be added. `organization` is such
a field: a v4.local artifact is encrypted with the plane's own key, so a daemon
cannot read its own claims and has nothing truthful to say about its tenant.
Resolving it in the hook means the daemon never asserts it, and a field the
client cannot set is a field the client cannot forge.

A refusal is **persisted, not aborted**. Returning `abort_reason` would fail the
request and leave no trace, and the record that an unknown machine presented a
revoked token at 03:00 is exactly the record a security officer wants. The
daemon is told `outcome = refused` and nothing more. A refusal does not spend
the token. The one case that does abort is the plane being unreachable, because
refusing there would write a permanent verdict on a transient fault.

The binding sets `required = true` on purpose. With `false`, a hook that was
down would be logged and the create would proceed — persisting a `Redemption`
that admitted nobody, refused nobody, and left a daemon believing it had
enrolled.

The hook talks to the plane over its REST API rather than its database, so
every row it creates goes through the same Cedar decision, the same `@require`
rules, and the same audit as a row a human creates. The transport is
`acton-service-client`, the consumer-side counterpart to the framework the plane
is built on; it already encodes the error-body shape, the versioned routes,
bearer auth, and the retry classification, so what remains in `plane.rs` is only
the part that is genuinely SchemaForge's. The bearer it holds is scoped by the
`enrollment_service` role, which appears in the `@access` lists of the
schemas it provisions, resolves, and (for the policy publish gate) assembles,
and nowhere else.

One constraint is worth recording because it is easy to design around and
impossible to configure around. The plane validates every bearer against the
single `issuer` in its `[token]` section, so an enrollment artifact minted
under a distinct issuer is a 401 at authentication and never reaches the hook.
Artifacts are therefore minted under the plane's own issuer, and
`hooks-service`'s expected issuer must match it. What separates an artifact
from a console bearer is not `iss` but the `enrollee` role, which is granted
write on `Redemption` and nothing else anywhere in the bundle. Issuer
separation would need the plane to accept more than one issuer.

Verified end to end against a live plane:

```
POST Redemption  tok_MATCH, unspent, operator resolvable
  201  outcome=accepted, install + credential + organization returned
       AgentInstall status=enrolled, InstallCredential status=active
       EnrollmentToken uses 0 -> 1, status issued -> redeemed
POST Redemption  tok_MATCH again
  201  outcome=refused, "token has already been fully redeemed"
       no install, no credential, token still at uses=1
POST Redemption  tok_OTHER, operator_upn nobody@agency.gov
  201  outcome=refused, "no operator is registered as 'nobody@agency.gov'"
       token still unspent
```

### Enrolling, from the agent's side — `agent/src/enrollment/`

The daemon's half is small on purpose. Redemption is an ordinary entity create,
so there is no bespoke protocol here to get wrong: the agent posts a row and
reads what came back.

Three files sit on disk, all under the Garrison config directory
(`$XDG_CONFIG_HOME/garrison`, else `~/.config/garrison`):

| File | Written by | Lives |
|---|---|---|
| `enrollment.toml` | whoever provisions the machine | until it is spent |
| `install-key.pem` | the daemon, at enrollment, mode 0600 | forever |
| `install.json` | the daemon, on acceptance | forever |

The packet carries two fields rather than one:

```toml
token_id = "tok_7f3a"
artifact = "v4.local...."
```

The `token_id` is there because the artifact is a PASETO **v4.local** token,
encrypted with the plane's own key. The daemon cannot read a single claim from
it, which is the right design, but the redemption body must still name the
`token_id` it is spending so the `@require` above has something to compare. So
the id travels in the clear beside the artifact. The id is not a secret. The
artifact is, which is why the packet is deleted the moment it has been spent.

The install key is generated here and never transmitted. What crosses the wire
is the public half in SPKI form. The alternative, a plane-issued shared secret,
would put a replayable credential in the plane's database, on the wire at every
heartbeat, and in a file on every workstation: three copies of something that
needs to exist in one place.

`install.json` is the whole first-run test. There is no separate flag whose
only job is to say "done" — a daemon is enrolled if and only if it can read
that record back, and the record exists only because a redemption succeeded.
One fact, one place, no way for the two to disagree. A *corrupt* record is an
error rather than a silent re-enrollment, which would spend a second grant and
leave two installs in the fleet for one machine.

Enrollment runs in `build_setup`, before any actor spawns, and has four
outcomes:

| Situation | What happens |
|---|---|
| No `[plane]` section | Nothing. A standalone agent starts as it always did. |
| Already enrolled | The record is logged and the daemon starts. No call is made. |
| Not enrolled, plane says yes | Identity is recorded, the packet is destroyed, the daemon starts. |
| Not enrolled, anything else | The daemon refuses to start. |

That last row is the one worth defending. A governed agent that starts anyway
when the plane turned it away is not governed; it is an agent with a policy
document next to it. The same holds for an unreachable plane on a machine that
has never enrolled: with no install record there is no organization, no seat,
and nothing to attribute a session to, which is exactly the unattributable
activity this plane exists to prevent.

An *already enrolled* daemon is deliberately not held to that. It does not call
the plane at all, so an outage cannot ground a fleet that has already been
admitted. Enrollment is a one-time gate, not a heartbeat.

What the daemon reports is what the process observed, not what a config file
claims. `sandbox_hardening` in particular is what the kernel actually granted,
so a machine whose Landlock support degraded says so and the fleet view shows
it. The agent's own vocabulary is wider than the plane's — it distinguishes "no
sandbox configured" from "configured, hardening off" — and both collapse to
`unavailable` on the way out, so the fleet view answers one question instead of
two.

Reading the answer fails closed. An `outcome` the daemon does not recognize, or
an acceptance missing any part of the identity it was supposed to carry, is
treated as a refusal. A daemon that decided it had enrolled on the strength of
a half-filled response would be a daemon whose local record disagrees with the
fleet.

Verified end to end, agent against a live plane, on a staged first-boot
machine with an empty config directory:

```
boot 1  packet present, no install record
  enrolling ... install_id=inst_01m17dz1j7 hostname=govcraft
  spent enrollment packet removed
  enrolled  install=agentinstall_01m17dz1vp credential=installcredential_01m17dz1xz
  daemon starts and listens
  plane:  EnrollmentToken issued -> redeemed, uses 0 -> 1
          AgentInstall status=enrolled, sandbox_hardening=best_effort,
                       isolation_active=true, operator resolved from the UPN
          InstallCredential kind=ed25519 status=active
          Redemption outcome=accepted
  disk:   enrollment.toml gone, install-key.pem 0600, install.json written
          the stored public_key is the public half of install-key.pem

boot 2  same machine, record present
  already enrolled ... no call to the plane
  daemon starts and listens

boot 3  a second machine presenting the same spent packet
  the control plane refused this install: token has already been fully redeemed
  exit 1, no install record written, packet left in place
  plane:  a second Redemption row, outcome=refused, reason recorded
          no second install, no second credential, token still at uses=1
```

An earlier attempt in this same run refused with `401 ... The claim 'iss'
failed validation` and is the reason the constraint above is written down. The
failure also exercised the path that matters most: the packet survived, no
record was written, and the daemon did not start.

### Fleet — `schemas/fleet.schema`

| Schema | What it answers |
|---|---|
| `AgentInstall` | Which daemons exist, on what, running which version |
| `AgentSession` | What one ACP conversation cost and how it ended |

`AgentInstall.enrolled_via` and `credentials` are the provenance chain: which
provisioning token admitted this machine, and every key it has held since.

`AgentInstall.sandbox_hardening` and `isolation_active` are reported by the
install's own `_garrison/status`, not asserted by the console. That is the
difference between "we require landlock and seccomp" as a policy statement and
as an observation, and it is the field a reviewer will ask about.

`AgentSession` is where seat utilization and cost accounting roll up.
`total_tokens` is `@compute("input_tokens + output_tokens")` — server-derived
at write time, overwriting whatever a client sends.

### Policy — `schemas/policy.schema`

| Schema | What it answers |
|---|---|
| `PolicyBundle` | The versioned, checksummed unit an install pulls |
| `CommandRule` | Prefix rules over canonicalized argv |
| `ToolRule` | Per-tool disposition for the agent's own tool surface |
| `ModelEndpoint` | Which model endpoints are approved, and on whose signature |
| `PolicyAssignment` | Which bundle applies to the org, a team, or one operator |

`CommandRule` follows the `execpolicy` shape described in
[garrison-agent-design.md](garrison-agent-design.md) §1.2: rules match the
canonicalized argv rather than the shell string, so `bash -lc "git status"`
cannot launder a decision, and `match_examples` / `not_match_examples` are unit
tests the agent runs when it loads a bundle — a rule that does not match its own
examples refuses to load.

`PolicyBundle.checksum` is a `@require`d BLAKE3 digest once a bundle is
published. An install reports the checksum it loaded; a mismatch is drift, and
drift is visible rather than deniable.

Publishing is gated by a `before_validate` hook on `PolicyBundle`, bound in
`config.toml` with `required = true`. When a bundle moves to `published`, the
hook assembles its rules and endpoints, runs every rule's own match examples,
and refuses the publish if any fail; otherwise it computes the checksum over
the canonical bundle and stamps `checksum`, `published_at`, and `published_by`
onto the row before it persists. The hook reads those rows with the hook
service's own bearer, which is why `enrollment_service` appears in the read
lists of `PolicyBundle`, `CommandRule`, `ToolRule`, and `ModelEndpoint`. It
holds no write grant on any of them: the checksum lands through the hook
response, not a PATCH. Until the gate is implemented, the hook refuses every
publish and passes drafting and retiring through untouched.

`ModelEndpoint` records authorization state (`pilot`, `interim_ato`, `ato`,
`denied`) alongside hosting, and an ATO endpoint must name who authorized it.

### Audit — `schemas/audit.schema`

| Schema | What it answers |
|---|---|
| `AuditTrail` | What the install says about its own trail: local head, shipped through |
| `AuditEvent` | One entry from an install's BLAKE3 chain, the sealed line verbatim |
| `AuditChain` | Where the plane has verified a trail's chain to, and whether it holds |

The agent keeps a hash-chained JSONL trail locally; acton-ai seals every entry
with its sequence, the previous hash, and the trail id it belongs to. The
three schemas are three vantage points on that one trail, and the split is
along who is allowed to say what.

`AuditTrail` is the daemon's claim. The `operator` token creates one row per
trail id and patches it as it ships: `local_head_seq` and `local_head_hash`
are where the local file is, `shipped_through` is the highest sequence the
daemon believes the plane acknowledged, `reported_at` is when it last said so,
and `halted_reason` is set when the daemon stops shipping on its own account.
Nothing here is verified.

`AuditEvent` is one shipped entry. `entry` holds the acton-ai `AuditEntry`
JSONL object verbatim, and `chain_seq`, `entry_hash`, and `prev_hash` are
lifted out of it for indexing: `entry_hash` is unique so a replay collides
instead of duplicating, `prev_hash` names the predecessor, `chain_seq` orders
them. The promise is that the plane can re-run chain verification over the
`entry` column of a trail and reproduce `head_hash`; that is the auditor's
proof. Every other column (`kind`, `decision`, `decider`, `outcome`,
`elapsed_ms`, and the rest) is a projection of `entry` that may be re-derived
and may change; the verbatim entry may not. `session` is optional: a trail
belongs to an install, and an entry can be sealed before any session is known
to the plane. `trail` is required.

`AuditChain` is the plane's answer, one per trail rather than one per session.
Only the `audit_service` role writes it. The `before_validate` hook on
`AuditEvent`, bound in `config.toml` with `required = true`, loads the chain
for the entry's trail, re-links the entry against `head_hash` and `head_seq`,
and either advances the chain, records a gap in `integrity` and `finding`, or
refuses the write outright as a fork or an edit. `verified_through` says how
far a background walk has re-derived the chain, and the `@require` on
`finding` forces a gap or a break to say what it was. `format` names the
sealing format of the entries, `acton-ai/1` for 1.0, defaulted so a row the
hook creates never fails on a field it did not send. Until the verifying
ingest is implemented, the hook refuses every `AuditEvent` write; a stub that
accepted would persist entries nobody verified while the daemon took the
success as an acknowledgement.

Silence is the difference between the first and the third over time. A trail
whose `local_head_seq` keeps moving while its chain's `head_seq` does not is
an install that stopped shipping; a trail whose `reported_at` stops moving is
an install that went dark. The two rows disagreeing is the finding, which is
why the install cannot write the chain and the plane does not write the trail.

Access here is deliberately lopsided. Operators — that is, agents — append and
cannot read. Auditors read and cannot append. `audit_service` reads all three
and writes only the chain.

Deletion needs more care than the DSL can express, and the obvious spelling is
a trap. `delete: []` does **not** mean "nobody": an empty list reads as
unconstrained and generates

```cedar
// Allow any authenticated user to delete AuditEvent entities
permit (principal is Forge::Principal,
        action == Action::"DeleteAuditEvent",
        resource is AuditEvent);
```

which is the opposite of the intent, and it fails open silently — the bundle
validates, the schema reads like a lockdown, and everyone can delete. Read the
generated policies rather than trusting the annotation.

So the generated permit is narrowed to `org_admin`, and the real rule lives in
`policies/custom/audit-append-only.cedar` as a Cedar `forbid` over
`UpdateAuditEvent`, `DeleteAuditEvent`, `DeleteAuditChain`, and
`DeleteAuditTrail`. A `forbid` beats every `permit`,
platform_admin's bypass included, which is what makes "nobody deletes" true
rather than aspirational. Narrowing the generated permit as well means a lost
custom policy file degrades to "only the highest role", not "everyone".

Records-retention deletion, when it comes, is a deliberate edit to that file
alongside a documented disposition schedule — not a permission somebody already
quietly holds.

Bulk export is a separate consent again. `@export` on both audit schemas
enables the endpoint; it grants nobody. The distinct `ExportAuditEvent` /
`ExportAuditChain` actions are permitted in the same custom file to the three
roles that already read the trail, and the exported column set is
`@exportable ∩ readable`. `AuditEvent.detail` and `AuditEvent.entry` are
deliberately left out: a bulk file is the wrong place for whatever a tool
happened to attach, and the verbatim entry is the verification input, not a
report column.

One more `forbid` sits on top of those permits, in
`policies/custom/directory-identity.cedar`: `ExportAuditEvent` is refused to
any principal that does not carry `entra_object_id`. A console login whose
`User` row has one gets it projected onto the token; a service bearer minted
with `schemaforge token generate` never does. Taking a copy of the trail is
the one action that must be attributable to a person the directory knows.

## Write-time rules: `@default` is what binds a value for `@require`

A `@require` predicate is evaluated against the in-flight write. A field the
client omitted is **not bound**, and an unbound reference is a fail-closed
rejection reported as a `500` schema-authoring fault — not the `422` carrying
the message the rule author wrote.

The literal `default(value)` *modifier* does not help: it is applied at
persistence, after the rule phases. Only the `@default("expr")` *annotation*
runs early enough (`@default` → `@compute` → `@require`).

None of that is a SchemaForge defect — the phase order and the fail-closed
treatment of an absent reference are both documented, and the `500` correctly
names the schema as the fault. It is written down here because the schemas in
this directory got it wrong first, and the failure surfaces on a request that
looks like it should have worked.

The consequence is easy to miss, because the failure is not in the rule's own
field. `Seat.revocation_reason` reads `status != 'revoked' || size(...) > 0`,
so a create that simply omitted `status` and took its default blew up on
`status`, on the ordinary happy path:

```
POST .../Seat/entities  {"operator": ..., "organization": ...}
  500  @require on field 'revocation_reason' could not be evaluated:
       undeclared reference to 'status'
```

So every field named by a `@require` anywhere in `schemas/` now carries a
`@default` annotation alongside its literal default. The pair looks redundant
and is not: the modifier is the column's declared default, the annotation is
what makes the predicate evaluable. Deleting either changes behavior.

The rule when adding a `@require`: list every field the expression names, and
confirm each is `required` or carries `@default`. Then test the create that
omits the optional fields, not just the one that violates the rule.

## Directory

The directory sync lives in `hooks-service/` as a supervised actor
(`src/sync.rs`) beside the enrollment hook, because the enrollment decision
now depends on the sync's freshness and one service is one config to audit.
It is configured by the `[directory]` table in `hooks-service/config.toml`
and holds its own plane bearer for the `directory_service` role, distinct from
the hook's `enrollment_service` bearer. Every write it makes goes through the
plane's REST API, so it is bounded by the same `@access` lists and
`@field_access` fences as a console user, and lands in the same audit table.
One hooks service reconciles one organization, named by
`[directory] organization`: the bearer is scoped to that tenant, and the
plane does not return the tenant-root `Organization` row itself from a
tenant-scoped listing, so the sync fetches the row it was told about by id
and nothing wider. Every row the sync writes carries that tenant; rows
written by a bearer with no tenant chain (the bootstrap `admin` login, for
one) land with no tenant and are invisible to the sync and to the enrollment
hook alike, so operators must be created inside the tenant.

Everything it decides is decided by one pure function,
`reconcile::reconcile`, whose tests are the specification. The rules, in the
words the code uses:

- **R1. Join key.** `Operator.entra_object_id` is the identity. A directory
  member with no row is created (`active`, or `suspended` if the account is
  disabled). A row whose member is absent from the listing is `offboarded`.
- **R2. One-time link, then rename in place.** A hand-typed row with no
  object id is linked exactly once, by case-insensitive UPN match, and stamped
  with the member's object id. After that `upn`, `display_name`, and `email`
  are directory-owned: a rename patches the same row and every install,
  session, and audit entry keeps pointing at the same person. A hand-typed
  row that matches nobody is reported in the sync detail and never offboarded;
  the directory never knew it.
- **R3. Deprovision.** A disabled account becomes `suspended`; a removed
  member becomes `offboarded`. Either way the operator's `assigned` and
  `active` seats are set `revoked` with `revoked_at` and a reason the
  `@require` rule demands: `directory: account disabled` or `directory:
  account removed`. `reconcile` also plans the console `User` with the same
  object id (or, before it is stamped, the same email) to `active = false`,
  never a `platform_admin`; but the plane's user store has no tenant column,
  so a tenant-scoped bearer cannot list it (the plane answers `502`, `column
  "_tenant" does not exist`). The sync therefore reconciles operators and
  seats, records `console users not reconciled` in `directory_sync_detail`,
  and leaves the console login to be closed by hand. That is a known gap,
  listed below, not a silent one. A member who reappears enabled is set
  `active` again, but no seat is re-assigned: that is an `org_admin`
  decision. On a running install a revocation reaches the daemon within
  `seat_check_secs` (`garrison.toml`, `[plane]`), which is the runtime lever;
  the directory sync is the provisioning lever.
- **R4. Enrollment admissibility.** The hook refuses, with a persisted
  `outcome = refused`, an operator whose `status` is not `active`, and, when
  `[directory] mode` is not `off`, one with no `entra_object_id` ("operator is
  not linked to the directory") or one whose organization has not synced
  successfully within `staleness` seconds ("directory view is stale;
  enrollment refused until the next successful sync"). An unreachable plane
  during the hook is still an abort, not a refusal.
- **R5. Bounded damage.** An empty listing is a failure, never "everyone
  left". A plan that would suspend or offboard more than `fraction` (default
  0.5) of the currently active operators is refused whole, so a wrong group
  id cannot empty a fleet. Both are recorded on the Organization as
  `directory_sync_status = failed` with the reason in `directory_sync_detail`,
  and no operator changes.
- **R6. Unreachable directory or plane.** The tick fails, the failure is
  recorded where it can be, and the next tick retries. While the view is
  stale, existing installs keep running and no new enrollment is admitted.
- **R7. Enrollment carries no directory identity.** The machine reports a
  UPN once, at first enrollment; the plane resolves it to a row and the row's
  object id is the identity from then on. A rename after enrollment changes
  nothing about the install.

Each successful tick stamps `Organization.directory_synced_at` and
`directory_sync_status = ok`, and `Operator.directory_synced_at` on every row
the listing confirmed, so "when did the directory last see this person" is a
column, not a log search.

### What has been proved, and against what

`cargo nextest run -p garrison-hooks` runs three layers:

- Unit tests on `reconcile` for every rule above, with no network.
- Fixture tests on the Graph parsers (`tests/fixtures/graph/`): a paged
  listing with `@odata.nextLink`, a guest UPN with `#EXT#` and `mail: null`,
  `accountEnabled: false`, a member missing `accountEnabled` (a failed page,
  not a guess), a throttled `429` body, and a token-endpoint error body.
- An integration test (`tests/directory_sync.rs`) that starts PostgreSQL in a
  container, applies this repository's schemas and policies, serves the plane,
  and runs `garrison-hooks` with `[directory] mode = "file"`. It proves that a
  member is provisioned into an operator a `Redemption` can bind to, that a
  hand-typed operator is linked by UPN, and that disabling the account
  suspends the operator, revokes the seat with the written reason, records
  the unreconciled console half in the sync detail, and refuses the next
  enrollment. It skips,
  saying why, without `schemaforge` on `PATH` or a container socket
  (`DOCKER_HOST=unix:///run/user/1000/podman/podman.sock` for rootless
  podman).

Running that test against the real plane changed two schemas, and the
reasons are worth keeping:

- `Organization.owner_id` lost its `@owner` annotation. The annotation
  generates a Cedar `forbid` on Read, List, Update, and Delete for every
  principal other than the owner, which hid the row from every role in its
  own `@access(read: ...)` list, `org_admin` included. The row is fenced by
  the tenant guard and the per-field `@field_access` writes instead.
- `Seat` now lists `directory_service` under `read`. It could already write
  a revocation; it could not find the seats to revoke.

The Graph transport (`src/directory/graph.rs`) has **not** been run against
a real tenant. Before trusting `mode = "graph"` in a deployment, confirm on
the actual tenant: that the app registration's `User.Read.All` and
`GroupMember.Read.All` application permissions are admin-consented; that
`accountEnabled` is populated for every member, including users synced from
on-premises AD (a missing value fails the tick rather than guessing); that
guest members are meant to be operators at all (they are listed, with their
`#EXT#` UPN); that a group of the expected size pages through `$top=999`
correctly; and that throttling under the tenant's real rate limits resolves
within `staleness`, because a run of failed ticks grounds new enrollments.

## Roles

`policies/role_ranks.toml` orders the hierarchy. Ranks drive the
no-upward-visibility rule (`principal.role_rank >= resource.role_rank`), so a
`team_lead` cannot manage a `security_officer`.

| Role | Rank | Scope |
|---|---|---|
| `org_admin` | 1000 | Seats, teams, installs, retirement |
| `security_officer` | 800 | Policy bundles and endpoint approvals |
| `auditor` | 600 | Reads the trail, writes nothing |
| `team_lead` | 400 | Their team's operators, installs, sessions |
| `operator` | 100 | Pulls policy, appends audit, nothing more |
| `directory_service` | 30 | The Entra reconciler: operators, seats, console logins, three organization fields |
| `enrollment_service` | 20 | The hook service provisioning an accepted enrollment |
| `audit_service` | 20 | The hook service verifying shipped audit entries; the only writer of `AuditChain` |
| `enrollee` | 10 | An enrollment artifact: create one `Redemption`, nothing else |

`platform_admin` is SchemaForge's reserved operator role, hardcoded at
`i64::MAX`. It is not a Garrison role and must not appear in that file or in
any `@access` list.

The four machine roles are ranked below every human role on purpose. Rank
gates visibility of *user* records, and none of them has any business seeing
one; their actual authority is the `@access` lists that name them and the
`@field_access` fences that bound what a write may touch. One hook-service
bearer carries both `enrollment_service` and `audit_service`.

The `operator` row is the one to read twice: it is the role a *daemon* holds,
and it is scoped to exactly the two things a daemon needs — read the policy it
must enforce, append the record of what it did.

## Running it

```sh
task plane:check      # parse + strict-mode Cedar validation; no database needed
task plane:key        # mint the PASETO v4 key into keys/ (gitignored)
task plane:plan       # migration plan, dry run
task plane:apply      # apply schemas and generate Cedar policies
task plane:serve      # serve the REST API
task plane:openapi    # export the OpenAPI spec
```

`config.toml` selects the backend by section: `[database]` is PostgreSQL,
`[surrealdb]` is SurrealDB, and declaring both is a startup error. The
`schemaforge` CLI ships one backend per build — the binary in use here is the
PostgreSQL flavor, so `[database]` is the live section and the SurrealDB block
is commented out. Point it at an environment with `ACTON_DATABASE_URL` rather
than editing the file.

`plane:apply` passes `--force`. Every `unique` field lands as an `AddUnique`
migration step, which the planner classifies `requires_confirmation` because
the DDL fails against existing duplicate rows. On an empty database there is
nothing to clean; against a populated one, clean the duplicates first and read
the plan from `plane:plan` before forcing anything.

`task plane:check` needs no database and should gate every pull request that
touches `schemas/` or `policies/` — strict-mode failures caught at review time
are failures the runtime would otherwise refuse to hot-swap after merge.

## Known gaps

- **The daemon-side client is enrollment only.** The agent enrolls itself
  under `[plane]` in `garrison.toml` and presents the credential
  `schemas/credential.schema` describes. Heartbeat, bundle pull, and audit
  shipping remain to be wired.
- **Schemas are unsigned.** Every command prints `schema signature
  verification is disabled (signing.mode = off)`. SchemaForge can require
  ed25519, SSH allowed-signers, or cosign-keyless signatures over `schemas/`
  before parsing, which is worth adopting here well before anything federal
  ships. The rollout is off → warn → enforce.
- **Graph is untested against a real tenant.** The directory sync's Microsoft
  Graph client is exercised against recorded responses only; the
  end-to-end proof uses `[directory] mode = "file"`. The "Directory" section
  lists what a real tenant must confirm. Until a console login has been
  stamped by a sync it carries no `entra_object_id`, and the export `forbid`
  in `directory-identity.cedar` refuses it; that is the fail-closed direction,
  stated here so nobody reads a 403 on export as a bug. `required` on the
  projected claims cannot be `true`: it is enforced against every bearer the
  plane accepts, including enrollment artifacts and service tokens, which
  carry no such claim by construction.
- **Console logins are not deactivated by the sync.** The plane's user store
  has no tenant column, so a tenant-scoped `directory_service` bearer cannot
  list `User`; the tick says so in `directory_sync_detail` and closes the
  operator and the seats. Closing the console login is a manual step until
  the plane can scope its user store, or the sync is given a second,
  unscoped bearer for that one read.
- **The directory bearer is tenant-scoped.** A `directory_service` token is
  minted with one organization's tenant chain, so one `garrison-hooks` syncs
  the organizations that bearer can see. A deployment with several
  organizations on one plane runs one hooks service per organization, or
  waits for a chain-less service bearer.
- **Two hooks are declared and refuse.** The `AuditEvent` and `PolicyBundle`
  `before_validate` hooks are bound and served, and both are stubs that fail
  closed: every audit ingest is refused, and every bundle publish is refused,
  until the verifying ingest and the publish gate are implemented.
- **No provisioned database.** The apply path has been exercised against a
  throwaway container, not against an environment anyone can point a client at.
  There is no migration history, no seeded organization, and no bootstrapped
  `platform_admin`.

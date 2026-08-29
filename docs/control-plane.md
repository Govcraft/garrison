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

15 schemas lower into 146 generated Cedar policies; 10 hand-written policies in
`policies/custom/` bring the bundle to 156, all strict-mode validated. The model
has also been applied end to end against a throwaway PostgreSQL 17 instance: 26
migration steps, 15 tables, every `unique` constraint and every CEL rule
type-checked at apply time. The server was then run against it and the
authorization and write-time rules exercised over HTTP — both delete
`forbid`s against a control case that succeeds, issuer separation between
enrollment artifacts and console bearers, and every `@require` on both its
passing and its failing branch. That database was discarded.

Tooling: `schemaforge` 0.37.2, PostgreSQL flavor.

**Planned:** everything that moves bytes. The agent does not yet pull policy
from this plane or push audit to it, no database has been provisioned, Entra ID
is modeled but not integrated, and there is no administration site. The model
landing first is deliberate — the wire contract between agent and plane is the
entity model, so it is the thing worth being wrong about early and cheaply.

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

Six files, fifteen schemas, one tenancy root.

### Tenancy — `schemas/organization.schema`

`Organization` is `@tenant(root)`: one boundary, one agency or program office.
Every other schema is `@tenant(parent: "Organization")`, so SchemaForge
generates a `forbid` policy per schema that rejects any access where the
principal is not a member of the record's tenant. Cross-tenant leakage is a
record-level Cedar decision, not a `WHERE` clause somebody has to remember.

`Team` groups operators so policy can be assigned to a squad rather than to
every developer by name.

### Identity and entitlement — `schemas/identity.schema`

| Schema | What it answers |
|---|---|
| `Operator` | Which Entra principal is this, what team, what status |
| `Seat` | Is that principal entitled to prompt a model right now |

`Operator.entra_object_id` is the stable join key; `upn` is the natural key an
agent presents and can change. `Seat` carries the offboarding lever, and a
`@require` rule makes revocation state what it is for — a revoked seat with no
recorded reason is rejected at write time, in-process, before any hook.

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

`ModelEndpoint` records authorization state (`pilot`, `interim_ato`, `ato`,
`denied`) alongside hosting, and an ATO endpoint must name who authorized it.

### Audit — `schemas/audit.schema`

| Schema | What it answers |
|---|---|
| `AuditEvent` | One entry from an install's BLAKE3 chain |
| `AuditChain` | Where a session's chain is, and whether it still verifies |

The agent already keeps a hash-chained JSONL trail locally. `AuditEvent` is
where those entries land centrally with the links intact: `entry_hash` is
unique, `prev_hash` names its predecessor, `chain_seq` orders them. The plane
re-verifies rather than trusting the install that shipped the entries, and
`AuditChain.integrity` records what the last walk found — with a `@require`
rule forcing a gap or a break to say what it was.

Access here is deliberately lopsided. Operators — that is, agents — append and
cannot read. Auditors read and cannot append.

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
`UpdateAuditEvent` and `DeleteAuditEvent`. A `forbid` beats every `permit`,
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
`@exportable ∩ readable`. `AuditEvent.detail` is deliberately left out: a bulk
file is the wrong place for whatever a tool happened to attach.

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

`platform_admin` is SchemaForge's reserved operator role, hardcoded at
`i64::MAX`. It is not a Garrison role and must not appear in that file or in
any `@access` list.

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

- **No daemon-side client.** The agent has never spoken to the plane. There is
  no enrollment, no heartbeat, no bundle pull, no audit shipping, and no
  `[control_plane]` section in `GarrisonConfig` — its only outbound network
  auth is to model providers. `schemas/credential.schema` describes the
  identity a daemon would present; nothing generates or presents one yet.
- **Schemas are unsigned.** Every command prints `schema signature
  verification is disabled (signing.mode = off)`. SchemaForge can require
  ed25519, SSH allowed-signers, or cosign-keyless signatures over `schemas/`
  before parsing, which is worth adopting here well before anything federal
  ships. The rollout is off → warn → enforce.
- **Entra claims are modeled, not wired.** `[schema_forge.authz.principal_claims]`
  in `config.toml` is commented out because projecting `entra_object_id` onto
  `Forge::Principal` requires those columns on the system `User` schema first.
  Until then, custom Cedar policies cannot scope by Entra identity.
- **No provisioned database.** The apply path has been exercised against a
  throwaway container, not against an environment anyone can point a client at.
  There is no migration history, no seeded organization, and no bootstrapped
  `platform_admin`.

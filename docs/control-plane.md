# Garrison control plane

The control plane is the administrative half of Garrison: the place an
organization says who may run the agent, what the agent is allowed to do, and
what it actually did. It is a [SchemaForge](https://github.com/Govcraft/schemaforge)
application, which means the entity model in `schemas/` is the source of truth
for its tables, REST API, migrations, Cedar policies, and OpenAPI spec — there
is no hand-written CRUD layer to drift from it.

Statements prefixed **Implemented** describe this checkout; **Planned**
describes intended work. As of 1.0 the four services behind the governance
claims are implemented; what remains planned is listed at the end of this
section and under "Known gaps".

## Status

**Implemented:** the entity model (`schemas/`), the role hierarchy
(`policies/role_ranks.toml`), the service configuration (`config.toml`), and
the two gates that run without a database:

```sh
task plane:check      # parse the schemas, then strict-mode validate the Cedar bundle
```

18 schemas lower into a Cedar bundle of 233 policies, 13 of them hand-written
in `policies/custom/`, all strict-mode validated. The model has also been
applied end to end against a throwaway PostgreSQL 16 instance: 31 migration
steps, 18 tables, every `unique` constraint and every CEL rule type-checked at
apply time, and the three hook bindings validated against the generated
descriptor at startup. The server was then run against it and the
authorization and write-time rules exercised over HTTP — both delete
`forbid`s against a control case that succeeds, the `enrollee` role's
one-action allowlist against a console bearer on the same route, and every
`@require` on both its passing and its failing branch. That database was discarded.

Tooling: `schemaforge` 0.37.2, PostgreSQL flavor.

The agent enrolls itself on first run (`agent/src/enrollment/`), against the
same endpoint and the same hook. It then authenticates every later call by
signing a short-lived assertion with its install key and trading it for a
15-minute bearer at `POST /api/v1/install/token` on `hooks-service/`; see
"Authenticating after enrollment" below. That exchange is the single
authenticated path from a daemon to the plane, and the policy pull, the seat
check and the audit shipper are all consumers of it rather than of their own
credentials.

Entra ID is the authority for operators: `hooks-service/` runs a directory
sync that creates, links, renames, suspends, and offboards `Operator` rows
from a Microsoft Graph listing (or a JSON file), and the enrollment hook
refuses anyone the directory has not vouched for. See "Directory" below for
the rules and for what has and has not been proved against a real tenant.

The agent pulls its policy bundle from this plane and ships its audit trail to
it, both over that same install bearer, and both as gates a turn passes through
rather than as background sync. See "Policy distribution" and "Audit shipping"
below.

**Planned:** no database has been provisioned, and there is no administration
site. A deployment therefore starts with `task plane:apply` against a fresh
database, a seeded organization, and a bootstrapped `platform_admin`. The model
landing first was deliberate — the wire contract between agent and plane is the
entity model, so it was the thing worth being wrong about early and cheaply,
and it is now frozen by `docs/compatibility.md`.

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
  --issuer garrison-control-plane --roles enrollee \
  --tenant-chain "[{\"schema\":\"Organization\",\"entity_id\":\"$ORG\"}]" \
  --custom-claim-string scope=organization \
  --custom-claim-long max_uses=25

schemaforge entity create EnrollmentToken \
  --set token_id=tok_7f3a \
  --set organization=$ORG --set scope=organization --set max_uses=25 \
  --set issued_by=so@agency.gov --set expires_at=2026-08-31T04:00:00Z
```

`--tenant-chain` is neither optional nor cosmetic. `_tenant` is injected from
that claim alone, and a row written without it lands untenanted, where it is
invisible to every tenant-scoped bearer, including the hooks service that has
to read it. The symptom is "no enrollment token matches this artifact" for a
row that plainly exists, which cost real time to diagnose once already.

Authenticity comes from the signature; the row supplies what a signature
cannot — revocation, use counting, and who issued it. The row is an ordinary
entity, so provisioning is scriptable with the CLI like everything else.

The two token families are kept apart by their role set, not by their issuer.
acton-service validates `iss` against exactly one configured issuer, so an
artifact minted under a second one is a 401 at the plane's middleware and never
reaches the redemption route at all. Both families are therefore minted under
`garrison-control-plane`. What separates them is that an artifact carries the
single role `enrollee`:

```
POST /schemas/Redemption/entities    (enrollment artifact as bearer)
  201
GET  /schemas/Organization/entities  (enrollment artifact as bearer)
  403  the `enrollee` role grants write on Redemption and nothing else
GET  /schemas/Organization/entities  (console bearer, same route)
  200
```

That is an allowlist of exactly one action rather than a credential merely
refused everywhere else, which is why the failure mode of getting it wrong is
a daemon that cannot enroll rather than one that can do more than enroll.

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

**Which grant is being spent is not the client's to say.** `Redemption.token_id`
is filled by the `before_validate` hook from the authenticated principal's
subject claim, exactly as `organization` is, and the daemon has no field to put
it in. A daemon holding `tok_A` cannot redeem `tok_B` because it cannot name
`tok_B` at all. This replaced a `@require` comparing a submitted `token_id`
against `principal.sub`, and it is the stronger of the two: a rule can only
refuse a mismatch, while a client with no field cannot attempt one. What holds
it closed is the binding's `required = true` — an unreachable hook fails the
request rather than persisting a row with no grant named on it.

**The `enrollee` role is scoped to exactly one action.** It holds no read grant
on `Redemption` itself, so the create response is the only thing a daemon ever
sees of this schema.

Everything that has to look at another row happens in a `before_validate` hook,
in `hooks-service/`:

| Step | Why it is there |
|---|---|
| Adjudicate the token | status, expiry, use count, tenant — in that order |
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
Artifacts are therefore minted under the plane's own issuer. What separates an
artifact from a console bearer is not `iss` but the `enrollee` role, which is
granted write on `Redemption` and nothing else anywhere in the bundle. Issuer
separation would need the plane to accept more than one issuer.

`EnrollmentToken` carried an `issuer` column until 1.0, compared against the
configured issuer on every redemption. Given the paragraph above, both sides
were the same string in every deployment, so the check caught a typo in a
hand-written row and nothing more, while reading like a security control. It
is gone. `garrison.issuer` in `hooks-service`'s config remains, because the
install-token exchange mints under it and that is a real use.

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

The packet carries one field:

```toml
artifact = "v4.local...."
```

It carried the `token_id` beside it until 1.0, because the artifact is a PASETO
**v4.local** token encrypted with the plane's own key: the daemon cannot read a
single claim from it, so it had to be told which grant it was holding for the
`@require` to have something to compare. Now the hook reads the subject off the
authenticated principal instead, and the field is gone from both the packet and
the request body. `Packet` carries `serde(deny_unknown_fields)`, so an unspent
two-field packet written before 1.0 fails at read time naming the file, rather
than being half-read. The artifact is the only secret here, which is why the
packet is deleted the moment it has been spent.

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

### Authenticating after enrollment: the install-token exchange

Enrollment answers "may this machine join". It does not answer the question
every later call asks: what does an enrolled daemon present when it wants to
read its policy bundle, check its seat, or ship an audit entry? It has an
Ed25519 private key and nothing else. It cannot present a console bearer,
because there is no human at 03:00, and it must not hold a long-lived one,
because a standing credential in a file on a workstation is a file an attacker
copies.

So there is exactly one authenticated path from a daemon to the plane:

```
daemon                         garrison-hooks                 plane
  |  sign a 120s assertion          |                            |
  |  with the install key           |                            |
  |-- POST /api/v1/install/token -->|                            |
  |                                 |-- GET InstallCredential -->|
  |                                 |-- GET AgentInstall ------->|
  |                                 |  verify signature, window, |
  |                                 |  nonce, both statuses      |
  |<-- 200 { token, expires_at } ---|  mint a 15-minute PASETO   |
  |                                                              |
  |------------- GET/POST/PATCH with that bearer --------------->|
```

The exchange is the only route `garrison-hooks` serves over HTTP; everything
else it does is a gRPC hook. It is registered through `VersionedApiBuilder`
with `.with_base_path("/api")` and exempted from the framework's bearer
middleware by `[token] public_paths = ["/api/v1/install/token"]`, because a
daemon arriving there has no bearer by definition. That exemption is a
**prefix** match, so no other route may begin with that string, and the
service refuses to boot without it rather than answering every exchange with a
401 raised by middleware the route never reaches.

What is on the wire is one type, defined once, in the workspace crate
`wire/` (`garrison-wire`) that both the daemon and the service depend on,
with a pinned test vector both sides compile against:

```json
{ "credential_id": "...",
  "assertion":  "base64url(JSON)",
  "signature":  "base64url(Ed25519 over the raw assertion bytes)" }
```

The assertion's JSON keys are `credential_id`, `install_id`, `iat`, `exp`,
`nonce`, in that order, and the signature covers the octets that arrived
rather than a re-serialization of the parsed value, so no canonicalization
step can disagree between the two ends.

The decision is a pure function, `adjudicate_assertion(now, body, credential,
install)` in `hooks-service/src/install_token.rs`. It takes a clock reading and
two rows and performs no I/O, so every branch below is a unit test that needs
neither a database nor a socket:

| Refused because | Status | `error` |
|---|---|---|
| no such credential row, or none this service may see | 401 | `unknown_credential` |
| the signature does not verify against the stored SPKI | 401 | `assertion_rejected` |
| the assertion names an install its credential does not belong to | 401 | `assertion_rejected` |
| `exp - iat > 120`, or `now` outside `[iat-30, exp+30]` | 401 | `assertion_window` / `assertion_expired` / `assertion_future` |
| the nonce is shorter than 22 characters | 401 | `assertion_nonce` |
| the nonce has been seen before | 401 | `assertion_replayed` |
| `credential_kind != "ed25519"` | 403 | `unsupported_credential_kind` |
| `credential.status != "active"` | 403 | `credential_rejected` |
| `install.status` is `quarantined` or `retired` | 403 | `install_not_active` |

The 401/403 split is the daemon's whole branch. A 401 is worth one retry with
a fresh assertion; a 403 is a decision somebody made, and a daemon that
retried it would turn a deliberate quarantine into a denial of service against
its own control plane. A refusal is never reported as "the plane is
unreachable", and an unreachable plane is never reported as a refusal.

Replay is the one check that is not in the pure function, because "have I seen
this before" is by construction a fact about state. It lives in a supervised
`NonceLedger` actor, so no lock is held in a request path, and entries are
dropped as they expire on the way through, so the ledger never holds more than
one assertion window's worth of traffic and needs no timer. A restart empties
it, which is bounded rather than a hole: an assertion outside its 120-second
window is refused whether or not its nonce is remembered.

The bearer is minted with the plane's own `[token]` key through
`PasetoGenerator` + `ClaimsBuilder`, so it is indistinguishable from one
`schemaforge token generate` produced and needs no second trust root:
`sub = "install:{install_id}"`, `roles = ["operator"]`, a `tenant_chain` of
the install's organization, and custom `install` and `credential_id` claims.
Lifetime is `[garrison] lifetime`, 900 seconds. The tenant chain is not
optional decoration: a bearer without it sees no tenant-scoped row at all.
The exchange then best-effort PATCHes `InstallCredential` with `last_used_at`,
`last_used_from` (the forwarded client address, when a proxy supplied one) and
`use_count + 1`; a failure there costs an audit detail rather than the
daemon's turn.

On the daemon's side the whole thing lives in `agent/src/plane/`, and the
invariant is worth stating plainly: **nothing outside that module builds an
authenticated client**. Every subsystem asks the `PlaneSession` actor for an
`Authenticate` and receives an `Api` that is already authenticated and already
scoped. The actor hands back the bearer it holds while more than 60 seconds
remain on it, and otherwise performs exactly one exchange with every other
asker parked on the result. Serialization is a property of the mailbox, not
of a lock somebody remembered to take. `_garrison/status` gains a `plane`
block reporting reachability, the last exchange, the current expiry, and the
last error, because when turns are being refused this is the first field an
operator should read: every governed subsystem spends the same bearer.

A daemon that has enrolled and then cannot read its install key does not
start (exit 2). The key is loaded, never created: generating a replacement
would leave a process that had quietly stopped being itself.

Verified end to end against the live development plane, with throwaway rows
and our own `garrison-hooks` on a free port:

```
POST /api/v1/install/token   valid assertion         200
  GET AgentInstall with the minted bearer            200  (hostname read back)
POST /api/v1/install/token   replayed nonce          401  assertion_replayed
POST /api/v1/install/token   forged signature        401  assertion_rejected
POST /api/v1/install/token   retired install         403  install_not_active
POST /api/v1/install/token   revoked credential      403  credential_rejected
POST /api/v1/install/token   unknown credential      401  unknown_credential
```

The same sequence runs in CI against a containerized plane
(`hooks-service/tests/install_token.rs`): one PostgreSQL 16, one
`schemaforge apply` and `serve`, one `garrison-hooks`, a keypair generated in
the test whose SPKI goes onto a real `InstallCredential` row.

### Seat entitlement, from the agent's side — `agent/src/entitlement/`

**Implemented.** A seat is not a line in a licence file. It is a row on this
plane, and the daemon runs only while that row says it may. Every turn passes
a gate that spends the seat, and a turn that starts on a live seat is ended
when the seat stops being live under it.

**What is read.** One check is three calls through the shared plane component,
in the order the rule needs them:

1. `AgentInstall`, this machine's own row, which names its operator.
2. `Seat`, filtered to that operator.
3. `Organization`, for `impact_level`, which sets how long a stale answer may
   be spent.

Nothing here holds a credential of its own. The reader asks `PlaneSession`
for an `Authenticate` and spends the `Api` it gets back, exactly like the
policy pull and the audit shipper. A 401 costs one `RevokeBearer` and one
retry, because the one benign cause of a 401 is a bearer that expired between
being handed out and being spent. A second 401 is the plane meaning it.

**The rule.** `entitlement::verdict::adjudicate` is a pure function over those
three rows, and it decides in this order:

| Condition | Answer |
|---|---|
| install `status` is not `enrolled` or `active` | refused, `install_not_active` |
| install has no operator | refused, `install_unbound` |
| an `active` seat for that operator, not past `expires_at` | entitled, at that seat's tier |
| a seat exists but every one is revoked | refused, `seat_revoked`, with the recorded reason |
| a seat exists but its `expires_at` has passed | refused, `seat_expired` |
| a seat exists in some other state | refused, `seat_not_active`, naming the state |
| no seat at all | refused, `no_seat` |

When several seats are live the longest-lasting one is spent, and a seat with
no expiry outlasts every dated one. An `expires_at` that does not parse counts
as expired: the daemon cannot tell whether an unreadable date is in the
future, and a seat it cannot date is not a seat it may spend.

**Where the answer comes from at turn time.** The gate answers from the
standing already in the actor's model, in one message pass, with no network
call on the turn path. That is not an optimization. A gate has five seconds to
answer, and a seat check is three plane calls behind a token exchange; a gate
that went to the network there would, on a slow plane, blow the deadline and
come back as the generic "a gate could not be asked", collapsing "your seat
was revoked" and "the plane is unreachable" into one indistinguishable
failure. Freshness is the timer's job instead: `[plane] seat_check_secs`
(default 60, clamped to 15..900) drives a repeating `send_every` refresh, and
the daemon performs one check at startup before it accepts a connection.

**Offline grace.** A plane that cannot be reached is not the same as a plane
that said no, and only the first gets a window. How long the last confirmed
entitlement may be spent without reconfirmation comes from the organization's
`impact_level` and the seat's tier:

| `impact_level` | standard | elevated |
|---|---|---|
| `commercial` | 72h | 24h |
| `fedramp_moderate`, `il2` | 24h | 4h |
| `fedramp_high`, `il4` | 4h | 0 |
| `il5`, or an unrecognized value | 0 | 0 |

`[plane] offline_grace_secs` may shorten any of these and can never lengthen
one: a deployment can be stricter than its impact level requires, never more
generous. A tier the daemon does not recognize is read as `elevated`, the
stricter row.

A refusal carries no window at all. A revoked seat refuses the next turn and
every turn after it, however long the plane is then unreachable for, because a
refusal is an answer rather than an outage. That is the property that stops a
revoked install from running out the rest of what would have been its grace.

**Two refusals, not one.** When the seat is revoked, absent, or expired, the
turn is refused with `SEAT_REFUSED` (-32014). When the seat cannot be
confirmed and the last confirmation has aged past its window, it is refused
with `PLANE_UNREACHABLE` (-32015). Both carry prose naming the plane and, for
a revocation, the reason the console recorded. An operator reading a refused
prompt can tell which of the two happened without reading a log.

**A turn in flight is not grandfathered.** When a refresh turns an admitting
standing into a refusing one, the monitor broadcasts `EntitlementLost` on the
runtime's broker. Sessions subscribe and end the turn they are running with
that refusal, so a revocation reaches a turn that has already started rather
than only the next one. The broadcast fires on the transition, so a
persistently revoked seat does not re-cancel anything.

**The cache.** `entitlement.json` beside the install key, mode 0600, holds the
last standing so a daemon that restarts while the plane is down still knows
what it last confirmed and how much of its window is left. It is deliberately
unsigned: the install key sits in the same directory under the same uid, so
anyone who can rewrite the cache can already sign it. What bounds the damage
is the grace table, not a signature, and at `fedramp_high` elevated, `il4`
elevated, `il5`, or an unrecognized impact level the window is zero and the
file buys an attacker nothing. Every read failure is a missing cache, which is
a refusal.

**Status.** `_garrison/status` gains an `entitlement` block: the state, the
seat and tier when entitled, the refusal reason when not, the impact level,
when the plane was last confirmed, the grace window and when it runs out, when
the next check is due, and the last error. `garrison-agent ping` prints a
`seat:` line from it.

**Proved end to end** against a containerized plane
(`agent/tests/seat_entitlement.rs`): one PostgreSQL 16, one `schemaforge
apply` and `serve` on this repository's own schemas and policies, and the
daemon's own reader spending an `operator` bearer. An `assigned` seat does not
entitle; activated, it does, at the tier the console set; a PATCH revoking a
seat with no reason is refused by the `@require`, so the explanation is a fact
the schema enforces rather than a convention; revoked with a reason, the very
next check refuses and carries that reason; that refusal is still a refusal
thirty days later; and a retired install is refused whatever its operator's
seats say.


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

#### Machines that will not exist tomorrow

**Implemented.** `AgentInstall.lifecycle` is `durable` or `ephemeral`, and an
ephemeral install carries an `expires_at` stamped when it was minted.

The problem it solves is that enrollment assumes a disk. A daemon is enrolled
if and only if it can read back its install record; the packet is destroyed
when spent; the signing key is generated locally and never transmitted. All
three are correct for a workstation and all three assume storage that outlives
the process. A CI runner has none, so every build is a first run. Without a way
to say so, a pipeline gets either one undifferentiated install row per build or
a spent packet and a refusal to start.

Three properties make the ephemeral case work rather than merely permitted.

**The grant decides, not the daemon.** `EnrollmentToken.install_lifecycle` says
what a grant mints and `install_ttl_secs` says for how long. The daemon has no
field to declare this in, deliberately: from inside, a fresh container and a
freshly imaged laptop are the same situation, so a machine asked to classify
itself would be guessing. Whoever provisions the runner knows, and the grant is
where they say it. Being multi-use is what `max_uses` already did, so a pipeline
grant is an ordinary grant with two more columns set.

**The window is stamped at mint time.** `expires_at` is computed once, at
redemption, from the clock and the grant's TTL. It is not recomputed later from
the grant, because a grant can be revoked, edited, or spent again, and none of
that should change when an install that already exists stops running.

**A missing window is a refusal, not a licence.** `adjudicate` refuses an
install marked ephemeral that carries no expiry, before it looks at a seat. The
tempting reading of an absent date is "no limit", and that reading would turn a
hook that failed to stamp the field into a standing pipeline identity, which is
the exact failure the column exists to prevent. An unparseable date is refused
the same way, matching how a seat's own expiry is read.

Enforcement lives in the seat gate rather than in a sweep, because that is the
one path every turn already passes. A sweep that retires expired rows is
housekeeping for the fleet view; it is not what makes an expired identity safe,
and nothing depends on it having run. Rows are retired rather than deleted:
`AgentSession` and every audit entry hang off the install, so deleting one
would orphan the evidence it was created to carry.

What this does **not** change is seat cost. A seat belongs to an operator, and
every ephemeral install a pipeline mints binds to the same CI operator and runs
on that operator's seat. A hundred builds a day is one seat, not a hundred.

`AgentSession` is where seat utilization and cost accounting roll up.
`total_tokens` is `@compute("input_tokens + output_tokens")` — server-derived
at write time, overwriting whatever a client sends.

A session whose history was compacted reports more tokens, not fewer: each
pass is a summarization request to the session's own provider, and its usage
is part of the turn's. The compaction itself is not an audit entry, because no
tool ran and nobody authorized anything; the chain an install reports is the
same length either way. See "Compaction, persisted sessions, and audit
evidence" in [garrison-agent-design.md](garrison-agent-design.md).

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

`PolicyBundle.checksum` is the BLAKE3 digest of the bundle as distributed. An
install reports the checksum it loaded; a mismatch is drift, and drift is
visible rather than deniable. The field carries no `@require`: the plane
evaluates `@require` ahead of `before_validate`, so a rule demanding 64
characters would be a rule the hook that produces them runs too late to
satisfy, and the only way through it would be a caller typing a hash the hook
then discards. What guarantees the field is the binding below, which is
`required = true`.

Publishing is gated by a `before_validate` hook on `PolicyBundle`, bound in
`config.toml` with `required = true`. When a bundle moves to `published`, the
hook assembles its rules and endpoints, runs every rule's own match examples,
and refuses the publish if any fail; otherwise it computes the checksum over
the canonical bundle and stamps `checksum`, `published_at`, and `published_by`
onto the row before it persists. The hook reads those rows with the hook
service's own bearer, which is why `enrollment_service` appears in the read
lists of `PolicyBundle`, `CommandRule`, `ToolRule`, and `ModelEndpoint`. It
holds no write grant on any of them: the checksum lands through the hook
response, not a PATCH. Publishing a bundle by *creating* it already published
is refused: the rules point at the bundle by id, and a row being created does
not have one yet, so a bundle is published by updating a draft.

Both ends of that comparison run the same code. `garrison-policy` is a
workspace crate with no IO, compiled by the hook service and by the daemon,
and it defines the canonical form the checksum is taken over. The canonical
form covers the bundle's name and version, its default approval mode, the two
recorded-but-unenforced fields, and every **enabled** rule's matching terms and
verdict, with rules sorted so the order two queries happened to return them in
is not part of the answer. It deliberately excludes row ids, timestamps, the
organization, the checksum itself, and justifications: rewording "because it
deletes files" must not invalidate every install's cache mid-shift. A pinned
fixture test in `policy/src/checksum.rs` makes a change to that form a
deliberate break rather than an accidental fleet-wide cache invalidation.

`ModelEndpoint` records authorization state (`pilot`, `interim_ato`, `ato`,
`denied`) alongside hosting, and an ATO endpoint must name who authorized it.

#### The rule, from the daemon's side

`agent/src/policy/` holds the daemon half: `pull.rs` walks
`AgentInstall` → `Operator` → `PolicyAssignment` → `PolicyBundle` → rules and
endpoints with the install's own bearer, `cache.rs` keeps the last verified
bundle at mode 0600, and `agent.rs` is the actor that holds the result. It is
registered as a turn gate through `agent/src/admission.rs` and as a
`_garrison/status` describer, so nothing on the turn path waits for the
network: a turn asks the actor, which answers from what it already holds.

The whole rule, and it is also in `garrison.toml`'s `[policy]` comments so an
operator finds it where they are configuring it:

1. A daemon without `[plane]` governs itself from `garrison.toml`. That is the
   only case in which `[approval].auto_approve` is read.
2. A daemon with `[plane]` runs turns only under a bundle the plane assigned to
   it. It checks that the bundle is published, that its content hashes to the
   checksum the plane recorded, and that every command rule matches its own
   examples. It then writes the bundle id and checksum to its `AgentInstall`
   row, which is what promotes the install from `enrolled` to `active`.
3. If the plane cannot be reached, the daemon keeps running on the last bundle
   it verified, for at most `offline_grace_secs` after that bundle was fetched
   (default 24 h; set 0 to forbid it). `_garrison/status` reports
   `source = "cache"` for the whole time. The window is measured from when the
   plane last spoke, so restarting the daemon does not buy another one.
4. If the plane answers and the answer is anything other than a verified bundle
   (no assignment, unpublished, checksum mismatch, a rule that fails its own
   examples, an install quarantined or retired, a credential refused), or the
   grace runs out, the daemon starts, answers status with the reason, and
   refuses every turn. It never falls back to `garrison.toml`.
5. Local edits to `garrison.toml` cannot widen a governed daemon: while
   governed, the local auto-approve list is not consulted, and `bash` is
   decided only by the bundle's command rules. `_garrison/status` and
   `garrison-agent ping` say so when a local list is being ignored.

`[policy] offline_grace_secs` is a **cap, not a grant**. When the control plane
supplies a bound of its own for the organization's impact level, the shorter of
the two applies: a local file may shorten how long a machine runs offline and
may never lengthen it.

The scope resolution in rule 2 is narrowest-first: an `operator`-scoped
assignment beats a `team`-scoped one, which beats `organization`. Among equally
narrow assignments the most recently effective wins. A team-scoped assignment
does not apply when the daemon could not read its operator's `Operator` row: a
permission failure must not widen or narrow policy by accident.

#### What a bundle says and what this release acts on

`network_egress` and `allow_unsandboxed_escalation` are pulled, covered by the
checksum, and reported in `_garrison/status` — and **nothing enforces them**.
They are part of the checksum deliberately: an author who changes them has
changed the published policy, and a fleet should see that. But a bundle author
could reasonably believe the daemon acts on them, so `garrison-agent ping`
prints them under "recorded in the bundle and NOT enforced by this release",
and `_garrison/status` carries the same list in `policy.governance.notEnforced`.

`ToolRule.sandbox_required` *is* enforced, against what the kernel actually
granted rather than what was configured: a rule that requires a sandbox denies
the call on a host where the sandbox degraded.

`agents_md_discovery` and `agents_md_allowed_paths` are also enforced, unlike
`network_egress`: they gate whether and how far `garrison-agent` searches the
approved root for `AGENTS.md` project instructions before a turn starts. See
[garrison-agent-design.md §1.7](garrison-agent-design.md) for the trust model
— project instructions are untrusted content that can shape a turn and never
widen what this bundle, the approved root, the sandbox, or the approval gate
allow.

#### What the cache does and does not buy

The cache at `~/.config/garrison/bundle.json` is 0600 and re-verified against
its own checksum on every read, so a bundle edited under the daemon is refused
rather than enforced. Someone holding the daemon's uid can rewrite the content
*and* the checksum consistently, and this check would accept it — but that same
uid could edit `garrison.toml` or run a different binary, so it is not a hole
the file format can close. What closes it is the write-back: the install
records the checksum it is running on its `AgentInstall` row, and a row whose
checksum is not the bundle the plane assigned is drift somebody can see. The
cache buys availability, not integrity.

### Audit — `schemas/audit.schema`

| Schema | What it answers |
|---|---|
| `AuditTrail` | What the install says about its own trail: local head, shipped through |
| `AuditEvent` | One entry from an install's BLAKE3 chain — a turn or a tool call — the sealed line verbatim |
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

`kind` says which of two things an entry is, and the distinction matters more
than it looks. A `tool_call` row is one invocation: what ran, with what
arguments, decided by which gate. A `turn` row is one attempted model turn,
sealed whether or not that turn called anything. Without it the export answers
"what did this install run" and never "what did this install ask" — a session
where the model produced code and called no tool left no row at all, and a
compliance regime that specifies audit logging as *user activity* would have
been reading a trail that quietly only covered half of it.

A `turn` row carries metadata and no content: `prompt_bytes`,
`response_bytes`, `input_tokens`, `output_tokens`, `provider`, and `model`.
The byte counts answer the user/timestamp/activity/response-length question
without copying a prompt or an answer into a trail that leaves the workstation
and lands in a SIEM. There is no column for prompt text; adding one would be a
decision about retention rather than about auditing, and it is not made here.

`decision` and `decider` mean the approval gate on a `tool_call` row and the
*admission* gate on a `turn` row: a turn that ran was let through
(`auto_approved` / `default`) and a turn that did not was refused
(`forbidden` / `policy`), with the rendered reason in `justification`.
Admission is a gate in exactly the sense approval is, so a turn fills the same
columns rather than needing its own. A refused turn has no `outcome`, for the
same reason a denied call has none: it never ran. `sandboxed` is written
`false` on every turn row rather than inheriting the schema's `default(true)`,
because a turn confines nothing.

An inline completion crosses the same gates and seals a row when it is refused,
under the same stable decision word. Only the refusal is sealed: an admitted
completion writes nothing, because a debounce timer decides how often that path
is entered and a trail written by a timer rather than by a person is noise
wearing the shape of evidence. What the trail therefore answers about
completions is the governance question — was this install spending on them
after its seat lapsed — and not the accounting one.

The ingest hook re-derives every one of those columns, turn columns included.
An install that could set its own `kind` could file a turn as a tool call and
vanish from a turn-level export; one that could set its own token counts could
under-report what it spent.

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

## Audit durability, degraded state, and anchoring

The three schemas above are the plane's view of a trail. This section is the
agent's, and it is deliberately independent of the plane: **the plane is not
on the durability path.** Durability is enforced on the machine that writes
the trail, the local anchor is written unconditionally, and no turn is ever
refused because a control plane was unreachable. Getting the trail off the
machine is a separate mechanism with a separate rule, described under "Audit
shipping" below: an unreachable plane never stops a turn there either, but a
backlog that has grown past its bound does. A deployment that wants "no plane,
no turns" is asking for a seat gate, not for this.

### What an append promises

`acton-ai.toml`'s `[audit] durability` says what an entry must have done
before the loop moves on:

| Value | What an append does | What a failed append does |
|---|---|---|
| `best_effort` | Appends and flushes | Logs, marks the writer degraded, and the turn continues |
| `strict` (Garrison's shipped default) | Appends, `fsync`s, and is acknowledged before the next tool call | Refuses every tool not declared idempotent for the rest of the process, and refuses the next turn outright |

Strict mode refuses at two layers, and they are different refusals for
different moments. Inside a turn, acton-ai's own guard refuses each
non-idempotent tool call. The tool that already ran cannot be un-run, so
failing the whole turn would lose the model's account of what happened, and a
read-only investigation stays possible. Between turns, Garrison's anchor
keeper answers `AdmitTurn` and refuses the next turn before a single tool
runs, with JSON-RPC code `-32017`. A writer that does not answer the health
question within its deadline is refused exactly as a degraded one is: "I
cannot find out whether this will be recorded" and "this will not be
recorded" have the same consequence for the record.

### The four states an operator triages on

`_garrison/status` reports `audit.state`, and `garrison-agent ping` prints it
first:

| State | Meaning | What to do |
|---|---|---|
| `disabled` | No trail is armed | Nothing is being recorded. Add `[audit]` to `acton-ai.toml`, or accept it on a standalone install |
| `configured` | A trail is armed and intact; nothing written yet in this process | Nothing. The daemon has not yet proved it can write, which is why this is not `healthy` |
| `healthy` | Every append in this process reached the disk | Nothing |
| `degraded` | At least one append did not | Stop the daemon, fix the disk, verify, restart (see below) |

A daemon that cannot ask its own writer reports `degraded`, never `healthy`.

Recovering from `degraded` is an operator procedure, not a self-healing one:

1. Stop the daemon. In strict mode it is already refusing turns; in
   best effort it is running and recording nothing.
2. Fix the cause the status names in `audit.lastError`: a full filesystem, a
   permission change, a trail replaced by something that is not a file.
3. Run `garrison-agent audit verify`. **Keep the trail.** A trail with a gap
   in it is evidence: the gap plus `audit.firstFailedSequence` plus
   `audit.degradedSince` are what an auditor needs to bound what was lost.
4. Restart. The in-memory head keeps advancing past a failed append on
   purpose, so a restart is what returns the writer to healthy; healing the
   gap silently would make the trail lie about the entry it lost.

### The anchor, and what a hash chain cannot notice

A hash chain detects a rewrite and detects an insertion. It does not detect a
**truncation**, because a prefix of a valid chain is itself a valid chain:
delete the last ten entries of a trail and `verify_chain` still reports it
intact, at a lower head, with nothing to say about what used to be above it.

So the daemon keeps the head somewhere the trail is not. `[audit] anchor_path`
in `garrison.toml` (default `$XDG_STATE_HOME/garrison/audit-anchor.json`, mode
0600) holds the last head this install vouched for, rewritten after **every
finished turn** rather than only at shutdown, so the window in which entries
could be deleted unnoticed is one turn rather than one session. The anchor
keeper learns a turn finished by subscribing to acton-ai's turn lifecycle;
nothing on the turn path knows it exists.

The anchor is not a security boundary. It sits on the same host, under the
same user, as the trail. It turns silent tail deletion into a refusal to start
and a non-zero exit from `garrison-agent audit verify`, which is precisely the
failure that would otherwise leave no trace. The independently protected copy
is the plane's `AuditChain` row, and `Anchor` carries exactly the fields that
row wants so #8 adds a sink rather than a mechanism.

Comparing a trail against its anchor has five verdicts, and only three of them
stop a daemon:

| Verdict | Meaning | At startup |
|---|---|---|
| `matches` | The trail ends where the anchor says | Starts |
| `advanced` | The trail grew past the anchor | Starts, with a warning. A daemon that died between its last append and its next anchor produces this routinely |
| `truncated` | The trail ends *before* the anchor: entries were removed from the tail | Refuses (exit 2) |
| `diverged` | Same sequence, different hash: history at or below the anchor was rewritten | Refuses (exit 2) |
| `trail_changed` | The file carries a different trail identity | Refuses (exit 2) |

`[audit] on_anchor_mismatch = "warn"` relaxes the three refusals into a log
line for a deployment that would rather run than stop. An anchor written for a
different trail path is treated as evidence about another file: the daemon
warns and re-anchors rather than refusing something it cannot reason about.

### `garrison-agent audit verify`

Two questions, two exit codes, and files only. It never talks to the daemon,
so it works on a trail copied off the machine:

```sh
garrison-agent audit verify                 # the armed trail and the configured anchor
garrison-agent audit verify --file t.jsonl --anchor a.json --json
```

| Exit | Finding |
|---|---|
| 0 | The chain verifies and agrees with its anchor |
| 2 | The trail or the anchor could not be read; no verdict was reached |
| 3 | The chain does not verify: an entry was rewritten or inserted |
| 4 | The chain verifies and no longer ends where the anchor says it ended |

4 is the only code this binary uses for that finding, and nothing else uses 4.
The comparison is run over the whole chain rather than the head alone, so a
trail rewritten *below* the anchor and then extended past it is caught rather
than read as ordinary growth.

### When a trail is required

**A `[plane]` section present while acton-ai arms no trail is a refusal to
start** (exit 2). An install that answers to an agency was configured to be
accountable to it, and an accountable agent that records nothing is the exact
failure an audit exists to prevent. A standalone developer install with no
`[plane]` starts unrecorded, with a warning, so first-run in an editor works.
`garrison.toml`'s `[audit] required = true|false` overrides the inference in
either direction. This rule lives in exactly one function,
`GarrisonConfig::audit_required`, because more than one subsystem asks it and
they must get the same answer.

## Sessions that outlive the process

A daemon restarts: it is upgraded, a supervisor bounces it, the machine
reboots. Without persistence every conversation an operator was having ends at
that moment, and the trail above acquires a gap exactly where a reader most
wants continuity. This section, like the audit one, is the agent's, and **the
plane is not on this path either**: persistence is local, and no turn is ever
refused because a control plane was unreachable.

### What is stored, and who owns it

acton-ai's `MemoryStore` owns a libSQL database, armed by `[checkpoint]` in
`acton-ai.toml`. Garrison writes four things into it and reimplements none of
them.

| Row | What it holds | Written |
|---|---|---|
| session | Keyed by the ACP session id itself, so a client's `sessionId` *is* the lookup key | on `session/new` |
| conversation | The message history the next turn sends | after every turn; rewritten in place when compaction elides a prefix, so the record follows the pointer |
| metadata | The canonical root, the client kind, the install/tenant/operator the session is attributed to, turn and token counts, and the turn that was open when it was last written | on create, when a turn opens, and when a turn settles |
| turn checkpoint | acton-ai's own record of a turn in progress, one per provider round | by the prompt loop |

The session row is written **before `session/new` answers**. A client holding
an id the store has never heard of is a session that vanishes at the next
restart with nothing to say about why, so the write is what the id is issued
against; a store that will not take it is `-32018` and no session at all.

Attribution is filled from the enrollment record when there is one, so a
governed install's sessions already carry the install and tenant an
`AgentSession` row wants. Shipping them to the fleet view is an addition
rather than a redesign.

### Two fail-closed rules

Both live in one pure function, `session::keeper::gate_decision`, and reach
the turn path through the same admission seam the seat, policy and audit gates
use.

| Condition | Code | Consequence |
|---|---|---|
| The store cannot be reached, or answered with an error | `-32018` `STORE_UNAVAILABLE` | Every turn is refused. "I cannot find out whether this will be saved" and "this will not be saved" have the same consequence for the record |
| The session's own record names a turn that is still open | `-32019` `TURN_INTERRUPTED` | That session refuses *new* prompts until an operator resumes or abandons the old one |

Both rules are about a session's stored record, so this is the one gate that
admits an inline completion without asking: a completion writes no record to
lose, and blocking a developer's editor because some earlier turn was left open
would refuse them for a reason that is not about them. It is also the only gate
that reaches the store to answer, so skipping the read is what keeps the gates
inside a completion's two-second budget. Every other gate answers a completion
exactly as it answers a turn.

The second is deliberately automatic in neither direction. Silently restarting
the turn would re-run tools that have already run and be paid for twice;
silently dropping it would throw away work the operator asked for. This is
also why `[checkpoint] policy` must be `resume_on_request`: **`resume_auto` is
refused at startup** (exit 2), because a turn resumed in the background would
settle its pending tool calls with no client connected to approve them, which
is the one thing a governed agent may never do.

A session created before the store came up has no stored record at all. That
is not an interrupted turn, and it is admitted: it runs in memory alone, as
every session did before this existed.

### Reopening a session

`session/load` is the one call that reaches a session this connection never
opened — which, after a restart, is every session there is. When the
supervisor holds no live actor for the id, the daemon reads the record back,
**re-checks the stored root against the approved roots** (an administrator may
have narrowed them since, and a stored record is not a way around the
boundary), rebuilds the session, and replays its history as `session/update`
events before the response, which is the ordering ACP asks for.

A stored session whose root is no longer approved is `-32020`
`SESSION_ROOT_UNAPPROVED` rather than a generic bad-parameters refusal, and
the record is left alone: the session is not deleted, it is simply not opened,
and re-approving the tree brings it back.

If that session was holding an interrupted turn, the response says so:

```json
{
  "_meta": {
    "garrison": {
      "interruptedTurn": {
        "turnId": "turn_01m17…",
        "startedAt": "2026-08-29T14:02:11Z",
        "prompt": "refactor the parser",
        "roundsCompleted": 3,
        "resumable": true
      }
    }
  }
}
```

`roundsCompleted` and `resumable` come from the checkpoint. A checkpoint that
cannot be read makes the turn *unresumable* rather than unreportable: the
operator still needs to know the session is blocked, and abandoning it is
still open to them.

Two extension methods settle it. Both take `{"sessionId": …}`, and both answer
`-32021` `NO_INTERRUPTED_TURN` when there is nothing to settle — never a
silently restarted turn, and never a pretended one.

| Method | Answers | Shape |
|---|---|---|
| `_garrison/session/resume` | deferred, resolved when the turn ends | Exactly like `session/prompt`, because it *is* the same turn: same identifier, carrying on from the round its checkpoint stopped at. The prompt replayed comes from the record, so a client that never saw the original still sees what was asked |
| `_garrison/session/abandon` | `{"turnId": "turn_…"}` | Immediate. The record is cleared and the checkpoint marked abandoned, and the session is promptable again |

Abandon is what keeps fail-closed from meaning stuck. Both of its halves are
best effort and neither is retried: the operator has said the work is not
wanted, and the metadata write is the one the gate reads.

`session/list` merges the live sessions this connection holds with the stored
ones it does not, filtered by the requested `cwd`, so an editor reopening a
project is offered the conversations belonging to it. A stored name that is
not one of Garrison's identities belongs to some other writer of that database
and is never offered.

### Retention

Persistence without retention is a growing disk and a growing disclosure:
every prompt an operator ever typed, kept forever, on a machine an agency has
to be able to say something definite about. `garrison.toml`'s `[sessions]`
owns the window. The sweep runs at startup — a daemon that has been down for a
month should not carry that month's expired sessions until tomorrow — and
every `sweep_interval_hours` after, and its plan is a pure function,
`session::plan_retention`.

```toml
[sessions]
required = true            # inferred: required exactly when [plane] is present
retain_days = 30
sweep_interval_hours = 24  # zero is read as one, in both keys
```

Three of the sweep's four rules are refusals to delete:

- a session touched inside the window stays;
- a session whose last-active date this daemon cannot parse stays, because a
  date it cannot read is not evidence that the session is stale;
- **a session holding an interrupted turn stays at any age**, because the
  operator has not said whether to resume it and sweeping it would make that
  decision for them.

The fourth deletes a checkpoint in a terminal state whatever its age: a
completed turn is already committed to the session's history, and an abandoned
one was abandoned on purpose. In-progress and failed records are precisely
what a resume needs, so they leave only when their session does.

### When a store is required

The same rule as the trail, for the same reason. **A `[plane]` section present
while `acton-ai.toml` arms no `[checkpoint]` is a refusal to start** (exit 2):
an operator whose work vanishes on every upgrade has not been given a governed
agent, only an unreliable one. A standalone install with no `[plane]` starts
without a store, with a warning, so first-run in an editor works. `[sessions]
required = true|false` overrides the inference in either direction, and the
rule lives in exactly one function, `GarrisonConfig::sessions_required`.

`db_path` must be an **absolute per-user path**. It is resolved against the
daemon's working directory and is not tilde-expanded, and that directory is
`$HOME` under systemd and under relay autostart. Omitting the key is worse
than getting it wrong: acton-ai then defaults to `acton-ai-checkpoints.db`
beside wherever the daemon happened to start, so an operator would get a
different set of sessions per directory. Same rule, and same reason, as the
trail's `path`.

### What `_garrison/status` reports

```json
"sessionStore": {
  "healthy": true,
  "sessions": 12,
  "interrupted": 1,
  "lastCheckpoint": "ckpt_01m17…",
  "retainDays": 30,
  "lastSwept": "2026-08-29T03:00:00Z"
}
```

`healthy: false` is the refusing state: turns are being turned away until the
store answers again, and `lastError` says what it last failed at. `interrupted`
counts the sessions that will refuse a prompt until somebody decides about
them. The whole field is absent on an install that persists nothing, which is
the standalone case saying so plainly rather than reporting a healthy store
that does not exist.
## Audit shipping

A hash chain proves that nobody edited the middle of a record. It proves
nothing at all about the end of one, because a prefix of a valid chain is
itself a valid chain: an operator who deletes the last hour and restarts
leaves a file that verifies perfectly. The only defence against that is a copy
somewhere the machine cannot reach. Shipping is how the copy gets there, and
it is what turns "tamper-evident audit" into a claim an auditor can check
without logging into the workstation.

### The daemon side

`agent/src/shipping/` is four files, one of which does I/O:

- `cursor.rs` remembers how far the trail has been shipped, durably, in
  `<trail>.shipped` beside the trail itself. Resuming compares the stored
  cursor against the file: a trail shorter than the cursor was truncated, and
  an entry at the cursor whose predecessor is not the hash the cursor recorded
  was rewritten. Either is a halt, not a retry.
- `reader.rs` reads whole entries out of a file the audit writer is still
  appending to. A line without a trailing newline is left for next time (the
  writer may be mid-line); a complete line that will not parse is an error
  rather than a skip.
- `policy.rs` holds the written rule for when a backlog stops the work, as
  pure functions over a status and a clock.
- `actor.rs` is `TrailShipper`: it polls, posts through the shared plane
  component in `agent/src/plane/`, and answers both `AdmitTurn` and
  `Describe`.

Entries go up **one at a time, in chain order, with one batch in flight**.
That is not a performance choice: two concurrent posts of sequences 8 and 9
would race the ingest's read-then-patch of `AuditChain` and manufacture a gap
finding out of a healthy trail. The mailbox provides the serialization.

The shipper learns that a turn ended from acton-ai's `TurnLifecycle`
broadcast, the same way the anchor keeper does. Nothing on the turn path sends
it a message.

### The rule: when shipping stops the work

`TrailShipper` is on the ordered `gates` vector in `launch.rs`, so it answers
`AdmitTurn` like every other gate. The rule is written down because the
default is easy to get wrong in both directions:

- **An unreachable control plane never stops a turn.** The trail file is the
  buffer. A laptop on a train is not a governance failure, and a daemon that
  stopped working every time a VPN dropped would be switched off within a
  week.
- **A backlog past its bound does stop turns**, when `[plane.shipping]
  fail_closed` is set, which it is by default. The bound is a day or ten
  thousand entries. No ordinary outage reaches it; an install that has kept a
  day of evidence to itself has very much reached it.
- **A halt stops turns always**, whatever `fail_closed` says. The plane
  refused an entry as forked or edited, the credential was rejected, or the
  local trail was rewritten under the cursor. None of those heal by waiting,
  and all of them are findings rather than outages.

A refusal is `TurnRefusal::AuditShipping`, JSON-RPC `-32017`, carrying the
sentence an operator reads. `_garrison/status` grows one field, `shipping`,
with the state, the backlog, the age of the oldest unshipped entry, the last
successful ship, and the last error. A disabled shipper still answers with
`state: "disabled"` rather than omitting the field: an absent status is not an
answer an auditor can use.

### The plane side: a verifying ingest

`hooks-service/src/hooks/audit_event.rs` serves `AuditEvent.before_validate`.
For each arriving entry it re-links the sealed entry against the trail's
`AuditChain` and decides, in this order:

1. **Do the flat columns agree with the sealed entry?** `garrison-wire`'s
   `audit::project` is the one definition of that mapping and both ends
   compile it, so the daemon's columns and the hook's expectations cannot
   drift apart. A disagreement on `chain_seq`, `entry_hash`, `prev_hash`, or
   `install` is refused. Every other projected column (the decision, the
   decider, the outcome, the tool, the command, the timestamp) is
   **re-derived from the entry and overwritten**, so an install cannot ship a
   truthful entry beside a flattering export.
2. **Does the entry belong to this trail?** The `trail_id` sealed into the
   entry must be the trail's own.
3. **Is it the next link?** `verify_next` against the chain head.

An entry **past** the head is accepted with the hole recorded
(`integrity = "gap"`, `finding` naming the missing sequences), because the
entry is still evidence and the hole is still the finding. Its own hash is
re-checked first, since `verify_next` stopped at the sequence and never
reached the seal. An entry **at or behind** the head is either the same entry
arriving twice, which is an acknowledgement, or different content in an
occupied position, which is a fork and is refused.

`operator` and `organization` are filled here from the `AgentInstall` row the
trail belongs to. The daemon never sends them, which is why
`AuditEvent.operator` is not marked `required` in the schema: required-field
validation runs *before* `before_validate`, so a field the client is meant not
to send cannot also be one the client must send. The binding is
`required = true`, so the hook always runs and always fills it. This is the
same shape as `Redemption.organization`.

A consequence worth stating: **the plane's `AuditChain` is intact-or-gapped by
construction.** `integrity = "broken"` is a value the ingest never writes,
because an entry that would break the chain never lands. The tamper-evidence
is that the tampered entry is *not here*, that the daemon halted, and that
`_garrison/status` says why.

### One channel, two meanings

A hook can refuse exactly one way: `abort_reason`, which the plane turns into
one status. "I do not believe your entry" and "I could not reach the plane to
check" demand opposite responses from the daemon: halt and fetch a human, or
back off and try again. The discriminator is the sentence
`garrison_wire::audit::INGEST_UNAVAILABLE`, which lives in the shared crate so
the side that writes it and the side that reads it compile the same bytes.

On the daemon side the mapping is `shipping::actor::rejection_verdict`: `409`
is an acknowledgement (the unique index on `entry_hash` answering a replay),
`401` re-exchanges the bearer once, `429` and `5xx` are waited out, and
anything else is a halt.

### Liveness: silence is the difference between two claims

`hooks-service/src/silence.rs` is a supervised actor that sweeps every
`[garrison] sweep` seconds. It compares three vantage points:

- `AuditTrail` is what the daemon **claims**: its local head, how far it says
  it has shipped, when it last reported. Written by the install's own bearer,
  so nothing on it is evidence.
- `AuditChain` is what the plane **verified** as entries arrived. The install
  cannot write it at all.
- `AgentInstall.status` says whether the machine is still supposed to be
  running.

Silence is their difference over time. The findings, most serious first, are
`broken` (the daemon recorded a halt, or the chain is broken), `gap` (entries
missing from the middle), `silent` (no report inside `[garrison] silence`
seconds), and `backlog` (the plane has verified less than the daemon says it
has written). A `retired` install is exempt from the last two, because silence
from a decommissioned machine is the point of decommissioning it; it is exempt
from nothing else.

The sweep **reads and never writes**. `AuditChain.integrity` is the ingest's
record of what it verified link by link, and a background job that could set
it from inference would put a guess in the same column as a proof. Findings go
to `tracing::warn!` on the `garrison.audit.liveness` target.

### Operational notes

- The hook makes three or four plane calls per entry (trail, install, chain,
  then a create or patch). A fleet shipping steadily will notice the plane's
  `[rate_limit]` budget before it notices anything else; size it for the
  fleet, not for the console.
- The hook's bearer needs `audit_service` beside `enrollment_service`. It is
  the only writer of `AuditChain`.
- Like the directory bearer, it is tenant-scoped, so one `garrison-hooks`
  serves the organizations its chain covers. See "Known gaps".
- `hooks-service/tests/audit_shipping.rs` runs the whole path against a real
  plane in a container: five sealed entries ship, the chain head matches the
  fifth entry's hash, the stored `entry` columns re-derive that same head, a
  replay collides with `409`, and an entry edited after sealing is refused
  without the "temporarily unavailable" sentence. It skips cleanly when
  `schemaforge` is not on `PATH` or no container runtime answers.

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

### And a hook cannot satisfy a `@require`

The same phase order puts `before_validate` *after* the rule phases, on create,
update, and patch alike. So a `@require` on a field a hook produces is a rule
nothing can satisfy: the write is rejected before the hook that would fill the
field is ever called. `PolicyBundle.checksum` was written that way first, and
every publish failed with `a published bundle must carry its BLAKE3 checksum`
while the gate that computes the checksum sat there having answered the create
and never the publish.

The fix is not a placeholder the caller types. A rule satisfied by 64 zeroes
guarantees nothing, and the hook discards the value anyway. It is to state the
requirement where it can be enforced: the hook binding, with `required = true`,
which fails the write when the gate cannot answer.

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

## Process topology on the agent side

One daemon per user per machine. `garrison-agent serve` is the only process
that ever builds an acton-ai runtime, so it is the only owner of the policy,
the sandbox host, the socket and the audit trail. Everything else is a
client of its socket (`$XDG_RUNTIME_DIR/garrison-agent.sock`):

- `garrison-agent acp`, the mode editors spawn, is a relay between its pipes
  and that socket. It never builds an engine, so a spawned child cannot be a
  second writer of the hash chain. Two VS Code windows, a JetBrains project
  and a terminal `chat` are four clients of one daemon, one policy, one
  trail.
- The daemon's configuration is the one in force. `--config` on the relay is
  read for `[server]` only; `--acton-config` is accepted and ignored with a
  warning.
- A daemon that is not running is started by the first `acp` or `chat` that
  needs it when `[server] autostart` is on: through `systemctl --user start
  garrison-agent` when that unit is loaded, otherwise as a detached child
  rooted at `$HOME`. An autostarted daemon reads only the XDG configuration
  files (`~/.config/garrison/garrison.toml`, `~/.config/acton-ai/config.toml`);
  the relay's flags are never handed to it. With `autostart = false` the
  client reports the missing daemon and starts nothing. `ping` never starts
  anything.
- Two guards, both kernel-owned and gone with the process, no pidfile: the
  socket is probed before it is bound, and a second daemon on a live socket
  refuses to start; acton-ai holds an exclusive advisory lock on the trail,
  and a second daemon over the same trail refuses to start rather than fork
  the chain.
- Exit codes from `serve`: 2 is "refused to start" (locked or broken trail,
  unusable configuration, a control plane that turned the install away), 3 is
  a rejection, 1 is a malfunction. The packaged unit
  (`packaging/systemd/garrison-agent.service`, `task daemon:install`) retries
  only 1; 2 and 3 wait for an operator.
- The boundary: with `[threads] project_root` unset the default root is the
  daemon's working directory, `$HOME` under systemd or autostart, so any
  workspace under home can host a session and each session is confined to
  its own `cwd`. Workspaces elsewhere need `workspace_roots`. Language
  servers are off in the shipped `garrison.toml` until they are spawned per
  session root; see the comment there.

Enrollment happens in that one daemon, before it listens, so a machine has
exactly one install identity: a fleet of editor windows is one
`AgentInstall`, one credential and one seat, not one per window.

## Known gaps

- **A bundle's `network_egress` and `allow_unsandboxed_escalation` are
  recorded and not enforced.** They are part of the checksum and reported in
  `_garrison/status`; no code acts on them. `ping` says so out loud.
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
- **A bundle's rules are checked against their own examples, and nothing
  checks the examples.** The publish gate refuses a rule whose
  `match_examples` it does not match, which catches a rule that does not do
  what its author thought. It cannot catch a rule whose examples are all wrong
  in the same direction. That is a review problem rather than a code one, and
  it is stated here so nobody reads a green publish as proof the policy is
  correct.
- **The audit bearer is tenant-scoped, like the directory one.** The ingest
  writes `AuditChain` with the chain its bearer was minted under, so one
  `garrison-hooks` serves one organization's trails. Several organizations on
  one plane means one hooks service each, or a chain-less service bearer.
- **No provisioned database.** The apply path has been exercised against a
  throwaway container, not against an environment anyone can point a client at.
  There is no migration history, no seeded organization, and no bootstrapped
  `platform_admin`.

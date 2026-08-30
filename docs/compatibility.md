# What Garrison 1.0 promises, and what it does not

This document exists because the cost of changing certain surfaces goes from
zero to real on the day the number lands. It states which those are, what the
promise on each one is, and — for the deliberate break pass tracked by #14 —
what was broken while it was still free and what was deliberately left alone.

A surface not listed here is not covered. That is the default, and it is meant
to be: a promise nobody wrote down is one nobody can keep.

## The covered surfaces

### 1. The entity model in `schemas/`

The wire contract between a daemon and the control plane. A deployed plane and
a deployed fleet have to agree on it, and every field anyone regrets needs a
migration path.

**Promised for 1.x:** no field is removed or renamed, no field becomes
`required` that was not, and no `@require` predicate is tightened in a way that
refuses a write 1.0 accepted. New optional fields, new entities, and new
`@access` grants are allowed.

**Not promised:** the Cedar policy bundle. A `forbid` may be added at any time
in a patch release. Narrowing who may do something is a security fix, and
tying it to a major version would mean shipping known-wrong authorization on
purpose.

### 2. The enrollment protocol

Three parts: the packet on disk (`agent/src/enrollment/record.rs`), the
redemption request body (`agent/src/enrollment/redeem.rs`), and the
`AgentInstall` record the plane keeps.

**Promised for 1.x:** a packet written by 1.0 is redeemable by any 1.x daemon
and any 1.x plane.

This surface is the least forgiving of the three, and it is worth being
explicit about why. A shipped install cannot re-enroll without spending
another grant, so a format change strands machines rather than inconveniencing
them. `Packet` also carries `#[serde(deny_unknown_fields)]`, which means the
freeze runs in both directions: a later daemon reading an unspent 1.0 packet
must still accept every field 1.0 wrote. Unspent packets sitting in a
provisioning share are exactly the population a format change hurts.

### 3. The ACP surface and `garrison.toml`

Two shipped editor extensions and every operator's config file.

**Promised for 1.x:**

- The JSON-RPC refusal codes -32014 through -32021 keep their meanings. A new
  refusal takes a new code.
- Process exit codes keep their meanings: `2` refused to start, `3` a
  rejection, `4` an audit verify mismatch, `1` a malfunction.
- `_garrison/status` only gains fields. Every block it can omit today it may
  still omit, so a client that reads a field must keep treating absence as an
  answer rather than an error.
- A `garrison.toml` valid under 1.0 stays valid. Keys are added, not removed
  or repurposed, and an unknown key is a hard error by design — which is why
  removing one is a break rather than a tidy-up.

### 4. The audit trail on disk

The entry format, the hash pre-image, the chain, and the `.trail` sidecar.

**Promised for 1.x:** a trail written by 1.0 verifies under any 1.x reader,
with the same head hash. This is the one an auditor actually depends on, so it
is the one pinned by a test rather than by intent: `agent/tests/audit_fixture.rs`
holds a trail a real daemon wrote and fails if today's code disagrees with it
about a single byte. Regenerating that fixture is the visible cost of breaking
this promise, and it is deliberately awkward.

Note what the chain does *not* promise, and never did: a prefix of a valid
chain is itself a valid chain, so truncation of the most recent entries is
undetectable from the file alone. That is why the trail ships off the box.

## The dependency pin policy

Garrison compiles four first-party crates in statically. No dependency is
resolved at runtime, so **a new release of any of them does nothing to an
already-shipped Garrison binary.** A fix reaches an operator through a rebuild
and a redeploy, never on its own. What the pin policy decides is only whether
the next rebuild picks a change up silently.

| Crate | Requirement | Why |
| --- | --- | --- |
| `acton-ai` | `=0.35.0` (exact) | It is 0.x, and `garrison-wire` re-exports its audit types as Garrison's own wire contract. An unreviewed 0.36 would silently redefine what an audit entry is, which is surface 4 above. Exact makes the bump a reviewed commit. |
| `acton-service` | `0.39` | Plane-side only (`hooks-service`). For a 0.x crate, caret already caps below 0.40, so caret and tilde are the same requirement here. |
| `acton-service-client` | `0.1.2` | Ships inside the agent binary, so a fix here needs an agent release, not just a plane redeploy. |
| `acton-reactive` | `9.2.1` | Post-1.0 semver, patch float. |

`Cargo.lock` is committed, and `task test` and `task check` pass `--locked`, so
even the caret requirements are pinned until somebody runs `cargo update`.

The blast radius worth stating plainly: `acton-service` is the code that mints
install tokens. A token-forgery fix there is an enrollment-protocol emergency
for the control plane, and not an emergency for the agent binary on an
operator's laptop.

## The 1.0 break pass

Every candidate was investigated against the code and then reviewed by a second
pass whose brief was to refute it. What follows is the disposition of each: what
was broken while it was still free, what was left alone, and why.

### Taken: acton-ai resolved from crates.io

`agent/` and `wire/` both carried `acton-ai` as a path dependency to
`../../acton-ai`, which resolves through a `.gitignore`d directory. **A clean
clone could not build.** The `version = "0.35.0"` beside the path was
decorative; `Cargo.lock` recorded `acton-ai` and `acton-ai-macros` with no
source and no checksum, so the audit types underpinning the tamper-evident
claim came from whatever sat in a sibling checkout on the build machine.

Now `=0.35.0` from the registry, with the checksum in the lockfile. The
published crate was verified byte-identical to the local checkout before the
switch. Also fixed: `acton-reactive = "9.1.0"` in `agent/`, which was
unsatisfiable — published `acton-ai` 0.35.0 requires 9.2, so 9.1.0 could never
have been what resolved.

### Taken: one issuer, and documentation that matches it

The plane validates `iss` against exactly one configured issuer. Four surfaces
still described an abandoned two-issuer model, two of them copy-pasteable:
`schemas/credential.schema` and `docs/control-plane.md` both claimed that
presenting an enrollment artifact as a session token is "a 401 before
authorization runs at all", and both gave a mint command
(`--issuer garrison-enrollment --roles ''`) that produces an artifact which
401s at the middleware and would be 403'd on `Redemption` even if it got
through. `hooks-service` defaulted `garrison.issuer` to the second issuer, so a
deployment that omitted the key booted clean and then refused every enrollment
with a message naming the wrong side of the mismatch.

What actually separates the two token families is the role set: an artifact
carries `enrollee`, which grants write on `Redemption` and nothing else
anywhere in the bundle. Both documents now say so, and the mint commands now
match the only path that has ever worked — including `--tenant-chain`, without
which `_tenant` is never injected and the resulting rows are invisible to the
hooks service that has to adjudicate them.

### Taken: the enrollment packet is one field, not two

The packet carried `token_id` in the clear beside the artifact because a
`v4.local` artifact is symmetric: the daemon cannot read its own `sub`, and the
plane's `@require` compared the request body against it. Switching to
`v4.public` was never Garrison's change to make.

The route taken instead is this repository's own idiom. `Redemption.token_id`
lost its `required` and its `@require`; the `before_validate` hook now fills it
from the authenticated principal's subject claim, exactly as it already fills
`organization` and as `AuditEvent.operator` is filled. `Packet` is the artifact
and nothing else, and the redemption body no longer carries the field at all.

This is stronger than what it replaced, not weaker. A rule comparing a
submitted `token_id` against `principal.sub` can only refuse a mismatch; a
client with no field to put a token id in cannot attempt one. What holds it
closed is the binding's `required = true`: an unreachable hook fails the
request rather than persisting a row that names no grant. Both refusal paths
in the hook stamp the field too, so a persisted refusal still says which grant
an unknown machine presented — the one fact that row exists to carry.

The route's open question was settled empirically before it was taken. It
depended on the hook's `user_id` being populated for an `enrollee` bearer,
which has no console `User` row. It is: probing the hook during the live
redemption in `hooks-service/tests/directory_sync.rs` — a real enrollee
artifact, posted to a real plane in a container — yielded
`user_id = Some("tok_alice_1")` against the `token_id` the `@require` was
comparing. That test now posts a body with no `token_id` in it and asserts the
hook filled the field on both the acceptance and the refusal.

The second decision the route implied was taken with it.
`policies/custom/credential-lifecycle.cedar` gained
`garrison.redemption.append_only`, a `forbid` on `UpdateRedemption`. Without
it the change would have removed a check on the update path without replacing
one: `write` covers update, and the hook no-ops on anything but a create.
Redemption rows are the evidence a security officer reads when an unknown
machine presents a revoked grant, so they are append-only now, like the audit
trail and the credential rows beside them.

Taken now because it could only be taken now. `deny_unknown_fields` means a
one-field daemon hard-fails on any unspent two-field packet, naming the file.
That is the right failure and it is a fleet-wide one, which is why it belongs
before the number lands rather than after.

### Declined: renaming `InstallCredential.kind`

Already done, in commit `8f9535d`. The field is `credential_kind` on both
schemas and the concept has one name.

### Declined: making `Redemption.organization` required

The proposal was to turn an untenanted enrollment row from an invisible write
into a `422`. It would instead have **refused every enrollment**, accepted and
refused alike. Required-field validation runs against the raw request body
before tenant injection, before the rule phases, and before any hook is dialed;
the daemon deliberately does not send `organization`, because the hook resolves
it. `schemas/audit.schema` already records this invariant on the sibling field:
"a field the client is meant not to send cannot also be one the client must
send."

It would also have weakened the property it aimed to protect. `required` is a
presence check, so satisfying it means the daemon starts sending an
`organization` key — and hook merges leave fields they do not set untouched, so
a client-asserted tenant would survive into a persisted refusal. That inverts
`enrollment.schema`'s own rule: a field the client cannot know is a field the
client cannot lie about.

The real defect behind the symptom was the documented mint command, which
omitted `--tenant-chain`. That is fixed above.

## Open, and the owner's to settle

One candidate is genuinely a decision rather than a finding. It is recorded in
`docs/control-plane.md` under "Known gaps" as well, so it cannot be mistaken
for a promise.

### `EnrollmentToken.issuer` is a typo check, not a security control

`adjudicate` compares the stored column against the configured issuer, and its
doc comment reads as though that stopped a token minted for another purpose. It
cannot: every artifact is minted under the one issuer the plane accepts, and an
attacker holding the signing key mints under that same one. The check is worth
keeping as a provisioning guard, but the column is `required indexed` on a
surface about to freeze.

The alternative is to re-found it on a custom claim projected onto
`Forge::Principal` and asserted in a `@require`. Whether that is possible turns
on a question outside this repository: can a `principal_claims` entry take its
value from a raw token claim, or only from `source = { user_field = ... }`,
which reads a console `User` row an enrollment artifact does not have?

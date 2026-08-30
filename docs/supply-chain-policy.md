# Supply-chain policy

What Garrison pins and why, how a dependency change gets reviewed, what
`cargo deny check` enforces on every push and every release, what ships
alongside a release to let someone verify it, and what happens when an
advisory lands on something already in the tree. This document is the
"written supply-chain policy" #43 asked for; the mechanics it describes live
in `deny.toml`, `.github/workflows/ci.yml`, and
`.github/workflows/release.yml`.

## The pin policy

Almost every dependency in this workspace is a caret range (`cargo add`'s
default), which is the normal Cargo trust model: a patch or minor bump is
assumed compatible, and `Cargo.lock` pins the resolved version until
something asks `cargo update` to move it.

`acton-ai` is the one exception:

```toml
acton-ai = { version = "=0.35.0", default-features = false, features = [...] }
```

An exact pin, not a caret range. `garrison-agent` installs `acton-ai`'s FIPS
crypto provider before it parses a command line and refuses to start if the
module is not operating in FIPS mode — see `release.yml`'s "There is no
non-FIPS release" header comment. A caret range would let `cargo update`
silently move that binding to a version whose FIPS behavior nobody has
checked. The exact pin means every `acton-ai` upgrade is a deliberate edit to
`agent/Cargo.toml`, not something that rides in on an unrelated
`cargo update`.

The cost of that pin is that `acton-ai` 0.35.0's own dependency tree — most
directly `libsql`, which it uses for its embedded-database feature — is
frozen too, RUSTSEC advisories against it included. See "Known,
accepted advisories" below.

## Adding or changing a dependency

1. `cargo add`/`cargo remove` only (see the crate-wide instruction; never
   hand-edit a `Cargo.toml` dependency line). This resolves the latest
   compatible version rather than whatever the editor happened to pin.
2. Run `cargo deny check` locally before opening the PR. A dependency
   pulling in a license not already in `deny.toml`'s `[licenses] allow` list,
   or a registry not on the `[sources] allow-registry` list, fails the check
   and needs one of:
   - the license or source is fine — add it to `deny.toml` in the same PR,
     with the crate that needed it visible in the diff;
   - it is not fine — find a different crate.
3. CI runs the same check (`ci.yml`'s `advisories` job) on the PR regardless;
   step 2 exists so that finding happens on a laptop in ten seconds rather
   than in a CI log ten minutes later.

## Advisory scanning

`cargo deny check advisories` runs against the RustSec advisory database:

- **Every push and every pull request** — `ci.yml`, job `advisories`. Fast:
  it reads `Cargo.lock` and crate metadata, it never compiles anything.
- **Every release** — `release.yml`, job `supply-chain`, gating `build`. A
  tag can point to a commit whose CI run predates an advisory published
  since; re-checking at release time catches that.

A crate landing on RUSTSEC with no matching entry in `deny.toml`'s
`[advisories] ignore` list fails both. That is the mechanism behind #43's
acceptance criterion: a known-vulnerable crate fails CI.

### Known, accepted advisories

As of the pin above, `acton-ai` 0.35.0's `libsql` dependency carries seven
open RUSTSEC advisories, all listed in `deny.toml` with a reason. Summary:

| Advisory | Crate | Why it is accepted for now |
|---|---|---|
| RUSTSEC-2025-0141 | bincode 1.3.3 | Unmaintained (no CVE); no safe upgrade on the 1.x line |
| RUSTSEC-2025-0134 | rustls-pemfile 2.2.0 | Unmaintained (no CVE); no safe upgrade |
| RUSTSEC-2026-0049 | rustls-webpki 0.102.8 | CRL distribution-point bug; garrison consumes no CRLs |
| RUSTSEC-2026-0098 | rustls-webpki 0.102.8 | Unenforced URI name constraints; garrison asserts no URI names |
| RUSTSEC-2026-0099 | rustls-webpki 0.102.8 | Wildcard name-constraint bug; requires a misissued cert to reach |
| RUSTSEC-2026-0104 | rustls-webpki 0.102.8 | Reachable panic parsing a CRL; garrison parses no CRLs |
| RUSTSEC-2026-0258 | h2 0.3.27 | Unbounded empty DATA frames (low severity); garrison is a client on this stack, not a server accepting the frames |

Every one of these is inherited through the exact pin above, not something
`cargo update` can resolve away on its own. Clearing them means moving the
`acton-ai` pin to a release whose `libsql` no longer resolves to the
affected versions — tracked in
[#47](https://github.com/Govcraft/garrison/issues/47).

## Responding to a new advisory

When `cargo deny check advisories` starts failing on something not already
in the ignore list:

1. Read the advisory (`cargo deny` prints the RustSec URL and the full
   dependency path to the affected crate).
2. Decide whether garrison's own use of the affected crate can reach the
   flaw. Most of this workspace's dependency surface is transitive, several
   layers under `acton-ai`, `acton-service`, or `acton-reactive`; a crate
   being *present* is not the same as garrison calling the affected code
   path, and the table above is full of the latter.
3. If a direct dependency is affected and a compatible fixed version exists,
   `cargo update -p <crate>` and re-run the check — this is the common case
   and needs no `deny.toml` change.
4. If the fix requires bumping something pinned (today, only `acton-ai`),
   or no fix exists yet, add an `ignore` entry to `deny.toml` with a reason
   that states which code path is or is not reachable, and open a tracking
   issue the way #47 tracks the table above. An ignore entry with no
   tracking issue is a debt nobody is watching.
5. If garrison's own code does reach the flaw and no upgrade is available,
   that is a stop-ship: do not add an ignore entry to make CI pass, fix the
   reachable path or drop the dependency.

## Software bill of materials

Each release archive (`release.yml`, job `build`) carries an `sbom/`
directory: one CycloneDX 1.5 SBOM per binary that archive ships, generated
by `cargo cyclonedx` from that leg's own `Cargo.lock` resolution and target
triple, so a target-specific dependency does not show up in a platform that
never builds it. `garrison-agent_bin.cdx.json` ships in every archive;
`garrison-hooks_bin.cdx.json` ships only where `garrison-hooks` does (Linux).

CycloneDX rather than SPDX: it is what `cargo-cyclonedx`
(the actively maintained option for a Rust workspace, see
`.github/workflows/release.yml`) produces directly from `cargo metadata`
without a second conversion step, and it is a component-and-dependency-graph
format, which is the shape an advisory scanner or auditor asks for.

## Signed release artifacts

`release.yml`'s `publish` job signs `SHA256SUMS` — which already contains a
hash of every `.tar.gz` in the release — with `cosign sign-blob`, keylessly:
the signing certificate is minted from that job's own GitHub Actions OIDC
identity (`id-token: write`, scoped to the `publish` job only) through
Sigstore's Fulcio, and the signature and certificate are logged to the
public Rekor transparency log. There is no private key for this repository
to generate, rotate, or leak.

`SHA256SUMS.sig` and `SHA256SUMS.pem` ship alongside `SHA256SUMS` on every
release. To verify a download:

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/Govcraft/garrison/\.github/workflows/release\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

shasum -a 256 -c SHA256SUMS --ignore-missing
```

The first command proves `SHA256SUMS` was signed by *this repository's*
release workflow and nothing else — the identity regexp is the check that
matters, not just "a signature exists." The second checks the downloaded
archive against those now-trusted hashes. This is also in the release notes
`publish` generates, next to the FIPS provenance description.

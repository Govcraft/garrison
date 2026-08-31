# Garrison

**Governed AI coding, inside your boundary.**

Garrison is an open-source coding agent for organizations that need to control
where code goes, what an agent may do, and how its actions are proved later.
It works from VS Code, JetBrains IDEs, or a terminal; connects to approved cloud
or local models; and runs tools inside the developer's authorized workspace.

Unlike an assistant governed mainly by user settings, Garrison can make
organizational policy, identity, seat entitlement, and audit delivery conditions
of execution. A turn proceeds only when those gates allow it.

Garrison runs in either of two modes:

- **Standalone** for evaluation and individual use, with policy configured on
  the machine.
- **Governed** for managed fleets, with identity, policy, entitlement, and audit
  evidence anchored in a control plane the workstation cannot override.

## Garrison is for teams that must prove control, not merely configure it

Garrison is a good fit when you need several of the following:

- Source code and tool execution must stay within an approved environment.
- Developers may use only approved model providers or private endpoints.
- File and command access must be bounded to the active workspace.
- Sensitive tool calls require a person or central policy to approve them.
- Sessions must survive restarts without silently repeating interrupted work.
- Every tool call needs a tamper-evident record that leaves the machine.
- Access must follow directory identity, machine enrollment, and live seats.
- The organization needs one policy across terminals and multiple IDE windows.

Garrison is probably not the right fit if you want a hosted assistant that
requires no infrastructure, a general-purpose chat product, or a turnkey
administration suite. Garrison's governance mechanisms are open source.
Turnkey administration, deployment automation, SIEM integration, compliance
packages, and enterprise support may be offered separately by Govcraft.

It is also not yet a complete enforcement point for network behavior. Policy
can record `network_egress` and `allow_unsandboxed_escalation`, but the current
agent reports rather than enforces those fields. Read the complete
[known gaps](docs/control-plane.md#known-gaps) before evaluating a production
deployment.

## Four gates turn governance claims into runtime decisions

In governed mode, every coding turn crosses four independently testable gates:

| Claim | What Garrison enforces |
|---|---|
| **Identity comes from the organization** | A machine enrolls once with an Ed25519 install key; its operator comes from the configured directory. |
| **Policy comes from the control plane** | The daemon accepts only its assigned, checksummed, self-tested bundle. A governed install never falls back to editable local approvals. |
| **A live seat is required** | Each turn spends current entitlement. Revoking a seat during a turn stops that turn. |
| **Evidence leaves the workstation** | Tool calls enter a BLAKE3-chained trail and ship to a plane that rejects edits, forks, and replays. |

These gates fail differently on purpose. A policy refusal is not reported as a
network outage; a revoked seat receives no offline grace; and an audit entry the
plane rejects halts new work rather than disappearing into a retry loop. The
[control-plane design](docs/control-plane.md) defines those decisions and their
failure modes.

## One daemon gives every client one boundary, one policy, and one trail

Garrison runs one daemon per user per machine. Terminal and editor processes
are clients of that daemon, not separate agents with separate state.

```text
VS Code ───── garrison-agent acp ─┐
JetBrains ─── garrison-agent acp ─┤
terminal ──── garrison-agent chat ┤ Unix socket
other ACP client ─────────────────┘
                                  │
                         garrison-agent serve
                                  │
                 ┌────────────────┼────────────────┐
                 │                │                │
              model loop     sandboxed tools   audit trail
                 │                │                │
          approved provider   session root    control plane
```

Text equivalent: VS Code, JetBrains, the terminal and any other ACP client
connect through relays to one Unix socket and one `garrison-agent serve`
daemon. That daemon branches to the model loop, sandboxed tools and audit
trail; those respectively connect to an approved provider, the bounded session
root and the control plane.

The daemon owns the model runtime, session store, sandbox host, policy, and
audit writer. Each session receives one canonical filesystem root. Symlinks and
`..` cannot move a tool outside it. On Linux, write-capable tools run in a
re-executed child hardened with resource limits, Landlock, and seccomp.

Because editor relays contain no engine, opening another project cannot create
a second audit writer or quietly apply a different policy. The first client can
autostart the daemon; the daemon then outlives that client.

## The agent covers chat, code changes, language intelligence, and review

The implemented agent provides:

- Streaming chat in VS Code, JetBrains IDEs, and an interactive terminal.
- Inline completion in both first-party editor integrations, crossing the same
  seat, audit and policy gates a turn crosses. It is a paid model call that
  sends the code around a cursor to a provider, so an install refused from
  running a turn is refused this too, and the refusal is sealed in the trail.
- Persistent sessions, cancellation, plans, and optional context compaction.
- Structural patching with fuzzy context matching and atomic application.
- Read-only LSP diagnostics, hover, definitions, and references.
- `AGENTS.md` project instructions, discovered under the session's approved root
  and gated by the policy bundle. A governed install's bundle decides whether
  discovery is enabled, confined to named paths, or off; an ungoverned install
  or a policy ask that errors loads nothing. The files that survive that gate
  are named in the turn's own audit entry by path and content hash, never by
  content, so the answer to what steered a turn is chained alongside the answer
  to what the turn did.
- Human approval round trips, timeouts, and connection-local approval caching.
- Sandboxed `bash`, file-write, and file-edit tools.
- Anthropic, OpenAI, Groq, Kimi, Ollama, and OpenAI-compatible endpoints through
  [acton-ai](https://github.com/rodzilla/acton-ai).
- Experimental, read-only pull-request review for Bitbucket Data Center.

Review mode ships disabled. When explicitly enabled, it reads a pull-request
diff, produces inline findings, and can set a build status. It cannot call
write-capable tools, and blocking a build remains opt-in. See
[review mode](docs/review-mode.md) before placing it in CI.

## Try Garrison locally before deploying its control plane

The standalone path lets you evaluate the agent without enrollment, directory
integration, or control-plane services.

### 1. Build the workspace

You need Rust 1.89 or newer. All Rust dependencies resolve from crates.io.

```sh
git clone https://github.com/Govcraft/garrison.git
cd garrison
cargo build --workspace --locked
```

The optional [Task](https://taskfile.dev/) runner provides shortcuts such as
`task check`, `task test`, and `task agent`. The commands below use Cargo
directly so Task is not required.

### 2. Choose a model

Set `default_provider` in `acton-ai.toml` to one of its configured providers.

For a local evaluation, choose `ollama` and make sure the configured model is
available from your Ollama server. For OpenAI, Anthropic, or Groq, choose the
matching provider and store its credential with:

```sh
cargo run -p garrison-agent -- login openai
# or: anthropic, groq
cargo run -p garrison-agent -- login anthropic
```

Kimi and compatible endpoints use the credential file and endpoint settings
documented in `acton-ai.toml`. Do not commit credentials to this repository.

### 3. Start the daemon

Before starting the daemon, set `[threads] project_root` in `garrison.toml` to
the project or parent directory Garrison may serve. The daemon rejects sessions
outside that boundary.

Then run it from the repository with the checked-in standalone configuration:

```sh
cargo run -p garrison-agent -- serve \
  --config ./garrison.toml \
  --acton-config ./acton-ai.toml
```

In another terminal, verify the connection:

```sh
cargo run -p garrison-agent -- ping
```

Then start an interactive session from the project you want Garrison to work
in:

```sh
cd /path/to/your/project
/path/to/garrison/target/debug/garrison-agent chat
```

The daemon must allow that project under `[threads] project_root` or
`workspace_roots` in `garrison.toml`. Without an explicit root, a daemon started
from this repository serves only workspaces under this repository.

### 4. Connect an editor

The first-party clients live in:

- [`extensions/vscode/`](extensions/vscode/README.md)
- [`extensions/jetbrains/`](extensions/jetbrains/README.md)

Both launch `garrison-agent acp`, which relays ACP over standard input and
output to the same daemon. Point the extension at the binary you just built,
then open a workspace allowed by the daemon configuration.

## Accessibility

Garrison provides accessible paths through VS Code, JetBrains and the terminal,
including line-oriented and single-message terminal modes. See
[Accessibility and support](docs/accessibility.md) for surface-specific
features, terminal presentation controls, current limitations, the
accessibility contact and available support accommodations.

## A governed deployment adds the plane; it does not replace the agent

To move from evaluation to centrally governed use, operators add a `[plane]`
section to `garrison.toml` and deploy the accompanying control-plane model and
hooks.

The repository contains:

| Path | Role |
|---|---|
| `agent/` | Daemon, ACP relay, terminal client, tools, session storage, and governance gates |
| `schemas/` | SchemaForge model for organizations, operators, seats, installs, policy, and audit chains |
| `policies/` | Role ranks and custom Cedar policies |
| `hooks-service/` | Enrollment, install-token exchange, policy publication, audit ingest, and directory synchronization |
| `policy/` | Shared, pure policy parsing, checksumming, validation, and decisions |
| `wire/` | Signed install assertion and audit wire formats shared by agent and plane |
| `extensions/` | VS Code and JetBrains clients |
| `packaging/` | Per-user systemd service and packaging guidance |

Start with the [control-plane guide](docs/control-plane.md). It explains the
entity model, enrollment sequence, directory synchronization, policy lifecycle,
seat checks, audit shipping, and the deployment gaps that remain. The
[packaging guide](packaging/README.md) describes the per-user daemon and its
filesystem layout.

Garrison deliberately has no “almost governed” fallback. Once `[plane]` is
present, an unverified or stale policy eventually refuses turns; a local file
cannot widen central policy. A deployment should therefore exercise enrollment,
offline behavior, revocation, and audit recovery before enrolling developers.

## The audit record is evidence with explicit limits

Every attempted turn and every tool call is appended to a BLAKE3-chained JSONL
trail. A turn is recorded whether or not it called anything, so a session where
the model answered in text and used no tool still leaves a record. Turn entries
carry metadata only — outcome, prompt and response byte counts, provider,
model, token counts — and never the prompt or the answer. Strict durability
waits for the append to reach disk and refuses further non-idempotent work after
an audit failure. An anchor stored outside the trail detects deletion of its
tail, which the chain alone cannot detect.

A turn Garrison's own admission gates refuse is sealed too, though the model
loop never runs it: a lapsed seat, an unreachable plane, a full shipping
backlog. The entry records the stable reason it was refused, so an install
refused fifty times in an afternoon reads differently from an install nobody
touched.

```sh
garrison-agent audit verify
```

The command exits `0` for a clean trail, `3` for a broken chain, and `4` for an
anchor mismatch. It reads files only, so operators can verify a copied trail
without running the daemon.

In governed mode, the trail also ships off the workstation. Temporary loss of
the plane does not immediately ground a laptop, but an over-limit backlog can
fail closed, and a remotely rejected entry always halts new turns. See the
[audit sections of the control-plane guide](docs/control-plane.md#audit-shipping)
for the full model.

## Stable interfaces are documented; experimental ones are labeled

Garrison 1.x preserves the enrollment packet, ACP refusal codes, configuration
keys, control-plane schema compatibility, and audit trail verification rules
described in [the compatibility contract](docs/compatibility.md).

Experimental features make a narrower promise. They ship off, require an
explicit opt-in, and may change behavior or exit codes before stabilization.

Released binaries carry their own provenance. Each archive ships a CycloneDX
SBOM per binary, generated for that archive's own target rather than for the
workspace as a whole, and `SHA256SUMS` is signed keylessly with `cosign`
against the release workflow's GitHub Actions identity rather than a stored
key. `cargo deny` gates every push, every pull request, and every tagged
release against the advisory, license, and source policy in `deny.toml`. The
advisories currently accepted, and why, are written down rather than silently
allowed.

Before adopting Garrison, also review:

- [Accessibility and support](docs/accessibility.md)
- [Supply-chain policy](docs/supply-chain-policy.md)
- [Known gaps and operational failure modes](docs/control-plane.md#known-gaps)
- [Agent and integration design](docs/garrison-agent-design.md)
- [Bitbucket review mode](docs/review-mode.md)
- [Packaging and systemd operation](packaging/README.md)

## Contributing and licensing

Run the same checks as CI with:

```sh
task gate
```

Some control-plane integration tests require SchemaForge and a container
runtime; `task test:live` makes missing prerequisites a failure instead of a
skip. See [CONTRIBUTING.md](CONTRIBUTING.md) and the contributor
[agreement](CLA.md) before opening a pull request.

Copyright © 2026 Govcraft. Garrison is available under the
[GNU Affero General Public License, version 3 only](LICENSE) and under separate
commercial terms from Govcraft. See [LICENSING.md](LICENSING.md) and the
[trademark policy](TRADEMARKS.md).

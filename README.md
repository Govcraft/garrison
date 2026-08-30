# Garrison

**Governed agentic coding inside your boundary.**

Garrison is an AI coding-agent daemon built on
[acton-ai](https://github.com/rodzilla/acton-ai). The checked-in product is a
Rust agent that speaks the Agent Client Protocol (ACP), routes tool approvals
to its client, provides structural patching and language-server queries, and
can use agency-approved model endpoints.

**1.0 means an agency can deploy Garrison and the four governance claims below
survive an auditor asking "prove it."** Policy comes from the plane, a seat is
spent per turn, the audit trail leaves the machine that wrote it, and identity
comes from the directory. Each is enforced by a gate a turn passes through
rather than described in a document, and each is verified end to end against a
real plane in a container rather than against a mock.

What 1.0 does *not* promise is listed plainly under "Known gaps" in
[docs/control-plane.md](docs/control-plane.md), and the compatibility surface it
freezes is in [docs/compatibility.md](docs/compatibility.md). The federal-ui
administration site, SIEM integration, and the compliance document sets are
direction, not checkout.

## What is implemented

- One daemon per user per machine, serving ACP v1 over a Unix-domain socket
  and owning the runtime, the sandbox host and the audit trail.
- ACP v1 over stdin/stdout for editor-spawned hosts, as a relay to that
  daemon: the spawned process runs no engine of its own.
- Session create, load, list, prompt, and cancellation, over sessions that
  survive the daemon: history and turn checkpoints are written to a libSQL
  store as the work happens, so a restart reopens the conversation and reports
  the turn it interrupted instead of losing both.
- Streaming model text and tool lifecycle events.
- Plans and context compaction as protocol events: an `update_plan` call
  reaches the one session that owns the turn as an ACP `plan` update, a
  summarized history is announced on `_garrison/session/compacted`, and the
  turn's final plan and every compaction pass are repeated in the prompt
  response's `_meta`. Compaction is off unless `[context] auto_compact` in
  `acton-ai.toml` turns it on.
- Human approval round-trips, timeouts, and per-connection approval caching.
- A structural `apply_patch` tool with fuzzy context matching, atomic planning,
  and project-root safety checks.
- One canonical filesystem boundary per session: a client's `cwd` is resolved
  through symlinks and `..` and must land inside a root the administrator
  approved, and every filesystem tool a turn registers is built for that root
  and no other directory.
- Read-only LSP tools for diagnostics, hover, definitions, and references.
- Inline completion at the cursor, in both editors: `_garrison/complete` takes
  the text either side of a cursor and answers with the code that goes between
  them. It runs off the session's message loop, so a keystroke never queues
  behind a running turn, and it is abandoned after two seconds because ghost
  text that lands after the next keystroke is a distraction rather than a
  suggestion. The session is still resolved, which is what proves the client
  owns it and holds the request inside the workspace boundary. It reaches no
  admission gate, which is a hole in the governance premise rather than a
  missing nicety; see
  [#22](https://github.com/Govcraft/garrison/issues/22) and "Known gaps" in
  [docs/control-plane.md](docs/control-plane.md).
- Anthropic, OpenAI, Groq, Kimi, Ollama, and compatible endpoints through acton-ai.
- An interactive terminal chat: streaming replies in the terminal's own
  scrollback, keystroke approvals, Esc to interrupt, and slash commands.
- Process sandboxing for the tools that write: `bash`, `write_file`, and
  `edit_file` run in a re-exec'd child with resource limits and, on Linux,
  landlock and seccomp hardening, confined to the session's root.
- Provider login/logout helpers and a `ping` smoke client.
- The control plane's administrative entity model: 18 SchemaForge schemas
  covering tenancy, operators and seats, machine identity for the daemons, the
  install fleet, policy bundles and command rules, approved model endpoints,
  and audit-chain aggregation — lowering into a 233-policy, strict-mode-
  validated Cedar bundle. See
  [docs/control-plane.md](docs/control-plane.md).
- Enrollment, end to end: the daemon redeems a single-use grant on its first
  start, generates an Ed25519 install key it never transmits, and records the
  identity the plane assigns. A machine the plane turns away does not start;
  one already enrolled never calls the plane again. The plane side is a
  `before_validate` gRPC hook in `hooks-service/`. A grant also says what it
  mints: `durable` is a workstation, which enrolls once and keeps its install
  record; `ephemeral`, with a lifetime the grant sets, is a CI runner, which
  has no disk that outlives the build and would otherwise leave a pipeline
  choosing between an undifferentiated install row per build and a spent packet
  that refuses to start. The grant decides and never the daemon, because from
  inside a container a fresh runner and a freshly imaged laptop look identical.
  An ephemeral install carrying no expiry is refused before a seat is
  consulted, and every install a pipeline mints binds to the same CI operator,
  so a hundred builds a day is one seat.
- One authenticated path from an enrolled daemon to the plane: it signs a
  120-second assertion with its install key, trades it at
  `POST /api/v1/install/token` for a 15-minute bearer scoped to its
  organization, and every governed subsystem spends that bearer rather than
  holding a credential of its own. Replay, clock skew, a revoked credential
  and a retired install are each their own refusal, and a refusal is never
  reported as an outage. See
  [docs/control-plane.md](docs/control-plane.md).
- Seat entitlement the daemon enforces: an enrolled install runs only while
  the plane says it holds a live seat. Every turn passes a gate that spends
  the seat, a seat revoked mid-turn ends the turn it is running rather than
  letting it finish, and a plane that cannot be reached buys a window set by
  the organization's impact level rather than an indefinite one. "Your seat
  was revoked" and "your plane is unreachable" are two different refusals with
  two different codes, each explained in prose. See
  [docs/control-plane.md](docs/control-plane.md#seat-entitlement-from-the-agents-side--agentsrcentitlement).
- Centrally managed policy the laptop cannot edit: the daemon pulls the bundle
  its organization assigned, verifies the content against the checksum the
  plane recorded, and runs every rule against its own examples before putting
  it in force. There are three states and deliberately no fourth — standalone
  (no `[plane]` section, `garrison.toml` governs), governed (a verified bundle,
  and the local auto-approve list is not read at all), and ungoverned (the
  plane said no, or said nothing for longer than the organization allows, and
  every turn is refused). A governed install never falls back to its local
  file, because that would make policy something a laptop can edit. The refresh
  is a timer, so nothing on the turn path waits for the network. The bundle
  write-back doubles as the heartbeat, so a wedged daemon does not look like a
  clean shutdown.
- An audit trail that leaves the box. A hash chain proves nobody edited the
  middle of a record and proves nothing about the end of one, because a prefix
  of a valid chain is itself a valid chain — so the trail ships to the plane,
  which refuses a forked or edited entry and collides a replay with a 409.
  Shipping is itself a gate: an unreachable plane never stops a turn (a laptop
  on a train is not a governance failure), a backlog past its bound does when
  `fail_closed`, and a halt always does, because a refused entry is a finding
  rather than an outage.
- Unattended pull request review against Bitbucket Data Center, **shipped
  experimental and off**: `review` refuses to start until a deployment enables
  it (`GARRISON_EXPERIMENTAL=review`, or `[experimental] review = true`),
  because its exit codes may still change and a warning nobody reads would not
  stop a pipeline depending on them.
  `garrison-agent review` fetches the diff, posts findings as inline comments
  at `file:line`, and sets a build status on the commit. It writes nothing:
  every tool call is refused, because a pipeline has nobody to answer a
  permission prompt. Blocking is opt-in and off by default, since failing a
  build on a model's opinion is a strong claim. An answer that cannot be
  parsed exits non-zero rather than reporting a clean review, because a green
  check on code nobody read is worse than no reviewer at all. It also waits
  for its audit trail to reach the plane before exiting, because a container
  is deleted minutes later and an entry still in its buffer is destroyed
  evidence rather than delayed evidence. See
  [docs/review-mode.md](docs/review-mode.md).
- acton-ai policy, accounting, audit, planning, context, MCP, and tool-loop
  primitives where enabled by configuration.

## What is planned

All four control-plane services named by the 1.0 gates are wired: enrollment,
policy distribution, seat entitlement, audit ingest, and the Entra ID directory
sync alongside them. These components are not present in this repository today:

- The federal-ui administration site.
- Infrastructure, SIEM integration, and compliance document sets.
- Command-prefix policy, turn diffs, repository context,
  project-instruction discovery, and persistent PTYs.

Some things the plane models are recorded rather than enforced, and the code
says so out loud rather than implying otherwise: a bundle's `network_egress`
and `allow_unsandboxed_escalation` are part of the checksum and reported in
`_garrison/status`, and no code acts on them. `ping` reports them as not
enforced. The full list is under "Known gaps" in
[docs/control-plane.md](docs/control-plane.md).

## Current architecture

```text
editor ─ garrison-agent acp (relay) ─┐
terminal ─ garrison-agent chat ──────┤ $XDG_RUNTIME_DIR/garrison-agent.sock
socket client ───────────────────────┘
  └─ garrison-agent serve (one per user; owns runtime, socket, audit trail,
     session store)
      └─ ClientConn actor
      └─ ThreadSupervisor / Thread actor
          └─ acton-ai prompt and tool loop
              ├─ configured LLM provider
              ├─ acton-ai built-in and MCP tools
              ├─ Garrison apply_patch and LSP tools
              └─ policy hook → ACP permission request
```

The intended control plane and IDE integrations are documented as roadmap
architecture in [docs/garrison-agent-design.md](docs/garrison-agent-design.md).

What 1.0 promises about the schemas, the enrollment protocol, the ACP surface,
`garrison.toml`, and the audit trail on disk — and what it deliberately does
not — is in [docs/compatibility.md](docs/compatibility.md).

## Process topology

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

## Repository layout

| Path | Status | Purpose |
|---|---|---|
| `agent/` | Implemented | `garrison-agent` Rust library, daemon, ACP client, tools, and tests |
| `docs/` | Implemented | Architecture and design notes |
| `schemas/` | Implemented | Control-plane entity model in the SchemaForge DSL |
| `policies/` | Implemented | Role ranks and hand-written Cedar policies |
| `garrison.toml` | Implemented | Server, approval, thread, plane, and LSP configuration |
| `bitbucket/` | Implemented | `garrison-bitbucket`: the Bitbucket Data Center client review mode reads pull requests and posts findings through |
| `wire/` | Implemented | `garrison-wire`: the install assertion both the daemon and the hook service compile against, with its test vector |
| `acton-ai.toml` | Implemented | Provider, context, sandbox, and acton-ai runtime configuration |
| `config.toml` | Implemented | Control-plane (SchemaForge on acton-service) configuration |
| `Taskfile.yml` | Implemented | Tasks that operate on this checkout |
| `packaging/` | Implemented | The per-user systemd unit and packaging notes |
| `hooks-service/` | Working | The enrollment hook, the install-token exchange, and the Entra ID directory sync: adjudicates a token, provisions the install and its credential, mints the bearers enrolled daemons spend, keeps operators in step with the directory |
| `site/` | Planned | Control-plane administration site |
| `extensions/vscode/` | Implemented | VS Code ACP client, sidebar chat, approvals, inline completion, and status |
| `extensions/jetbrains/` | Implemented | JetBrains ACP client, tool-window chat, approvals, inline completion, and status |
| `infra/`, `docs/compliance/` | Planned | Deployment and compliance material |

## Development quickstart

The only prerequisite is a Rust toolchain at 1.89 or newer, which is where
`std::fs::File::try_lock` stabilized and what acton-ai's single-writer audit
lock needs. Every dependency resolves from crates.io: a clone builds.

```sh
# Compile and run the test suite.
task test

# Start the daemon on the configured Unix socket (or: task daemon:install).
task agent

# In another terminal, inspect the running daemon. Never starts one.
task ping
```

Editors spawn the relay, which connects to the daemon and starts it if
`[server] autostart` allows:

```sh
cargo run -p garrison-agent -- acp
```

Cloud providers require credentials configured in `acton-ai.toml`; use
`cargo run -p garrison-agent -- login <anthropic|openai>` where supported, or
populate the provider's configured key file. Ollama can be selected for a local
deployment. `garrison.toml` configures the project root, approval behavior,
optional language servers, an optional `[audit]` section, an optional
`[sessions]` section governing how long stored conversations are kept, and an
optional `[plane]` section naming the control plane to enroll with. Without
that last section the agent runs standalone.

## The audit trail

Every tool call is appended to a BLAKE3-chained JSONL trail that acton-ai
seals, one trail per daemon and so one per user. Garrison adds what a
deployment needs on top of it.

`acton-ai.toml`'s `[audit] durability` says what an append promises.
`best_effort` appends and flushes. `strict`, which the shipped configuration
sets, fsyncs and waits for the acknowledgement; once an append has failed it
refuses every tool not declared idempotent, and Garrison refuses the next turn
outright with JSON-RPC code `-32017` rather than running it unrecorded. A
writer that will not answer the health question is refused the same way,
because "I cannot find out whether this will be recorded" and "this will not
be recorded" mean the same thing to the record.

`_garrison/status` reports `audit.state` as one of four words, and
`garrison-agent ping` prints it first: `disabled` (nothing is being recorded),
`configured` (a trail is armed and nothing has been written to it yet),
`healthy` (every append reached the disk), `degraded` (at least one did not,
so the record is incomplete). A daemon that cannot ask its own writer says
`degraded`, never `healthy`. Recovery is an operator procedure and not a
self-healing one: stop, fix the disk, verify, keep the trail as evidence,
restart.

A hash chain cannot notice its own truncation, because a prefix of a valid
chain is a valid chain. So the daemon writes the head somewhere the trail is
not: `[audit] anchor_path` in `garrison.toml`, defaulting to
`$XDG_STATE_HOME/garrison/audit-anchor.json` at mode 0600, rewritten after
every finished turn. A trail that ends before its anchor, or that reaches the
anchored sequence carrying a different hash, refuses to start the daemon (exit
2) unless `[audit] on_anchor_mismatch = "warn"` says otherwise.

```sh
garrison-agent audit verify        # exit 0 clean, 3 broken chain, 4 anchor mismatch
```

Exit 3 says the chain does not hang together. Exit 4 says it hangs together
perfectly and no longer ends where the anchor says it ended, which is what
deleting the tail of a trail looks like and is the one finding the chain
cannot make about itself. The command reads files only, so it works on a trail
copied off the machine.

A `[plane]` section present while `acton-ai.toml` arms no trail is a refusal to
start: an install that answers to an agency and records nothing is the failure
an audit exists to prevent. `[audit] required` overrides that inference either
way.

## Sessions that survive a restart

`acton-ai.toml`'s `[checkpoint]` section arms a libSQL store, and its presence
is what turns persistence on. Every session is written down before its id is
handed to the client, its history is saved as turns finish, and each turn
checkpoints after every provider round. A daemon that comes back up reopens a
session on `session/load` and replays its history, having held nothing in
memory across the restart.

Two rules fail closed. A store that cannot be reached refuses every turn with
`-32018`, rather than running work no restart could find. A session whose
record names a turn that was still open refuses *new* prompts with `-32019`
until an operator settles the old one, because restarting it silently would
re-run tools that already ran and dropping it silently would throw away work
somebody asked for. `session/load` reports the interrupted turn in
`_meta.garrison.interruptedTurn`, and `_garrison/session/resume` picks it up
from the round its checkpoint reached while `_garrison/session/abandon` gives
up on it and makes the session promptable again. For the same reason,
`[checkpoint] policy` must be `resume_on_request`; `resume_auto` refuses to
start, since a turn resumed in the background would settle its tool calls with
no client connected to approve them.

`garrison.toml`'s `[sessions]` owns the window sessions are kept for
(`retain_days`, swept every `sweep_interval_hours`, starting at launch). A
session holding an interrupted turn is never swept at any age: the operator has
not yet said what to do with it. As with the trail, a `[plane]` section present
while no store is armed is a refusal to start, and `[sessions] required`
overrides that inference either way. `_garrison/status` reports the store under
`sessionStore`, including how many sessions are waiting on a decision.

## Target architecture

The agent is connected to the control plane whose model lives in `schemas/`:
identity, centrally managed policy, seats, and audit aggregation are each wired
end to end, and the editor extensions consume the same ACP service. What
remains direction rather than checkout is the administration site, SIEM export,
and compliance certification — claims about those describe intended product
capabilities rather than this repository's runnable state.

## Status

1.1. The agent daemon, the VS Code and JetBrains clients, and the four
control-plane services behind the governance claims are implemented and
verified against a live plane. `docs/compatibility.md` states what the number
promises on each covered surface and what it deliberately does not.

1.1 adds inline completion at the cursor in both editors, unattended Bitbucket
pull request review shipped experimental and off, and enrollment grants that
mint an install identity expiring with the build that redeemed it. Everything
1.0 froze is unchanged: the additions are new fields, new methods, and a new
crate, and nothing was removed or repurposed.

The one deployment fact worth stating next to the number: there is no
provisioned database. The apply path has been exercised against throwaway
containers, so a deployment starts with `task plane:apply` against a fresh
database, a seeded organization, and a bootstrapped `platform_admin`.

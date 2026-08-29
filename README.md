# Garrison

**Governed agentic coding inside your boundary.**

Garrison is a pre-alpha AI coding-agent daemon built on
[acton-ai](https://github.com/rodzilla/acton-ai). The checked-in product is a
Rust agent that speaks the Agent Client Protocol (ACP), routes tool approvals
to its client, provides structural patching and language-server queries, and
can use agency-approved model endpoints.

The control plane's entity model has landed as SchemaForge schemas, and the
agent enrolls itself against it on first run; the services that would carry
policy and audit between the two have not. The rest of the federal product
described below is direction, not checkout.

## What is implemented

- One daemon per user per machine, serving ACP v1 over a Unix-domain socket
  and owning the runtime, the sandbox host and the audit trail.
- ACP v1 over stdin/stdout for editor-spawned hosts, as a relay to that
  daemon: the spawned process runs no engine of its own.
- In-memory session create, load, list, prompt, and cancellation.
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
- Anthropic, OpenAI, Groq, Kimi, Ollama, and compatible endpoints through acton-ai.
- An interactive terminal chat: streaming replies in the terminal's own
  scrollback, keystroke approvals, Esc to interrupt, and slash commands.
- Process sandboxing for the tools that write: `bash`, `write_file`, and
  `edit_file` run in a re-exec'd child with resource limits and, on Linux,
  landlock and seccomp hardening, confined to the session's root.
- Provider login/logout helpers and a `ping` smoke client.
- The control plane's administrative entity model: 16 SchemaForge schemas
  covering tenancy, operators and seats, machine identity for the daemons, the
  install fleet, policy bundles and command rules, approved model endpoints,
  and audit-chain aggregation — lowering into a 170-policy, strict-mode-
  validated Cedar bundle. See
  [docs/control-plane.md](docs/control-plane.md).
- Enrollment, end to end: the daemon redeems a single-use grant on its first
  start, generates an Ed25519 install key it never transmits, and records the
  identity the plane assigns. A machine the plane turns away does not start;
  one already enrolled never calls the plane again. The plane side is a
  `before_validate` gRPC hook in `hooks-service/`.
- acton-ai policy, accounting, audit, planning, context, MCP, and tool-loop
  primitives where enabled by configuration.

## What is planned

These components are not present in this repository today:

- The rest of the control-plane *services*: policy distribution to installs
  and audit ingest. The model those services will speak is in `schemas/`;
  enrollment and the Entra ID directory sync are the paths wired against it
  so far.
- The federal-ui administration site.
- Infrastructure, SIEM integration, and compliance document sets.
- Command-prefix policy, turn diffs, repository context,
  project-instruction discovery, persistent PTYs, and Bitbucket review mode.

Active tracking issues include
[documentation alignment](https://github.com/Govcraft/garrison/issues/2),
[session persistence](https://github.com/Govcraft/garrison/issues/3), and
[audit durability](https://github.com/Govcraft/garrison/issues/4).

## Current architecture

```text
editor ─ garrison-agent acp (relay) ─┐
terminal ─ garrison-agent chat ──────┤ $XDG_RUNTIME_DIR/garrison-agent.sock
socket client ───────────────────────┘
  └─ garrison-agent serve (one per user; owns runtime, socket, audit trail)
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
| `garrison.toml` | Implemented | Server, approval, thread, and LSP configuration |
| `acton-ai.toml` | Implemented | Provider, context, sandbox, and acton-ai runtime configuration |
| `config.toml` | Implemented | Control-plane (SchemaForge on acton-service) configuration |
| `Taskfile.yml` | Implemented | Tasks that operate on this checkout |
| `packaging/` | Implemented | The per-user systemd unit and packaging notes |
| `hooks-service/` | Working | The enrollment hook and the Entra ID directory sync: adjudicates a token, provisions the install and its credential, keeps operators in step with the directory |
| `site/` | Planned | Control-plane administration site |
| `extensions/vscode/` | Implemented | VS Code ACP client, sidebar chat, approvals, and status |
| `extensions/jetbrains/` | Implemented | JetBrains ACP client, tool-window chat, approvals, and status |
| `infra/`, `docs/compliance/` | Planned | Deployment and compliance material |

## Development quickstart

Prerequisites are a Rust toolchain and the sibling acton-ai checkout expected
by `agent/Cargo.toml` at `../../acton-ai`.

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
optional language servers, and an optional `[plane]` section naming the control
plane to enroll with. Without that section the agent runs standalone.

## Target architecture

The roadmap connects the agent to the control plane whose model now lives in
`schemas/` — identity, centrally managed policy, seats, and audit aggregation —
and adds editor extensions that consume the same ACP service. Until those components land, claims about centralized
governance, SIEM export, or compliance certification describe intended product
capabilities rather than this repository's runnable state.

## Status

Pre-alpha. The agent daemon and first VS Code and JetBrains clients are
implemented. The control plane exists as a validated entity model with one
service behind it: enrollment, which the agent now uses to join a fleet.

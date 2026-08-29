# Garrison

**Governed agentic coding inside your boundary.**

Garrison is a pre-alpha AI coding-agent daemon built on
[acton-ai](https://github.com/rodzilla/acton-ai). The checked-in product is a
Rust agent that speaks the Agent Client Protocol (ACP), routes tool approvals
to its client, provides structural patching and language-server queries, and
can use agency-approved model endpoints.

The control plane's entity model has landed as SchemaForge schemas; the
services that would carry data between it and the agent have not. The rest of
the federal product described below is direction, not checkout.

## What is implemented

- ACP v1 over stdin/stdout for editor-spawned agents.
- ACP v1 over a Unix-domain socket for a long-lived daemon.
- In-memory session create, load, list, prompt, and cancellation.
- Streaming model text and tool lifecycle events.
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
- The control plane's administrative entity model: 15 SchemaForge schemas
  covering tenancy, operators and seats, machine identity for the daemons, the
  install fleet, policy bundles and command rules, approved model endpoints,
  and audit-chain aggregation — lowering into a 170-policy, strict-mode-
  validated Cedar bundle. See
  [docs/control-plane.md](docs/control-plane.md).
- acton-ai policy, accounting, audit, planning, context, MCP, and tool-loop
  primitives where enabled by configuration.

## What is planned

These components are not present in this repository today:

- Control-plane *services*: Entra ID integration, policy distribution to
  installs, and audit ingest. The model those services will speak is in
  `schemas/`; nothing pushes or pulls against it yet.
- Hooks service and federal-ui administration site.
- Infrastructure, SIEM integration, and compliance document sets.
- Command-prefix policy, turn diffs, repository context,
  project-instruction discovery, persistent PTYs, and Bitbucket review mode.

Active tracking issues include
[documentation alignment](https://github.com/Govcraft/garrison/issues/2),
[session persistence](https://github.com/Govcraft/garrison/issues/3), and
[audit durability](https://github.com/Govcraft/garrison/issues/4).

## Current architecture

```text
ACP client (editor, terminal, or socket client)
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
| `hooks-service/` | Working | The enrollment hook: adjudicates a token, provisions the install and its credential |
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

# Start the ACP daemon on the configured Unix socket.
task agent

# In another terminal, inspect the running daemon.
task ping
```

For editor-spawned stdio mode, run:

```sh
cargo run -p garrison-agent -- acp
```

Cloud providers require credentials configured in `acton-ai.toml`; use
`cargo run -p garrison-agent -- login <anthropic|openai>` where supported, or
populate the provider's configured key file. Ollama can be selected for a local
deployment. `garrison.toml` configures the project root, approval behavior, and
optional language servers.

## Target architecture

The roadmap connects the agent to the control plane whose model now lives in
`schemas/` — identity, centrally managed policy, seats, and audit aggregation —
and adds editor extensions that consume the same ACP service. Until those components land, claims about centralized
governance, SIEM export, or compliance certification describe intended product
capabilities rather than this repository's runnable state.

## Status

Pre-alpha. The agent daemon and first VS Code and JetBrains clients are
implemented. The control plane exists as a validated entity model with no
services behind it yet.

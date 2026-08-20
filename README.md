# Garrison

**Governed agentic coding inside your boundary.**

Garrison is a pre-alpha AI coding-agent daemon built on
[acton-ai](https://github.com/rodzilla/acton-ai). The checked-in product is a
Rust agent that speaks the Agent Client Protocol (ACP), routes tool approvals
to its client, provides structural patching and language-server queries, and
can use agency-approved model endpoints.

The broader federal control plane described below is the product direction,
not part of this checkout yet.

## What is implemented

- ACP v1 over stdin/stdout for editor-spawned agents.
- ACP v1 over a Unix-domain socket for a long-lived daemon.
- In-memory session create, load, list, prompt, and cancellation.
- Streaming model text and tool lifecycle events.
- Human approval round-trips, timeouts, and per-connection approval caching.
- A structural `apply_patch` tool with fuzzy context matching, atomic planning,
  and project-root safety checks.
- Read-only LSP tools for diagnostics, hover, definitions, and references.
- Anthropic, OpenAI, Groq, Kimi, Ollama, and compatible endpoints through acton-ai.
- An interactive terminal chat: streaming replies in the terminal's own
  scrollback, keystroke approvals, Esc to interrupt, and slash commands.
- Process sandboxing for the tools that write: `bash`, `write_file`, and
  `edit_file` run in a re-exec'd child with resource limits and, on Linux,
  landlock and seccomp hardening, confined to the session's root.
- Provider login/logout helpers and a `ping` smoke client.
- acton-ai policy, accounting, audit, planning, context, MCP, and tool-loop
  primitives where enabled by configuration.

## What is planned

These components are not present in this repository today:

- SchemaForge control plane, Entra ID integration, Cedar administration, seat
  management, policy distribution, and audit aggregation.
- VS Code and JetBrains extensions.
- Hooks service and federal-ui administration site.
- Infrastructure, SIEM integration, and compliance document sets.
- Command-prefix policy, sandbox escalation, turn diffs, repository context,
  project-instruction discovery, persistent PTYs, and Bitbucket review mode.

Active tracking issues include
[documentation alignment](https://github.com/Govcraft/garrison/issues/2),
[session persistence](https://github.com/Govcraft/garrison/issues/3),
[audit durability](https://github.com/Govcraft/garrison/issues/4), and
[filesystem boundaries](https://github.com/Govcraft/garrison/issues/5).

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
| `garrison.toml` | Implemented | Server, approval, thread, and LSP configuration |
| `acton-ai.toml` | Implemented | Provider, context, sandbox, and acton-ai runtime configuration |
| `Taskfile.yml` | Implemented | Tasks that operate on this checkout |
| `schemas/`, `policies/`, `hooks-service/`, `site/` | Planned | Control-plane services and policy assets |
| `extensions/` | Planned | VS Code and JetBrains clients |
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

The roadmap adds a SchemaForge control plane for identity, centrally managed
policy, seats, and audit aggregation, plus editor extensions that consume the
same ACP service. Until those components land, claims about centralized
governance, SIEM export, or compliance certification describe intended product
capabilities rather than this repository's runnable state.

## Status

Pre-alpha. The agent daemon is implemented and tested; the control plane and
editor products remain roadmap work.

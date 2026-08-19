# Garrison

**Governed agentic coding inside your boundary.**

Garrison is a federal-ready AI coding assistant: an agentic coding engine built
on [acton-ai](https://github.com/rodzilla/acton-ai), administered through a
SchemaForge control plane. Code never leaves the agency's approved data-handling
boundary; every agent action passes a policy gate and lands in a tamper-evident
audit chain.

Named for what it is: a force stationed inside the perimeter, operating under
standing orders, keeping a duty log.

## Why it exists

Agencies buying AI coding assistants (see USAC RFQ IT-26-107 as the reference
requirements set) need what seat-license SaaS vendors structurally cannot give
them:

- **No vendor tenant.** BYO model provider (Bedrock in GovCloud, or any
  Anthropic/OpenAI-compatible endpoint). The subprocessor list is one row.
- **Governance tiers as enforcement, not policy PDFs.** Tier A/B/C agentic
  scopes (inline suggest → human-gated multi-file edits → PMO-approved
  autonomy) enforced by the acton-ai approval gate, centrally distributed.
- **Evidence, not logs.** BLAKE3 hash-chained append-only audit trail per
  seat, aggregated to the control plane, SIEM-exportable, `verify`-able.
- **FIPS build path.** aws-lc-rs FIPS crypto provider process-wide.

## Architecture

```
┌─ developer workstation ────────────────────┐   ┌─ control plane (SchemaForge) ──┐
│  IDE (VS Code / JetBrains)                 │   │  Entra ID OIDC SSO             │
│    └─ extension ── IPC ──> garrison-agent  │──▶│  Cedar RBAC (admin/dev/auditor)│
│         (acton-ai: prompt loop, tools,     │   │  Org policy distribution       │
│          policy gate, audit chain, FIPS)   │◀──│  Seat & license management     │
│                └──> LLM provider           │   │  Audit aggregation + SIEM      │
│                     (Bedrock GovCloud /    │   │  Usage & acceptance-rate KPIs  │
│                      agency-approved API)  │   │  Admin dashboards (federal-ui) │
└────────────────────────────────────────────┘   └────────────────────────────────┘
```

## Layout

| Path | What |
|---|---|
| `agent/` | `garrison-agent` — Rust daemon + CLI built on acton-ai (prompt loop, tools, IPC for IDE extensions, policy pull, audit push) |
| `schemas/` | SchemaForge `.schema` files: User, Seat, PolicyProfile, AuditEvent, UsageReport, ... |
| `policies/` | Cedar policies (admin / developer / read-only auditor) |
| `hooks-service/` | SchemaForge lifecycle hooks (gRPC, acton-service) |
| `site/` | Admin console — `schema-forge site generate`, federal-ui, WCAG 2.1 AA |
| `extensions/vscode/` | VS Code extension (inline completion + chat over agent IPC) |
| `extensions/jetbrains/` | JetBrains plugin (IntelliJ Platform, inline completion API) |
| `infra/` | Dockerfiles, terraform, runbook |
| `docs/compliance/` | VPAT/ACR, NIST 800-53 Moderate compensating-controls plan, IRP, subprocessor table |
| `keys/` | PASETO keys (dev only, never committed) |
| `scripts/` | Dev/ops helpers |

## Dev quickstart

`task dev` (see `Taskfile.yml`) brings up the control plane backend, hooks
service, and admin site, mirroring the Meridian stack layout. The agent runs
from `agent/` with `cargo run`.

## Status

Pre-alpha scaffold. Requirements source of truth: USAC RFQ IT-26-107 + Q&A
(quote due 2026-08-31). Build order: acton-reactive Windows unblock →
VS Code extension over agent IPC → control plane schemas/policies →
JetBrains MVP → VPAT + 800-53 plan → Bitbucket DC PR review.

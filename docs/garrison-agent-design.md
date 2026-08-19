# garrison-agent: from AI agent to coding agent

**Source study:** openai/codex @ `~/code/reference/codex` (Apache-2.0), codex-rs
workspace, ~100 crates. **Date:** 2026-08-19.

The question this document answers: what does codex-rs know that acton-ai
doesn't, and which of those things must garrison-agent build to be a *coding
agent* rather than a general agent with a bash tool.

## 0. Reuse decision

Codex's core/CLI are not reusable for us: `codex-core` is a monolith welded to
the Responses API, ChatGPT auth, and OpenAI's cloud-tasks/analytics stack, and
none of the official crates are published to crates.io. Decision: **reference
architecture only.** We implement Garrison-native equivalents on acton-ai
actors. Where we port a specific algorithm (notably `apply-patch`'s
`seek_sequence` fuzzy context matching), we attribute under Apache-2.0 in
NOTICE.

## 1. What codex teaches: the coding-agent delta

A coding agent is a general agent plus twelve capabilities. Ranked by how much
they define the product:

### 1.1 A real edit tool: `apply_patch`
Codex does not edit files with exact-string replace. `apply_patch` is a
structural patch format (lark grammar, streaming parser) applied with
**fuzzy context seeking** (`seek_sequence.rs`): hunks locate themselves by
surrounding context with tolerance for drift, so edits survive the file having
changed since the model last read it. Every patch passes a **safety
assessment** (`safety.rs`): `SafetyCheck::{AutoApprove, AskUser, Reject}`
against writable roots, outside-project writes, and read-only sandbox policy —
*before* the bytes move.

→ **Garrison:** `garrison-patch` module. Patch format + fuzzy apply + safety
assessment wired into the acton-ai approval gate as a rule provider. This is
the single highest-leverage build item.

### 1.2 Command policy as a language: `execpolicy`
Prefix-rule policy (Starlark): `prefix_rule(pattern=["git", ["status","log"]],
decision="allow"|"prompt"|"forbidden", justification=..., match=[...],
not_match=[...])`. Two ideas worth stealing wholesale:
- **Load-time validated examples** — `match`/`not_match` are unit tests that
  run when the policy loads. A policy that doesn't match its own examples
  refuses to load. Federal reviewers will love this.
- **Command canonicalization** (`command_canonicalization.rs`) — `bash -lc
  "git status"` is parsed down to the argv it actually runs before matching,
  so policy can't be laundered through a shell wrapper.

→ **Garrison:** `garrison-execpolicy` implementing prefix rules (TOML, not
Starlark — matches our config idiom) + canonicalization, plugged into the
acton-ai `PolicyHook` we shipped 2026-08-19. Decisions map: allow →
auto-approve, prompt → callback (IDE round-trip), forbidden → deny-with-reason
fed back to the model. `justification` surfaces in the audit entry.

### 1.3 Sandbox escalation as a flow, not a wall
Codex runs commands sandboxed by default; on sandbox-caused failure it asks
"retry without sandbox?" (`shell-escalation`). Network approval is a separate
axis from filesystem approval. Approval modes: `untrusted | on-failure |
on-request | never | granular`, with per-session **approved-prefix caching**
("remember this approval": `approved_command_prefix_saved.rs`).

→ **Garrison:** acton-ai's ProcessSandbox already does the isolation; the
escalation *flow* (sandboxed fail → approval round-trip → unsandboxed retry,
recorded in the audit chain as an escalation) is new prompt-loop behavior.
Approved-prefix caching lives in per-turn policy state. This maps 1:1 onto
USAC Tier A/B/C: escalation is precisely a Tier B→C transition with a human
gate — the audit chain makes it *evidence*.

### 1.4 Persistent PTY sessions: `unified_exec`
One-shot bash is not how developers work. `unified_exec` maintains PTY-backed
sessions (`exec_command.rs` + `write_stdin.rs`): start a dev server, keep the
handle, write stdin to a REPL three tool-calls later, read incremental output.

→ **Garrison:** a `PtySession` actor per live session under a supervisor
(actor-per-resource is acton-reactive's native shape; the socket has one
owner, no `Arc<Mutex<pty>>`). Tools: `exec_session`, `write_stdin`,
`read_output`, `kill_session`.

### 1.5 Turn diff tracking
`turn_diff_tracker.rs` accumulates a unified diff of everything the turn
changed — apply_patch results *and* exec side effects (via git status +
fsmonitor baselines) — with a 100ms diff timeout falling back to coarse diff.
The UI can always answer "what did the agent just do to my tree?"

→ **Garrison:** `TurnDiff` actor fed by the audit pipeline (we already
broadcast every tool outcome). Per-turn diff is the artifact USAC Tier B
review gates on: "explicit developer review and approval before merge" needs
a *thing to review*. This is a compliance feature wearing a UX costume.

### 1.6 Repo awareness: `git-utils`
Baseline snapshots, branch/status introspection, fsmonitor, structured diff
apply. The agent knows it's in a repo, whether the tree is dirty, and what it
changed vs what the user changed. The system prompt encodes the etiquette
("you may be in a dirty worktree; NEVER revert changes you did not make").

→ **Garrison:** `garrison-git` module (shell out to git; no libgit2 dep).
Environment context (branch, dirty state, recent commits) injected as a
context fragment at turn start.

### 1.7 Project instruction discovery: AGENTS.md
`agents_md.rs` + `find_up`: walk up from cwd, load AGENTS.md hierarchy, layer
user instructions over project instructions. This is the CLAUDE.md idea as a
portable convention.

→ **Garrison:** support AGENTS.md (the emerging cross-vendor standard) and
GARRISON.md, hierarchical, nearest-wins-per-key. acton-ai's SkillRegistry
already covers the skills half.

### 1.8 Context management: budget + compaction + rollouts
- `compact.rs`: auto-summarization when the window fills, with pre/post-compact
  hooks and templated summary prefixes.
- `rollout/`: every session is an append-only JSONL rollout (compressed,
  reverse-scannable, indexed) — resumable, forkable, searchable.
- `get_context_remaining` is exposed *as a tool* so the model can see its own
  budget.

→ **Garrison:** acton-ai has context truncation (`memory/context.rs`) and
libSQL persistence; missing are summarization-compaction and resumable
in-flight turns. The latter is already scoped as acton-ai issue #12 — upstream
it there, not in garrison. Add `get_context_remaining` as a builtin.

### 1.9 Plan tool
`update_plan`: the model maintains a structured step list with states; the
prompt tells it when planning is worth it ("skip for the easiest 25%; never
single-step plans"). Cheap to build, large effect on multi-file task quality.

→ **Garrison:** builtin `update_plan` tool + plan state in turn context,
streamed to the IDE.

### 1.10 Review mode
Dedicated prompts (`review_request.rs`, `review_exit.rs`) and prompt rules:
findings first, ordered by severity, file:line references, explicit "no
findings" statement. Review is a *mode*, not a vibe.

→ **Garrison:** `garrison review` — and this is the Bitbucket DC integration
point (RFQ §3.A.2 "pull-request-level AI review is strongly desired"): fetch
PR diff via Bitbucket DC REST, run review mode, post findings as PR comments.

### 1.11 Model-specific coding prompts
Codex ships per-model system prompts (~80 focused lines) plus
`prompt_with_apply_patch_instructions.md` for models that need the patch
format taught. The prompt is coding-domain: rg-first search, editing
etiquette, dirty-worktree rules, plan discipline, final-answer format.

→ **Garrison:** a Garrison system prompt in this style, per-provider variants
(Claude-on-Bedrock primary), patch-format instructions included only when the
provider lacks native editing affordances.

### 1.12 The agent as a server: `app-server` + protocol
Codex's IDE extensions don't shell out to a CLI; they speak a versioned
JSON-RPC protocol to a daemon (`app-server-protocol`): thread lifecycle,
streamed events, **approval requests as protocol round-trips** (the IDE
renders the approve/deny UI), turn diffs as events.

→ **Garrison:** extend acton-ai's introspection IPC socket into the
**Garrison Agent Protocol**: newline-delimited JSON-RPC over UDS (Windows:
named pipe), methods for thread create/resume/message, events for tokens,
tool lifecycle, turn diff, plan updates, and approval round-trips. Both IDE
extensions consume this one protocol — build it once, before either extension.

## 2. What acton-ai already provides (don't rebuild)

Prompt loop with tool rounds and structural history repair; streaming;
multi-provider + failover/circuit-breaking; MCP client (supervised,
reconnecting); builtins (bash, read/write/edit, glob, grep, web_fetch);
ProcessSandbox (rlimits + landlock/seccomp); path confinement; **policy gate +
approval hooks + BLAKE3 audit chain (v0.32.0)**; budgets + cost accounting;
OTel; skills; sessions (libSQL); structured extract; sub-agent delegation;
IPC introspection socket (the protocol's foundation).

Codex independently converges on the same architecture we shipped this
afternoon (SafetyCheck ≈ PolicyDecision, approved-prefix cache ≈ per-turn
policy state, executed_tool_calls ≈ audit entries). That's validation, and it
means every §1 item has a socket to plug into.

## 3. Where each piece lives

| Capability | Home | Rationale |
|---|---|---|
| apply_patch, execpolicy, git-utils, AGENTS.md, PTY sessions, turn diff, review mode, coding prompts, Agent Protocol, Bitbucket DC | **garrison-agent** (`agent/`) | Coding-domain; acton-ai stays a general framework |
| Compaction, checkpoint/resume (#12), `get_context_remaining`, plan tool | **acton-ai upstream** | Generic agent capabilities; every consumer benefits |
| Central policy pull, audit push | **garrison-agent ↔ control plane** | Product glue over acton-ai's policy/audit APIs |

## 4. Actor topology (garrison-agent)

```
GarrisonRuntime (acton-ai / acton-reactive)
├── acton-ai core: providers, tool registry, policy gate, audit actor, accountant
├── ProtocolServer        — UDS/named-pipe JSON-RPC; one ClientConn actor per IDE connection
├── ThreadSupervisor      — one Thread actor per conversation (owns turn state, plan)
├── PtySupervisor         — one PtySession actor per live exec session
├── TurnDiff              — subscribes tool outcomes; owns per-turn diff state
├── RepoContext           — git status/branch baseline; environment context fragments
└── PlaneSync             — control-plane client: policy pull, audit push, seat heartbeat
```

Approval round-trip: policy gate → callback → ProtocolServer → IDE dialog →
decision → gate → audit entry with decider = `Callback` and the protocol
client identity.

## 5. Build order (RFQ-demo-first)

1. **Garrison Agent Protocol** over the IPC socket (everything downstream
   needs it; unblocks both extensions)
2. **apply_patch + safety assessment** (demo criterion: task completion
   quality on multi-file edits)
3. **execpolicy + canonicalization + escalation flow** (demo criterion:
   "enterprise policy-control functionality, and agentic capability scope")
4. **Turn diff tracker + repo context** (Tier B review gate artifact)
5. **Coding system prompt + AGENTS.md discovery**
6. **Plan tool + review mode**
7. **PTY unified exec**
8. **Upstream to acton-ai:** compaction, #12 checkpoint/resume,
   `get_context_remaining`
9. **Bitbucket DC PR review** (review mode over REST API)

Items 1–5 are the demo-critical path. 6–9 are differentiators in evaluation
order.

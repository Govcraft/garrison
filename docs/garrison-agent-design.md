# garrison-agent: from AI agent to coding agent

**Source study:** openai/codex @ `~/code/reference/codex` (Apache-2.0), codex-rs
workspace, ~100 crates. **Date:** 2026-08-19. **Updated for acton-ai 0.33.0:**
2026-08-20.

This is a roadmap document. Statements prefixed with **Implemented** describe
this checkout; statements prefixed with **Planned** describe intended work.

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

→ **Implemented:** `agent/src/patch/` provides the format, fuzzy apply, safety
assessment, acton-ai tool registration, and approval preflight.

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

→ **Planned:** `garrison-execpolicy` implementing prefix rules (TOML, not
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

→ **Sandboxing implemented, escalation planned:** Garrison enables acton-ai's
`ProcessSandbox` from `[sandbox]` in `acton-ai.toml` and dispatches the
sandbox-child entry point as the first operation in `main`, so `bash`,
`write_file`, and `edit_file` run in a re-exec'd child under resource limits
and, on Linux, landlock and seccomp. The child is confined to the session's
root, which travels with each call. `_garrison/status` reports whether
isolation and hardening are in force. The escalation *flow* (sandboxed fail
→ approval round-trip → unsandboxed retry,
recorded in the audit chain as an escalation) is new prompt-loop behavior.
Approved-prefix caching lives in per-turn policy state. This maps 1:1 onto
USAC Tier A/B/C: escalation is precisely a Tier B→C transition with a human
gate — the audit chain makes it *evidence*.

### 1.4 Persistent PTY sessions: `unified_exec`
One-shot bash is not how developers work. `unified_exec` maintains PTY-backed
sessions (`exec_command.rs` + `write_stdin.rs`): start a dev server, keep the
handle, write stdin to a REPL three tool-calls later, read incremental output.

→ **Planned:** a `PtySession` actor per live session under a supervisor
(actor-per-resource is acton-reactive's native shape; the socket has one
owner, no `Arc<Mutex<pty>>`). Tools: `exec_session`, `write_stdin`,
`read_output`, `kill_session`.

### 1.5 Turn diff tracking
`turn_diff_tracker.rs` accumulates a unified diff of everything the turn
changed — apply_patch results *and* exec side effects (via git status +
fsmonitor baselines) — with a 100ms diff timeout falling back to coarse diff.
The UI can always answer "what did the agent just do to my tree?"

→ **Planned:** `TurnDiff` actor fed by the audit pipeline (acton-ai
broadcast every tool outcome). Per-turn diff is the artifact USAC Tier B
review gates on: "explicit developer review and approval before merge" needs
a *thing to review*. This is a compliance feature wearing a UX costume.

### 1.6 Repo awareness: `git-utils`
Baseline snapshots, branch/status introspection, fsmonitor, structured diff
apply. The agent knows it's in a repo, whether the tree is dirty, and what it
changed vs what the user changed. The system prompt encodes the etiquette
("you may be in a dirty worktree; NEVER revert changes you did not make").

→ **Planned:** `garrison-git` module (shell out to git; no libgit2 dep).
Environment context (branch, dirty state, recent commits) injected as a
context fragment at turn start.

### 1.7 Project instruction discovery: AGENTS.md
`agents_md.rs` + `find_up`: walk up from cwd, load AGENTS.md hierarchy, layer
user instructions over project instructions. This is the CLAUDE.md idea as a
portable convention.

→ **Planned:** support AGENTS.md (the emerging cross-vendor standard) and
GARRISON.md, hierarchical, nearest-wins-per-key. acton-ai's SkillRegistry
already covers the skills half.

### 1.8 Context management: budget + compaction + rollouts
- `compact.rs`: auto-summarization when the window fills, with pre/post-compact
  hooks and templated summary prefixes.
- `rollout/`: every session is an append-only JSONL rollout (compressed,
  reverse-scannable, indexed) — resumable, forkable, searchable.
- `get_context_remaining` is exposed *as a tool* so the model can see its own
  budget.

→ **Available upstream, compaction wired, persistence incomplete:** acton-ai
0.35.0 has context truncation, model-generated compaction, libSQL persistence,
fingerprinted checkpoint/resume, and the `get_context_remaining` builtin.
Garrison enables the builtin and exposes compaction as configuration
(`[context] auto_compact` in `acton-ai.toml`): a pass is announced to the
owning session as `_garrison/session/compacted`, summarized in the prompt
response's `_meta`, counted at `_garrison/status`, and adopted into the
session's stored history. Attaching ACP sessions and turns to acton-ai
persistence and checkpoints remains to do. See section 6.

### 1.9 Plan tool
`update_plan`: the model maintains a structured step list with states; the
prompt tells it when planning is worth it ("skip for the easiest 25%; never
single-step plans"). Cheap to build, large effect on multi-file task quality.

→ **Implemented:** acton-ai 0.35.0 ships the `update_plan` builtin and
`PlanUpdated` turn events. Garrison enables the tool, auto-approves it (it
writes nothing and is declared idempotent upstream), and routes each broadcast
plan through the turn router to the one session that owns the turn, as a
spec-native ACP `plan` update with Garrison's correlation in `_meta`. The
turn's final plan is repeated in the prompt response's `_meta`, so a client
that missed an event still ends the turn agreeing with the agent about what
the plan was.

### 1.10 Review mode
Dedicated prompts (`review_request.rs`, `review_exit.rs`) and prompt rules:
findings first, ordered by severity, file:line references, explicit "no
findings" statement. Review is a *mode*, not a vibe.

→ **Planned:** `garrison review` — and this is the Bitbucket DC integration
point (RFQ §3.A.2 "pull-request-level AI review is strongly desired"): fetch
PR diff via Bitbucket DC REST, run review mode, post findings as PR comments.

### 1.11 Model-specific coding prompts
Codex ships per-model system prompts (~80 focused lines) plus
`prompt_with_apply_patch_instructions.md` for models that need the patch
format taught. The prompt is coding-domain: rg-first search, editing
etiquette, dirty-worktree rules, plan discipline, final-answer format.

→ **Partially implemented:** Garrison supports a configured system prompt.
Per-provider coding prompts and project-instruction layering remain planned;
patch-format instructions are supplied by the implemented tool definition.

### 1.12 The agent as a server: `app-server` + protocol
Codex's IDE extensions don't shell out to a CLI; they speak a versioned
JSON-RPC protocol to a daemon (`app-server-protocol`): thread lifecycle,
streamed events, **approval requests as protocol round-trips** (the IDE
renders the approve/deny UI), turn diffs as events.

→ **Implemented in part:** Garrison speaks ACP v1 as newline-delimited JSON-RPC
over stdio and Unix-domain sockets. It implements initialize; session create,
load, list, prompt, and cancel; token and tool events; approval round-trips;
a namespaced status method; and plan and compaction events. Windows named
pipes, turn diffs, and first VS Code and JetBrains clients now exercise that
protocol.

## 2. What acton-ai already provides (don't rebuild)

Prompt loop with tool rounds and structural history repair; streaming;
multi-provider + failover/circuit-breaking; MCP client (supervised,
reconnecting); builtins (bash, read/write/edit, glob, grep, web_fetch);
opt-in ProcessSandbox (rlimits + landlock/seccomp); path confinement; **policy gate +
approval hooks + BLAKE3 audit chain (v0.32.0)**; budgets + cost accounting;
OTel; skills; sessions (libSQL); model-generated compaction; fingerprinted
checkpoint/resume; `get_context_remaining`; `update_plan` and plan events;
structured extract; sub-agent delegation;
IPC introspection socket (the protocol's foundation).

Codex independently converges on the same architecture we shipped this
afternoon (SafetyCheck ≈ PolicyDecision, approved-prefix cache ≈ per-turn
policy state, executed_tool_calls ≈ audit entries). That's validation, and it
means every §1 item has a socket to plug into.

## 3. Where each piece lives

| Capability | Home | Rationale |
|---|---|---|
| apply_patch | **garrison-agent** (`agent/`) — implemented | Coding-domain structural editing and root-aware safety |
| ACP server, sessions, approval round-trip, LSP tools | **garrison-agent** (`agent/`) — implemented | Editor-facing product protocol and code intelligence |
| execpolicy, git-utils, AGENTS.md, PTY sessions, turn diff, review mode, coding prompts, Bitbucket DC | **garrison-agent** (`agent/`) — planned | Coding-domain; acton-ai stays a general framework |
| Compaction, checkpoint/resume, `get_context_remaining`, plan tool/events | **acton-ai upstream** — implemented in 0.35.0 | Garrison exposes compaction and plan events; checkpoint/resume is still to wire |
| Central policy pull, audit push | **garrison-agent ↔ control plane** | Product glue over acton-ai's policy/audit APIs |

## 4. Actor topology (garrison-agent)

```
GarrisonRuntime (acton-ai / acton-reactive)
├── acton-ai core: providers, tool registry, policy gate, audit actor, accountant
├── ProtocolServer        — implemented: UDS ACP; one ClientConn per client
│                            (one daemon per user; `acp` is a stdio relay to it)
├── ThreadSupervisor      — implemented: one in-memory Thread per conversation
├── LspServer             — implemented: one actor per configured language server
├── PtySupervisor         — planned
├── TurnDiff              — planned
├── RepoContext           — planned
└── PlaneSync             — planned control-plane policy/audit/seat integration
                            (the plane side already deprovisions: the directory
                            sync in hooks-service revokes a seat when Entra
                            disables the account; the daemon side reads it)
```

Approval round-trip: policy gate → callback → ProtocolServer → IDE dialog →
decision → gate → audit entry with decider = `Callback` and the protocol
client identity.

## 5. Build order (RFQ-demo-first)

1. ~~**ACP server over stdio and Unix sockets**~~ — implemented; stdio is now
   a relay to the per-user daemon (README, "Process topology")
2. ~~**apply_patch + safety assessment**~~ — implemented
3. ~~**Harden the implemented boundary:** enable sandboxing, validate ACP roots,
   and align every builtin with the session filesystem boundary~~ — implemented
4. **execpolicy + canonicalization + escalation flow** (demo criterion:
   "enterprise policy-control functionality, and agentic capability scope")
5. **Turn diff tracker + repo context** (Tier B review gate artifact)
6. **Coding system prompt + AGENTS.md discovery**
7. **Integrate acton-ai capabilities:** persistent ACP sessions/checkpoints
   (~~compaction configuration and ACP plan events~~: implemented, see
   section 6)
8. **Review mode + PTY unified exec**
9. **Bitbucket DC PR review** (review mode over REST API)

Items 3–6 are the current agent-critical path. Control-plane, extension, and
compliance work is tracked separately from this agent implementation plan.

## 6. Compaction, persisted sessions, and audit evidence

Compaction rewrites what the model is told. Three readers care about a
session's history for different reasons, and the rules below are what keep
them from disagreeing about what happened.

**Plans are audit evidence; compaction is not.** A plan reaches a client
because the model called `update_plan`, and that call passes the policy gate
and the audit actor like any other tool call. The plan the client renders and
the plan in the audit trail are one event seen twice. Compaction is not a tool
call: nothing an operator authorized happened, so nothing is appended to the
chain.

**The chain never shortens.** Compaction elides messages, not entries. A
compacted session's audit chain is the chain the same session would have had
without compaction, so `chain_head` at `_garrison/status` stays meaningful
across a long conversation. What a compacted turn does cost is tokens: the
summary is a paid request to the turn's own provider, and it lands in the same
usage the turn reports.

**A persisted session stores the adopted history, not the original.** The
prompt loop compacts its own copy of the messages and hands back one
`CompactionRecord` per pass. Garrison replays those records onto the session's
history with `CompactionRecord::adopt` before it appends the answer, so the
session actor holds exactly what the next turn will send. Keeping the
pre-compaction history alongside the records would leave two sources of truth,
one of them stale, and a `session/load` would replay messages the model can no
longer see. A record's `elided_prefix_len` can name more messages than the
session owns, because the loop's copy also carried this turn's tool rounds;
adoption clamps rather than eating into the answer.

**A summary is labelled, not disguised.** The adopted summary is a user
message whose text opens with acton-ai's compaction notice, which is how the
model, a stored session, and a replay all tell it apart from something the
operator said. On `session/load` Garrison replays it as an agent thought
rather than as user text, so nobody reads the framework's words as the
operator's.

**Compaction is off unless the operator turns it on.** `[context]
auto_compact` in `acton-ai.toml` is the only switch, and Garrison sets no
default in code. The resolved policy and the number of passes are readable at
`_garrison/status` under `context`; each pass is announced to the owning
session as `_garrison/session/compacted`; every pass of a turn is summarized
in the prompt response's `_meta.garrison.compactions`, counts only, never the
summary text. A summarization request that fails or is refused changes
nothing: the turn proceeds with its full history and takes its chances at the
provider.

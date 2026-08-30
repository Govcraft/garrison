# Garrison for VS Code

The first-party VS Code client for Garrison. It spawns `garrison-agent acp`,
opens a session rooted in the current workspace, streams replies and tool
activity into the Garrison sidebar, and routes tool approvals through native
VS Code confirmation dialogs.

## How it reaches the agent

`garrison-agent acp` is a relay, not an engine. There is one `garrison-agent
serve` daemon per user per machine; it owns the acton-ai runtime, the sandbox
host and the audit trail, and listens on `$XDG_RUNTIME_DIR/garrison-agent.sock`.
Every VS Code window spawns its own relay, and every relay is one more client
of that one daemon, so windows on different repositories share a single
policy and a single hash-chained audit trail instead of each forking their
own.

When no daemon is listening, the relay starts one (through the user's
`garrison-agent.service` systemd unit when it is loaded, otherwise as a
detached child) if the daemon's `[server] autostart` is on; otherwise the
window shows the relay's error and nothing is started. The daemon outlives
the window: `systemctl --user stop garrison-agent` is the off switch.

The daemon's `garrison.toml` and acton-ai configuration are the ones in
force. A workspace must lie under the daemon's project root (its working
directory, `$HOME` under systemd or autostart) or be listed in its
`[threads] workspace_roots`.

## Settings

| Setting | Meaning |
|---|---|
| `garrison.agentPath` | The `garrison-agent` executable (default: found on `PATH`). |
| `garrison.socket` | The daemon's socket, if not the default. Passed as `--socket`. |
| `garrison.configPath` | A `garrison.toml` the relay reads for `[server]` only. Never passed to an autostarted daemon. |

## Inline completion

Garrison suggests code at the cursor as you type, as ghost text. Suggestions
come from the same agent and the same session as the chat, over the
`_garrison/complete` extension method, so they are inside the same workspace
boundary and the same governance as everything else the agent does. The
request carries no tools, so a keystroke can never raise an approval dialog.

- `garrison.inlineCompletion.enabled` turns it off and on; **Garrison: Toggle
  Inline Completion** does the same from the command palette.
- `garrison.inlineCompletion.debounceMs` (default 250) is how long typing must
  pause before the agent is asked. Explicit invocations ignore it.

A suggestion that fails is logged to the Garrison output channel and never
raises a dialog: it is speculative work you did not ask for. After a failure
the agent is left alone for 30 seconds rather than being asked again on the
next keystroke.

## Development

1. Build `garrison-agent` and make it available on `PATH`, or set
   `garrison.agentPath` to the binary's absolute path.
2. Run `npm install && npm run compile` in this directory.
3. Open this directory in VS Code and run the **Extension** launch target.

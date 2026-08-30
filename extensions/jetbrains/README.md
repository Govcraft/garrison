# Garrison for JetBrains IDEs

The first-party JetBrains client for Garrison. It spawns `garrison-agent acp`,
opens an ACP session rooted in the current project, streams replies and tool
activity into a Garrison tool window, and routes tool approvals through native
IDE dialogs.

## How it reaches the agent

`garrison-agent acp` is a relay, not an engine. There is one `garrison-agent
serve` daemon per user per machine; it owns the acton-ai runtime, the sandbox
host and the audit trail, and listens on `$XDG_RUNTIME_DIR/garrison-agent.sock`.
Every open project spawns its own relay, and every relay is one more client of
that one daemon, so projects share a single policy and a single hash-chained
audit trail instead of each forking their own.

When no daemon is listening, the relay starts one (through the user's
`garrison-agent.service` systemd unit when it is loaded, otherwise as a
detached child) if the daemon's `[server] autostart` is on; otherwise the tool
window shows the relay's error and nothing is started. The daemon outlives the
IDE: `systemctl --user stop garrison-agent` is the off switch.

The daemon's `garrison.toml` and acton-ai configuration are the ones in force.
A project must lie under the daemon's project root (its working directory,
`$HOME` under systemd or autostart) or be listed in its
`[threads] workspace_roots`.

## Settings (Settings | Tools | Garrison)

| Field | Meaning |
|---|---|
| Agent executable | The `garrison-agent` binary (default: found on `PATH`). |
| Daemon socket | The daemon's socket, if not the default. Passed as `--socket`. |
| Garrison config | A `garrison.toml` the relay reads for `[server]` only. Never passed to an autostarted daemon. |

## Inline completion

Garrison suggests code at the cursor as you type, as ghost text. Suggestions
come from the same agent and the same session as the tool window, over the
`_garrison/complete` extension method, so they are inside the same project
boundary and the same governance as everything else the agent does. The
request carries no tools, so a keystroke can never raise an approval dialog.

Both settings live under **Settings | Tools | Garrison**: a checkbox to turn
it off and on, and the delay (default 250 ms) typing must pause for before the
agent is asked. An explicit invocation ignores the delay.

A suggestion that fails is logged and never raises a dialog: it is speculative
work you did not ask for. After a failure the agent is left alone for 30
seconds rather than being asked again on the next keystroke.

The provider is the plugin's only Kotlin source. The platform's inline
completion API declares its work as a `suspend` function and identifies
providers with an inline value class, neither of which Java can implement.

## Accessibility

The tool window follows JetBrains keyboard navigation, focus, font scaling,
theme and screen reader behavior; approvals use native dialogs with safe
defaults. Ctrl+Enter sends from the multiline composer. Send, cancel, new
session and governance status are available through **Find Action** and the IDE
keymap. Inline completion can be disabled in Garrison settings. The terminal's
line-oriented mode is an alternative path to the same daemon and sessions. See
the shared
[Accessibility and support](../../docs/accessibility.md) guide for features,
limitations, contact information and accommodations.

## Development

1. Build `garrison-agent` and make it available on `PATH`.
2. Use Java 21 and run `./gradlew buildPlugin` in this directory.
3. Run `./gradlew runIde` to launch a development IDE with the plugin loaded.

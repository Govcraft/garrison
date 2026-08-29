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

## Development

1. Build `garrison-agent` and make it available on `PATH`.
2. Use Java 21 and run `./gradlew buildPlugin` in this directory.
3. Run `./gradlew runIde` to launch a development IDE with the plugin loaded.

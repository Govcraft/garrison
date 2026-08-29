# Packaging garrison-agent

What a package of the agent installs, and why each piece is where it is.

## Files

| Path | What |
|---|---|
| `/usr/bin/garrison-agent` | The one binary: `serve` (the engine), `acp` (the relay editors spawn), `ping`, `chat`, `login`. |
| `/usr/lib/systemd/user/garrison-agent.service` | The per-user unit in `systemd/`. A user enables it with `systemctl --user enable --now garrison-agent`. |
| `~/.config/garrison/garrison.toml` | Garrison's configuration. Ship the repository's `garrison.toml` as the example. |
| `~/.config/acton-ai/config.toml` | acton-ai's configuration (providers, sandbox, audit). Ship the repository's `acton-ai.toml` as the example; the file name differs because acton-ai's own search path names it. |

## Process topology

There is one daemon per user per machine, and it is the only process that
ever builds an acton-ai runtime. Everything an editor spawns is a relay to
the daemon's socket (`$XDG_RUNTIME_DIR/garrison-agent.sock`). The daemon
owns the audit trail: acton-ai holds an exclusive advisory lock on it, so a
second daemon over the same trail refuses to start rather than forking the
hash chain, and a second daemon on the same socket refuses to start rather
than stealing the endpoint.

The unit is `Type=notify`: `serve` reports readiness once the socket is
accepting, so `systemctl --user start` returns when clients can connect, and
reports stopping before it tears its actors down.

## Exit codes

| Code | Meaning | systemd |
|---|---|---|
| 0 | Stopped cleanly (SIGINT or SIGTERM). | |
| 1 | Malfunction. | Retried (`Restart=on-failure`, three times per minute). |
| 2 | Refused to start: a locked or broken audit trail, a configuration it will not accept, a control plane that turned this install away. | Not retried (`RestartPreventExitStatus=2 3`). Read `journalctl --user -u garrison-agent`. |
| 3 | A rejection. | Not retried. |

## Where things land

| What | Where |
|---|---|
| Socket | `$XDG_RUNTIME_DIR/garrison-agent.sock` |
| Audit trail | `$XDG_DATA_HOME/acton-ai/audit.jsonl` unless `[audit] path` names an absolute path (acton-ai does not expand `~` or `$XDG_DATA_HOME` in that key; see the shipped `acton-ai.toml`). |
| Daemon log when a relay spawned it (no unit loaded) | `$XDG_STATE_HOME/garrison/agent.log` |
| Chat log | `$XDG_STATE_HOME/garrison/chat.log` |
| Install identity and key (enrolled installs) | `~/.config/garrison/install.json`, `install-key.pem` |

## Without systemd

When no unit is loaded, the relay spawns `garrison-agent serve` itself as a
detached child (its own process group, cwd `$HOME`, output appended to
`agent.log`) and waits `[server].start_timeout_secs` for the socket. Set
`[server] autostart = false` on hosts where only an operator may start the
engine; the relay then reports the missing daemon and starts nothing.

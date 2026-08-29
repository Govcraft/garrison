# Garrison for JetBrains IDEs

The first-party JetBrains client for Garrison. It starts `garrison-agent acp`,
opens an ACP session rooted in the current project, streams replies and tool
activity into a Garrison tool window, and routes tool approvals through native
IDE dialogs.

## Development

1. Build `garrison-agent` and make it available on `PATH`.
2. Use Java 21 and run `./gradlew buildPlugin` in this directory.
3. Run `./gradlew runIde` to launch a development IDE with the plugin loaded.

The agent executable and optional configuration files can be changed under
**Settings | Tools | Garrison**. The project must be allowed by Garrison's
`[threads] workspace_roots` boundary.

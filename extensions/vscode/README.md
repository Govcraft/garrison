# Garrison for VS Code

The first-party VS Code client for Garrison. It starts `garrison-agent acp`,
opens a session rooted in the current workspace, streams replies and tool
activity into the Garrison sidebar, and routes tool approvals through native
VS Code confirmation dialogs.

## Development

1. Build `garrison-agent` and make it available on `PATH`, or set
   `garrison.agentPath` to the binary's absolute path.
2. Run `npm install && npm run compile` in this directory.
3. Open this directory in VS Code and run the **Extension** launch target.

Optional `garrison.configPath` and `garrison.actonConfigPath` settings are
passed to the spawned agent. The workspace must be allowed by Garrison's
`[threads] workspace_roots` boundary.

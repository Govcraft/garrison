import * as vscode from "vscode";
import { AcpClient, Json } from "./acpClient";

interface NewSessionResponse { sessionId: string }

/** A frame the agent sent that was not an answer to something we asked. */
export interface AgentNotification { method: string; params: unknown }

/** A request the agent made of us, which must be answered. */
export interface AgentRequest { id: number | string; method: string; params: unknown }

/**
 * The one connection to `garrison-agent`, shared by everything that needs it.
 *
 * Both the chat view and the inline completion provider talk to the same agent
 * process and the same session: a second connection would mean a second child
 * process, a second session, and a second copy of whatever the agent is
 * holding for this workspace. It lives here rather than inside the chat view
 * because completions have to work whether or not that view was ever opened.
 *
 * Connecting is idempotent and safe to race — the first caller's attempt is
 * shared with everyone who asks while it is in flight, so a burst of
 * keystrokes at startup spawns one agent rather than one per keystroke.
 */
export class GarrisonConnection implements vscode.Disposable {
  private client: AcpClient | undefined;
  private sessionId: string | undefined;
  private connecting: Promise<AcpClient> | undefined;
  private opening: Promise<string> | undefined;

  private readonly notifications = new vscode.EventEmitter<AgentNotification>();
  private readonly requests = new vscode.EventEmitter<AgentRequest>();
  private readonly closures = new vscode.EventEmitter<Error>();

  /** Fires for every notification the agent sends, such as `session/update`. */
  readonly onNotification = this.notifications.event;
  /** Fires when the agent asks us something, such as for a permission. */
  readonly onRequest = this.requests.event;
  /** Fires when the connection drops, for any reason. */
  readonly onClosed = this.closures.event;

  constructor(private readonly output: vscode.LogOutputChannel) {}

  /** Whether a session is already open, without opening one. */
  get hasSession(): boolean {
    return this.sessionId !== undefined;
  }

  /** Connects if needed and returns the client. */
  async connect(): Promise<AcpClient> {
    if (this.client) return this.client;
    this.connecting ??= this.doConnect().finally(() => { this.connecting = undefined; });
    return this.connecting;
  }

  /** Connects and opens a session if needed, returning its identifier. */
  async session(): Promise<string> {
    if (this.sessionId) return this.sessionId;
    this.opening ??= this.doOpenSession().finally(() => { this.opening = undefined; });
    return this.opening;
  }

  /** Sends a request on the connection, opening one if needed. */
  async request<T>(method: string, params: Json = {}): Promise<T> {
    const client = await this.connect();
    return client.request<T>(method, params);
  }

  /** Sends a notification. Does nothing when not connected. */
  notify(method: string, params: Json = {}): void {
    this.client?.notify(method, params);
  }

  /** Answers a request the agent made. Does nothing when not connected. */
  respond(id: number | string, result: Json): void {
    this.client?.respond(id, result);
  }

  /**
   * Forgets the current session so the next caller opens a fresh one.
   *
   * The connection itself is kept: the agent process is fine, it is the
   * conversation that is being restarted.
   */
  resetSession(): void {
    this.sessionId = undefined;
  }

  dispose(): void {
    this.client?.dispose();
    this.notifications.dispose();
    this.requests.dispose();
    this.closures.dispose();
  }

  private async doConnect(): Promise<AcpClient> {
    const config = vscode.workspace.getConfiguration("garrison");
    // `garrison-agent acp` is a relay to the per-user daemon, not an engine:
    // the flags only tell it where the socket is. The daemon's own
    // configuration governs every session, which is why there is no
    // acton-ai config setting here.
    const command = config.get<string>("agentPath", "garrison-agent");
    const args: string[] = [];
    const socket = config.get<string>("socket", "");
    const configPath = config.get<string>("configPath", "");
    if (socket) args.push("--socket", socket);
    if (configPath) args.push("--config", configPath);
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();

    const client = new AcpClient(line => this.output.info(line));
    this.client = client;
    client.on("notification", (method, params) =>
      this.notifications.fire({ method: String(method), params }));
    client.on("request", (id, method, params) =>
      this.requests.fire({ id: id as number | string, method: String(method), params }));
    client.on("close", (error: Error) => {
      if (this.client !== client) return;
      this.client = undefined;
      this.sessionId = undefined;
      this.closures.fire(error);
    });

    try {
      await client.start(command, args, cwd);
      await client.request("initialize", {
        protocolVersion: 1,
        clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
        clientInfo: { name: "garrison-vscode", version: "0.1.0" },
      });
    } catch (error) {
      client.dispose();
      if (this.client === client) this.client = undefined;
      throw error;
    }
    return client;
  }

  private async doOpenSession(): Promise<string> {
    const client = await this.connect();
    const root = vscode.workspace.workspaceFolders?.[0]?.uri;
    if (!root || root.scheme !== "file") {
      throw new Error("Open a local workspace folder to start Garrison");
    }
    const response = await client.request<NewSessionResponse>("session/new", {
      cwd: root.fsPath,
      mcpServers: [],
    });
    this.sessionId = response.sessionId;
    return response.sessionId;
  }
}

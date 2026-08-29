import * as vscode from "vscode";
import { AcpClient, Json } from "./acpClient";

interface NewSessionResponse { sessionId: string }
interface Update { sessionUpdate?: string; content?: { type?: string; text?: string } | Json[]; toolCallId?: string; title?: string; status?: string; rawInput?: Json }
interface SessionNotification { sessionId: string; update: Update }
interface PermissionOption { optionId: string; name: string; kind: string }
interface PermissionRequest { toolCall: { title?: string; toolCallId?: string; rawInput?: Json; fields?: Update }; options: PermissionOption[] }

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Garrison", { log: true });
  const provider = new ChatViewProvider(context.extensionUri, output);
  context.subscriptions.push(
    output,
    provider,
    vscode.window.registerWebviewViewProvider("garrison.chat", provider, { webviewOptions: { retainContextWhenHidden: true } }),
    vscode.commands.registerCommand("garrison.newSession", () => provider.newSession()),
    vscode.commands.registerCommand("garrison.cancelTurn", () => provider.cancel()),
    vscode.commands.registerCommand("garrison.showStatus", () => provider.showStatus()),
  );
}

export function deactivate(): void {}

class ChatViewProvider implements vscode.WebviewViewProvider, vscode.Disposable {
  private view: vscode.WebviewView | undefined;
  private client: AcpClient | undefined;
  private sessionId: string | undefined;
  private busy = false;
  private readonly pendingPermissions = new Set<number | string>();

  constructor(private readonly extensionUri: vscode.Uri, private readonly output: vscode.LogOutputChannel) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true, localResourceRoots: [this.extensionUri] };
    view.webview.html = this.html(view.webview);
    view.webview.onDidReceiveMessage(message => {
      if (message?.type === "prompt" && typeof message.text === "string") void this.prompt(message.text);
      if (message?.type === "cancel") void this.cancel();
      if (message?.type === "newSession") void this.newSession();
    });
  }

  async newSession(): Promise<void> {
    if (this.busy) await this.cancel();
    this.sessionId = undefined;
    this.post({ type: "reset" });
    try {
      await this.ensureSession();
      this.post({ type: "ready" });
    } catch (error) { this.report(error); }
  }

  async prompt(text: string): Promise<void> {
    text = text.trim();
    if (!text || this.busy) return;
    this.busy = true;
    this.post({ type: "user", text });
    this.post({ type: "busy", value: true });
    try {
      const sessionId = await this.ensureSession();
      await this.client!.request("session/prompt", {
        sessionId,
        prompt: [{ type: "text", text }],
      });
      this.post({ type: "turnEnd" });
    } catch (error) { this.report(error); }
    finally { this.busy = false; this.post({ type: "busy", value: false }); }
  }

  async cancel(): Promise<void> {
    if (!this.busy || !this.sessionId || !this.client) return;
    this.client.notify("session/cancel", { sessionId: this.sessionId });
    for (const id of this.pendingPermissions) {
      this.client.respond(id, { outcome: { outcome: "cancelled" } });
    }
    this.pendingPermissions.clear();
  }

  async showStatus(): Promise<void> {
    try {
      await this.ensureConnected();
      const status = await this.client!.request<Record<string, Json>>("_garrison/status", {});
      this.output.info(JSON.stringify(status, null, 2));
      this.output.show(true);
    } catch (error) { this.report(error); }
  }

  dispose(): void { this.client?.dispose(); }

  private async ensureSession(): Promise<string> {
    await this.ensureConnected();
    if (this.sessionId) return this.sessionId;
    const root = vscode.workspace.workspaceFolders?.[0]?.uri;
    if (!root || root.scheme !== "file") throw new Error("Open a local workspace folder to start Garrison");
    const response = await this.client!.request<NewSessionResponse>("session/new", { cwd: root.fsPath, mcpServers: [] });
    this.sessionId = response.sessionId;
    return response.sessionId;
  }

  private async ensureConnected(): Promise<void> {
    if (this.client) return;
    const config = vscode.workspace.getConfiguration("garrison");
    const command = config.get<string>("agentPath", "garrison-agent");
    const args: string[] = [];
    const configPath = config.get<string>("configPath", "");
    const actonConfigPath = config.get<string>("actonConfigPath", "");
    if (configPath) args.push("--config", configPath);
    if (actonConfigPath) args.push("--acton-config", actonConfigPath);
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
    const client = new AcpClient(line => this.output.info(line));
    this.client = client;
    client.on("notification", (method, params) => this.notification(String(method), params));
    client.on("request", (id, method, params) => void this.agentRequest(id as number | string, String(method), params));
    client.on("close", (error: Error) => {
      if (this.client === client) this.client = undefined;
      this.sessionId = undefined;
      this.post({ type: "disconnected", text: error.message });
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
  }

  private notification(method: string, params: unknown): void {
    if (method !== "session/update") return;
    const event = params as SessionNotification;
    const update = event.update;
    if (update.sessionUpdate === "agent_message_chunk") {
      const text = !Array.isArray(update.content) ? update.content?.text : undefined;
      this.post({ type: "chunk", text: text ?? "" });
    } else if (update.sessionUpdate === "tool_call") {
      this.post({ type: "tool", id: update.toolCallId, title: update.title, status: update.status, input: update.rawInput });
    } else if (update.sessionUpdate === "tool_call_update") {
      this.post({ type: "toolUpdate", id: update.toolCallId, status: update.status, content: update.content });
    }
  }

  private async agentRequest(id: number | string, method: string, raw: unknown): Promise<void> {
    if (method !== "session/request_permission") {
      this.client?.respond(id, { outcome: { outcome: "cancelled" } });
      return;
    }
    const request = raw as PermissionRequest;
    this.pendingPermissions.add(id);
    const title = request.toolCall.title ?? request.toolCall.toolCallId ?? "tool";
    const input = request.toolCall.rawInput;
    const detail = input === undefined ? undefined : `Arguments: ${JSON.stringify(input, null, 2)}`;
    const labels = request.options.map(option => option.name);
    const selected = await vscode.window.showWarningMessage(
      `Garrison requests permission to run ${title}`,
      { modal: true, detail },
      ...labels,
    );
    const option = request.options.find(candidate => candidate.name === selected)
      ?? request.options.find(candidate => candidate.kind === "reject_once");
    const outcome: Json = option
      ? { outcome: "selected", optionId: option.optionId }
      : { outcome: "cancelled" };
    if (this.pendingPermissions.delete(id)) this.client?.respond(id, { outcome });
  }

  private report(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    this.output.error(message);
    this.post({ type: "error", text: message });
    void vscode.window.showErrorMessage(`Garrison: ${message}`, "Show Log").then(choice => {
      if (choice === "Show Log") this.output.show(true);
    });
  }

  private post(message: object): void { void this.view?.webview.postMessage(message); }

  private html(webview: vscode.Webview): string {
    const nonce = randomNonce();
    return `<!doctype html><html><head><meta charset="UTF-8">
      <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <style>
        body{padding:0;color:var(--vscode-foreground);font:var(--vscode-font-size)/1.5 var(--vscode-font-family)}
        #messages{padding:12px 12px 130px;display:flex;flex-direction:column;gap:12px}
        .message{white-space:pre-wrap;overflow-wrap:anywhere}.user{background:var(--vscode-input-background);padding:8px 10px;border-radius:6px}
        .agent{border-left:2px solid var(--vscode-focusBorder);padding-left:10px}.error{color:var(--vscode-errorForeground)}
        .tool{font-size:.9em;color:var(--vscode-descriptionForeground);padding:5px 8px;border:1px solid var(--vscode-widget-border);border-radius:4px}
        #composer{position:fixed;bottom:0;left:0;right:0;padding:10px;background:var(--vscode-sideBar-background);border-top:1px solid var(--vscode-widget-border)}
        textarea{box-sizing:border-box;width:100%;min-height:64px;resize:vertical;color:var(--vscode-input-foreground);background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);padding:7px}
        .actions{display:flex;justify-content:flex-end;gap:6px;margin-top:6px}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;padding:5px 12px}button:disabled{opacity:.5}
      </style></head><body><div id="messages"></div><div id="composer"><textarea id="input" placeholder="Ask Garrison…"></textarea><div class="actions"><button id="cancel" hidden>Cancel</button><button id="send">Send</button></div></div>
      <script nonce="${nonce}">
        const vscode=acquireVsCodeApi(), messages=document.querySelector('#messages'), input=document.querySelector('#input'), send=document.querySelector('#send'), cancel=document.querySelector('#cancel'); let agent, busy=false;
        const add=(kind,text)=>{const el=document.createElement('div');el.className='message '+kind;el.textContent=text;messages.append(el);window.scrollTo(0,document.body.scrollHeight);return el};
        const submit=()=>{const text=input.value.trim();if(!text||busy)return;input.value='';vscode.postMessage({type:'prompt',text})}; send.onclick=submit; cancel.onclick=()=>vscode.postMessage({type:'cancel'});
        input.onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();submit()}};
        window.addEventListener('message',({data:m})=>{switch(m.type){case'reset':messages.replaceChildren();agent=undefined;break;case'user':add('user',m.text);agent=undefined;break;case'chunk':if(!agent)agent=add('agent','');agent.textContent+=m.text;window.scrollTo(0,document.body.scrollHeight);break;case'tool':add('tool',(m.title||'Tool')+' · '+(m.status||'started'));break;case'toolUpdate':add('tool',(m.id||'Tool')+' · '+(m.status||'updated'));break;case'turnEnd':agent=undefined;break;case'error':add('error',m.text);break;case'disconnected':add('error',m.text);break;case'busy':busy=m.value;send.disabled=busy;cancel.hidden=!busy;input.disabled=busy;break;}});
      </script></body></html>`;
  }
}

function randomNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

import * as vscode from "vscode";
import { Json } from "./acpClient";
import { GarrisonConnection } from "./connection";
import { InlineCompletionProvider } from "./inlineCompletion";

interface Update { sessionUpdate?: string; content?: { type?: string; text?: string } | Json[]; toolCallId?: string; title?: string; status?: string; rawInput?: Json }
interface SessionNotification { sessionId: string; update: Update }
interface PermissionOption { optionId: string; name: string; kind: string }
interface PermissionRequest { toolCall: { title?: string; toolCallId?: string; rawInput?: Json; fields?: Update }; options: PermissionOption[] }

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Garrison", { log: true });
  const connection = new GarrisonConnection(output);
  const provider = new ChatViewProvider(connection, context.extensionUri, output);

  context.subscriptions.push(
    output,
    connection,
    provider,
    vscode.window.registerWebviewViewProvider("garrison.chat", provider, { webviewOptions: { retainContextWhenHidden: true } }),
    vscode.languages.registerInlineCompletionItemProvider(
      { pattern: "**" },
      new InlineCompletionProvider(connection, output),
    ),
    vscode.commands.registerCommand("garrison.newSession", () => provider.newSession()),
    vscode.commands.registerCommand("garrison.cancelTurn", () => provider.cancel()),
    vscode.commands.registerCommand("garrison.showStatus", () => provider.showStatus()),
    vscode.commands.registerCommand("garrison.toggleInlineCompletion", () => toggleInlineCompletion(output)),
  );
}

export function deactivate(): void {}

/**
 * Flips `garrison.inlineCompletion.enabled` and says which way it went.
 *
 * Written to the workspace when the workspace already says something about
 * it, and globally otherwise, so toggling in one project does not silently
 * become a decision about every project.
 */
async function toggleInlineCompletion(output: vscode.LogOutputChannel): Promise<void> {
  const config = vscode.workspace.getConfiguration("garrison");
  const setting = config.inspect<boolean>("inlineCompletion.enabled");
  const enabled = config.get<boolean>("inlineCompletion.enabled", true);
  const target = setting?.workspaceValue === undefined
    ? vscode.ConfigurationTarget.Global
    : vscode.ConfigurationTarget.Workspace;

  await config.update("inlineCompletion.enabled", !enabled, target);
  const state = enabled ? "disabled" : "enabled";
  output.info(`inline completion ${state}`);
  void vscode.window.showInformationMessage(`Garrison inline completion ${state}.`);
}

class ChatViewProvider implements vscode.WebviewViewProvider, vscode.Disposable {
  private view: vscode.WebviewView | undefined;
  private busy = false;
  private readonly pendingPermissions = new Set<number | string>();
  private readonly subscriptions: vscode.Disposable[] = [];

  constructor(
    private readonly connection: GarrisonConnection,
    private readonly extensionUri: vscode.Uri,
    private readonly output: vscode.LogOutputChannel,
  ) {
    this.subscriptions.push(
      connection.onNotification(({ method, params }) => this.notification(method, params)),
      connection.onRequest(({ id, method, params }) => void this.agentRequest(id, method, params)),
      connection.onClosed(error => this.post({ type: "disconnected", text: error.message })),
    );
  }

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
    this.connection.resetSession();
    this.post({ type: "reset" });
    try {
      await this.connection.session();
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
      const sessionId = await this.connection.session();
      await this.connection.request("session/prompt", {
        sessionId,
        prompt: [{ type: "text", text }],
      });
      this.post({ type: "turnEnd" });
    } catch (error) { this.report(error); }
    finally { this.busy = false; this.post({ type: "busy", value: false }); }
  }

  async cancel(): Promise<void> {
    if (!this.busy || !this.connection.hasSession) return;
    const sessionId = await this.connection.session();
    this.connection.notify("session/cancel", { sessionId });
    for (const id of this.pendingPermissions) {
      this.connection.respond(id, { outcome: { outcome: "cancelled" } });
    }
    this.pendingPermissions.clear();
  }

  async showStatus(): Promise<void> {
    try {
      const status = await this.connection.request<Record<string, Json>>("_garrison/status", {});
      this.output.info(JSON.stringify(status, null, 2));
      this.output.show(true);
    } catch (error) { this.report(error); }
  }

  dispose(): void {
    for (const subscription of this.subscriptions) subscription.dispose();
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
      this.connection.respond(id, { outcome: { outcome: "cancelled" } });
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
    if (this.pendingPermissions.delete(id)) this.connection.respond(id, { outcome });
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
        .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
        .actions{display:flex;justify-content:flex-end;gap:6px;margin-top:6px}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;padding:5px 12px}button:disabled{opacity:.5}
      </style></head><body><main><div id="messages" role="log" aria-live="polite" aria-relevant="additions text" aria-busy="false"></div></main><form id="composer" aria-label="Message Garrison"><label class="sr-only" for="input">Message Garrison</label><textarea id="input" placeholder="Ask Garrison…"></textarea><div class="actions"><button id="cancel" type="button" hidden>Cancel</button><button id="send" type="submit">Send</button></div></form>
      <script nonce="${nonce}">
        const vscode=acquireVsCodeApi(), messages=document.querySelector('#messages'), composer=document.querySelector('#composer'), input=document.querySelector('#input'), send=document.querySelector('#send'), cancel=document.querySelector('#cancel'); let agent, busy=false;
        const speakers={user:'You',agent:'Garrison',tool:'Tool',error:'Error'};
        const atBottom=()=>{const root=document.scrollingElement;return !root||root.scrollHeight-root.scrollTop-root.clientHeight<=2};
        const scrollToBottom=()=>window.scrollTo(0,document.body.scrollHeight);
        const add=(kind,text)=>{const stick=atBottom(),el=document.createElement('div'),label=document.createElement('span'),content=document.createElement('span');el.className='message '+kind;if(kind==='error')el.setAttribute('role','alert');else label.className='sr-only';label.textContent=(speakers[kind]||'Message')+': ';content.textContent=text;el.append(label,content);messages.append(el);if(stick)scrollToBottom();return content};
        const submit=()=>{const text=input.value.trim();if(!text||busy)return;input.value='';vscode.postMessage({type:'prompt',text})}; composer.onsubmit=e=>{e.preventDefault();submit()}; cancel.onclick=()=>vscode.postMessage({type:'cancel'});
        input.onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();submit()}};
        window.addEventListener('message',({data:m})=>{switch(m.type){case'reset':messages.replaceChildren();agent=undefined;break;case'user':add('user',m.text);agent=undefined;break;case'chunk':{const stick=atBottom();if(!agent)agent=add('agent','');agent.textContent+=m.text;if(stick)scrollToBottom();break}case'tool':add('tool',(m.title||'Tool')+' · '+(m.status||'started'));break;case'toolUpdate':add('tool',(m.id||'Tool')+' · '+(m.status||'updated'));break;case'turnEnd':agent=undefined;break;case'error':add('error',m.text);break;case'disconnected':add('error',m.text);break;case'busy':busy=m.value;messages.setAttribute('aria-busy',String(busy));send.disabled=busy;cancel.hidden=!busy;input.disabled=busy;break;}});
      </script></body></html>`;
  }
}

function randomNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

import * as vscode from "vscode";
import { GarrisonConnection } from "./connection";

interface CompletionResponse { completion?: string }

/** How much text on each side of the cursor is worth sending. */
const PREFIX_BUDGET = 4_000;
const SUFFIX_BUDGET = 1_000;

/**
 * How long the agent is left alone after a failure before it is asked again.
 *
 * Without this, an agent that cannot start is asked to complete on every
 * keystroke and answers with an error every time — which turns one
 * misconfiguration into a stream of them, and does it while somebody is
 * trying to type.
 */
const FAILURE_COOLDOWN_MS = 30_000;

/** The last `budget` characters of `text`. */
export function tail(text: string, budget: number): string {
  return text.length <= budget ? text : text.slice(text.length - budget);
}

/** The first `budget` characters of `text`. */
export function head(text: string, budget: number): string {
  return text.length <= budget ? text : text.slice(0, budget);
}

/**
 * Whether a document is one worth completing in.
 *
 * Output panels, the SCM commit box, debug consoles, and diff views all arrive
 * here as documents. None of them is a file the developer is writing code in,
 * and suggesting into them is noise.
 */
export function isCompletable(document: vscode.TextDocument): boolean {
  return document.uri.scheme === "file" || document.uri.scheme === "untitled";
}

/**
 * Waits `ms`, resolving false if the token is cancelled first.
 *
 * This is the debounce. VS Code asks for completions on every keystroke and
 * cancels the previous ask as it does, so a request that survives the wait is
 * one the developer actually paused on.
 */
function settle(ms: number, token: vscode.CancellationToken): Promise<boolean> {
  if (ms <= 0) return Promise.resolve(!token.isCancellationRequested);
  return new Promise(resolve => {
    const timer = setTimeout(() => { subscription.dispose(); resolve(true); }, ms);
    const subscription = token.onCancellationRequested(() => {
      clearTimeout(timer);
      subscription.dispose();
      resolve(false);
    });
  });
}

/**
 * Ghost text from `garrison-agent`, through the same governed connection the
 * chat view uses.
 *
 * The provider deliberately does nothing clever with the suggestion it gets
 * back: the agent already strips the fences and the echoes, because that is
 * logic worth having once and testing rather than reimplementing in every
 * editor client.
 */
export class InlineCompletionProvider implements vscode.InlineCompletionItemProvider {
  private coolingUntil = 0;

  constructor(
    private readonly connection: GarrisonConnection,
    private readonly output: vscode.LogOutputChannel,
  ) {}

  async provideInlineCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
    context: vscode.InlineCompletionContext,
    token: vscode.CancellationToken,
  ): Promise<vscode.InlineCompletionItem[]> {
    const config = vscode.workspace.getConfiguration("garrison");
    if (!config.get<boolean>("inlineCompletion.enabled", true)) return [];
    if (!isCompletable(document)) return [];

    const invoked = context.triggerKind === vscode.InlineCompletionTriggerKind.Invoke;

    // An explicit invocation is a decision, so it ignores both the debounce
    // and the cooldown: the developer asked, and is owed either a suggestion
    // or the error that explains why there is not one.
    if (!invoked) {
      if (Date.now() < this.coolingUntil) return [];
      const debounce = config.get<number>("inlineCompletion.debounceMs", 250);
      if (!await settle(debounce, token)) return [];
    }

    const prefix = tail(
      document.getText(new vscode.Range(new vscode.Position(0, 0), position)),
      PREFIX_BUDGET,
    );
    const suffix = head(
      document.getText(new vscode.Range(position, document.lineAt(document.lineCount - 1).range.end)),
      SUFFIX_BUDGET,
    );

    // Nothing above the cursor is nothing to continue from.
    if (!prefix.trim()) return [];

    let completion: string;
    try {
      const sessionId = await this.connection.session();
      if (token.isCancellationRequested) return [];

      const response = await this.connection.request<CompletionResponse>("_garrison/complete", {
        sessionId,
        uri: document.uri.toString(),
        languageId: document.languageId,
        prefix,
        suffix,
      });
      completion = response.completion ?? "";
    } catch (error) {
      // A failed completion is never worth a dialog: it is speculative work
      // the developer did not ask for and is not waiting on.
      const message = error instanceof Error ? error.message : String(error);
      this.output.warn(`inline completion failed: ${message}`);
      this.coolingUntil = Date.now() + FAILURE_COOLDOWN_MS;
      return [];
    }

    // The answer may have arrived after the developer moved on. Inserting it
    // now would put it at a cursor it was never computed for.
    if (token.isCancellationRequested || !completion) return [];

    return [new vscode.InlineCompletionItem(completion, new vscode.Range(position, position))];
  }
}

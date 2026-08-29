import { ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createInterface, Interface } from "node:readline";
import { EventEmitter } from "node:events";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

interface RpcError { code: number; message: string; data?: Json }
interface Pending { resolve(value: unknown): void; reject(error: Error): void }

export class AcpClient extends EventEmitter {
  private child: ChildProcessWithoutNullStreams | undefined;
  private lines: Interface | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  constructor(private readonly log: (line: string) => void) { super(); }

  async start(command: string, args: string[], cwd: string): Promise<void> {
    if (this.child) return;
    const child = spawn(command, ["acp", ...args], { cwd, stdio: ["pipe", "pipe", "pipe"] });
    this.child = child;
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", data => this.log(String(data).trimEnd()));
    child.once("error", error => this.close(error));
    child.once("exit", (code, signal) => {
      this.close(new Error(`garrison-agent exited (${signal ?? code ?? "unknown"})`));
    });
    this.lines = createInterface({ input: child.stdout });
    this.lines.on("line", line => this.receive(line));

    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", reject);
    });
  }

  request<T>(method: string, params: Json = {}): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try { this.write({ jsonrpc: "2.0", id, method, params }); }
      catch (error) { this.pending.delete(id); reject(error); }
    });
  }

  notify(method: string, params: Json = {}): void {
    this.write({ jsonrpc: "2.0", method, params });
  }

  respond(id: number | string, result: Json): void {
    this.write({ jsonrpc: "2.0", id, result });
  }

  dispose(): void {
    this.lines?.close();
    this.child?.kill();
    this.close(new Error("Garrison connection closed"));
  }

  private receive(line: string): void {
    if (!line.trim()) return;
    let frame: Record<string, unknown>;
    try { frame = JSON.parse(line) as Record<string, unknown>; }
    catch { this.log(`Invalid ACP frame: ${line}`); return; }

    if ("method" in frame) {
      if ("id" in frame) this.emit("request", frame.id, frame.method, frame.params);
      else this.emit("notification", frame.method, frame.params);
      return;
    }

    const id = typeof frame.id === "number" ? frame.id : undefined;
    const pending = id === undefined ? undefined : this.pending.get(id);
    if (!pending || id === undefined) return;
    this.pending.delete(id);
    if (frame.error) {
      const rpc = frame.error as RpcError;
      const detail = rpc.data === undefined ? "" : `: ${typeof rpc.data === "string" ? rpc.data : JSON.stringify(rpc.data)}`;
      pending.reject(new Error(`${rpc.message} (${rpc.code})${detail}`));
    } else pending.resolve(frame.result);
  }

  private write(frame: object): void {
    if (!this.child?.stdin.writable) throw new Error("Garrison agent is not connected");
    this.child.stdin.write(`${JSON.stringify(frame)}\n`);
  }

  private close(error: Error): void {
    if (!this.child) return;
    this.child = undefined;
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    this.emit("close", error);
  }
}

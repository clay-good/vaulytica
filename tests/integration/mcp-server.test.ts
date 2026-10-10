/**
 * The MCP server as an agent host meets it: a child process speaking JSON-RPC
 * over stdio (spec-v48 §3, Step 304).
 *
 *  - both handshakes: `initialize` (2025-11-25) and `server/discover`
 *    (2026-07-28), driven by the SDK's own client over a real spawned process;
 *  - stdout carries protocol frames and nothing else;
 *  - the process opens no network connection across a whole session;
 *  - killing the launcher leaves no child behind.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { describe, expect, it } from "vitest";
import { analyzeFile } from "../../tools/cli/api.js";

const ROOT = process.cwd();
const BIN = join(ROOT, "bin", "vaulytica.mjs");
const SERVER = join(ROOT, "tools", "mcp", "server.ts");
const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const NO_SOCKET = pathToFileURL(join(ROOT, "tests", "integration", "_mcp", "no-socket.mjs")).href;
const STRAY_LOG = pathToFileURL(join(ROOT, "tests", "integration", "_mcp", "stray-log.mjs")).href;
const NDA = "tests/fixtures/specimens/mutual-nda-complete.txt";

type Frame = {
  id?: number;
  result?: {
    content?: Array<{ text: string }>;
    isError?: boolean;
    tools?: Array<{ name: string }>;
  };
  error?: { code: number; message: string };
};

/** Send frames to a server process, close stdin, and collect everything it wrote. */
function session(
  command: string[],
  frames: unknown[],
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, command, { cwd: ROOT });
    let stdout = "";
    let stderr = "";
    let answered = 0;
    const expected = frames.filter((f) => (f as { id?: number }).id !== undefined).length;
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
      answered = stdout.split("\n").filter(Boolean).length;
      // EOF is how a host says goodbye; send it once every request is answered.
      if (answered >= expected) child.stdin.end();
    });
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("exit", (code) => resolve({ stdout, stderr, code }));
    for (const f of frames) child.stdin.write(JSON.stringify(f) + "\n");
  });
}

const INIT = [
  {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "test", version: "0" },
    },
  },
  { jsonrpc: "2.0", method: "notifications/initialized" },
];
const call = (id: number, name: string, args: Record<string, unknown>): unknown => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: args },
});

describe("the MCP server over stdio", { timeout: 180_000 }, () => {
  it.each([
    ["initialize (2025-11-25)", "legacy" as const],
    ["server/discover (2026-07-28)", { pin: "2026-07-28" }],
  ])("answers the %s handshake and serves the tools", async (_name, mode) => {
    const client = new Client(
      { name: "vaulytica-test", version: "0.0.0" },
      { versionNegotiation: { mode } },
    );
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [BIN, "mcp"],
        cwd: ROOT,
        stderr: "pipe",
      }),
    );
    try {
      expect(client.getServerVersion()?.name).toBe("vaulytica");
      expect(client.getInstructions()).toMatch(/deterministic rule engine/);
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual([
        "analyze_document",
        "analyze_folder",
        "compare_documents",
        "describe_document_type",
        "explain_rule",
        "export_report",
        "list_document_types",
      ]);
      for (const t of tools) {
        // Every tool but the one that writes files is read-only; none is open-world.
        expect(t.annotations).toMatchObject({
          readOnlyHint: t.name !== "export_report",
          destructiveHint: false,
          openWorldHint: false,
        });
        expect(t.description!.length).toBeLessThanOrEqual(2048);
        // Flat schemas: hosts do not reliably enforce a root-level oneOf.
        expect(JSON.stringify(t.inputSchema)).not.toMatch(/oneOf|anyOf/);
      }

      const analyzed = await client.callTool({
        name: "analyze_document",
        arguments: { path: NDA },
      });
      const text = (analyzed.content as Array<{ text: string }>)[0]!.text;
      const brief = JSON.parse(text) as { result_hash: string; findings: unknown[] };
      const direct = await analyzeFile(join(ROOT, NDA), { secondaryFamilies: true });
      expect(brief.result_hash).toBe(direct.run.result_hash);
      expect(brief.findings).toHaveLength(direct.run.findings.length);
      expect(text.length).toBeLessThanOrEqual(8 * 1024);
      // Returned once, as text: `structuredContent` would double every budget.
      expect(analyzed.structuredContent).toBeUndefined();

      const listed = await client.callTool({
        name: "list_document_types",
        arguments: { query: "mutual nda" },
      });
      expect((listed.content as Array<{ text: string }>)[0]!.text).toContain("mutual-nda-deep");

      const refused = await client.callTool({
        name: "analyze_document",
        // A real place outside the root on every OS.
        arguments: { path: tmpdir() },
      });
      expect(refused.isError).toBe(true);
      expect((refused.content as Array<{ text: string }>)[0]!.text).toMatch(/outside the folders/);
    } finally {
      await client.close();
    }
  });

  it("writes only protocol frames to stdout, opens no socket, and exits on EOF", async () => {
    const r = await session(
      ["--import", NO_SOCKET, "--import", STRAY_LOG, "--import", TSX, SERVER],
      [
        ...INIT,
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
        call(3, "analyze_document", { path: NDA }),
        // The container formats load pdf.js and mammoth, which is where a stray
        // console.log or a fetch would come from.
        call(4, "analyze_document", { path: "tests/fixtures/contracts/bad-nda.docx" }),
        call(5, "analyze_document", { text: "This Agreement is made between A and B." }),
        call(6, "list_document_types", {}),
        { jsonrpc: "2.0", id: 7, method: "no/such-method" },
        call(8, "no_such_tool", {}),
        call(9, "analyze_document", {}),
      ],
    );
    expect(r.code).toBe(0);
    expect(r.stderr).not.toContain("SOCKET-OPENED");
    // A dependency printed throughout the session; it all went to stderr.
    expect(r.stderr).toContain("STRAY-LOG");
    expect(r.stdout).not.toContain("STRAY");
    const lines = r.stdout.split("\n").filter(Boolean);
    const frames = lines.map((l) => JSON.parse(l) as Frame);
    expect(frames.every((f) => (f as { jsonrpc?: string }).jsonrpc === "2.0")).toBe(true);
    // One answer per request; the notification is accepted silently.
    expect(frames.map((f) => f.id).sort((a, b) => a! - b!)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const byId = new Map(frames.map((f) => [f.id, f]));
    for (const id of [3, 4, 5, 6]) expect(byId.get(id)!.result!.isError ?? false).toBe(false);
    expect(byId.get(7)!.error!.code).toBe(-32601);
    // A bad argument is a result a person can act on, not a protocol error.
    expect(byId.get(9)!.result!.isError).toBe(true);
    expect(byId.get(9)!.result!.content![0]!.text).toMatch(/exactly one of/);
    // An unknown tool is the protocol's to refuse.
    const unknown = byId.get(8)!;
    expect(unknown.error !== undefined || unknown.result?.isError === true).toBe(true);
  });

  it("the socket guard does trip on a real connection attempt", () => {
    // The assertion above is worth what this one proves: the preload is live.
    const r = spawnSync(
      process.execPath,
      [
        "--import",
        NO_SOCKET,
        "-e",
        "import('node:net').then((n) => n.connect(9, '127.0.0.1')).catch(() => {})",
      ],
      { encoding: "utf8" },
    );
    expect(r.stderr).toContain("SOCKET-OPENED:net.Socket.connect");
  });

  it.skipIf(process.platform === "win32")(
    "killing the launcher takes the server with it",
    async () => {
      const launcher: ChildProcess = spawn(process.execPath, [BIN, "mcp"], { cwd: ROOT });
      // The first answer proves the server child is up.
      await new Promise<void>((resolve, reject) => {
        launcher.stdout!.once("data", () => resolve());
        launcher.once("exit", () => reject(new Error("launcher exited early")));
        launcher.stdin!.write(JSON.stringify(INIT[0]) + "\n");
      });
      const children = spawnSync("pgrep", ["-P", String(launcher.pid)], { encoding: "utf8" })
        .stdout.split("\n")
        .filter(Boolean)
        .map(Number);
      expect(children.length).toBeGreaterThan(0);
      const gone = new Promise<void>((resolve) => launcher.once("exit", () => resolve()));
      launcher.kill("SIGTERM");
      await gone;
      const alive = (pid: number): boolean => {
        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      };
      for (let i = 0; i < 50 && children.some(alive); i++) {
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(children.filter(alive)).toEqual([]);
    },
  );
});

describe("what the server depends on", () => {
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as {
    packages: Record<string, { dev?: boolean; dependencies?: Record<string, string> }>;
  };

  it("brings no HTTP framework into the runtime tree", () => {
    const runtime = Object.entries(lock.packages)
      .filter(([path, p]) => path.startsWith("node_modules/") && !p.dev)
      .map(([path]) => path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length));
    const frameworks = runtime.filter((name) =>
      /^(express|hono|@hono\/.*|cors|fastify|koa|connect|body-parser|@modelcontextprotocol\/(sdk|express|hono|fastify|node))$/.test(
        name,
      ),
    );
    expect(frameworks).toEqual([]);
    expect(runtime).toContain("@modelcontextprotocol/server");
  });

  it("the server package depends on zod and its own core, and nothing else", () => {
    const server = lock.packages["node_modules/@modelcontextprotocol/server"]!;
    expect(Object.keys(server.dependencies ?? {}).sort()).toEqual([
      "@modelcontextprotocol/core",
      "zod",
    ]);
    const core = lock.packages["node_modules/@modelcontextprotocol/core"]!;
    expect(Object.keys(core.dependencies ?? {})).toEqual(["zod"]);
  });

  it("is never imported by the browser bundle", () => {
    const hits = spawnSync(
      "git",
      ["grep", "-l", "-E", "tools/mcp|modelcontextprotocol", "--", "src"],
      {
        cwd: ROOT,
        encoding: "utf8",
      },
    ).stdout.trim();
    expect(hits).toBe("");
  });
});

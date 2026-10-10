/**
 * `vaulytica mcp` — a Model Context Protocol server over stdio (spec-v48).
 *
 * Started by an agent host as a child process on the user's own machine. It
 * wraps `tools/cli/api.ts` and nothing else: the same deterministic engine the
 * browser runs, returning the compact projection so six findings cost a few KB
 * instead of 75K tokens. There is no hosted endpoint and no HTTP transport;
 * this process opens no network connection.
 *
 * The agent is a CONSUMER of the report, never a participant in producing it.
 *
 * Rules of the process:
 *  - stdout carries protocol frames and nothing else — `console.log`, `info`
 *    and `debug` are rebound to stderr before anything else is imported;
 *  - every path is resolved with `realpath` and must sit under an allowed root;
 *  - a bad argument or an unreadable file is a RESULT with `isError: true` and
 *    a sentence a person can act on, never a protocol error.
 *
 * Never imported by `src/`.
 */

import "../cli/no-localstorage.js";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { loadAccuracyDeps } from "../cli/api.js";
import { parseRoots } from "./roots.js";
import {
  EXPORT_FORMATS,
  ToolError,
  analyzeDocumentTool,
  analyzeFolderTool,
  compareDocumentsTool,
  describeDocumentTypeTool,
  explainRuleTool,
  exportReportTool,
  listDocumentTypesTool,
} from "./tools.js";
import {
  ANALYZE_DOCUMENT,
  ANALYZE_FOLDER,
  COMPARE_DOCUMENTS,
  DESCRIBE_DOCUMENT_TYPE,
  EXPLAIN_RULE,
  EXPORT_REPORT,
  INSTRUCTIONS,
  LIST_DOCUMENT_TYPES,
} from "./text.js";

// Anything a dependency prints must not reach the protocol stream.
for (const method of ["log", "info", "debug"] as const) {
  console[method] = (...args: unknown[]) => console.error(...args);
}

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

/** Run a tool body; a {@link ToolError} becomes an `isError` result a person can act on. */
async function answer(body: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return { content: [{ type: "text", text: JSON.stringify(await body()) }] };
  } catch (e) {
    if (e instanceof ToolError)
      return { content: [{ type: "text", text: e.message }], isError: true };
    throw e;
  }
}

const READ_ONLY = {
  readOnlyHint: true,
  idempotentHint: true,
  openWorldHint: false,
  destructiveHint: false,
} as const;

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stderr.write(
      "usage: vaulytica mcp [--root <dir>]…\n" +
        "  A Model Context Protocol server over stdio, started by an agent host.\n" +
        "  Reads only under --root (repeatable), else VAULYTICA_MCP_ROOTS, else the\n" +
        "  working directory. See docs/reference.md.\n",
    );
    return;
  }
  const roots = await parseRoots(process.argv.slice(2), process.env, process.cwd());
  const here = dirname(fileURLToPath(import.meta.url));
  const { version } = JSON.parse(
    await readFile(join(here, "..", "..", "package.json"), "utf8"),
  ) as { version: string };
  // Loaded once: a warm process answers in tens of milliseconds.
  const deps = loadAccuracyDeps();

  const handle = serveStdio(() => {
    const server = new McpServer(
      { name: "vaulytica", version },
      { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
    );

    server.registerTool(
      "analyze_document",
      {
        title: "Analyze one legal document",
        description: ANALYZE_DOCUMENT,
        inputSchema: z.object({
          path: z
            .string()
            .optional()
            .describe("A .docx, .pdf, .txt or .md file under an allowed root."),
          text: z.string().optional().describe("The document's text, instead of a path."),
          filename: z
            .string()
            .optional()
            .describe("With `text`: the name to record. Default pasted-text.txt."),
          document_type: z
            .string()
            .optional()
            .describe("A document-type id, to skip auto-detection."),
          min_severity: z.enum(["critical", "warning", "info"]).optional(),
          include: z.array(z.enum(["secondary_findings"])).optional(),
          excerpts: z
            .boolean()
            .optional()
            .describe("false: offsets only, no quoted document text."),
          cursor: z.string().optional().describe("`next_cursor` from a truncated result."),
        }),
        annotations: READ_ONLY,
      },
      (args) => answer(async () => analyzeDocumentTool(args, { roots, deps: await deps })),
    );

    server.registerTool(
      "list_document_types",
      {
        title: "List the document types Vaulytica recognizes",
        description: LIST_DOCUMENT_TYPES,
        inputSchema: z.object({
          query: z.string().optional().describe("Words to match; adds each type's summary."),
          limit: z.number().int().min(1).max(100).optional(),
          cursor: z.string().optional().describe("`next_cursor` from the previous page."),
        }),
        annotations: READ_ONLY,
      },
      (args) => answer(() => listDocumentTypesTool(args)),
    );

    server.registerTool(
      "analyze_folder",
      {
        title: "Analyze a folder of legal documents",
        description: ANALYZE_FOLDER,
        inputSchema: z.object({
          dir: z.string().optional().describe("A folder or .zip under an allowed root."),
          paths: z.array(z.string()).optional().describe("Instead of `dir`: the files to read."),
          related: z.boolean().optional().describe("true: these files are one deal."),
          cursor: z.string().optional().describe("`next_cursor` from the previous page."),
        }),
        annotations: READ_ONLY,
      },
      (args, ctx) =>
        answer(async () => {
          const token = ctx.mcpReq._meta?.progressToken;
          return analyzeFolderTool(
            args,
            { roots, deps: await deps },
            {
              signal: ctx.mcpReq.signal,
              // Progress only when the host asked for it.
              ...(token !== undefined
                ? {
                    report: (progress: number, total: number) =>
                      ctx.mcpReq.notify({
                        method: "notifications/progress",
                        params: { progressToken: token, progress, total },
                      }),
                  }
                : {}),
            },
          );
        }),
    );

    server.registerTool(
      "compare_documents",
      {
        title: "Compare two versions of a document",
        description: COMPARE_DOCUMENTS,
        inputSchema: z.object({
          base_path: z.string().optional(),
          base_text: z.string().optional(),
          revised_path: z.string().optional(),
          revised_text: z.string().optional(),
          document_type: z.string().optional().describe("Hold both versions to one type id."),
        }),
        annotations: READ_ONLY,
      },
      (args) => answer(async () => compareDocumentsTool(args, { roots, deps: await deps })),
    );

    server.registerTool(
      "describe_document_type",
      {
        title: "What a document type is checked for",
        description: DESCRIBE_DOCUMENT_TYPE,
        inputSchema: z.object({ id: z.string().describe("A type id from list_document_types.") }),
        annotations: READ_ONLY,
      },
      (args) => answer(async () => describeDocumentTypeTool(args, { roots, deps: await deps })),
    );

    server.registerTool(
      "explain_rule",
      {
        title: "Explain a rule",
        description: EXPLAIN_RULE,
        inputSchema: z.object({ rule_id: z.string().describe("A finding's `rule_id`.") }),
        annotations: READ_ONLY,
      },
      (args) => answer(async () => explainRuleTool(args, { roots, deps: await deps })),
    );

    server.registerTool(
      "export_report",
      {
        title: "Write report files for a document",
        description: EXPORT_REPORT,
        inputSchema: z.object({
          path: z.string().describe("The document, under an allowed root."),
          formats: z.array(z.enum(EXPORT_FORMATS)).min(1),
          out_dir: z.string().describe("Where to write, under an allowed root."),
          overwrite: z.boolean().optional().describe("true: replace existing files."),
        }),
        // Writes files; never deletes, and replaces one only when told to.
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      (args) => answer(async () => exportReportTool(args, { roots, deps: await deps })),
    );

    return server;
  });

  // The host closing stdin, or a signal, ends the process; nothing is left behind.
  const stop = (): void => {
    void handle.close().finally(() => process.exit(0));
  };
  process.stdin.on("end", stop);
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

void main().catch((err) => {
  process.stderr.write(`vaulytica mcp: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});

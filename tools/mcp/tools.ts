/**
 * The tools, as functions from arguments to a result (spec-v48 §5–§9).
 *
 * Kept apart from the protocol wiring so each can be called by a test with no
 * transport. A request a person can fix throws {@link ToolError}; the server
 * answers it as an `isError` result.
 */

import { extname } from "node:path";
import {
  analyzeDocument,
  buildBrief,
  isDocumentType,
  listDocumentTypes,
  type AccuracyDeps,
  type Brief,
  type BriefFinding,
} from "../cli/api.js";
import { ToolError, resolveInRoots } from "./roots.js";

export { ToolError };

/** A result is truncated with a cursor past this many characters (spec-v48 §6). */
export const MAX_RESULT_CHARS = 40_000;

/**
 * The longest `text` a call may carry. Analysis is synchronous at roughly
 * 5 ms per KB, so this bounds how long the server can answer nothing else.
 */
export const MAX_TEXT_CHARS = 1_000_000;

/** Characters held back on each page for `findings_total` and `next_cursor`. */
const CURSOR_ALLOWANCE = 256;

const READABLE = new Set([".txt", ".md", ".markdown", ".text", ".docx", ".pdf"]);
const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 } as const;

type Context = {
  roots: readonly string[];
  deps: AccuracyDeps;
  /** The page budget; {@link MAX_RESULT_CHARS} unless a test narrows it. */
  maxResultChars?: number;
};

/* ---------------- cursors ---------------- */

/**
 * Paging is stateless: a cursor carries the input's SHA-256 and an offset.
 * The call is re-run and the hash compared, so a file that changed between
 * pages is an error, never a page from a different document.
 */
function encodeCursor(c: { sha?: string; offset: number }): string {
  return Buffer.from(JSON.stringify(c)).toString("base64url");
}

function decodeCursor(cursor: string | undefined): { sha?: string; offset: number } {
  if (cursor === undefined) return { offset: 0 };
  try {
    const c = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as {
      sha?: unknown;
      offset?: unknown;
    };
    if (Number.isInteger(c.offset) && (c.offset as number) >= 0) {
      return { offset: c.offset as number, ...(typeof c.sha === "string" ? { sha: c.sha } : {}) };
    }
  } catch {
    // Fall through to the one message.
  }
  throw new ToolError("That cursor is not one this server issued. Call again without `cursor`.");
}

/* ---------------- analyze_document ---------------- */

export type AnalyzeDocumentArgs = {
  path?: string;
  text?: string;
  filename?: string;
  document_type?: string;
  min_severity?: keyof typeof SEVERITY_RANK;
  include?: ReadonlyArray<"secondary_findings">;
  excerpts?: boolean;
  cursor?: string;
};

export type AnalyzeDocumentResult =
  | (Brief & { findings_total: number; next_cursor?: string })
  | { not_analyzed: string; document: { name: string } };

export async function analyzeDocumentTool(
  args: AnalyzeDocumentArgs,
  ctx: Context,
): Promise<AnalyzeDocumentResult> {
  if ((args.path === undefined) === (args.text === undefined)) {
    throw new ToolError("Pass exactly one of `path` or `text`.");
  }
  const from = decodeCursor(args.cursor);
  // An unknown id is not an error to the engine — it falls back to detection,
  // and the caller would read the result as the type it asked for.
  if (args.document_type !== undefined && !(await isDocumentType(args.document_type))) {
    throw new ToolError(
      `"${args.document_type}" is not a document type id. Find one with list_document_types.`,
    );
  }
  const opts = { deps: ctx.deps, playbookId: args.document_type, secondaryFamilies: true };

  let input: Parameters<typeof analyzeDocument>[0];
  let name: string;
  if (args.path !== undefined) {
    const real = await resolveInRoots(args.path, ctx.roots);
    if (!READABLE.has(extname(real).toLowerCase())) {
      throw new ToolError(
        `${args.path} is not a type this tool reads (${[...READABLE].sort().join(", ")}).`,
      );
    }
    input = { path: real };
    name = args.path;
  } else {
    if (args.text!.length > MAX_TEXT_CHARS) {
      throw new ToolError(
        `That text is ${args.text!.length.toLocaleString("en-US")} characters; this tool takes up to ` +
          `${MAX_TEXT_CHARS.toLocaleString("en-US")}. Save it to a file and pass \`path\`.`,
      );
    }
    input = { text: args.text!, ...(args.filename ? { filename: args.filename } : {}) };
    name = args.filename ?? "pasted-text.txt";
  }

  let result: Awaited<ReturnType<typeof analyzeDocument>>;
  try {
    result = await analyzeDocument(input, opts);
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    // The file was not checked. Say so in a field no reader can take for a report.
    return { not_analyzed: reason, document: { name } };
  }

  if (from.sha !== undefined && from.sha !== result.run.source_file.sha256) {
    throw new ToolError(
      "The document changed since that cursor was issued. Call again without `cursor`.",
    );
  }

  const wantSecondary = args.include?.includes("secondary_findings") ?? false;
  const brief = buildBrief(result, {
    excerpts: args.excerpts ?? true,
    secondaryFindings: wantSecondary,
  });
  const floor = SEVERITY_RANK[args.min_severity ?? "info"];
  const keep = (f: BriefFinding): boolean => SEVERITY_RANK[f.severity] <= floor;

  // One stream to page: the document's own findings, then each secondary
  // family's (when asked for). `family` is the index into `secondary_families`.
  const stream: Array<{ family?: number; finding: BriefFinding }> = [
    ...brief.findings.filter(keep).map((finding) => ({ finding })),
    ...(brief.secondary_families ?? []).flatMap((s, family) =>
      (s.findings ?? []).filter(keep).map((finding) => ({ family, finding })),
    ),
  ];
  const primaryTotal = stream.filter((e) => e.family === undefined).length;

  // Fill the page until the budget is spent. At least one finding always goes
  // out, so a page can never be empty and a cursor always advances.
  const families = brief.secondary_families?.map(({ id, counts }) => ({
    id,
    counts,
    ...(wantSecondary ? { findings: [] as BriefFinding[] } : {}),
  }));
  const page: BriefFinding[] = [];
  const budget = ctx.maxResultChars ?? MAX_RESULT_CHARS;
  // The envelope, plus room for `findings_total` and a cursor.
  let size =
    JSON.stringify({ ...brief, findings: [], secondary_families: families }).length +
    CURSOR_ALLOWANCE;
  let end = from.offset;
  while (end < stream.length) {
    const entry = stream[end]!;
    const cost = JSON.stringify(entry.finding).length + 1;
    if (end > from.offset && size + cost > budget) break;
    if (entry.family === undefined) page.push(entry.finding);
    else families![entry.family]!.findings!.push(entry.finding);
    size += cost;
    end++;
  }
  return {
    ...brief,
    findings: page,
    ...(families ? { secondary_families: families } : {}),
    findings_total: primaryTotal,
    ...(end < stream.length
      ? { next_cursor: encodeCursor({ sha: result.run.source_file.sha256, offset: end }) }
      : {}),
  };
}

/* ---------------- list_document_types ---------------- */

export async function listDocumentTypesTool(args: {
  query?: string;
  limit?: number;
  cursor?: string;
}): Promise<{
  total: number;
  types: Array<{ id: string; name: string; summary?: string }>;
  next_cursor?: string;
}> {
  const { offset } = decodeCursor(args.cursor);
  const page = await listDocumentTypes({ query: args.query, limit: args.limit, offset });
  return {
    total: page.total,
    types: page.types,
    ...(page.next_offset !== undefined
      ? { next_cursor: encodeCursor({ offset: page.next_offset }) }
      : {}),
  };
}

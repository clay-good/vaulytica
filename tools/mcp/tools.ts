/**
 * The tools, as functions from arguments to a result (spec-v48 §5–§9).
 *
 * Kept apart from the protocol wiring so each can be called by a test with no
 * transport. A request a person can fix throws {@link ToolError}; the server
 * answers it as an `isError` result.
 */

import { extname } from "node:path";
import {
  EXPORT_FORMATS,
  FolderTooLargeError,
  NOT_LEGAL_ADVICE_BUNDLE,
  analyzeDocument,
  analyzeFolder,
  buildBrief,
  checkConsistency,
  compareFiles,
  describeDocumentType,
  explainRule,
  exportArtifacts,
  isDocumentType,
  listDocumentTypes,
  type AccuracyDeps,
  type Brief,
  type BriefFinding,
  type ExportFormat,
} from "../cli/api.js";
import { ToolError, resolveInRoots, resolveNewInRoots } from "./roots.js";

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

/**
 * A document the ingest found no words in was not analyzed, whatever the
 * engine went on to say about the empty tree. A PDF in that state is almost
 * always a scan: the headless path does not run OCR, so there is no text layer
 * to read. Reported in a field of its own, never as a short clean report.
 */
function notAnalyzedReason(
  result: Awaited<ReturnType<typeof analyzeDocument>>,
  name: string,
): string | null {
  if (result.ingest.word_count > 0) return null;
  return extname(name).toLowerCase() === ".pdf"
    ? "no text layer: this PDF has no selectable text (it is probably a scan), and this server does not run OCR. Nothing in it was checked."
    : "no readable text: the file is empty or holds no words. Nothing in it was checked.";
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

  const unread = notAnalyzedReason(result, name);
  if (unread) return { not_analyzed: unread, document: { name } };

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

/* ---------------- analyze_folder ---------------- */

/** A folder call reads at most this many files (spec-v48 §9). */
export const MAX_FOLDER_FILES = 200;
/** …walking at most this many directory levels down. */
export const MAX_FOLDER_DEPTH = 8;
/** Rows per page: each is held to 300 bytes, so a page is about 15 KB. */
export const FOLDER_PAGE_ROWS = 50;

export type FolderRow = {
  path: string;
  /** Absent when the file was not analyzed; `not_analyzed` says why. */
  type?: string;
  /** Critical / warning / info, the primary match only. */
  c?: number;
  w?: number;
  i?: number;
  sha?: string;
  /** No family matched: only the generic rule set ran, so a short row means little. */
  unmatched?: true;
  /** Other families detected from vocabulary — detected, not confirmed. */
  secondary?: number;
  /** Ingest warnings on this file; read them with analyze_document. */
  caveats?: number;
  not_analyzed?: string;
};

export type AnalyzeFolderArgs = {
  dir?: string;
  paths?: readonly string[];
  related?: boolean;
  cursor?: string;
};

type Progress = {
  signal?: AbortSignal;
  report?: (done: number, total: number) => void | Promise<void>;
};

const rowPath = (path: string): string =>
  path.length <= 160 ? path : `…${path.slice(path.length - 159)}`;

export async function analyzeFolderTool(
  args: AnalyzeFolderArgs,
  ctx: Context,
  progress: Progress = {},
): Promise<{
  documents: number;
  totals: { critical: number; warning: number; info: number };
  rows: FolderRow[];
  unreadable: Array<{ path: string; reason: string }>;
  skipped: Array<{ path: string; reason: string }>;
  cross_document?: { result_hash: string; findings: unknown[] } | { not_run: string };
  caveats: { folder: string; not_legal_advice: string };
  next_cursor?: string;
}> {
  if ((args.dir === undefined) === (args.paths === undefined)) {
    throw new ToolError("Pass exactly one of `dir` or `paths`.");
  }
  const { offset } = decodeCursor(args.cursor);
  let target: string | string[];
  if (args.dir !== undefined) {
    target = await resolveInRoots(args.dir, ctx.roots);
  } else {
    if (args.paths!.length > MAX_FOLDER_FILES) throw tooMany(args.paths!.length);
    target = [];
    for (const p of args.paths!) target.push(await resolveInRoots(p, ctx.roots));
  }

  let folder: Awaited<ReturnType<typeof analyzeFolder>>;
  try {
    folder = await analyzeFolder(target, {
      deps: ctx.deps,
      secondaryFamilies: true,
      limits: { maxFiles: MAX_FOLDER_FILES, maxDepth: MAX_FOLDER_DEPTH },
      onDocument: async (done, total) => {
        // Analysis is synchronous; yielding here is what lets a cancellation in.
        await new Promise((r) => setImmediate(r));
        await progress.report?.(done, total);
        return !progress.signal?.aborted;
      },
    });
  } catch (e) {
    if (e instanceof FolderTooLargeError) throw tooMany(e.limit, true);
    throw e;
  }
  if (progress.signal?.aborted) throw new ToolError("Cancelled before every file was read.");
  if (folder.documents.length + folder.unreadable.length === 0) {
    throw new ToolError("No file this tool reads (.docx, .pdf, .txt, .md) was found there.");
  }
  const skipped = folder.skipped;

  const rows: FolderRow[] = [];
  const totals = { critical: 0, warning: 0, info: 0 };
  for (const d of folder.documents) {
    const empty = notAnalyzedReason(d.result, d.file);
    if (empty) {
      rows.push({ path: rowPath(d.label), not_analyzed: empty });
      continue;
    }
    const b = buildBrief(d.result, { excerpts: false });
    totals.critical += b.counts.critical;
    totals.warning += b.counts.warning;
    totals.info += b.counts.info;
    rows.push({
      path: rowPath(d.label),
      type: b.document.type,
      c: b.counts.critical,
      w: b.counts.warning,
      i: b.counts.info,
      sha: b.document.sha256.slice(0, 12),
      ...(b.caveats.classification_notice ? { unmatched: true as const } : {}),
      ...(b.secondary_families ? { secondary: b.secondary_families.length } : {}),
      ...(b.caveats.ingest_warnings ? { caveats: b.caveats.ingest_warnings.length } : {}),
    });
  }
  const unreadable = folder.unreadable.map((u) => ({ path: rowPath(u.file), reason: u.reason }));
  for (const u of unreadable) rows.push({ path: u.path, not_analyzed: u.reason.slice(0, 120) });
  rows.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const end = offset + FOLDER_PAGE_ROWS;
  return {
    documents: folder.documents.length,
    totals,
    rows: rows.slice(offset, end),
    unreadable,
    skipped: skipped.map((s) => ({ path: rowPath(s.file), reason: s.reason })),
    ...(args.related ? { cross_document: await crossDocument(folder, ctx) } : {}),
    caveats: {
      folder:
        "One row per file, in path order — not a ranking. Counts are the primary document type only. " +
        "A row marked `not_analyzed` was not checked at all; `unmatched` means only a small generic " +
        "rule set ran. Open a document with analyze_document before acting on its row.",
      not_legal_advice: NOT_LEGAL_ADVICE_BUNDLE,
    },
    ...(end < rows.length ? { next_cursor: encodeCursor({ offset: end }) } : {}),
  };
}

function tooMany(count: number, orMore = false): ToolError {
  return new ToolError(
    `That is ${orMore ? "more than " : ""}${count} files; one call reads at most ${MAX_FOLDER_FILES}. ` +
      `Point at a subfolder, or pass up to ${MAX_FOLDER_FILES} \`paths\`.`,
  );
}

/** The cross-document rules, only because the caller said these files are one deal. */
async function crossDocument(
  folder: Awaited<ReturnType<typeof analyzeFolder>>,
  ctx: Context,
): Promise<{ result_hash: string; findings: unknown[] } | { not_run: string }> {
  const run = await checkConsistency(folder.documents, ctx.deps);
  if (!run) return { not_run: "Fewer than two documents were read; there is nothing to compare." };
  return {
    result_hash: run.result_hash,
    findings: run.findings.slice(0, 40).map((f) => ({
      id: f.id,
      rule_id: f.rule_id,
      severity: f.severity,
      title: f.title,
      explanation: f.explanation,
      ...(f.recommendation ? { recommendation: f.recommendation } : {}),
      documents: f.excerpts.map((e) => e.doc_id),
    })),
    ...(run.findings.length > 40 ? { findings_omitted: run.findings.length - 40 } : {}),
  };
}

/* ---------------- compare_documents ---------------- */

export type CompareDocumentsArgs = {
  base_path?: string;
  base_text?: string;
  revised_path?: string;
  revised_text?: string;
  document_type?: string;
};

async function side(
  which: "base" | "revised",
  path: string | undefined,
  text: string | undefined,
  ctx: Context,
): Promise<Parameters<typeof compareFiles>[0]> {
  if ((path === undefined) === (text === undefined)) {
    throw new ToolError(`Pass exactly one of \`${which}_path\` or \`${which}_text\`.`);
  }
  if (path !== undefined) return { path: await resolveInRoots(path, ctx.roots) };
  if (text!.length > MAX_TEXT_CHARS) {
    throw new ToolError(
      `The ${which} text is over ${MAX_TEXT_CHARS.toLocaleString("en-US")} characters.`,
    );
  }
  return { text: text!, filename: `${which}.txt` };
}

const delta = (f: { rule_id: string; severity: string; title: string }) => ({
  rule_id: f.rule_id,
  severity: f.severity,
  title: f.title,
});

export async function compareDocumentsTool(args: CompareDocumentsArgs, ctx: Context) {
  const base = await side("base", args.base_path, args.base_text, ctx);
  const revised = await side("revised", args.revised_path, args.revised_text, ctx);
  if (args.document_type !== undefined && !(await isDocumentType(args.document_type))) {
    throw new ToolError(
      `"${args.document_type}" is not a document type id. Find one with list_document_types.`,
    );
  }
  let r: Awaited<ReturnType<typeof compareFiles>>;
  try {
    r = await compareFiles(base, revised, { deps: ctx.deps, playbookId: args.document_type });
  } catch (e) {
    // A cross-family pair, or a side that could not be read: both are the
    // caller's to fix, and both arrive as a sentence.
    throw new ToolError(e instanceof Error ? e.message : String(e));
  }
  const { comparison: cmp, clause_diff: diff } = r;
  return {
    comparison_hash: cmp.result_hash,
    base: { name: cmp.base.name, type: cmp.base.playbook_id, result_hash: cmp.base.result_hash },
    revised: {
      name: cmp.revised.name,
      type: cmp.revised.playbook_id,
      result_hash: cmp.revised.result_hash,
      sha256: r.revised.run.source_file.sha256,
    },
    counts: {
      resolved: cmp.delta.counts.resolved.total,
      introduced: cmp.delta.counts.introduced.total,
      unchanged: cmp.delta.counts.unchanged.total,
    },
    resolved: cmp.delta.resolved.map(delta),
    introduced: cmp.delta.introduced.map(delta),
    unchanged: cmp.delta.unchanged.map((u) => ({
      ...delta(u.finding),
      clause_changed: u.clause_changed,
    })),
    clauses: {
      rewritten: diff.changed.length,
      added: diff.added.length,
      removed: diff.removed.length,
      unchanged: diff.unchanged_count,
    },
    caveats: {
      ...(cmp.dkb_mismatch
        ? { dkb_mismatch: "The two sides were analyzed against different knowledge-base versions." }
        : {}),
      comparison:
        "Findings are matched by rule. `resolved` means a named check no longer fires — which also " +
        "happens when the clause it read was deleted, so read `clauses.removed` beside it. It does " +
        "not mean the document is complete, balanced, or enforceable.",
      not_legal_advice: NOT_LEGAL_ADVICE_BUNDLE,
    },
  };
}

/* ---------------- describe_document_type, explain_rule ---------------- */

export async function describeDocumentTypeTool(args: { id: string }, ctx: Context) {
  const type = await describeDocumentType(args.id, { deps: ctx.deps });
  if (!type) {
    throw new ToolError(
      `"${args.id}" is not a document type id. Find one with list_document_types.`,
    );
  }
  return type;
}

export async function explainRuleTool(args: { rule_id: string }, ctx: Context) {
  const rule = await explainRule(args.rule_id, { deps: ctx.deps });
  if (!rule) {
    throw new ToolError(
      `"${args.rule_id}" is not a rule id. A finding's \`rule_id\` (for example NDA-D-003) is one.`,
    );
  }
  return rule;
}

/* ---------------- export_report ---------------- */

export { EXPORT_FORMATS };

export async function exportReportTool(
  args: { path: string; formats: readonly string[]; out_dir: string; overwrite?: boolean },
  ctx: Context,
) {
  const path = await resolveInRoots(args.path, ctx.roots);
  const outDir = await resolveNewInRoots(args.out_dir, ctx.roots);
  if (args.formats.length === 0) throw new ToolError("Pass at least one format.");
  try {
    return await exportArtifacts(path, args.formats as ExportFormat[], outDir, {
      deps: ctx.deps,
      overwrite: args.overwrite ?? false,
    });
  } catch (e) {
    throw new ToolError(e instanceof Error ? e.message : String(e));
  }
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

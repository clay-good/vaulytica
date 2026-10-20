/**
 * The tools, as functions from arguments to a result (spec-v48 §5–§9).
 *
 * Kept apart from the protocol wiring so each can be called by a test with no
 * transport. A request a person can fix throws {@link ToolError}; the server
 * answers it as an `isError` result.
 */

import type { DeliveryReport } from "../../src/delivery/types.js";
import { buildDocumentAbstract, type DocumentAbstract } from "../../src/report/abstract.js";
import { ABSTRACT_STATEMENT } from "../../src/report/disclaimers.js";
import { titleCorpus } from "../../src/playbooks/matcher.js";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, sep } from "node:path";
import {
  parseCustomPlaybookJson,
  type CustomPlaybook,
} from "../../src/playbooks/custom-playbook.js";
import {
  ConfigError,
  discoverConfig,
  documentTypeFor,
  isRelated,
  namedTypeIds,
  provenance,
  type ConfigProvenance,
  type LoadedConfig,
} from "../cli/config.js";
import {
  EXPORT_FORMATS,
  FolderTooLargeError,
  NOT_LEGAL_ADVICE_BUNDLE,
  SLOT_QUESTION,
  analyzeDocument,
  analyzeFolder,
  buildBrief,
  buildComparisonBrief,
  checkConsistency,
  compareFiles,
  describeDocumentType,
  explainRule,
  generalChecksFor,
  exportArtifacts,
  isDocumentType,
  listDocumentTypes,
  triageFolder,
  type AccuracyDeps,
  type Brief,
  type BriefFinding,
  type ExportFormat,
  type Triage,
  type TriageRow,
} from "../cli/api.js";
import { ToolError, resolveInRoots, resolveNewInRoots, shownInRoots } from "./roots.js";

export { ToolError };

/** A result is truncated with a cursor past this many characters (spec-v48 §6). */
export const MAX_RESULT_CHARS = 40_000;

/**
 * The longest `text` a call may carry, and the largest text file a `path` may
 * name. Analysis is synchronous, and while it runs the server can answer
 * nothing — not even a cancellation. Measured on 9.859.0 (one document
 * repeated, secondary families on, a loaded machine): 255 KB in 1.0 s, 509 KB
 * in 2.3 s, 1,008 KB in 4.0 s, 2,005 KB in 8.3 s — about 4 ms per KB. The cap
 * holds the worst call near two seconds; 500,000 characters is a contract of
 * some 250 pages. The CLI's limit stays 50 MB.
 */
export const MAX_TEXT_CHARS = 500_000;

/** The largest .docx or .pdf a call reads. The container is larger than its text. */
export const MAX_CONTAINER_BYTES = 10 * 1024 * 1024;

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

/** The most bytes this surface reads from a file of this type. */
const sizeLimit = (path: string): number =>
  /\.(?:docx|pdf)$/i.test(path) ? MAX_CONTAINER_BYTES : MAX_TEXT_CHARS;

/** Refuse a file past this surface's size limits before reading it. */
async function assertReadableSize(real: string, shown: string): Promise<void> {
  const { size } = await stat(real);
  const limit = sizeLimit(real);
  if (size > limit) {
    throw new ToolError(
      `${shown} is ${size.toLocaleString("en-US")} bytes; this server reads up to ` +
        `${limit.toLocaleString("en-US")} for that file type. The command line has no such limit: ` +
        "`vaulytica analyze <file> --format brief-json`.",
    );
  }
}

/* ---------------- the project configuration ---------------- */

/**
 * What a `vaulytica.config.json` contributes to one call (add-project-config-file).
 * The server honours the keys that shape WHAT is analyzed — `document_types`,
 * `playbook`, `playbook_file` and `related`. Exit gates, formats and output
 * folders belong to a command line and have no meaning here.
 */
type Applied = {
  playbookId?: string;
  customPlaybook?: CustomPlaybook;
  playbookFor?: (file: string) => string | undefined;
  related?: boolean;
  config?: ConfigProvenance;
};

/**
 * The configuration for a path under an allowed root: the nearest file at or
 * above it, never above the root. `explicitType` and `explicitRelated` are the
 * caller's own arguments, which win.
 */
async function projectConfig(
  real: string,
  ctx: Context,
  explicit: { type?: string; related?: boolean } = {},
  /**
   * Which keys this tool can honour. Provenance lists only those, so a result
   * never claims a key shaped it when the tool had no use for it.
   */
  honours: { playbookFile?: boolean; related?: boolean } = { playbookFile: true },
): Promise<Applied> {
  const root = ctx.roots.find((r) => real === r || real.startsWith(r.endsWith(sep) ? r : r + sep));
  if (root === undefined) return {};
  const start = (await stat(real)).isDirectory() ? real : dirname(real);
  let config: LoadedConfig | null;
  try {
    config = await discoverConfig(start, root);
  } catch (e) {
    if (e instanceof ConfigError) throw new ToolError(e.message.replaceAll(root, "<root>"));
    throw e;
  }
  if (config === null) return {};
  for (const id of namedTypeIds(config)) {
    if (!(await isDocumentType(id))) {
      throw new ToolError(
        `${shownInRoots(config.path, ctx.roots)}: "${id}" is not a document type id. Find one with list_document_types.`,
      );
    }
  }
  const v = config.values;
  const applied: string[] = [];
  const overridden: string[] = [];
  const out: Applied = {};

  if (v.document_types !== undefined || v.playbook !== undefined) {
    const keys = [
      ...(v.document_types !== undefined ? ["document_types"] : []),
      ...(v.playbook !== undefined ? ["playbook"] : []),
    ];
    if (explicit.type !== undefined) overridden.push(...keys);
    else {
      applied.push(...keys);
      if (v.playbook !== undefined) out.playbookId = v.playbook;
      if (v.document_types !== undefined) {
        out.playbookFor = (file) => documentTypeFor(config, file);
      }
    }
  }
  if (v.playbook_file !== undefined && honours.playbookFile) {
    const text = await readFile(v.playbook_file, "utf8").catch(() => null);
    const parsed = text === null ? null : parseCustomPlaybookJson(text);
    if (parsed === null || !parsed.ok) {
      throw new ToolError(
        `${shownInRoots(config.path, ctx.roots)}: playbook_file ${shownInRoots(v.playbook_file, ctx.roots)} ` +
          (parsed === null
            ? "cannot be read"
            : `is not a valid playbook: ${parsed.errors.join("; ")}`),
      );
    }
    out.customPlaybook = parsed.playbook;
    applied.push("playbook_file");
  }
  if (v.related !== undefined && honours.related) {
    if (explicit.related !== undefined) overridden.push("related");
    else {
      applied.push("related");
      if (isRelated(config, real)) out.related = true;
    }
  }
  if (applied.length + overridden.length > 0) {
    out.config = provenance(config, root, applied, overridden);
  }
  return out;
}

/* ---------------- analyze_document ---------------- */

export type AnalyzeDocumentArgs = {
  path?: string;
  text?: string;
  filename?: string;
  document_type?: string;
  min_severity?: keyof typeof SEVERITY_RANK;
  include?: ReadonlyArray<"secondary_findings" | "delivery">;
  excerpts?: boolean;
  cursor?: string;
};

export type AnalyzeDocumentResult =
  | (Brief & {
      findings_total: number;
      next_cursor?: string;
      config?: ConfigProvenance;
      delivery?: DeliveryBlock;
    })
  | { not_analyzed: string; document: { name: string } };

/**
 * The input half every per-document tool shares: exactly one of `path` or
 * `text`, a known type id, a path inside an allowed root and of a type this
 * tool reads, the project configuration for a path, and the analysis itself.
 * A file that could not be checked comes back as `not_analyzed`.
 */
async function analyzeInput(
  args: Pick<AnalyzeDocumentArgs, "path" | "text" | "filename" | "document_type">,
  ctx: Context,
  extra: { delivery?: boolean } = {},
): Promise<
  | { result: Awaited<ReturnType<typeof analyzeDocument>>; name: string; applied: Applied }
  | { not_analyzed: string; document: { name: string } }
> {
  if ((args.path === undefined) === (args.text === undefined)) {
    throw new ToolError("Pass exactly one of `path` or `text`.");
  }
  // An unknown id is not an error to the engine — it falls back to detection,
  // and the caller would read the result as the type it asked for.
  if (args.document_type !== undefined && !(await isDocumentType(args.document_type))) {
    throw new ToolError(
      `"${args.document_type}" is not a document type id. Find one with list_document_types.`,
    );
  }
  let opts: Parameters<typeof analyzeDocument>[1] = {
    deps: ctx.deps,
    playbookId: args.document_type,
    secondaryFamilies: true,
  };
  let applied: Applied = {};

  let input: Parameters<typeof analyzeDocument>[0];
  let name: string;
  if (args.path !== undefined) {
    const real = await resolveInRoots(args.path, ctx.roots);
    if (!READABLE.has(extname(real).toLowerCase())) {
      throw new ToolError(
        `${args.path} is not a type this tool reads (${[...READABLE].sort().join(", ")}).`,
      );
    }
    await assertReadableSize(real, args.path);
    input = { path: real };
    name = args.path;
    // Text arrives with no location, so only a path reads a project configuration.
    applied = await projectConfig(real, ctx, { type: args.document_type });
    opts = {
      ...opts,
      playbookId: args.document_type ?? applied.playbookFor?.(real) ?? applied.playbookId,
      ...(applied.customPlaybook ? { customPlaybook: applied.customPlaybook } : {}),
    };
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
    // The pre-disclosure scan reads a file's CONTAINER; pasted text has none.
    result = await analyzeDocument(input, {
      ...opts,
      ...(extra.delivery && args.path !== undefined ? { delivery: true } : {}),
    });
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    // The file was not checked. Say so in a field no reader can take for a report.
    return { not_analyzed: reason, document: { name } };
  }

  const unread = notAnalyzedReason(result, name);
  if (unread) return { not_analyzed: unread, document: { name } };
  return { result, name, applied };
}

export async function analyzeDocumentTool(
  args: AnalyzeDocumentArgs,
  ctx: Context,
): Promise<AnalyzeDocumentResult> {
  const from = decodeCursor(args.cursor);
  const input = await analyzeInput(args, ctx, {
    delivery: args.include?.includes("delivery") ?? false,
  });
  if ("not_analyzed" in input) return input;
  const { result, applied } = input;
  if (from.sha !== undefined && from.sha !== result.run.source_file.sha256) {
    throw new ToolError(
      "The document changed since that cursor was issued. Call again without `cursor`.",
    );
  }

  const wantSecondary = args.include?.includes("secondary_findings") ?? false;
  const delivery = result.delivery
    ? deliveryBlock(result.delivery, args.excerpts ?? true)
    : undefined;
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
    JSON.stringify({ ...brief, findings: [], secondary_families: families, delivery }).length +
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
    ...(applied.config ? { config: applied.config } : {}),
    ...(delivery ? { delivery } : {}),
  };
}

/**
 * The pre-disclosure scan as the agent sees it (add-redaction-integrity-scan):
 * what the container still carries — tracked changes, comments, hidden text,
 * metadata, sensitive patterns, liftable redactions — and the hash that pins
 * it. A redaction's evidence is already its masked SHAPE. `excerpts: false`
 * drops the evidence lines too, because a tracked change or a comment quotes
 * the document.
 */
export type DeliveryBlock = {
  summary: string;
  inspectable: boolean;
  findings: Array<{
    rule_id: string;
    severity: string;
    title: string;
    count: number;
    evidence?: string[];
  }>;
  delivery_hash: string;
};

function deliveryBlock(d: DeliveryReport, excerpts: boolean): DeliveryBlock {
  return {
    summary: d.summary,
    inspectable: d.inspectable,
    findings: d.findings.map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      title: f.title,
      count: f.count,
      ...(excerpts ? { evidence: f.evidence.slice(0, 10) } : {}),
    })),
    delivery_hash: d.delivery_hash,
  };
}

/* ---------------- analyze_folder ---------------- */

/** A folder call reads at most this many files (spec-v48 §9). */
export const MAX_FOLDER_FILES = 200;
/** …walking at most this many directory levels down. */
export const MAX_FOLDER_DEPTH = 8;
/**
 * Matched documents per page (spec-v52 §7). Everything that is not an ordinary
 * matched document — unread, caveated, unmatched — is always on the first
 * page in full: those are the rows a person must not miss.
 */
export const FOLDER_PAGE_ROWS = 20;

/** One file on the triage page, cut to what fits in 300 bytes. */
export type FolderRow = {
  path: string;
  /** 1 not read · 2 read with a caveat · 3 unmatched · 4 matched. */
  tier: 1 | 2 | 3 | 4;
  /** Why it is in that tier; for tier 1, why it was not analyzed. */
  why?: string;
  type?: string;
  /** Unmatched only: the closest type and its score. Not a match. */
  near?: string;
  /** Critical / warning / info, the primary match only. */
  c?: number;
  w?: number;
  i?: number;
  /** Findings that carry a recommendation — what there is to work through. */
  act?: number;
  /** The first critical in document order. */
  first?: string;
  sha?: string;
  /** Other types detected from vocabulary — detected, not confirmed. */
  secondary?: number;
  /** Byte-identical copies, analyzed once. */
  same_as?: string[];
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
  path.length <= 120 ? path : `…${path.slice(path.length - 119)}`;

function folderRow(r: TriageRow): FolderRow {
  return {
    path: rowPath(r.path),
    tier: r.tier,
    ...(r.tier !== 4 ? { why: r.reason.slice(0, 90) } : {}),
    ...(r.type && r.tier !== 3 ? { type: r.type } : {}),
    ...(r.near_type ? { near: `${r.near_type.id} (${r.near_type.score})` } : {}),
    ...(r.counts ? { c: r.counts.critical, w: r.counts.warning, i: r.counts.info } : {}),
    ...(r.actionable !== undefined ? { act: r.actionable } : {}),
    ...(r.first_critical
      ? { first: `${r.first_critical.rule_id}: ${r.first_critical.title}`.slice(0, 70) }
      : {}),
    ...(r.sha ? { sha: r.sha } : {}),
    ...(r.secondary ? { secondary: r.secondary } : {}),
    ...(r.duplicates ? { same_as: r.duplicates.slice(0, 2).map(rowPath) } : {}),
  };
}

/** The first page is the whole triage; a later page is only more matched rows. */
export type FolderResult = {
  triage_hash: string;
  rows: FolderRow[];
  next_cursor?: string;
  engine_version?: string;
  dkb_version?: string;
  /** Every file that got a row, and how many of them were read. */
  files?: number;
  documents?: number;
  totals?: Triage["totals"];
  matched_total?: number;
  caveats?: Triage["caveats"];
  hidden?: string[];
  systemic?: Triage["systemic"];
  systemic_total?: number;
  spot_check?: Triage["spot_check"];
  slot_questions?: typeof SLOT_QUESTION;
  cross_document?: { result_hash: string; findings: unknown[] } | { not_run: string };
  /** The project configuration that shaped this call, when one was found. */
  config?: ConfigProvenance;
  notes?: { order: string; rows: string; not_legal_advice: string };
};

export async function analyzeFolderTool(
  args: AnalyzeFolderArgs,
  ctx: Context,
  progress: Progress = {},
): Promise<FolderResult> {
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
  // Paths on the page are relative to the allowed root that holds them, so
  // each can be handed straight back to analyze_document.
  const anchor = typeof target === "string" ? target : target[0]!;
  const root = ctx.roots.find((r) => anchor === r || anchor.startsWith(r));
  const applied = await projectConfig(
    anchor,
    ctx,
    { related: args.related },
    { playbookFile: true, related: true },
  );
  const related = args.related ?? applied.related ?? false;

  let result: Awaited<ReturnType<typeof triageFolder>>;
  try {
    result = await triageFolder(target, {
      deps: ctx.deps,
      root,
      ...(applied.playbookId ? { playbookId: applied.playbookId } : {}),
      ...(applied.playbookFor ? { playbookFor: applied.playbookFor } : {}),
      ...(applied.customPlaybook ? { customPlaybook: applied.customPlaybook } : {}),
      limits: { maxFiles: MAX_FOLDER_FILES, maxDepth: MAX_FOLDER_DEPTH },
      // One oversized file becomes a not-read row, not a stalled server.
      maxFileBytes: sizeLimit,
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
  const { triage, folder } = result;
  if (triage.rows.length === 0) {
    throw new ToolError("No file this tool reads (.docx, .pdf, .txt, .md) was found there.");
  }

  // The first page is the whole triage with the first matched rows; a later
  // page is only more matched rows.
  const urgent = triage.rows.filter((r) => r.tier !== 4);
  const matched = triage.rows.filter((r) => r.tier === 4);
  const end = offset + FOLDER_PAGE_ROWS;
  const page = matched.slice(offset, end).map(folderRow);
  const next = end < matched.length ? { next_cursor: encodeCursor({ offset: end }) } : {};
  if (offset > 0) return { triage_hash: triage.triage_hash, rows: page, ...next };
  const config = applied.config ? { config: applied.config } : {};

  return {
    triage_hash: triage.triage_hash,
    engine_version: triage.engine_version,
    dkb_version: triage.dkb_version,
    files: triage.rows.length,
    documents: triage.documents,
    totals: triage.totals,
    rows: [...urgent.map(folderRow), ...page],
    matched_total: matched.length,
    caveats: triage.caveats.map((c) => ({ ...c, files: c.files.slice(0, 10).map(rowPath) })),
    ...(triage.hidden.length > 0 ? { hidden: triage.hidden.slice(0, 10).map(rowPath) } : {}),
    systemic: triage.systemic.slice(0, 8),
    systemic_total: triage.systemic.length,
    spot_check: triage.spot_check,
    slot_questions: SLOT_QUESTION,
    ...(related ? { cross_document: await crossDocument(folder, ctx) } : {}),
    notes: {
      order: triage.statements.tiers,
      rows:
        "Tier 1 was not analyzed at all. Tier 3 matched no document type: only a small generic " +
        "rule set ran, so a short row means little. Counts are the primary type only. Open a " +
        "document with analyze_document before acting on its row.",
      not_legal_advice: NOT_LEGAL_ADVICE_BUNDLE,
    },
    ...config,
    ...next,
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
  if (path !== undefined) {
    const real = await resolveInRoots(path, ctx.roots);
    await assertReadableSize(real, path);
    return { path: real };
  }
  if (text!.length > MAX_TEXT_CHARS) {
    throw new ToolError(
      `The ${which} text is over ${MAX_TEXT_CHARS.toLocaleString("en-US")} characters.`,
    );
  }
  return { text: text!, filename: `${which}.txt` };
}

export async function compareDocumentsTool(args: CompareDocumentsArgs, ctx: Context) {
  const base = await side("base", args.base_path, args.base_text, ctx);
  const revised = await side("revised", args.revised_path, args.revised_text, ctx);
  if (args.document_type !== undefined && !(await isDocumentType(args.document_type))) {
    throw new ToolError(
      `"${args.document_type}" is not a document type id. Find one with list_document_types.`,
    );
  }
  // The base draft's location decides the project configuration: the revision
  // is held to the base's type anyway.
  const applied =
    "path" in base ? await projectConfig(base.path, ctx, { type: args.document_type }) : {};
  try {
    // The two drafts are one document by construction, so the revision is held
    // to the base draft's type: a heavy rewrite must not turn every
    // type-specific check into "fixed".
    const brief = buildComparisonBrief(
      await compareFiles(base, revised, {
        deps: ctx.deps,
        playbookId:
          args.document_type ??
          ("path" in base ? applied.playbookFor?.(base.path) : undefined) ??
          applied.playbookId,
        ...(applied.customPlaybook ? { customPlaybook: applied.customPlaybook } : {}),
        pinType: true,
      }),
    );
    return applied.config ? { ...brief, config: applied.config } : brief;
  } catch (e) {
    // A side that could not be read is the caller's to fix, and arrives as a sentence.
    throw new ToolError(e instanceof Error ? e.message : String(e));
  }
}

/* ---------------- describe_document_type, explain_rule ---------------- */

export async function describeDocumentTypeTool(
  args: { id: string; general?: boolean },
  ctx: Context,
) {
  const unknown = (): ToolError =>
    new ToolError(`"${args.id}" is not a document type id. Find one with list_document_types.`);
  if (args.general) {
    // The general checks are a result of their own: with the type's own checks
    // they would not fit in one.
    const general = await generalChecksFor(args.id, { deps: ctx.deps });
    if (!general) throw unknown();
    return {
      id: args.id,
      general,
      note: "These run on every document of this type. `recommendation` is what the rule asks for when the thing is missing; a check without one flags a clause that is present.",
    };
  }
  const type = await describeDocumentType(args.id, { deps: ctx.deps });
  if (!type) throw unknown();
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

/* ---------------- abstract_document ---------------- */

export type AbstractDocumentArgs = Pick<
  AnalyzeDocumentArgs,
  "path" | "text" | "filename" | "document_type" | "excerpts"
>;

/**
 * One document's abstract (add-contract-abstract-inventory): type, parties,
 * effective date, renewal, law, forum, cap and assignment, each with the
 * section it was read from, and a blank where nothing was read. Read-only, with
 * the same input rules as analyze_document. `excerpts: false` withholds the
 * one cell that quotes the document (the assignment sentence), the same
 * promise analyze_document makes about quoted text.
 */
export async function abstractDocumentTool(
  args: AbstractDocumentArgs,
  ctx: Context,
): Promise<
  (DocumentAbstract & { statement: string }) | { not_analyzed: string; document: { name: string } }
> {
  const input = await analyzeInput(args, ctx);
  if ("not_analyzed" in input) return input;
  const { result, name } = input;
  const abstract = await buildDocumentAbstract({
    file: name,
    tree: result.ingest.tree,
    run: result.run,
    playbookName: result.playbook.name,
    title: titleCorpus(result.ingest.tree, name).split("\n")[0]!.trim().slice(0, 160),
  });
  if (args.excerpts === false && abstract.assignment) {
    abstract.assignment = {
      value: "present (quoted text withheld: excerpts false)",
      ...(abstract.assignment.section ? { section: abstract.assignment.section } : {}),
    };
  }
  return { statement: ABSTRACT_STATEMENT, ...abstract };
}

/* ---------------- export_report ---------------- */

export { EXPORT_FORMATS };

export async function exportReportTool(
  args: { path: string; formats: readonly string[]; out_dir: string; overwrite?: boolean },
  ctx: Context,
) {
  const path = await resolveInRoots(args.path, ctx.roots);
  await assertReadableSize(path, args.path);
  const outDir = await resolveNewInRoots(args.out_dir, ctx.roots);
  if (args.formats.length === 0) throw new ToolError("Pass at least one format.");
  // The writer takes a document type, not a team playbook: `playbook_file`
  // shapes analyze_document and analyze_folder, not the exported files.
  const applied = await projectConfig(path, ctx, {}, { playbookFile: false });
  try {
    const r = await exportArtifacts(path, args.formats as ExportFormat[], outDir, {
      deps: ctx.deps,
      overwrite: args.overwrite ?? false,
      playbookId: applied.playbookFor?.(path) ?? applied.playbookId,
      ...(applied.config ? { config: applied.config } : {}),
    });
    return {
      ...r,
      written: r.written.map((w) => ({ ...w, path: shownInRoots(w.path, ctx.roots) })),
    };
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

/**
 * Folder triage (spec-v52): one page for a directory.
 *
 * Point the tool at a folder and it has always produced a complete report per
 * document — and nothing that says which document needs a person first, or
 * which few things to open to check the tool's own work. This is that page.
 *
 * The order is TIERS, not a score. Match confidence takes five values across
 * the whole specimen corpus, so it cannot rank, and a blended number would be
 * an invented one. Every tier is a fact the run already recorded:
 *
 *   1  not read       corrupt, unsupported, empty, no text layer
 *   2  read, caveat   tracked changes, not English, OCR, a rule that crashed
 *   3  unmatched      no document type matched; only the generic rules ran
 *   4  matched        by criticals, then warnings, then path
 *
 * The spot check is FIXED SLOTS, each a different way the run could be wrong
 * (§6). Ties are broken by a hash of the input and the rule, so the same
 * folder gives the same sample on any machine.
 *
 * Pure: takes a {@link FolderAnalysis}, returns values. A folder is not a
 * bundle — nothing here runs the cross-document rules.
 */

import { relative, resolve } from "node:path";
import { isActionable, type Finding, type Severity } from "../../src/engine/finding.js";
import { stableStringify } from "../../src/engine/runner.js";
import { truncate } from "../../src/engine/text.js";
import { sha256Hex } from "../../src/ingest/hash.js";
import { flattenText } from "../../src/ingest/types.js";
import { ingestWarningCodes, type IngestWarningCode } from "../../src/ingest/warning-codes.js";
import { determinismStatement, nonAdviceStatement } from "../../src/report/disclaimers.js";
import { GENERIC_FALLBACK_ID } from "../../src/playbooks/types.js";
import type { AnalyzeResult } from "./api.js";

export const TRIAGE_SCHEMA = "vaulytica.triage.v1";

export type TriageTier = 1 | 2 | 3 | 4;

export const TIER_LABEL: Record<TriageTier, string> = {
  1: "Not read",
  2: "Read with a caveat",
  3: "Unmatched",
  4: "Matched",
};

/** Why each tier comes where it does — printed with the page. */
export const TIER_MEANING: Record<TriageTier, string> = {
  1: "The tool has no opinion on these. A person must look.",
  2: "Findings may be incomplete or wrong.",
  3: "No document type matched, so only a small generic rule set ran. A short row means little.",
  4: "Ordered by criticals, then warnings, then path.",
};

type Counts = Record<Severity, number>;

export type TriageRow = {
  /** Relative to the folder, with `/` separators on every machine. */
  path: string;
  tier: TriageTier;
  reason: string;
  type?: string;
  /** Tier 3 only: the closest family and its score. Not a match. */
  near_type?: { id: string; score: number };
  confidence?: number;
  /** The primary match only, as `--fail-on` counts them. */
  counts?: Counts;
  actionable?: number;
  /** The first critical in DOCUMENT order, with what the document calls its section. */
  first_critical?: { rule_id: string; title: string; section_label?: string };
  rules_run?: { family: number; general: number };
  /** First 12 characters of the input's SHA-256. */
  sha?: string;
  /** Other families detected from vocabulary — detected, not confirmed. */
  secondary?: number;
  /** Byte-identical copies, analyzed once and shown on this one row. */
  duplicates?: string[];
  /** Where this document's own report was written, when one was. */
  report?: string;
};

export type SystemicRule = {
  rule_id: string;
  /** What the rule SAID on these documents — its commonest finding title. */
  title: string;
  type: string;
  /** Fired on this many documents of the type… */
  fired: number;
  /** …of this many. */
  of: number;
};

export type SpotSlot = "type" | "criticals" | "systemic" | "absence" | "quoted" | "clean";

export type SpotCheckItem = {
  slot: SpotSlot;
  path: string;
  /** Type slot: what the tool decided, beside the document's own first line. */
  type?: string;
  near_type?: { id: string; score: number };
  confidence?: number;
  title_line?: string;
  /** Finding slots. */
  finding_id?: string;
  rule_id?: string;
  severity?: Severity;
  actionable?: boolean;
  title?: string;
  section_label?: string;
  start_offset?: number;
  end_offset?: number;
  excerpt?: string;
  /** Absence slot: what the rule looks for, in its own words. */
  rule_description?: string;
  /** Clean slot: rules that ran on this document and stayed silent. */
  silent_rules?: Array<{ rule_id: string; name: string }>;
};

/** The question each slot puts to the person, and what a wrong answer means. */
export const SLOT_QUESTION: Record<SpotSlot, { ask: string; if_wrong: string }> = {
  type: {
    ask: "Is this document what the tool says it is?",
    if_wrong: "disregard its type-specific findings.",
  },
  criticals: {
    ask: "Is this really wrong?",
    if_wrong: "read that rule's other findings here before acting on them.",
  },
  systemic: {
    ask: "Is the template wrong, or the rule?",
    if_wrong: "a wrong rule is wrong on every document it fired on.",
  },
  absence: {
    ask: "Is the clause truly missing?",
    if_wrong: "the rule missed the clause as drafted; its other absences here are unconfirmed.",
  },
  quoted: {
    ask: "Does the quote say what the finding says?",
    if_wrong: "the rule misread the clause; check its other findings.",
  },
  clean: {
    ask: "Should something have fired here?",
    if_wrong: "a silence is not a clean bill; the rules have a gap on this kind of document.",
  },
};

export type Triage = {
  schema: typeof TRIAGE_SCHEMA;
  engine_version: string;
  dkb_version: string;
  documents: number;
  rows: TriageRow[];
  totals: {
    by_tier: Record<TriageTier, number>;
    /** Over the documents that were read, primary match only. */
    by_severity: Counts;
    actionable: number;
  };
  /** Each caveat once, with the files that carry it. */
  caveats: Array<{ code: string; meaning: string; files: string[] }>;
  /** Present and deliberately not read: dotfiles and dot-folders. */
  hidden: string[];
  /** A rule that fires on most documents of one type: a template problem, or a rule problem. */
  systemic: SystemicRule[];
  spot_check: {
    items: SpotCheckItem[];
    /** "k of N findings, m of D documents" — a check of the tool, not an error rate. */
    coverage: {
      /** Distinct critical rules that fired, and how many of them the sample asks about. */
      critical_rules: number;
      critical_rules_sampled: number;
      findings_sampled: number;
      findings: number;
      documents_sampled: number;
      documents: number;
    };
    note: string;
  };
  statements: { not_legal_advice: string; determinism: string; tiers: string };
  /** SHA-256 over this page with the hash itself blanked. Outside every `result_hash`. */
  triage_hash: string;
};

export type TriageInput = {
  documents: ReadonlyArray<{ file: string; label: string; result: AnalyzeResult }>;
  unreadable: ReadonlyArray<{ file: string; reason: string }>;
  skipped: ReadonlyArray<{ file: string; reason: string }>;
  duplicates?: ReadonlyArray<{ file: string; of: string }>;
};

const CAVEAT_MEANING: Record<string, string> = {
  "tracked-changes": "Tracked changes: analyzed as if every change were accepted.",
  "not-english": "Not English: the rules did not read most of the document.",
  ocr: "Read through OCR: the text may be wrong.",
  "rule-errored": "A rule could not be evaluated, so the document was not checked against it.",
  "no-text-layer": "A PDF with no text layer: nothing in it was checked (no OCR on this path).",
  empty: "No words in the file: nothing was checked.",
  other: "The ingest left a notice on this file; read it in the document's own report.",
  "secondary-cap": "More document types were detected than were scanned.",
};

/** The codes that put a document that WAS read into tier 2. */
const TIER_2_CODES: ReadonlySet<IngestWarningCode> = new Set([
  "tracked-changes",
  "not-english",
  "ocr",
]);

const HIDDEN = /^hidden\b/;

/** `label` relative to `root`, with `/` separators so a page hashes the same on every OS. */
function relativePath(label: string, root: string | undefined): string {
  let p = label;
  if (root !== undefined) {
    // Compared as resolved paths: `dir//sub` and `dir/sub` are one folder.
    const inside = relative(resolve(root), resolve(label));
    if (inside !== "" && !inside.startsWith("..")) p = inside;
  }
  return p.replace(/\\/g, "/").replace(/^\/+/, "");
}

const countsOf = (findings: readonly Finding[]): Counts => {
  const c: Counts = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
};

/** One printable line, capped: document text is data wherever it is shown. */
function line(text: string, max = 120): string {
  // eslint-disable-next-line no-control-regex
  return truncate(text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").trim(), max);
}

type RuleInfo = { name: string; description: string; family: boolean };

export async function buildTriage(
  input: TriageInput,
  opts: {
    /** The folder (or archive) that was walked; paths are shown relative to it. */
    root?: string;
    /** Rule metadata: names, descriptions, and which rules are gated to a family. */
    rules: ReadonlyMap<string, RuleInfo>;
    /** Where each document's own report was written, by label. */
    reportFor?: (label: string) => string | undefined;
    engineVersion: string;
    dkbVersion: string;
  },
): Promise<Triage> {
  const rel = (p: string): string => relativePath(p, opts.root);
  const duplicatesOf = new Map<string, string[]>();
  for (const d of input.duplicates ?? []) {
    duplicatesOf.set(d.of, [...(duplicatesOf.get(d.of) ?? []), rel(d.file)].sort());
  }

  const rows: TriageRow[] = [];
  const caveatFiles = new Map<string, string[]>();
  const note = (code: string, path: string): void => {
    caveatFiles.set(code, [...(caveatFiles.get(code) ?? []), path]);
  };
  /** The documents that were read and have findings to speak of, by path. */
  const read = new Map<string, AnalyzeResult>();

  for (const d of input.documents) {
    const path = rel(d.label);
    const r = d.result;
    const codes = ingestWarningCodes({ source: r.ingest.source, warnings: r.ingest.warnings });
    const dup = duplicatesOf.get(d.label);
    const base = {
      path,
      sha: r.run.source_file.sha256.slice(0, 12),
      ...(dup ? { duplicates: dup } : {}),
    };
    if (r.ingest.word_count === 0) {
      const code = codes.includes("no-text-layer") ? "no-text-layer" : "empty";
      note(code, path);
      rows.push({
        ...base,
        tier: 1,
        reason: code === "no-text-layer" ? "no text layer (scanned PDF)" : "empty",
      });
      continue;
    }
    read.set(path, r);
    const errored = r.run.execution_log.some((e) => e.errored);
    const reasons = codes.filter((c) => TIER_2_CODES.has(c)) as string[];
    if (errored) reasons.push("rule-errored");
    for (const c of new Set([...reasons, ...codes.filter((x) => x === "other")])) note(c, path);
    if (r.secondary_families_present > r.secondary_families.length) note("secondary-cap", path);

    // The run's own notice that no family matched — the same fact every other
    // surface prints as a banner — is what makes a row tier 3.
    const unmatched =
      r.run.classification_notice !== undefined || r.playbook_id === GENERIC_FALLBACK_ID;
    const firstCritical = [...r.run.findings]
      .filter((f) => f.severity === "critical")
      .sort((a, b) => a.document_position - b.document_position)[0];
    const ran = r.run.execution_log.filter((e) => e.ran);
    const family = ran.filter((e) => opts.rules.get(e.rule_id)?.family).length;
    const report = opts.reportFor?.(d.label);
    rows.push({
      ...base,
      tier: reasons.length > 0 ? 2 : unmatched ? 3 : 4,
      reason:
        reasons.length > 0
          ? [...new Set(reasons)].join(", ")
          : unmatched
            ? "no document type matched"
            : "matched",
      type: r.playbook_id,
      ...(unmatched && r.near_miss
        ? { near_type: { id: r.near_miss.playbook_id, score: r.near_miss.score } }
        : {}),
      ...(r.run.playbook_match_confidence !== undefined
        ? { confidence: r.run.playbook_match_confidence }
        : {}),
      counts: countsOf(r.run.findings),
      actionable: r.run.findings.filter(isActionable).length,
      ...(firstCritical
        ? {
            first_critical: {
              rule_id: firstCritical.rule_id,
              title: line(firstCritical.title, 70),
              ...(firstCritical.excerpt.section_label
                ? { section_label: line(firstCritical.excerpt.section_label, 40) }
                : {}),
            },
          }
        : {}),
      rules_run: { family, general: ran.length - family },
      ...(r.secondary_families.length > 0 ? { secondary: r.secondary_families.length } : {}),
      ...(report ? { report: report.replace(/\\/g, "/") } : {}),
    });
  }
  for (const u of input.unreadable) {
    rows.push({ path: rel(u.file), tier: 1, reason: `could not be read: ${line(u.reason, 100)}` });
  }
  const hidden: string[] = [];
  for (const s of input.skipped) {
    if (HIDDEN.test(s.reason)) hidden.push(rel(s.file));
    else rows.push({ path: rel(s.file), tier: 1, reason: s.reason });
  }

  const byPath = (a: TriageRow, b: TriageRow): number =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  rows.sort(
    (a, b) =>
      a.tier - b.tier ||
      (a.tier === 4
        ? b.counts!.critical - a.counts!.critical || b.counts!.warning - a.counts!.warning
        : 0) ||
      byPath(a, b),
  );

  const by_tier: Record<TriageTier, number> = { 1: 0, 2: 0, 3: 0, 4: 0 };
  const by_severity: Counts = { critical: 0, warning: 0, info: 0 };
  let actionable = 0;
  for (const row of rows) {
    by_tier[row.tier]++;
    if (!row.counts) continue;
    by_severity.critical += row.counts.critical;
    by_severity.warning += row.counts.warning;
    by_severity.info += row.counts.info;
    actionable += row.actionable ?? 0;
  }

  const systemic = systemicRules(rows, read);
  const spot_check = await spotCheck(rows, read, systemic, opts.rules);

  const page: Triage = {
    schema: TRIAGE_SCHEMA,
    engine_version: opts.engineVersion,
    dkb_version: opts.dkbVersion,
    documents: read.size,
    rows,
    totals: { by_tier, by_severity, actionable },
    caveats: [...caveatFiles]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([code, files]) => ({
        code,
        meaning: CAVEAT_MEANING[code] ?? code,
        files: [...new Set(files)].sort(),
      })),
    hidden: hidden.sort(),
    systemic,
    spot_check,
    statements: {
      not_legal_advice: nonAdviceStatement("folder"),
      determinism: determinismStatement("folder"),
      tiers:
        "The order is a sort on facts the run recorded: tiers, then counts. It is never a risk score.",
    },
    triage_hash: "",
  };
  // Report paths are where this run happened to write; they are not part of
  // what the page says about the folder, so they stay outside its hash.
  const hashed = { ...page, rows: page.rows.map(({ report: _report, ...row }) => row) };
  page.triage_hash = await sha256Hex(stableStringify(hashed));
  return page;
}

/**
 * A rule is systemic for a type when it fires on at least three documents of
 * that type and at least half of them: "NDA-D-001 on 14 of 20 NDAs" is a
 * template problem. Listing every rule made this section most of the page.
 */
function systemicRules(
  rows: readonly TriageRow[],
  read: ReadonlyMap<string, AnalyzeResult>,
): SystemicRule[] {
  const byType = new Map<string, string[]>();
  for (const row of rows) {
    if (row.tier !== 4) continue;
    byType.set(row.type!, [...(byType.get(row.type!) ?? []), row.path]);
  }
  const out: SystemicRule[] = [];
  for (const [type, paths] of byType) {
    if (paths.length < 3) continue;
    const fired = new Map<string, number>();
    const titles = new Map<string, Map<string, number>>();
    for (const p of paths) {
      const seen = new Set<string>();
      for (const f of read.get(p)!.run.findings) {
        if (seen.has(f.rule_id)) continue;
        seen.add(f.rule_id);
        fired.set(f.rule_id, (fired.get(f.rule_id) ?? 0) + 1);
        const t = titles.get(f.rule_id) ?? new Map<string, number>();
        titles.set(f.rule_id, t.set(f.title, (t.get(f.title) ?? 0) + 1));
      }
    }
    for (const [rule_id, n] of fired) {
      if (n < 3 || n * 2 < paths.length) continue;
      // The rule's NAME describes the check ("Venue clause present"); what a
      // reader needs is what it said here ("No venue / forum clause detected").
      const title = [...titles.get(rule_id)!].sort(
        (a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1),
      )[0]![0];
      out.push({ rule_id, title: line(title, 90), type, fired: n, of: paths.length });
    }
  }
  return out.sort(
    (a, b) => b.fired - a.fired || (a.type + a.rule_id < b.type + b.rule_id ? -1 : 1),
  );
}

/* ---------------- the spot check ---------------- */

type Candidate = { path: string; result: AnalyzeResult; finding: Finding; key: string };

const isAbsence = (f: Finding): boolean => f.excerpt.end_offset <= f.excerpt.start_offset;

/**
 * How many findings a slot may take. A folder of drafts from one bad template
 * has dozens of distinct critical rules, and a sample that long is not read.
 * What was left out is counted on the page, never dropped silently.
 */
export const SPOT_CHECK_CAPS = { criticals: 6, systemic: 3 } as const;

/** How many systemic rules the page lists before it says how many more there are. */
export const SYSTEMIC_LISTED = 6;

async function spotCheck(
  rows: readonly TriageRow[],
  read: ReadonlyMap<string, AnalyzeResult>,
  systemic: readonly SystemicRule[],
  rules: ReadonlyMap<string, RuleInfo>,
): Promise<Triage["spot_check"]> {
  // Every tie is broken by SHA-256(input SHA-256 + rule id): the same folder
  // gives the same sample across runs, machines and input order, and across an
  // engine upgrade that changes no finding.
  const tie = (sha: string, id: string): Promise<string> => sha256Hex(sha + id);
  const candidates: Candidate[] = [];
  for (const [path, result] of read) {
    for (const finding of result.run.findings) {
      candidates.push({
        path,
        result,
        finding,
        key: await tie(result.run.source_file.sha256, finding.rule_id),
      });
    }
  }
  candidates.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const docKey = new Map<string, string>();
  for (const [path, result] of read) docKey.set(path, await tie(result.run.source_file.sha256, ""));
  const byDocKey = (a: string, b: string): number => (docKey.get(a)! < docKey.get(b)! ? -1 : 1);

  const items: SpotCheckItem[] = [];
  const takenFindings = new Set<string>();
  let observations = 0;
  const findingItem = (slot: SpotSlot, c: Candidate, extra: Partial<SpotCheckItem> = {}): void => {
    const f = c.finding;
    takenFindings.add(`${c.path}\u0000${f.id}`);
    if (!isActionable(f)) observations++;
    items.push({
      slot,
      path: c.path,
      finding_id: f.id,
      rule_id: f.rule_id,
      severity: f.severity,
      actionable: isActionable(f),
      title: line(f.title),
      ...(f.excerpt.section_label ? { section_label: line(f.excerpt.section_label, 80) } : {}),
      start_offset: f.excerpt.start_offset,
      end_offset: f.excerpt.end_offset,
      ...extra,
    });
  };
  /** At most one observation in the whole sample: a "clause present" teaches little. */
  const eligible = (c: Candidate): boolean =>
    !takenFindings.has(`${c.path}\u0000${c.finding.id}`) &&
    (isActionable(c.finding) || observations === 0);

  // TYPE — the three ways a type can be wrong: nothing matched and something
  // was close; a match the tool was least sure of; and one of each type seen.
  const typePaths = new Set<string>();
  const typeItem = (row: TriageRow): void => {
    if (typePaths.has(row.path)) return;
    typePaths.add(row.path);
    const text = flattenText(read.get(row.path)!.ingest.tree);
    items.push({
      slot: "type",
      path: row.path,
      type: row.type,
      ...(row.near_type ? { near_type: row.near_type } : {}),
      ...(row.confidence !== undefined ? { confidence: row.confidence } : {}),
      title_line: line(text.split("\n").find((l) => l.trim() !== "") ?? "", 100),
    });
  };
  for (const row of rows) if (row.tier === 3 && row.near_type) typeItem(row);
  const matched = rows.filter((r) => r.tier === 4);
  [...matched]
    .sort((a, b) => (a.confidence ?? 1) - (b.confidence ?? 1) || byDocKey(a.path, b.path))
    .slice(0, 3)
    .forEach(typeItem);
  const seenTypes = new Set<string>();
  let perType = 0;
  for (const row of [...matched].sort((a, b) => byDocKey(a.path, b.path))) {
    if (perType >= 5) break;
    if (seenTypes.has(row.type!)) continue;
    seenTypes.add(row.type!);
    if (!typePaths.has(row.path)) perType++;
    typeItem(row);
  }

  // CRITICALS — one finding per distinct critical rule, different documents
  // first. Rules are taken in tie-break order, not alphabetical, so the cap
  // does not always keep the same end of the alphabet.
  const usedDocs = new Set<string>();
  const sampledRules = new Set<string>();
  const criticals = candidates.filter((c) => c.finding.severity === "critical");
  const criticalRules = [...new Set(criticals.map((c) => c.finding.rule_id))];
  for (const rule_id of criticalRules) {
    if (sampledRules.size >= SPOT_CHECK_CAPS.criticals) break;
    const of = criticals.filter((c) => c.finding.rule_id === rule_id && eligible(c));
    const pick = of.find((c) => !usedDocs.has(c.path)) ?? of[0];
    if (!pick) continue;
    usedDocs.add(pick.path);
    sampledRules.add(rule_id);
    findingItem("criticals", pick);
  }

  // SYSTEMIC — one finding from each systemic rule not already asked about.
  let systemicTaken = 0;
  for (const s of systemic) {
    if (systemicTaken >= SPOT_CHECK_CAPS.systemic) break;
    if (sampledRules.has(s.rule_id)) continue;
    const pick = candidates.find(
      (c) => c.finding.rule_id === s.rule_id && c.result.playbook_id === s.type && eligible(c),
    );
    if (!pick) continue;
    systemicTaken++;
    sampledRules.add(s.rule_id);
    findingItem("systemic", pick);
  }

  // ABSENCE — at least two, each with what the rule looks for.
  for (const c of candidates.filter((x) => isAbsence(x.finding))) {
    if (items.filter((i) => i.slot === "absence").length >= 2) break;
    if (!eligible(c) || sampledRules.has(c.finding.rule_id)) continue;
    sampledRules.add(c.finding.rule_id);
    findingItem("absence", c, {
      rule_description: line(rules.get(c.finding.rule_id)?.description ?? "", 240),
    });
  }

  // QUOTED — at least two, with the quote and its offsets.
  for (const c of candidates.filter((x) => !isAbsence(x.finding))) {
    if (items.filter((i) => i.slot === "quoted").length >= 2) break;
    if (!eligible(c) || sampledRules.has(c.finding.rule_id)) continue;
    sampledRules.add(c.finding.rule_id);
    findingItem("quoted", c, { excerpt: line(c.finding.excerpt.text, 240) });
  }

  // CLEAN — the two documents with the fewest findings, each naming two rules
  // that ran and stayed silent. Family rules first: they are about this type.
  const cleanest = [...matched]
    .sort(
      (a, b) =>
        a.counts!.critical +
          a.counts!.warning +
          a.counts!.info -
          (b.counts!.critical + b.counts!.warning + b.counts!.info) || byDocKey(a.path, b.path),
    )
    .slice(0, 2);
  for (const row of cleanest) {
    const r = read.get(row.path)!;
    const silent: Array<{ id: string; key: string; family: boolean }> = [];
    for (const e of r.run.execution_log) {
      if (!e.ran || e.fired) continue;
      silent.push({
        id: e.rule_id,
        key: await tie(r.run.source_file.sha256, e.rule_id),
        family: rules.get(e.rule_id)?.family ?? false,
      });
    }
    silent.sort((a, b) => Number(b.family) - Number(a.family) || (a.key < b.key ? -1 : 1));
    items.push({
      slot: "clean",
      path: row.path,
      type: row.type,
      silent_rules: silent
        .slice(0, 2)
        .map((s) => ({ rule_id: s.id, name: rules.get(s.id)?.name ?? s.id })),
    });
  }

  const sampledDocs = new Set(items.map((i) => i.path));
  return {
    items,
    coverage: {
      critical_rules: criticalRules.length,
      critical_rules_sampled: items.filter((i) => i.slot === "criticals").length,
      findings_sampled: items.filter((i) => i.finding_id !== undefined).length,
      findings: candidates.length,
      documents_sampled: sampledDocs.size,
      documents: read.size,
    },
    note: "A check of the tool: not a random sample, and not an estimate of an error rate.",
  };
}

/* ---------------- rendering ---------------- */

/** The page as JSON: stable key order, one trailing newline. */
export function buildTriageJson(t: Triage): string {
  return JSON.stringify(t, null, 2) + "\n";
}

const cell = (s: string): string => s.replace(/\|/g, "\\|");

/** The page a person reads first. */
export function buildTriageMarkdown(t: Triage): string {
  const out: string[] = [];
  const { by_tier, by_severity } = t.totals;
  out.push("# Folder triage");
  out.push("");
  out.push(
    `${t.rows.length} files · ${t.documents} read · ${by_severity.critical} critical, ${by_severity.warning} warning, ${by_severity.info} info · ${t.totals.actionable} actionable`,
  );
  out.push(`Engine ${t.engine_version} · DKB ${t.dkb_version} · Triage hash \`${t.triage_hash}\``);
  out.push("");
  out.push(`> ${t.statements.tiers}`);

  for (const tier of [1, 2, 3, 4] as const) {
    const rows = t.rows.filter((r) => r.tier === tier);
    if (rows.length === 0) continue;
    out.push("");
    out.push(`## ${tier}. ${TIER_LABEL[tier]} (${by_tier[tier]})`);
    out.push("");
    out.push(TIER_MEANING[tier]);
    out.push("");
    if (tier === 1) {
      out.push("| File | Why |");
      out.push("|---|---|");
      for (const r of rows) out.push(`| ${cell(r.path)} | ${cell(r.reason)} |`);
      continue;
    }
    out.push("| File | Type | C / W / I | To do | First critical | Rules run | SHA-256 |");
    out.push("|---|---|---|---|---|---|---|");
    for (const r of rows) {
      const unmatched = r.type === GENERIC_FALLBACK_ID;
      const named = unmatched
        ? r.near_type
          ? `none (closest: ${r.near_type.id}, ${r.near_type.score})`
          : "none"
        : r.type!;
      const type = tier === 2 ? `${named} — ${r.reason}` : named;
      const first = r.first_critical
        ? `${r.first_critical.rule_id}: ${r.first_critical.title}${r.first_critical.section_label ? ` (${r.first_critical.section_label})` : ""}`
        : "—";
      const flags = [
        r.secondary ? `+${r.secondary} type${r.secondary === 1 ? "" : "s"} detected` : "",
        r.duplicates ? `same bytes as ${r.duplicates.join(", ")}` : "",
      ].filter(Boolean);
      const file = r.report ? `[${r.path}](${encodeURI(r.report)})` : r.path;
      out.push(
        `| ${cell(file)}${flags.length ? `<br>_${cell(flags.join("; "))}_` : ""} | ${cell(type)} | ${r.counts!.critical} / ${r.counts!.warning} / ${r.counts!.info} | ${r.actionable} | ${cell(first)} | ${r.rules_run!.family} + ${r.rules_run!.general} | \`${r.sha}\` |`,
      );
    }
  }

  if (t.caveats.length > 0) {
    out.push("");
    out.push("## Caveats");
    out.push("");
    for (const c of t.caveats) out.push(`- **${c.meaning}** ${c.files.join(", ")}`);
  }
  if (t.hidden.length > 0) {
    out.push("");
    out.push(`_Not read, by design — names starting with a dot: ${t.hidden.join(", ")}_`);
  }

  if (t.systemic.length > 0) {
    out.push("");
    out.push("## Rules that fire across a type");
    out.push("");
    out.push(
      "A rule that fires on most documents of one type points at the template, or at the rule.",
    );
    out.push("");
    for (const s of t.systemic.slice(0, SYSTEMIC_LISTED)) {
      out.push(`- \`${s.rule_id}\` ${s.title} — ${s.fired} of ${s.of} \`${s.type}\``);
    }
    if (t.systemic.length > SYSTEMIC_LISTED) {
      out.push(
        `- …and ${t.systemic.length - SYSTEMIC_LISTED} more. The JSON form of this page lists them all.`,
      );
    }
  }

  const sc = t.spot_check;
  out.push("");
  out.push("## Spot check");
  out.push("");
  out.push(
    `${sc.coverage.findings_sampled} of ${sc.coverage.findings} findings, ${sc.coverage.documents_sampled} of ${sc.coverage.documents} documents, ${sc.coverage.critical_rules_sampled} of ${sc.coverage.critical_rules} distinct critical rules. ${sc.note}`,
  );
  for (const slot of ["type", "criticals", "systemic", "absence", "quoted", "clean"] as const) {
    const items = sc.items.filter((i) => i.slot === slot);
    if (items.length === 0) continue;
    out.push("");
    out.push(`**${SLOT_QUESTION[slot].ask}** _If not, ${SLOT_QUESTION[slot].if_wrong}_`);
    out.push("");
    for (const i of items) {
      if (slot === "type") {
        const decided = i.near_type
          ? `no type (closest: \`${i.near_type.id}\`, ${i.near_type.score})`
          : `\`${i.type}\`${i.confidence !== undefined ? ` (${i.confidence})` : ""}`;
        out.push(`- [ ] ${i.path} → ${decided}. It begins: "${i.title_line}"`);
      } else if (slot === "clean") {
        out.push(
          `- [ ] ${i.path} (\`${i.type}\`) — ran and stayed silent: ${i.silent_rules!.map((s) => `\`${s.rule_id}\` ${s.name}`).join("; ")}`,
        );
      } else {
        const where = i.section_label ? `, ${i.section_label}` : "";
        const span = i.end_offset! > i.start_offset! ? ` at ${i.start_offset}–${i.end_offset}` : "";
        const detail =
          slot === "absence"
            ? ` The rule looks for: ${i.rule_description}`
            : slot === "quoted"
              ? ` "${i.excerpt}"`
              : "";
        out.push(`- [ ] ${i.path}${where}${span} — \`${i.rule_id}\` ${i.title}.${detail}`);
      }
    }
  }

  out.push("");
  out.push("---");
  out.push("");
  out.push(t.statements.not_legal_advice);
  out.push("");
  out.push(t.statements.determinism);
  out.push("");
  return out.join("\n");
}

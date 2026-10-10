/**
 * The compact projection (spec-v48 §6, spec-v50 §4).
 *
 * The full JSON report for a six-finding NDA is 293,645 bytes, and 274 KB of
 * it is the execution log. That report is what `verify`, the certificate and
 * every golden depend on, so it stays exactly as it is. This is a second VIEW
 * of the same analysis for a reader with a budget — a script, or an agent —
 * and the one owner of that view: `--format brief-json` writes it and the MCP
 * server returns it.
 *
 * What it keeps is what lets a person check a finding against the document:
 * the finding's `id`, its offsets into the ingested text, and the excerpt.
 * What it drops is the log (replaced by `rules_run`), all but one citation per
 * finding, and the secondary families' findings (kept as ids and counts — they
 * are detected from vocabulary, not confirmed).
 *
 * Every caveat the full report carries is carried here. A brief is a render
 * surface, and a short report with no caveat reads as a clean bill.
 */

import type { Finding, Severity } from "../../src/engine/finding.js";
import { truncate } from "../../src/engine/text.js";
import { nonAdviceStatement } from "../../src/report/disclaimers.js";
import { erroredRuleNotice } from "../../src/report/execution-log.js";
import type { AnalyzeResult } from "./api.js";

export const BRIEF_SCHEMA = "vaulytica.brief.v1";

/** A quoted excerpt is capped here; the offsets still locate the whole span. */
export const BRIEF_EXCERPT_CHARS = 300;

/** Said wherever a secondary family is listed without its findings. */
export const SECONDARY_FAMILY_CAVEAT =
  "Detected from this document's vocabulary, not confirmed. Where the document is not of that family, an absence reported under it is a clause it was never supposed to carry.";

type Counts = Record<Severity, number>;

export type BriefFinding = {
  id: string;
  rule_id: string;
  rule_version: string;
  severity: Severity;
  title: string;
  explanation: string;
  recommendation?: string;
  section_label?: string;
  /** Offsets into the ingested text; they survive `excerpts: false`. */
  start_offset: number;
  end_offset: number;
  excerpt?: string;
  citation?: { source: string; source_url: string };
  citations_total: number;
};

export type Brief = {
  schema: typeof BRIEF_SCHEMA;
  document: {
    name: string;
    sha256: string;
    type: string;
    confidence?: number;
    match_reasoning?: string;
  };
  counts: Counts;
  findings: BriefFinding[];
  secondary_families?: Array<{ id: string; counts: Counts; findings?: BriefFinding[] }>;
  /** Families clearly present that the cap left unscanned. */
  secondary_families_omitted?: number;
  caveats: {
    ingest_warnings?: string[];
    classification_notice?: string;
    secondary_families?: string;
    rules_errored?: string;
    not_legal_advice: string;
  };
  /** In place of the execution log: how many rules ran, of how many registered. */
  rules_run: number;
  rules_registered: number;
  result_hash: string;
  dkb_version: string;
  engine_version: string;
};

/**
 * Document text is data. A contract can carry control characters or a line
 * shaped like a protocol frame; every document-derived string is flattened to
 * one line of printable text before it leaves in a named field.
 */
function printable(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ");
}

function countsOf(findings: readonly Finding[]): Counts {
  const counts: Counts = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function briefFinding(f: Finding, excerpts: boolean): BriefFinding {
  const first = f.source_citations[0];
  return {
    id: f.id,
    rule_id: f.rule_id,
    rule_version: f.rule_version,
    severity: f.severity,
    title: truncate(printable(f.title), BRIEF_EXCERPT_CHARS),
    explanation: f.explanation,
    ...(f.recommendation ? { recommendation: f.recommendation } : {}),
    ...(f.excerpt.section_label
      ? { section_label: truncate(printable(f.excerpt.section_label), BRIEF_EXCERPT_CHARS) }
      : {}),
    start_offset: f.excerpt.start_offset,
    end_offset: f.excerpt.end_offset,
    ...(excerpts ? { excerpt: truncate(printable(f.excerpt.text), BRIEF_EXCERPT_CHARS) } : {}),
    ...(first ? { citation: { source: first.source, source_url: first.source_url } } : {}),
    citations_total: f.source_citations.length,
  };
}

export function buildBrief(
  r: AnalyzeResult,
  opts: {
    /** `false` returns findings with offsets and no quoted document text. */
    excerpts?: boolean;
    /** Carry the secondary families' findings, not only their ids and counts. */
    secondaryFindings?: boolean;
  } = {},
): Brief {
  const excerpts = opts.excerpts ?? true;
  const run = r.run;
  const omitted = r.secondary_families_present - r.secondary_families.length;
  const errored = erroredRuleNotice(run.execution_log);
  return {
    schema: BRIEF_SCHEMA,
    document: {
      name: truncate(printable(run.source_file.name), BRIEF_EXCERPT_CHARS),
      sha256: run.source_file.sha256,
      type: run.playbook_id,
      ...(run.playbook_match_confidence !== undefined
        ? { confidence: run.playbook_match_confidence }
        : {}),
      ...(run.playbook_match_reasoning
        ? { match_reasoning: printable(run.playbook_match_reasoning) }
        : {}),
    },
    counts: countsOf(run.findings),
    findings: run.findings.map((f) => briefFinding(f, excerpts)),
    ...(r.secondary_families.length > 0
      ? {
          secondary_families: r.secondary_families.map((s) => ({
            id: s.playbook_id,
            counts: s.counts,
            ...(opts.secondaryFindings
              ? { findings: s.findings.map((f) => briefFinding(f, excerpts)) }
              : {}),
          })),
        }
      : {}),
    ...(omitted > 0 ? { secondary_families_omitted: omitted } : {}),
    caveats: {
      ...(r.ingest.warnings.length > 0 ? { ingest_warnings: r.ingest.warnings } : {}),
      ...(run.classification_notice
        ? { classification_notice: run.classification_notice.message }
        : {}),
      ...(r.secondary_families.length > 0 ? { secondary_families: SECONDARY_FAMILY_CAVEAT } : {}),
      ...(errored ? { rules_errored: errored } : {}),
      not_legal_advice: nonAdviceStatement("document"),
    },
    rules_run: run.execution_log.filter((e) => e.ran).length,
    rules_registered: run.execution_log.length,
    result_hash: run.result_hash,
    dkb_version: run.dkb_version,
    engine_version: run.version,
  };
}

/** The brief as `--format brief-json` writes it: minified, one line. */
export function buildBriefJson(
  r: AnalyzeResult,
  opts: Parameters<typeof buildBrief>[1] = {},
): string {
  return JSON.stringify(buildBrief(r, opts));
}

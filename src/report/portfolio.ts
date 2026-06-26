/**
 * Portfolio risk matrix (spec-v6 Part V, Step 97).
 *
 * The bundle engine already runs each document independently. This module
 * adds a deterministic aggregation layer on top: a documents × key-checks
 * grid that answers the portfolio question — "across these 40 vendor
 * agreements, which lack a liability cap? which auto-renew? which are
 * missing a breach-notice clause?" — plus the rollups that summarize it.
 *
 * Each cell is a pure projection of one document's {@link EngineRun}: it
 * reads the execution log (did the rule run?) and the findings (did it
 * fire?). Nothing here re-runs a rule or guesses; a check whose underlying
 * rule never ran for a document renders an honest `N/A`, never a wrong
 * `Risk`. The shading vocabulary mirrors the v3 compliance matrix.
 *
 * Determinism: the matrix is a sorted, canonical projection of the runs.
 * {@link portfolioFingerprint} extends the existing bundle fingerprint by
 * folding in the canonical matrix, so the same folder yields the same
 * fingerprint on any machine.
 */

import type { EngineRun } from "../engine/finding.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";

/**
 * Cell status. `ok` = the desirable state holds; `risk` = an undesirable
 * state (uncapped, missing clause); `flag` = present-and-noteworthy (the
 * document auto-renews); `na` = the check's rule did not run for this
 * document, so no claim is made.
 */
export type PortfolioStatus = "ok" | "risk" | "flag" | "na";

export type PortfolioCellEval = {
  status: PortfolioStatus;
  /** Short answer shown in the cell, e.g. "Capped", "Uncapped", "Auto-renews". */
  label: string;
  /** Contributing rule id(s), surfaced in the cell like the v3 matrix. */
  rule_ids?: string[];
};

/** Hard cap on matrix rows (matches the v4 §8 bundle file cap). Beyond it,
 * the matrix renders the first {@link PORTFOLIO_MATRIX_MAX_ROWS} rows and
 * notes how many documents were included — never silently truncating. */
export const PORTFOLIO_MATRIX_MAX_ROWS = 50;

type PortfolioCheckDef = {
  key: string;
  label: string;
  /** Plain-language column meaning, used for the rollup phrasing. */
  evaluate: (run: EngineRun) => PortfolioCellEval;
  /** Optional rollup: count the rows whose status is in `statuses`. */
  rollup?: { statuses: PortfolioStatus[]; phrase: string };
};

function logEntry(run: EngineRun, ruleId: string) {
  return run.execution_log.find((e) => e.rule_id === ruleId);
}
function ran(run: EngineRun, ruleId: string): boolean {
  return logEntry(run, ruleId) !== undefined;
}
function fired(run: EngineRun, ruleId: string): boolean {
  return logEntry(run, ruleId)?.fired === true;
}

/**
 * The curated, high-signal checks (spec-v6 §17). Each maps to rules that
 * already exist in the catalog. Rules that only run for a given family
 * (DPA, privacy) render `N/A` for documents that were not scanned as that
 * family, which is the honest answer.
 */
export const PORTFOLIO_CHECKS: ReadonlyArray<PortfolioCheckDef> = [
  {
    key: "liability_cap",
    label: "Liability cap",
    rollup: { statuses: ["risk"], phrase: "lack a capped liability clause" },
    evaluate: (run) => {
      if (fired(run, "RISK-009"))
        return { status: "risk", label: "Uncapped", rule_ids: ["RISK-009"] };
      if (fired(run, "RISK-005"))
        return { status: "risk", label: "No cap clause", rule_ids: ["RISK-005"] };
      if (ran(run, "RISK-005")) return { status: "ok", label: "Capped", rule_ids: ["RISK-005"] };
      return { status: "na", label: "N/A" };
    },
  },
  {
    key: "auto_renew",
    label: "Auto-renewal",
    rollup: { statuses: ["flag"], phrase: "auto-renew" },
    evaluate: (run) => {
      if (fired(run, "TEMP-004"))
        return { status: "flag", label: "Auto-renews", rule_ids: ["TEMP-004"] };
      if (ran(run, "TEMP-004"))
        return { status: "ok", label: "No auto-renew", rule_ids: ["TEMP-004"] };
      return { status: "na", label: "N/A" };
    },
  },
  {
    key: "governing_law",
    label: "Governing law",
    rollup: { statuses: ["risk"], phrase: "do not specify governing law" },
    evaluate: (run) => {
      if (fired(run, "CHOICE-001"))
        return { status: "risk", label: "Unspecified", rule_ids: ["CHOICE-001"] };
      if (ran(run, "CHOICE-001"))
        return { status: "ok", label: "Specified", rule_ids: ["CHOICE-001"] };
      return { status: "na", label: "N/A" };
    },
  },
  {
    key: "data_processing",
    label: "Data-processing terms",
    evaluate: (run) => {
      // Scanned as a DPA/GDPR document → data-processing terms are in scope.
      // We assert presence only when the DPA rule family actually ran.
      if (ran(run, "DPA-001")) return { status: "ok", label: "Present", rule_ids: ["DPA-001"] };
      return { status: "na", label: "N/A" };
    },
  },
  {
    key: "breach_notice",
    label: "Breach-notice clause",
    rollup: { statuses: ["risk"], phrase: "are missing a breach-notification clause" },
    evaluate: (run) => {
      if (fired(run, "DPA-024")) return { status: "risk", label: "Missing", rule_ids: ["DPA-024"] };
      if (ran(run, "DPA-024")) return { status: "ok", label: "Present", rule_ids: ["DPA-024"] };
      return { status: "na", label: "N/A" };
    },
  },
];

export type PortfolioRow = {
  doc_id: string;
  source_file_name: string;
  /** Parallel to {@link PORTFOLIO_CHECKS}. */
  cells: PortfolioCellEval[];
};

export type PortfolioRollup = {
  key: string;
  /** Full sentence, e.g. "12 of 40 documents lack a capped liability clause." */
  text: string;
  count: number;
  /** Names of the documents counted, sorted. */
  documents: string[];
};

export type PortfolioMatrix = {
  checks: { key: string; label: string }[];
  rows: PortfolioRow[];
  rollups: PortfolioRollup[];
  /** Rows rendered in the matrix. */
  included: number;
  /** Total documents in the bundle. */
  total: number;
  /** True when `total > PORTFOLIO_MATRIX_MAX_ROWS` and rows were capped. */
  truncated: boolean;
};

export type PortfolioInputDocument = {
  doc_id: string;
  source_file_name: string;
  run: EngineRun;
};

/**
 * Build the portfolio matrix from the per-document runs. Rows are sorted by
 * `source_file_name` then `doc_id` for a stable, canonical projection.
 */
export function buildPortfolioMatrix(
  documents: ReadonlyArray<PortfolioInputDocument>,
): PortfolioMatrix {
  const sorted = [...documents].sort(
    (a, b) =>
      a.source_file_name.localeCompare(b.source_file_name, "en") ||
      a.doc_id.localeCompare(b.doc_id, "en"),
  );
  const total = sorted.length;
  const truncated = total > PORTFOLIO_MATRIX_MAX_ROWS;
  const kept = truncated ? sorted.slice(0, PORTFOLIO_MATRIX_MAX_ROWS) : sorted;

  const rows: PortfolioRow[] = kept.map((d) => ({
    doc_id: d.doc_id,
    source_file_name: d.source_file_name,
    cells: PORTFOLIO_CHECKS.map((c) => c.evaluate(d.run)),
  }));

  const rollups: PortfolioRollup[] = [];
  PORTFOLIO_CHECKS.forEach((check, i) => {
    if (!check.rollup) return;
    const matched = rows.filter((r) => check.rollup!.statuses.includes(r.cells[i]!.status));
    rollups.push({
      key: check.key,
      text: `${matched.length} of ${rows.length} ${rows.length === 1 ? "document" : "documents"} ${check.rollup.phrase}.`,
      count: matched.length,
      documents: matched.map((r) => r.source_file_name).sort(),
    });
  });

  return {
    checks: PORTFOLIO_CHECKS.map((c) => ({ key: c.key, label: c.label })),
    rows,
    rollups,
    included: rows.length,
    total,
    truncated,
  };
}

export type PortfolioDocumentDigest = {
  doc_id: string;
  source_file_name: string;
  critical: number;
  warning: number;
  info: number;
  /** One-line headline: the worst severity present, with counts. */
  digest: string;
};

export type PortfolioExecutiveSummary = {
  documents: number;
  critical: number;
  warning: number;
  info: number;
  /** One-line bundle headline. */
  headline: string;
  per_document: PortfolioDocumentDigest[];
};

/**
 * Portfolio executive summary (spec-v7 §17): the rolled-up
 * critical/warning/info counts across the bundle plus a one-line digest
 * per document, so a deal folder opens with the headline, not the
 * detail. Pure aggregation over the per-document runs; lives outside
 * every `result_hash`. Documents are sorted canonically (file name,
 * then doc id) to match the matrix projection.
 */
export function buildPortfolioExecutiveSummary(
  documents: ReadonlyArray<PortfolioInputDocument>,
): PortfolioExecutiveSummary {
  const sorted = [...documents].sort(
    (a, b) =>
      a.source_file_name.localeCompare(b.source_file_name, "en") ||
      a.doc_id.localeCompare(b.doc_id, "en"),
  );
  const per_document = sorted.map((d): PortfolioDocumentDigest => {
    let critical = 0;
    let warning = 0;
    let info = 0;
    for (const f of d.run.findings) {
      if (f.severity === "critical") critical += 1;
      else if (f.severity === "warning") warning += 1;
      else info += 1;
    }
    return {
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      critical,
      warning,
      info,
      digest: digestLine(critical, warning, info),
    };
  });
  const critical = per_document.reduce((a, d) => a + d.critical, 0);
  const warning = per_document.reduce((a, d) => a + d.warning, 0);
  const info = per_document.reduce((a, d) => a + d.info, 0);
  const n = per_document.length;
  return {
    documents: n,
    critical,
    warning,
    info,
    headline: `${n} ${n === 1 ? "document" : "documents"} · ${critical} critical · ${warning} warning · ${info} info`,
    per_document,
  };
}

function digestLine(critical: number, warning: number, info: number): string {
  if (critical > 0)
    return `${critical} critical, ${warning} warning, ${info} info — review the critical findings first`;
  if (warning > 0) return `No critical findings; ${warning} warning, ${info} info`;
  if (info > 0) return `Clean of critical/warning findings; ${info} info`;
  return "No findings";
}

/**
 * Portfolio fingerprint (spec-v6 §17): extends the bundle fingerprint by
 * folding in the canonical matrix (statuses + labels + rollup counts, which
 * carry no wall-clock and no file names that vary across machines beyond the
 * inputs themselves). Same folder → same fingerprint.
 */
export async function portfolioFingerprint(
  bundleFingerprint: string,
  matrix: PortfolioMatrix,
): Promise<string> {
  const canonical = {
    checks: matrix.checks,
    rows: matrix.rows.map((r) => ({
      doc_id: r.doc_id,
      cells: r.cells.map((c) => ({ status: c.status, label: c.label })),
    })),
    rollups: matrix.rollups.map((r) => ({ key: r.key, count: r.count })),
    included: matrix.included,
    total: matrix.total,
    truncated: matrix.truncated,
  };
  return sha256Hex(bundleFingerprint + "\n" + stableStringify(canonical));
}

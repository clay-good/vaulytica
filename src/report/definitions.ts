/**
 * Definitions report (add-defined-terms-report): the dedicated
 * defined-terms surface — every defined term with its location, every
 * used-but-undefined term, unused terms, duplicates, and terms used
 * before they are defined — projected purely from facts the extraction
 * layer already computes (`extracted.definitions`). No engine change,
 * no new detection: this is the deliverable over existing data.
 *
 * Bucket discipline: every term lands in exactly ONE primary bucket,
 * risk-ordered — used-but-undefined first (the reader's biggest risk),
 * then duplicates, used-before-defined, unused, and cleanly defined.
 * Circular-definition chains are a secondary annotation (a term in a
 * cycle still has a primary bucket). The JSON model carries a
 * namespaced `definitions_hash` so the artifact is re-derivable and
 * tamper-evident like every other Vaulytica artifact.
 */

import type { DocPosition, ExtractedData } from "../extract/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";

export const DEFINITIONS_REPORT_SCHEMA = "vaulytica.definitions-report.v1";

export type DefinitionsReport = {
  schema: typeof DEFINITIONS_REPORT_SCHEMA;
  /** Used in the document but never defined — the top review risk. */
  undefined_used: Array<{ term: string; use_count: number; positions: DocPosition[] }>;
  /** Defined more than once; every definition location listed. */
  duplicates: Array<{ term: string; defined_at: DocPosition[] }>;
  /** Defined, but first used earlier in the document than the definition. */
  used_before_defined: Array<{ term: string; defined_at: DocPosition; first_use_at: DocPosition }>;
  /** Defined but never used outside the definition. */
  unused: Array<{ term: string; defined_at: DocPosition }>;
  /** Cleanly defined and used. */
  defined: Array<{ term: string; defined_at: DocPosition; use_count: number }>;
  /** Secondary annotation: definition cycles (each an ordered term list). */
  circular: string[][];
  counts: {
    undefined_used: number;
    duplicates: number;
    used_before_defined: number;
    unused: number;
    defined: number;
  };
  definitions_hash: string;
};

/**
 * Project the report from extraction facts. Pure and deterministic:
 * buckets and their members are sorted (risk order between buckets,
 * term order within), so the same extraction always yields the same
 * model and hash.
 */
export async function buildDefinitionsReport(
  extracted: Pick<ExtractedData, "definitions">,
): Promise<DefinitionsReport> {
  const defs = extracted.definitions;
  const byTerm = new Map<string, typeof defs.entries>();
  for (const e of defs.entries) {
    const list = byTerm.get(e.term) ?? [];
    list.push(e);
    byTerm.set(e.term, list);
  }
  const unusedSet = new Set(defs.unused_terms);

  const duplicates: DefinitionsReport["duplicates"] = [];
  const used_before_defined: DefinitionsReport["used_before_defined"] = [];
  const unused: DefinitionsReport["unused"] = [];
  const defined: DefinitionsReport["defined"] = [];

  for (const [term, entries] of byTerm) {
    if (entries.length > 1) {
      duplicates.push({ term, defined_at: entries.map((e) => e.defined_at) });
      continue;
    }
    const entry = entries[0]!;
    const earliestUse = entry.used_at.reduce<DocPosition | null>(
      (min, p) => (min === null || p.start < min.start ? p : min),
      null,
    );
    if (earliestUse && earliestUse.start < entry.defined_at.start) {
      used_before_defined.push({
        term,
        defined_at: entry.defined_at,
        first_use_at: earliestUse,
      });
      continue;
    }
    if (unusedSet.has(term) || entry.used_at.length === 0) {
      unused.push({ term, defined_at: entry.defined_at });
      continue;
    }
    defined.push({ term, defined_at: entry.defined_at, use_count: entry.used_at.length });
  }

  const undefined_used: DefinitionsReport["undefined_used"] = defs.undefined_capitalized.map(
    (u) => ({ term: u.term, use_count: u.positions.length, positions: u.positions }),
  );

  const byTermName = <T extends { term: string }>(arr: T[]): T[] =>
    [...arr].sort((a, b) => (a.term < b.term ? -1 : a.term > b.term ? 1 : 0));

  const body: Omit<DefinitionsReport, "definitions_hash"> = {
    schema: DEFINITIONS_REPORT_SCHEMA,
    undefined_used: byTermName(undefined_used),
    duplicates: byTermName(duplicates),
    used_before_defined: byTermName(used_before_defined),
    unused: byTermName(unused),
    defined: byTermName(defined),
    circular: defs.circular_terms ?? [],
    counts: {
      undefined_used: undefined_used.length,
      duplicates: duplicates.length,
      used_before_defined: used_before_defined.length,
      unused: unused.length,
      defined: defined.length,
    },
  };
  const definitions_hash = await sha256Hex(
    `${DEFINITIONS_REPORT_SCHEMA}\n${stableStringify(body)}`,
  );
  return { ...body, definitions_hash };
}

/** Re-derive and check the report's own hash. */
export async function verifyDefinitionsHash(report: DefinitionsReport): Promise<boolean> {
  const { definitions_hash, ...body } = report;
  return (
    (await sha256Hex(`${DEFINITIONS_REPORT_SCHEMA}\n${stableStringify(body)}`)) === definitions_hash
  );
}

// ---------------------------------------------------------------------------
// Renderers

const loc = (p: DocPosition): string => `§${p.section_id}`;

/** Risk-ordered CSV: bucket,term,detail,locations. */
export function buildDefinitionsCsv(report: DefinitionsReport): string {
  const esc = (s: string): string => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  const rows: string[] = ["bucket,term,detail,locations"];
  for (const u of report.undefined_used) {
    rows.push(
      [
        "undefined-but-used",
        esc(u.term),
        `${u.use_count} use(s), never defined`,
        esc(u.positions.map(loc).join("; ")),
      ].join(","),
    );
  }
  for (const d of report.duplicates) {
    rows.push(
      [
        "defined-more-than-once",
        esc(d.term),
        `${d.defined_at.length} definitions`,
        esc(d.defined_at.map(loc).join("; ")),
      ].join(","),
    );
  }
  for (const u of report.used_before_defined) {
    rows.push(
      [
        "used-before-defined",
        esc(u.term),
        `first use ${loc(u.first_use_at)} precedes definition ${loc(u.defined_at)}`,
        esc(`${loc(u.first_use_at)}; ${loc(u.defined_at)}`),
      ].join(","),
    );
  }
  for (const u of report.unused) {
    rows.push(["defined-but-unused", esc(u.term), "never used", esc(loc(u.defined_at))].join(","));
  }
  for (const d of report.defined) {
    rows.push(["defined", esc(d.term), `${d.use_count} use(s)`, esc(loc(d.defined_at))].join(","));
  }
  return rows.join("\n") + "\n";
}

/** Markdown section for the CLI summary / fix-list style consumers. */
export function buildDefinitionsMarkdown(report: DefinitionsReport): string {
  const lines: string[] = ["## Definitions report", ""];
  const c = report.counts;
  lines.push(
    `${c.defined} defined · ${c.undefined_used} used-but-undefined · ${c.unused} unused · ${c.duplicates} duplicate · ${c.used_before_defined} used-before-defined`,
  );
  lines.push("");
  if (report.undefined_used.length > 0) {
    lines.push("### Used but never defined");
    for (const u of report.undefined_used) {
      lines.push(`- **${u.term}** — ${u.use_count} use(s) at ${u.positions.map(loc).join(", ")}`);
    }
    lines.push("");
  }
  if (report.duplicates.length > 0) {
    lines.push("### Defined more than once");
    for (const d of report.duplicates) {
      lines.push(`- **${d.term}** — definitions at ${d.defined_at.map(loc).join(", ")}`);
    }
    lines.push("");
  }
  if (report.used_before_defined.length > 0) {
    lines.push("### Used before defined");
    for (const u of report.used_before_defined) {
      lines.push(
        `- **${u.term}** — first used at ${loc(u.first_use_at)}, defined at ${loc(u.defined_at)}`,
      );
    }
    lines.push("");
  }
  if (report.unused.length > 0) {
    lines.push("### Defined but never used");
    for (const u of report.unused) lines.push(`- **${u.term}** (${loc(u.defined_at)})`);
    lines.push("");
  }
  if (report.circular.length > 0) {
    lines.push("### Circular definitions");
    for (const cycle of report.circular) lines.push(`- ${cycle.join(" → ")}`);
    lines.push("");
  }
  lines.push(`definitions_hash: \`${report.definitions_hash}\``);
  return lines.join("\n") + "\n";
}

export function definitionsCsvBlob(report: DefinitionsReport): Blob {
  return new Blob([buildDefinitionsCsv(report)], { type: "text/csv" });
}

export function definitionsJsonBlob(report: DefinitionsReport): Blob {
  return new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
}

// ---------------------------------------------------------------------------
// Bundle mode

import type { ConsistencyDocument } from "../engine/consistency/types.js";
import { findDefinedTermMismatches } from "../engine/consistency/rules/v4/_helpers.js";

export const BUNDLE_DEFINITIONS_SCHEMA = "vaulytica.definitions-report.bundle.v1";

export type BundleDefinitionsReport = {
  schema: typeof BUNDLE_DEFINITIONS_SCHEMA;
  documents: Array<{ document: string; report: DefinitionsReport }>;
  /**
   * Terms defined with materially different definitions across documents —
   * the exact comparison CROSS-DEFTERM-001 runs (`findDefinedTermMismatches`,
   * reused unchanged), so this surface can never disagree with the
   * cross-document consistency findings.
   */
  cross_document_redefinitions: Array<{
    term: string;
    a: { document: string; definition: string };
    b: { document: string; definition: string };
  }>;
  definitions_hash: string;
};

/** Bundle projection: per-document reports + cross-document redefinitions. */
export async function buildBundleDefinitionsReport(
  docs: ReadonlyArray<
    Pick<ConsistencyDocument, "doc_id" | "extracted" | "tree" | "source_file_name" | "playbook_id">
  >,
): Promise<BundleDefinitionsReport> {
  const documents: BundleDefinitionsReport["documents"] = [];
  for (const d of docs) {
    documents.push({
      document: d.source_file_name,
      report: await buildDefinitionsReport(d.extracted),
    });
  }
  const cross: BundleDefinitionsReport["cross_document_redefinitions"] = [];
  for (let i = 0; i < docs.length; i++) {
    for (let j = i + 1; j < docs.length; j++) {
      const a = docs[i]! as ConsistencyDocument;
      const b = docs[j]! as ConsistencyDocument;
      for (const m of findDefinedTermMismatches(a, b)) {
        cross.push({
          term: m.term,
          a: { document: a.source_file_name, definition: m.a.definition },
          b: { document: b.source_file_name, definition: m.b.definition },
        });
      }
    }
  }
  cross.sort((x, y) => (x.term < y.term ? -1 : x.term > y.term ? 1 : 0));
  const body: Omit<BundleDefinitionsReport, "definitions_hash"> = {
    schema: BUNDLE_DEFINITIONS_SCHEMA,
    documents,
    cross_document_redefinitions: cross,
  };
  const definitions_hash = await sha256Hex(
    `${BUNDLE_DEFINITIONS_SCHEMA}\n${stableStringify(body)}`,
  );
  return { ...body, definitions_hash };
}

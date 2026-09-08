/**
 * The `*Blob` wrappers — the functions the BROWSER actually calls.
 *
 * Every builder in `exports.ts` is well tested. None of these ten one-line
 * wrappers around them was, and they are the product path: the tab downloads
 * files, so it calls `deadlinesIcsBlob`, never `buildDeadlinesIcs`. Mutation
 * testing reported the lot as **NoCoverage** — a whole layer between the tested
 * logic and the user, executed by nobody.
 *
 * Two properties, and the second is the one a user feels:
 *
 *   1. The bytes are the builder's bytes — no wrapper quietly transforms,
 *      truncates or reorders on the way out.
 *   2. The **MIME type is right**. It is not decoration: a `.ics` served as
 *      `text/csv` opens in a spreadsheet instead of a calendar, and a reader
 *      who gets a wall of `BEGIN:VEVENT` in Excel concludes the export is
 *      broken. Each type here is asserted by name so a copy-paste between two
 *      adjacent wrappers cannot go unnoticed — which is exactly the mistake
 *      this file's shape invites.
 */

import { describe, expect, it } from "vitest";

import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
  buildCriticalDatesMarkdown,
  buildCriticalDatesIcs,
  buildClosingChecklistMarkdown,
  buildClosingChecklistCsv,
  buildNegotiationPostureMarkdown,
  buildNegotiationPostureCsv,
  fixListMarkdownBlob,
  fixListCsvBlob,
  obligationsCsvBlob,
  deadlinesIcsBlob,
  criticalDatesMarkdownBlob,
  criticalDatesIcsBlob,
  closingChecklistMarkdownBlob,
  closingChecklistCsvBlob,
  negotiationPostureMarkdownBlob,
  negotiationPostureCsvBlob,
} from "./exports.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { ExtractedData } from "../extract/types.js";
import type { CriticalDatesRegister } from "./critical-dates.js";
import type { ClosingChecklist } from "./closing-checklist.js";
import type { NegotiationPosture } from "../playbooks/custom-interpreter.js";

const finding: Finding = {
  id: "CAP-1-s1-0",
  rule_id: "CAP-1",
  rule_version: "1.0.0",
  severity: "critical",
  title: "Uncapped liability",
  description: "No cap on liability.",
  explanation: "An uncapped indemnity is unbounded exposure.",
  recommendation: "Add a cap.",
  excerpt: { text: "liability is unlimited", section_id: "s1", start_offset: 0, end_offset: 22 },
  source_citations: [],
  document_position: 0,
};

const run = {
  version: "9.9.9",
  dkb_version: "v0.0.1-starter",
  playbook_id: "msa-general",
  source_file: { name: "msa.docx", sha256: "a".repeat(64), size_bytes: 1 },
  executed_at: "",
  findings: [finding],
  execution_log: [],
  result_hash: "c".repeat(64),
} as unknown as EngineRun;

const extracted = {
  parties: [],
  dates: [],
  amounts: [],
  jurisdictions: [],
  definitions: { entries: [] },
  crossrefs: [],
  sections: [],
  classified: [],
  obligations: [
    {
      obligor: "The Supplier",
      modal: "shall",
      action: "deliver the goods",
      trigger: "within 30 days",
      qualifier: "",
      raw_text: "The Supplier shall deliver the goods within 30 days.",
      position: { section_id: "s1", start: 0, end: 50 },
    },
  ],
} as unknown as ExtractedData;

const register: CriticalDatesRegister = {
  register: [],
  critical_dates_hash: "d".repeat(64),
} as unknown as CriticalDatesRegister;

const checklist: ClosingChecklist = { items: [] } as unknown as ClosingChecklist;
const posture: NegotiationPosture = {
  positions: [],
  counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
  posture_hash: "e".repeat(64),
};

/** wrapper → [its builder's output, the MIME type it must carry]. */
const CASES: ReadonlyArray<[string, Blob, string, string]> = [
  ["fixListMarkdownBlob", fixListMarkdownBlob(run), buildFixListMarkdown(run), "text/markdown"],
  ["fixListCsvBlob", fixListCsvBlob(run), buildFixListCsv(run), "text/csv"],
  ["obligationsCsvBlob", obligationsCsvBlob(extracted), buildObligationsCsv(extracted), "text/csv"],
  ["deadlinesIcsBlob", deadlinesIcsBlob(extracted), buildDeadlinesIcs(extracted), "text/calendar"],
  [
    "criticalDatesMarkdownBlob",
    criticalDatesMarkdownBlob(register),
    buildCriticalDatesMarkdown(register),
    "text/markdown",
  ],
  [
    "criticalDatesIcsBlob",
    criticalDatesIcsBlob(register),
    buildCriticalDatesIcs(register),
    "text/calendar",
  ],
  [
    "closingChecklistMarkdownBlob",
    closingChecklistMarkdownBlob(checklist),
    buildClosingChecklistMarkdown(checklist),
    "text/markdown",
  ],
  [
    "closingChecklistCsvBlob",
    closingChecklistCsvBlob(checklist),
    buildClosingChecklistCsv(checklist),
    "text/csv",
  ],
  [
    "negotiationPostureMarkdownBlob",
    negotiationPostureMarkdownBlob(posture),
    buildNegotiationPostureMarkdown(posture),
    "text/markdown",
  ],
  [
    "negotiationPostureCsvBlob",
    negotiationPostureCsvBlob(posture),
    buildNegotiationPostureCsv(posture),
    "text/csv",
  ],
];

describe("the export Blob wrappers the browser calls", () => {
  it("covers every wrapper the module exports (guards the list itself)", async () => {
    // A list that silently falls behind the module is the same defect one layer
    // up: a new wrapper would be untested and nothing would say so.
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    // `import.meta.url` is not a file: URL under this runner, so resolve from
    // the repo root instead of from the module.
    const src = readFileSync(join(process.cwd(), "src", "report", "exports.ts"), "utf8");
    const declared = [...src.matchAll(/^export function (\w+Blob)\(/gm)].map((m) => m[1]!);
    expect(declared.length).toBeGreaterThan(8);
    expect(CASES.map(([name]) => name).sort()).toEqual(declared.slice().sort());
  });

  for (const [name, blob, expected, mime] of CASES) {
    it(`${name} carries the builder's bytes as ${mime}`, async () => {
      expect(await blob.text()).toBe(expected);
      // A .ics served as text/csv opens in a spreadsheet, not a calendar.
      expect(blob.type, `${name} has the wrong MIME type`).toBe(mime);
    });
  }
});

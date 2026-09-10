/**
 * Render every artifact for the clean documents and READ it.
 *
 * This file is the automated form of the method that produced 9.651–9.663.
 * Almost every defect in that run was invisible to the finding set and to
 * every golden: the ladder's dead metrics, `at-will` read as an obligation
 * modal, a fifth of the deadlines calendar being duplicate events, a register
 * that rendered 20 duplicates as a checklist and 0 as a calendar, and a
 * cover page that said the analysis ran on **1 January 1970**. Each was found
 * by building the artifact a user actually receives and looking at it.
 *
 * What a machine can check is narrower than what a person reading it can, and
 * the checks here are deliberately the mechanical ones — the shapes that are
 * never right, whoever is reading:
 *
 *  - a value that leaked as `undefined` / `null` / `NaN` / `[object Object]`;
 *  - a blanked timestamp printed as the Unix epoch;
 *  - an unfilled template placeholder;
 *  - two identical rows in a table a person works down.
 *
 * The specimens are the `*-complete.txt` clean documents, because a defect
 * that shows up on a COMPLETE, well-drafted contract is unambiguous — there is
 * no "the document really is like that" explanation available.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { analyzeText } from "../../tools/cli/api.js";
import { buildCriticalDates } from "../../src/report/critical-dates.js";
import { buildClosingChecklist } from "../../src/report/closing-checklist.js";
import { buildDefinitionsReport, buildDefinitionsCsv } from "../../src/report/definitions.js";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
  buildCriticalDatesMarkdown,
  buildCriticalDatesIcs,
  buildClosingChecklistMarkdown,
  buildClosingChecklistCsv,
} from "../../src/report/exports.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const CLEAN = readdirSync(DIR)
  .filter((f) => f.endsWith("-complete.txt"))
  .sort();

/**
 * Shapes that are never right in rendered prose.
 *
 * ⚠️ The words matter, and the first draft of this list got it wrong twice
 * over. `\bnull\b` is deliberately absent — "null and void" is ordinary
 * contract English, quoted verbatim by these artifacts. And `undefined` is
 * matched only in a VALUE POSITION (a whole CSV cell, or the right-hand side
 * of a `label: value`), because OBLI-008's finding title is *"Efforts standard
 * \"commercially reasonable efforts\" undefined"* — the English word, on six
 * of the fourteen clean documents. A leaked JavaScript `undefined` stands
 * alone where a value should be; the adjective never does.
 */
const LEAKED = [
  { name: "an undefined value", re: /(?:^|[,|])\s*undefined\s*(?:$|[,|])|(?::|=)\s*undefined\s*$/ },
  { name: "NaN", re: /\bNaN\b/ },
  { name: "a stringified object", re: /\[object [A-Z]/ },
  { name: "the Unix epoch", re: /\b1970-01-01\b|\b1 Jan 1970\b|Thu, 01 Jan 1970/ },
  { name: "an unfilled template placeholder", re: /\{\{|\$\{|<%=/ },
];

/** Rows of a delimited artifact, minus its header and blank lines. */
function bodyRows(text: string, sep: string): string[] {
  return text
    .split(sep)
    .slice(1)
    .filter((l) => l.trim() !== "");
}

describe("every artifact a user receives, over the clean documents", () => {
  it("leaks no placeholder, no stringified object and no epoch", async () => {
    expect(CLEAN.length).toBeGreaterThanOrEqual(14);
    const leaks: string[] = [];
    let rendered = 0;

    for (const file of CLEAN) {
      const text = readFileSync(join(DIR, file), "utf8");
      const ingest = await ingestPaste(text);
      const extracted = extractAll(ingest.tree);
      const r = await analyzeText(text, file);
      const register = await buildCriticalDates(extracted, ingest.tree);
      const checklist = buildClosingChecklist(r.run);
      const definitions = await buildDefinitionsReport(extracted);

      const artifacts: ReadonlyArray<[string, string]> = [
        ["fix list (md)", buildFixListMarkdown(r.run, extracted)],
        ["fix list (csv)", buildFixListCsv(r.run)],
        ["obligations (csv)", buildObligationsCsv(extracted)],
        ["definitions (csv)", buildDefinitionsCsv(definitions)],
        ["deadlines (ics)", buildDeadlinesIcs(extracted)],
        ["critical dates (md)", buildCriticalDatesMarkdown(register)],
        ["critical dates (ics)", buildCriticalDatesIcs(register)],
        ["closing checklist (md)", buildClosingChecklistMarkdown(checklist)],
        ["closing checklist (csv)", buildClosingChecklistCsv(checklist)],
      ];

      for (const [what, body] of artifacts) {
        rendered += 1;
        for (const line of body.split(/\r?\n/)) {
          for (const leak of LEAKED) {
            if (leak.re.test(line)) {
              leaks.push(`${file} / ${what}: ${leak.name} — ${line.trim().slice(0, 90)}`);
            }
          }
        }
      }
    }

    // Anti-vacuity: a loop that rendered nothing passes trivially.
    expect(rendered).toBe(CLEAN.length * 9);
    expect(leaks.sort()).toEqual([]);
  }, 300_000);

  it("gives a reader no row twice in a table they work down", async () => {
    const dupes: string[] = [];
    let rows = 0;

    for (const file of CLEAN) {
      const text = readFileSync(join(DIR, file), "utf8");
      const ingest = await ingestPaste(text);
      const extracted = extractAll(ingest.tree);
      const r = await analyzeText(text, file);
      const register = await buildCriticalDates(extracted, ingest.tree);
      const checklist = buildClosingChecklist(r.run);

      const tables: ReadonlyArray<[string, string[]]> = [
        ["fix list (csv)", bodyRows(buildFixListCsv(r.run), "\r\n")],
        ["closing checklist (csv)", bodyRows(buildClosingChecklistCsv(checklist), "\r\n")],
        // The register's Markdown is a CHECKLIST: two identical lines are two
        // identical checkboxes for one thing to verify.
        [
          "critical dates (md)",
          buildCriticalDatesMarkdown(register)
            .split("\n")
            .filter((l) => l.startsWith("- [ ] ")),
        ],
        // A calendar event's identity is everything but its UID.
        [
          "deadlines (ics)",
          [...buildDeadlinesIcs(extracted).matchAll(/BEGIN:VEVENT\r\n([\s\S]*?)END:VEVENT/g)].map(
            (m) => m[1]!.replace(/^UID:.*\r\n/m, ""),
          ),
        ],
        [
          "critical dates (ics)",
          [
            ...buildCriticalDatesIcs(register).matchAll(/BEGIN:VEVENT\r\n([\s\S]*?)END:VEVENT/g),
          ].map((m) => m[1]!.replace(/^UID:.*\r\n/m, "")),
        ],
      ];

      for (const [what, list] of tables) {
        rows += list.length;
        const seen = new Map<string, number>();
        for (const row of list) seen.set(row, (seen.get(row) ?? 0) + 1);
        for (const [row, n] of seen) {
          if (n > 1) dupes.push(`${file} / ${what}: ×${n} — ${row.trim().slice(0, 90)}`);
        }
      }
    }

    expect(rows).toBeGreaterThan(200);
    expect(dupes.sort()).toEqual([]);
  }, 300_000);
});

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildClosingChecklist } from "./closing-checklist.js";
import { buildClosingChecklistMarkdown, buildClosingChecklistCsv } from "./exports.js";
import type { EngineRun, Finding } from "../engine/finding.js";

/**
 * The closing checklist is the artifact a reader ticks off before closing, and
 * an item it cannot tick is not an item.
 *
 * `labelFor` used to carry the comment "the finding titles are already
 * one-line and checkable". That is false for every RECONCILIATION rule in the
 * readiness set — the title is a COUNT ("Referenced attachments not present:
 * 3") and the names are in the finding's `description`, which reached no
 * checklist surface. Over the 327-specimen corpus the checklists hold 109
 * items across 107 documents, and 107 of those items are a bare count.
 *
 * Two halves:
 *
 *  - the behavioural half asserts the names survive into the two artifacts a
 *    script can obtain (`--format checklist-md` / `checklist-csv`);
 *  - the static half is the REACH list. A checklist item is rendered on five
 *    surfaces, and a fix written for whichever one its author happened to open
 *    is how a field ends up on one surface and not the others. **A new surface
 *    that renders a checklist item must join `DETAIL_SURFACES`.**
 */

function finding(rule_id: string, title: string, description: string, section = "s1"): Finding {
  return {
    id: `${rule_id}-${section}-0`,
    rule_id,
    rule_version: "1.0.0",
    severity: "warning",
    title,
    description,
    excerpt: { text: "x", section_id: section, start_offset: 0, end_offset: 1 },
    explanation: "",
    source_citations: [],
    document_position: 0,
  };
}

function run(findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0",
    playbook_id: "p",
    source_file: { name: "x.docx", sha256: "0".repeat(64), size_bytes: 1 },
    executed_at: "",
    findings,
    execution_log: [],
    result_hash: "",
  };
}

/** The real shape STRUCT-018 emits: a count in the title, the names below. */
const ATTACHMENTS = finding(
  "STRUCT-018",
  "Referenced attachments not present: 3",
  "Exhibit A, Exhibit B, Schedule 2.1 are referenced but not attached to the document.",
);

describe("a closing-checklist item names what it counted", () => {
  it("carries the finding's names as the item detail", () => {
    const cl = buildClosingChecklist(run([ATTACHMENTS]));
    expect(cl.items).toHaveLength(1);
    expect(cl.items[0]!.detail).toContain("Exhibit A");
    expect(cl.items[0]!.detail).toContain("Schedule 2.1");
  });

  it("suppresses a detail that would only restate the label", () => {
    const cl = buildClosingChecklist(
      run([finding("STRUCT-003", "No signature block detected", "No signature block detected.")]),
    );
    expect(cl.items[0]!.detail).toBeUndefined();
  });

  it("names them in the Markdown checklist", () => {
    const md = buildClosingChecklistMarkdown(buildClosingChecklist(run([ATTACHMENTS])));
    expect(md).toContain("Referenced attachments not present: 3");
    expect(md).toContain("Exhibit A, Exhibit B, Schedule 2.1");
  });

  it("gives the CSV its own detail column", () => {
    const csv = buildClosingChecklistCsv(buildClosingChecklist(run([ATTACHMENTS])));
    const [header, row] = csv.split("\r\n") as [string, string];
    expect(header).toBe("category,rule_id,item,detail,section");
    expect(row).toContain("Exhibit A");
  });

  it("keeps a handoff item's label self-describing, with no detail", () => {
    const cl = buildClosingChecklist(run([]), [
      { rule_id: "HANDOFF-002", title: "Comments present", count: 4 },
    ]);
    expect(cl.items[0]!.label).toMatch(/4 comments/);
    expect(cl.items[0]!.detail).toBeUndefined();
  });
});

/**
 * Every module that renders a checklist item, and the function in it that
 * does. A surface added here without reading `detail` prints a bare count.
 */
const DETAIL_SURFACES: ReadonlyArray<{ file: string; fn: string }> = [
  { file: "../report/exports.ts", fn: "buildClosingChecklistMarkdown" },
  { file: "../report/exports.ts", fn: "buildClosingChecklistCsv" },
  { file: "../report/html.ts", fn: "renderClosingChecklistSection" },
  { file: "../report/docx.ts", fn: "renderClosingChecklistSection" },
  { file: "../ui/states.ts", fn: "renderClosingChecklist" },
];

/** The body of `function <name>(` up to the next top-level `}`. */
function functionBody(source: string, name: string): string {
  const start = source.indexOf(`function ${name}(`);
  expect(start, `${name} not found`).toBeGreaterThan(-1);
  const end = source.indexOf("\n}\n", start);
  return source.slice(start, end === -1 ? source.length : end);
}

describe("every checklist surface renders the detail", () => {
  for (const { file, fn } of DETAIL_SURFACES) {
    it(`${file} → ${fn}`, () => {
      const source = readFileSync(fileURLToPath(new URL(file, import.meta.url)), "utf8");
      // A MEMBER ACCESS, not the bare word: the first form of this assertion
      // matched `/\bdetail\b/` and stayed green through `const detail = ""`,
      // which is the local variable the deletion leaves behind.
      expect(functionBody(source, fn)).toMatch(/\w\.detail\b/);
    });
  }

  it("carries the item through the UI's own re-mapping", () => {
    // `main.ts` rebuilds each item field by field before handing it to the
    // renderer, which is exactly where a new field is silently dropped.
    // Indirected through a variable: Vite statically rewrites a literal
    // `new URL("…", import.meta.url)` into an asset URL, which is not a file.
    const main = "../ui/main.ts";
    const source = readFileSync(fileURLToPath(new URL(main, import.meta.url)), "utf8");
    const block = source.slice(source.indexOf("closing_checklist: result.closing_checklist"));
    expect(block.slice(0, 400)).toMatch(/detail: i\.detail/);
  });
});

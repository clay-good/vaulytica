/**
 * The emailable report and the Word report must not disagree about CONTENT.
 *
 * `src/report/html.ts` keeps a written list of what the DOCX has and it
 * deliberately does not, and the list was doing real work — it is how the
 * secondary-family findings and the cross-document appendix were both caught
 * missing. But two entries did not belong on it:
 *
 *   - **Jurisdiction overlays.** A California non-compete's Bus. & Prof. Code
 *     § 16600 entry is the single most consequential thing this tool can say
 *     about that document, and `uncovered_states` is an honest coverage gap
 *     that must not read as a clean pass.
 *   - **The obligations ledger.** Who owes what, by when.
 *
 * Both were filed under "the paginated report's navigation and reference
 * apparatus", next to the findings index and the audit trail. They are not
 * apparatus. Filing content there is how a deliberate-omissions list stops
 * being a decision and becomes a place things go.
 *
 * This test asserts the content, on a real document, in both surfaces — not
 * the comment.
 */

import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { extractAll } from "../../src/extract/index.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildDocxReport } from "../../src/report/docx.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

/** A California employment agreement — the family with a real overlay catalog. */
const SPECIMEN = join(
  process.cwd(),
  "tests",
  "fixtures",
  "specimens",
  "il-employment-noncompete.txt",
);

describe("the HTML report carries the same CONTENT as the DOCX", () => {
  it("renders the jurisdiction overlays and the obligations ledger", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const extracted = extractAll(r.ingest.tree);
    const html = buildHtmlReport(
      r.run,
      r.ingest,
      deps.dkb,
      r.playbook,
      undefined,
      undefined,
      undefined,
      undefined,
      extracted,
    );
    const docxXml = strFromU8(
      unzipSync(
        new Uint8Array(
          await (
            await buildDocxReport(r.run, r.ingest, deps.dkb, r.playbook, undefined, extracted)
          ).arrayBuffer(),
        ),
      )["word/document.xml"]!,
    );

    // Guard the fixture: if this specimen ever stops producing overlays or
    // obligations, the assertions below would pass vacuously.
    expect(docxXml).toContain("Jurisdiction Overlays");
    expect(docxXml).toContain("Obligations Ledger");
    expect(extracted.obligations.length).toBeGreaterThan(0);

    expect(html).toContain("Jurisdiction overlays");
    expect(html).toContain("Obligations ledger");
    // The coverage gap has to say it is a gap, in both.
    if (html.includes("No overlay on file for")) {
      expect(html).toContain("honest coverage gap — not a clean pass");
    }
  }, 180_000);

  it("leads every finding with its PROOF, in both of the two honest shapes", async () => {
    // The DOCX has led every finding with "Evidence — <locator>" + the quoted
    // clause (or "Basis — ... this finding is about what is absent") since the
    // report was made to lead with evidence. This file rendered NEITHER: a
    // reader of the emailable report could not check a single finding against
    // the document, and could not tell a finding about text from a finding
    // about an absence. Worse since 9.578.0 — the same page now prints "N of M
    // findings quote the exact clause text they fired on" while showing none.
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);

    const withSpan = r.run.findings.filter((f) => f.excerpt.end_offset > f.excerpt.start_offset);
    const absences = r.run.findings.filter((f) => f.excerpt.end_offset <= f.excerpt.start_offset);
    // Guard the fixture: this specimen must exercise BOTH shapes or the test
    // proves half of what it claims.
    expect(withSpan.length, "findings with a quoted span").toBeGreaterThan(0);
    expect(absences.length, "findings about an absence").toBeGreaterThan(0);

    expect(html).toContain("<strong>Evidence</strong> — ");
    expect(html).toContain("this finding is about what is absent");
    // Never the shape the DOCX comment calls "the worst line in it": a marker
    // string presented as a quotation at a zero-width range.
    expect(html).not.toContain("characters 0–0");
    // And the actual clause text, not just the label.
    const quoted = withSpan[0]!.excerpt.text.trim().slice(0, 40);
    expect(html).toContain(quoted.replace(/&/g, "&amp;").replace(/</g, "&lt;"));
  }, 180_000);

  it("carries the public model clause — what good looks like — beside the finding", async () => {
    // In the DOCX and the JSON since spec-v6 Part IV, and absent here. It was
    // not on the deliberate-omissions list either, so it was a silent omission
    // rather than a decision.
    const { modelClauseForRule } = await import("../../src/dkb/model-clauses.js");
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const withClause = r.run.findings.filter((f) => modelClauseForRule(f.rule_id));
    expect(withClause.length, "findings whose rule has a model clause").toBeGreaterThan(0);
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);
    expect(html).toContain("Reference model clause");
    expect(html).toContain("Reference only — Vaulytica does not draft.");
    expect(html).toContain(modelClauseForRule(withClause[0]!.rule_id)!.title);
  }, 180_000);

  it("states what is wrong, not only the reasoning for it", async () => {
    // The DOCX renders `description` AND `explanation`. This file rendered only
    // the second, so every finding opened with the reasoning for a claim the
    // reader had not been given.
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);
    const withBoth = r.run.findings.filter(
      (f) => f.description && f.explanation && f.description !== f.explanation,
    );
    expect(withBoth.length, "findings carrying both fields").toBeGreaterThan(0);
    const f = withBoth[0]!;
    const esc = (t: string): string => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    expect(html).toContain(esc(f.description.slice(0, 60)));
    expect(html).toContain(esc(f.explanation.slice(0, 60)));
  }, 180_000);

  it("says when a finding came from YOUR playbook, not Vaulytica's catalog", () => {
    // The DOCX has carried this since custom playbooks shipped; the HTML
    // rendered the rule id alone, so a finding from a user-supplied standard
    // was presented exactly like one from the catalog.
    const base = {
      id: "f1",
      rule_id: "CUSTOM-1",
      rule_version: "1.0.0",
      severity: "warning" as const,
      title: "t",
      description: "d",
      explanation: "e",
      source_citations: [],
      excerpt: { text: "", start_offset: 0, end_offset: 0 },
      document_position: 0,
    };
    const run = {
      findings: [{ ...base, source: "custom-playbook" }],
      execution_log: [],
      version: "9.9.9",
      dkb_version: "v0.0.1-starter",
      playbook_id: "p",
      source_file: { name: "x.docx", sha256: "a".repeat(64), size_bytes: 1 },
      executed_at: "",
      result_hash: "c".repeat(64),
    } as never;
    const ingest = {
      source: "docx",
      word_count: 1,
      page_count: 1,
      language: "en",
      sha256: "a".repeat(64),
      warnings: [],
      tree: { sections: [] },
    } as never;
    const dkb = loadStarterDkbSync();
    expect(buildHtmlReport(run, ingest, dkb)).toContain("your playbook");
    // Anti-vacuity: a catalog finding must NOT say it.
    const catalogRun = { ...(run as object), findings: [base] } as never;
    expect(buildHtmlReport(catalogRun, ingest, dkb)).not.toContain("your playbook");
  });

  /**
   * The structural version of the four omissions above.
   *
   * Each of them — the proof, the model clause, `description`, the "your
   * playbook" marker — was found by reading the DOCX's finding renderer beside
   * this one, field by field, and each took its own release. The next one will
   * not be found that way unless someone happens to do the same read.
   *
   * So: for a real document, every non-empty TEXT field the engine puts on a
   * finding has to appear in the HTML. Not a comment, not a list — the content
   * itself, checked against the run that produced it.
   */
  it("carries every text field the engine put on every finding", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);
    // The report's own escaper, not an approximation of it: an approximation
    // reports a MISSING FIELD when the difference is a quote mark, which is a
    // false accusation against the renderer and exactly the kind of probe error
    // this repo keeps finding.
    const esc = (t: string): string =>
      t
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

    expect(r.run.findings.length, "the specimen must produce findings").toBeGreaterThan(3);
    const missing: string[] = [];
    for (const f of r.run.findings) {
      for (const [field, value] of [
        ["title", f.title],
        ["description", f.description],
        ["explanation", f.explanation],
        ["recommendation", f.recommendation ?? ""],
        // The excerpt is truncated at 900 chars in the render, so compare a
        // prefix — the point is that the document's own words are present at
        // all, which is what "checkable" means.
        //
        // 🚨 Only for findings that HAVE a span. A finding about an absence
        // carries the rule's own marker string in `excerpt.text`, and printing
        // that under an evidence label is the failure the DOCX's comment calls
        // "the worst line in it" — words the contract never contained,
        // presented as a quotation. RISK-001 and TERM-005 on this specimen are
        // exactly that shape, and the first draft of this test accused the
        // renderer of dropping them.
        [
          "excerpt",
          f.excerpt.end_offset > f.excerpt.start_offset ? f.excerpt.text.trim().slice(0, 80) : "",
        ],
      ] as const) {
        if (!value || value.trim().length === 0) continue;
        if (html.includes(esc(value.slice(0, 80)))) continue;
        missing.push(`${f.rule_id}.${field}`);
      }
      if (!html.includes(f.rule_id)) missing.push(`${f.rule_id}.rule_id`);
    }
    expect(
      [...new Set(missing)],
      `the HTML report drops these finding fields:\n  ${[...new Set(missing)].join("\n  ")}`,
    ).toEqual([]);
  }, 180_000);

  it("renders neither section when there is nothing to render", async () => {
    // Anti-vacuity: without `extracted` the two sections are absent, exactly as
    // they are absent from a DOCX built without it. A report that invents an
    // empty "Jurisdiction overlays" heading tells a reader there was nothing to
    // say, which is a different claim from not having looked.
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);
    expect(html).not.toContain("Jurisdiction overlays");
    expect(html).not.toContain("Obligations ledger");
  }, 180_000);
});

import { describe, expect, it } from "vitest";
import type { Finding } from "../engine/finding.js";
import type { DocumentAbstract } from "../report/abstract.js";
import { LOOP_CLEAN_STATEMENT } from "../report/disclaimers.js";
import {
  buildResultsModel,
  copyText,
  keyTermsOf,
  renderResults,
  resultsPageHtml,
  rowsHtml,
} from "./results-page.js";
import { wireResultsPage } from "./results-wire.js";
import { renderState, select } from "./states.js";

function finding(over: Partial<Finding> & Pick<Finding, "rule_id" | "severity">): Finding {
  return {
    id: over.rule_id,
    rule_version: "1.0.0",
    title: `${over.rule_id} title`,
    description: "",
    excerpt: { text: "(clause absent from the document)", start_offset: 0, end_offset: 0 },
    explanation: "Because it matters.",
    source_citations: [],
    document_position: 0,
    ...over,
  };
}

const ABSTRACT: DocumentAbstract = {
  file: "nda.txt",
  document_type: "mutual-nda-deep",
  document_type_label: "Mutual NDA — Deep Analysis",
  title: "",
  parties: [
    { name: "Northgate Instrument Company", role: "Northgate", formation: "Ohio" },
    { name: "Meridian Growth Partners III", section: "§ 1.1" },
    { name: "Priya Raghunathan", section: "§ 13" },
  ],
  governing_law: { value: "Delaware", section: "§ 12" },
  word_count: 900,
  result_hash: "h",
};

const signers = (name: string) => name === "Priya Raghunathan";
const noLink = () => null;

describe("buildResultsModel", () => {
  it("lists exactly the actionable findings, in report order, plus critical and warning delivery items", () => {
    const findings = [
      finding({ rule_id: "A-1", severity: "critical", recommendation: "Add a cap." }),
      finding({ rule_id: "A-2", severity: "warning" }),
      finding({ rule_id: "A-3", severity: "info", recommendation: "Optional fix." }),
    ];
    const model = buildResultsModel({
      run: { findings },
      abstract: ABSTRACT,
      delivery: [
        {
          rule_id: "HANDOFF-001",
          severity: "critical",
          title: "Tracked changes",
          description: "d",
          evidence: ["3 insertions"],
        },
        {
          rule_id: "HANDOFF-004",
          severity: "info",
          title: "Author name",
          description: "d",
          evidence: [],
        },
      ],
      isSigner: signers,
      reportUrl: noLink,
    });
    expect(model.todo_rows.map((r) => r.rule_id)).toEqual(["A-1", "A-3"]);
    expect(model.delivery_rows.map((r) => r.rule_id)).toEqual(["HANDOFF-001"]);
    expect(model.observations.map((r) => r.rule_id)).toEqual(["A-2", "HANDOFF-004"]);
    expect(model.headline).toBe("3 things to raise before you sign");
    expect(model.clean_statement).toBeUndefined();
  });

  it("says one thing, and with nothing to raise carries the clean-result statement", () => {
    const one = buildResultsModel({
      run: { findings: [finding({ rule_id: "A-1", severity: "warning", recommendation: "x" })] },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: noLink,
    });
    expect(one.headline).toBe("1 thing to raise before you sign");
    const none = buildResultsModel({
      run: { findings: [finding({ rule_id: "A-2", severity: "info" })] },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: noLink,
    });
    expect(none.headline).toBe("Nothing to raise");
    expect(none.clean_statement).toBe(LOOP_CLEAN_STATEMENT);
    expect(none.headline + none.clean_statement).not.toMatch(/\b(clean|safe|compliant)\b/i);
  });

  it("quotes only a pinned span; a placeholder is never a quote", () => {
    const model = buildResultsModel({
      run: {
        findings: [
          finding({
            rule_id: "Q-1",
            severity: "warning",
            recommendation: "x",
            excerpt: {
              text: "Seller may assign",
              section_label: "§ 9",
              start_offset: 10,
              end_offset: 27,
            },
          }),
          finding({ rule_id: "Q-2", severity: "warning", recommendation: "y" }),
        ],
      },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: noLink,
    });
    const [quoted, absent] = model.todo_rows;
    expect(quoted).toMatchObject({ quote: "Seller may assign", section: "§ 9" });
    expect(quoted!.absent).toBeUndefined();
    expect(absent).toMatchObject({ absent: "(clause absent from the document)" });
    expect(absent!.quote).toBeUndefined();
    const html = rowsHtml(model.todo_rows, "t", "list");
    expect(html).toContain("“Seller may assign”");
    expect(html).not.toContain("“(clause absent");
    expect(html).toContain("Not in the document:");
  });
});

describe("keyTermsOf", () => {
  it("keeps a party with no role, moves a signature-line name to Signed by, and leaves blanks blank", () => {
    const terms = keyTermsOf(ABSTRACT, signers);
    const get = (label: string) => terms.find((t) => t.label === label);
    expect(get("Parties")!.value).toBe(
      "Northgate Instrument Company (Ohio) · Meridian Growth Partners III",
    );
    expect(get("Signed by")!.value).toBe("Priya Raghunathan");
    expect(get("Governing law")).toEqual({
      label: "Governing law",
      value: "Delaware",
      section: "§ 12",
    });
    expect(get("Liability cap")!.value).toBeUndefined();
    expect(
      resultsPageHtml(
        buildResultsModel({
          run: { findings: [] },
          abstract: ABSTRACT,
          isSigner: signers,
          reportUrl: noLink,
        }),
      ),
    ).toContain("Not found in the text");
  });
});

describe("rendering", () => {
  it("escapes document text and links only web or same-site URLs", () => {
    const model = buildResultsModel({
      run: {
        findings: [
          finding({
            rule_id: "X-1",
            severity: "warning",
            title: "<img src=x onerror=alert(1)>",
            recommendation: "Add <b>this</b>.",
            source_citations: [
              {
                id: "a",
                source: "Good",
                source_url: "https://example.com/a",
                retrieved_at: "",
                license: "",
                license_url: "",
              },
              {
                id: "b",
                source: "Bad",
                source_url: "javascript:alert(1)",
                retrieved_at: "",
                license: "",
                license_url: "",
              },
            ],
          }),
        ],
      },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: () => "/report#rule=X-1",
    });
    const html = resultsPageHtml(model);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    expect(html).toContain('href="https://example.com/a"');
    expect(html).not.toContain("javascript:");
    expect(html).toContain('href="/report#rule=X-1"');
  });

  it("opens and closes a row in place, and copies the suggested change", async () => {
    const model = buildResultsModel({
      run: {
        findings: [finding({ rule_id: "C-1", severity: "critical", recommendation: "Add a cap." })],
      },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: noLink,
    });
    const root = document.createElement("div");
    root.innerHTML = resultsPageHtml(model);
    document.body.append(root);
    wireResultsPage(root);
    const toggle = root.querySelector<HTMLButtonElement>('[data-role="result-row"]')!;
    const detail = root.querySelector<HTMLElement>("#rp-todo-0")!;
    expect(detail.hidden).toBe(true);
    toggle.click();
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(detail.hidden).toBe(false);
    toggle.click();
    expect(detail.hidden).toBe(true);

    let copied = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (t: string) => void (copied = t) },
    });
    root.querySelector<HTMLButtonElement>('[data-role="copy-suggested"]')!.click();
    await new Promise((r) => setTimeout(r, 0));
    expect(copied).toBe(copyText(model.todo_rows[0]!));
    expect(copied.startsWith("Add a cap.")).toBe(true);
    root.remove();
  });
});

describe("the complete state", () => {
  const base = {
    kind: "complete" as const,
    filename: "nda.txt",
    playbook_name: "Mutual NDA",
    counts: { critical: 0, warning: 1, info: 1 },
    docx_blob: new Blob(),
    json_blob: new Blob(),
    docx_filename: "a.docx",
    json_filename: "a.json",
  };

  it("leads with the page and folds every panel the result showed before", () => {
    const results = buildResultsModel({
      run: {
        findings: [
          finding({ rule_id: "A-1", severity: "warning", recommendation: "x" }),
          finding({ rule_id: "A-2", severity: "info" }),
        ],
      },
      abstract: ABSTRACT,
      isSigner: signers,
      reportUrl: noLink,
    });
    const dz = document.createElement("div");
    renderState(dz, { ...base, results: renderResults(results) });
    expect(select(dz, "results-headline")!.textContent).toBe("1 thing to raise before you sign");
    expect(select(dz, "results-page")!.hidden).toBe(false);
    expect(select(dz, "also-noted-summary")!.textContent).toBe("Also noted (1)");
    expect((select(dz, "covered-fold") as HTMLDetailsElement).open).toBe(false);
    // Every role the complete template carried before add-results-page.
    const before = [
      "classification-notice",
      "clause-evidence",
      "closing-checklist",
      "compare-button",
      "compare-input",
      "compare-row",
      "complete-filename",
      "compliance-frame-chips",
      "compliance-frame-hint",
      "counts",
      "critical-dates",
      "delivery",
      "docx-download",
      "download-status",
      "export-certificate-docx",
      "export-certificate-json",
      "export-closing-checklist-csv",
      "export-closing-checklist-md",
      "export-critical-dates-ics",
      "export-critical-dates-md",
      "export-deadlines-ics",
      "export-definitions-csv",
      "export-definitions-json",
      "export-fixlist-csv",
      "export-fixlist-md",
      "export-html",
      "export-negotiation-csv",
      "export-negotiation-md",
      "export-negotiation-sheet",
      "export-obligations-csv",
      "export-reviewed-docx",
      "export-row",
      "export-sarif",
      "input-notice",
      "json-download",
      "jurisdiction-overlays",
      "negotiation",
      "playbook-provenance",
      "reasoning",
      "regime-coverage",
      "report-link",
      "review-coverage",
      "rule-errored",
      "scope-of-review",
      "secondary-families",
      "v3-family",
    ];
    for (const role of before) expect(select(dz, role), role).not.toBeNull();
    // The three trust notices sit above the headline.
    const order = (role: string) =>
      Array.from(dz.querySelectorAll("[data-role]")).indexOf(select(dz, role)!);
    for (const role of ["input-notice", "classification-notice", "rule-errored"]) {
      expect(order(role)).toBeLessThan(order("results-page"));
    }
  });

  it("without a results model leaves the panels open, as before", () => {
    const dz = document.createElement("div");
    renderState(dz, base);
    expect(select(dz, "results-page")!.hidden).toBe(true);
    expect((select(dz, "covered-fold") as HTMLDetailsElement).open).toBe(true);
  });
});

import { describe, expect, it, vi } from "vitest";
import { renderState, select } from "./states.js";

/** Small fixture helper — supplies the per-doc blob/filename fields
 *  required by the bundle-complete `documents` array so individual
 *  tests can focus on the field(s) they exercise. */
function cardDoc(overrides: {
  filename: string;
  family_label?: string;
  detection_confidence?: number;
  playbook_name: string;
  playbook_deprecated?: boolean;
  counts: { critical: number; warning: number; info: number };
  secondary_families?: ReadonlyArray<{
    playbook_name: string;
    counts: { critical: number; warning: number; info: number };
  }>;
  input_warnings?: ReadonlyArray<string>;
  classification_notice?: string;
  docx_blob?: Blob;
  json_blob?: Blob;
  docx_filename?: string;
  json_filename?: string;
}): {
  filename: string;
  family_label?: string;
  detection_confidence?: number;
  playbook_name: string;
  playbook_deprecated?: boolean;
  counts: { critical: number; warning: number; info: number };
  secondary_families?: ReadonlyArray<{
    playbook_name: string;
    counts: { critical: number; warning: number; info: number };
  }>;
  input_warnings?: ReadonlyArray<string>;
  classification_notice?: string;
  docx_blob: Blob;
  json_blob: Blob;
  docx_filename: string;
  json_filename: string;
} {
  return {
    ...(overrides.input_warnings ? { input_warnings: overrides.input_warnings } : {}),
    ...(overrides.classification_notice
      ? { classification_notice: overrides.classification_notice }
      : {}),
    filename: overrides.filename,
    family_label: overrides.family_label,
    detection_confidence: overrides.detection_confidence,
    playbook_name: overrides.playbook_name,
    playbook_deprecated: overrides.playbook_deprecated,
    counts: overrides.counts,
    secondary_families: overrides.secondary_families,
    docx_blob: overrides.docx_blob ?? new Blob(["docx"]),
    json_blob: overrides.json_blob ?? new Blob(["{}"]),
    docx_filename: overrides.docx_filename ?? `${overrides.filename}.docx`,
    json_filename: overrides.json_filename ?? `${overrides.filename}.json`,
  };
}

describe("renderState", () => {
  it("renders empty state with the v3 §63 headline + sub", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "empty" });
    expect(dz.getAttribute("data-state")).toBe("empty");
    expect(dz.querySelector(".dropzone-title")?.textContent).toMatch(/Drop a PDF/);
    expect(dz.querySelector(".dropzone-title")?.textContent).toMatch(/four/);
    const sub = dz.querySelector(".dropzone-sub")!.textContent ?? "";
    // Spec-v3 §63 asked the empty state to name the families it understands.
    // The families now live in the landing page's document-type index, which
    // names all 145 rather than the handful that fit in a drop-zone caption —
    // guarded by tests/integration/site-document-types.test.ts. What the sub
    // still owes the reader at this moment is the two facts that bear on
    // whether to drop a file at all.
    expect(sub).toMatch(/nothing is uploaded/);
    expect(sub).toMatch(/pair/);
  });

  it("renders error state with structured title + detail when an error code is passed (spec-v3 §63)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "error",
      message: "fallback",
      code: "scc-module-2-empty-annex",
    });
    expect(select(dz, "error-title")!.textContent).toMatch(/SCC Module 2/);
    expect(select(dz, "error-message")!.textContent).toMatch(/Annex/);
  });

  it("renders error state with the freeform message when no code is passed", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "error", message: "Ingest failed: bad bytes." });
    expect(select(dz, "error-message")!.textContent).toBe("Ingest failed: bad bytes.");
  });

  it("renders analyzing state with filename + ticker host", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "analyzing", filename: "contract.pdf", dkb_version: "v2026-05-12" });
    expect(dz.getAttribute("data-state")).toBe("analyzing");
    expect(select(dz, "analyzing-filename")?.textContent).toBe("contract.pdf");
    expect(select(dz, "analyzing-dkb")?.textContent).toBe("DKB v2026-05-12");
    expect(select(dz, "ticker")).not.toBeNull();
    expect(select(dz, "progress")).not.toBeNull();
  });

  it("renders complete state with counts, download buttons and reasoning", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      match_reasoning: "matched on title and recipient/discloser phrasing",
      counts: { critical: 2, warning: 5, info: 11 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    expect(dz.getAttribute("data-state")).toBe("complete");
    const docx = select<HTMLButtonElement>(dz, "docx-download")!;
    const json = select<HTMLButtonElement>(dz, "json-download")!;
    expect(docx.tagName).toBe("BUTTON");
    expect(json.tagName).toBe("BUTTON");
    expect(docx.textContent).toMatch(/Download report \(Word\)/);
    expect(json.textContent).toMatch(/Download structured data \(JSON\)/);
    expect(select(dz, "download-status")).not.toBeNull();
    expect(select(dz, "counts")!.textContent).toMatch(/2/);
    expect(select(dz, "counts")!.textContent).toMatch(/5/);
    expect(select(dz, "counts")!.textContent).toMatch(/11/);
    expect(select(dz, "reasoning")!.textContent).toContain("matched on title");
    // No exports supplied → the v6 export row stays hidden.
    expect(select(dz, "export-row")!.hasAttribute("hidden")).toBe(true);
    // No custom playbook → provenance line stays hidden.
    expect(select(dz, "playbook-provenance")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the v3 ladder detail (band, met rung, approved fallback) in the posture card", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "msa.docx",
      playbook_name: "Team ladder",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "msa-vaulytica.docx",
      json_filename: "msa-vaulytica.json",
      negotiation_posture: {
        counts: { ideal: 0, acceptable: 1, below_acceptable: 1, unevaluable: 0 },
        positions: [
          {
            dimension: "Liability cap",
            tier: "acceptable",
            detail: "8x",
            met_rung: "7x cap",
            size_band: "≥ $1M",
          },
          {
            dimension: "Indemnity",
            tier: "below-acceptable",
            approved_language: "Indemnity shall be mutual.",
          },
        ],
      },
    });
    const card = select(dz, "negotiation")!;
    expect(card.hidden).toBe(false);
    expect(card.textContent).toContain("Deal-size band: ≥ $1M");
    expect(card.textContent).toContain("met rung: 7x cap");
    expect(card.textContent).toContain("Your approved fallback: Indemnity shall be mutual.");
  });

  it("renders the unmatched-document banner and hides scope when generic-fallback", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "mystery.pdf",
      playbook_name: "Generic Fallback",
      counts: { critical: 0, warning: 1, info: 3 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      classification_notice: { message: "No known document family matched this document." },
    });
    const banner = select(dz, "classification-notice")!;
    expect(banner.hasAttribute("hidden")).toBe(false);
    expect(banner.textContent).toContain("Document type not recognized");
    expect(banner.textContent).toContain("No known document family matched");
    // No registered pack → scope block stays hidden.
    expect(select(dz, "scope-of-review")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the scope-of-review block for a regulated pack", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "baa.docx",
      playbook_name: "HIPAA BAA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      scope_of_review: {
        pack: "HIPAA Business Associate Agreement",
        reviewed_for: ["breach-notification terms"],
        not_reviewed_for: ["any determination of HIPAA compliance"],
      },
    });
    const scope = select(dz, "scope-of-review")!;
    expect(scope.hasAttribute("hidden")).toBe(false);
    expect(scope.textContent).toContain("HIPAA Business Associate Agreement");
    expect(scope.textContent).toContain("breach-notification terms");
    expect(scope.textContent).toContain("any determination of HIPAA compliance");
    // The unmatched banner stays hidden for a matched pack.
    expect(select(dz, "classification-notice")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the regime-coverage block when regimes were asserted, hides it otherwise", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "notice.docx",
      playbook_name: "Privacy Notice",
      counts: { critical: 0, warning: 1, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      regime_coverage: [
        {
          regime: "ccpa",
          regime_name: "California (CCPA/CPRA)",
          found_count: 1,
          total: 2,
          items: [
            { rule_id: "PNOT-CA-001", item: "Categories of personal information", found: true },
            { rule_id: "PNOT-CA-002", item: "Right to delete", found: false },
          ],
        },
      ],
    });
    const el = select(dz, "regime-coverage")!;
    expect(el.hasAttribute("hidden")).toBe(false);
    expect(el.textContent).toContain("California (CCPA/CPRA) — 1 of 2 items found");
    expect(el.textContent).toContain("Found — Categories of personal information (PNOT-CA-001)");
    expect(el.textContent).toContain("Not detected — Right to delete (PNOT-CA-002)");
    // The presence-only caveat travels with the table.
    expect(el.textContent).toContain("never that the notice is adequate or compliant");

    const bare = document.createElement("div");
    renderState(bare, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
    });
    expect(select(bare, "regime-coverage")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the v6 custom-playbook provenance line when a playbook drove the run", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "msa.docx",
      playbook_name: "MSA — Vendor",
      counts: { critical: 1, warning: 2, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "msa-vaulytica.docx",
      json_filename: "msa-vaulytica.json",
      custom_playbook: {
        name: "Acme SaaS Buyer Standard",
        mode: "augment",
        custom_finding_count: 3,
        unevaluable_count: 1,
      },
    });
    const prov = select(dz, "playbook-provenance")!;
    expect(prov.hasAttribute("hidden")).toBe(false);
    expect(prov.textContent).toContain("Acme SaaS Buyer Standard");
    expect(prov.textContent).toMatch(/3 findings/);
    expect(prov.textContent).toMatch(/your playbook \+ the built-in catalog/);
    expect(prov.textContent).toMatch(/1 custom rule could not be evaluated/);
  });

  it("renders the multi-family 'also checked' block when secondary families activated", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "msa.docx",
      playbook_name: "MSA — Vendor",
      counts: { critical: 1, warning: 2, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "msa-vaulytica.docx",
      json_filename: "msa-vaulytica.json",
      secondary_families: [
        {
          playbook_id: "dpa-controller-processor",
          playbook_name: "DPA (Controller–Processor)",
          counts: { critical: 1, warning: 0, info: 0 },
        },
        {
          playbook_id: "ip-licensing-patent",
          playbook_name: "Patent License",
          counts: { critical: 0, warning: 0, info: 0 },
        },
      ],
    });
    const block = select(dz, "secondary-families")!;
    expect(block.hasAttribute("hidden")).toBe(false);
    const items = select(dz, "secondary-families-list")!.querySelectorAll("li");
    expect(items).toHaveLength(2);
    expect(block.textContent).toContain("DPA (Controller–Processor)");
    expect(block.textContent).toMatch(/1 critical/);
    expect(block.textContent).toContain("Patent License");
    expect(block.textContent).toMatch(/no findings/);
  });

  it("hides the multi-family block when no secondary families", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    expect(select(dz, "secondary-families")!.hasAttribute("hidden")).toBe(true);
  });

  it("shows what the findings rest on, under the counts", () => {
    // The most load-bearing sentence this tool emits, and until 9.576.0 the
    // tab — where a user drops a document and reads three severity counts —
    // said nothing about it.
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 1, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
      review_coverage:
        "0 of 1 findings cite an attorney-reviewed rule — every rule applied here is author-asserted, grounded in a cited authority but not yet signed off by a licensed attorney.",
    });
    const block = select(dz, "review-coverage")!;
    expect(block.hasAttribute("hidden")).toBe(false);
    expect(block.textContent).toContain("0 of 1 findings cite an attorney-reviewed rule");
  });

  it("shows how checkable the findings are, under the review line", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 1, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
      clause_evidence:
        "2 of 3 findings quote the exact clause text they fired on; the remaining 1 rest on a pattern or structural match and warrant a read against the document.",
    });
    const block = select(dz, "clause-evidence")!;
    expect(block.hasAttribute("hidden")).toBe(false);
    expect(block.textContent).toContain("2 of 3 findings quote the exact clause text");
  });

  it("hides the review-coverage line when the surface did not compute one", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    expect(select(dz, "review-coverage")!.hasAttribute("hidden")).toBe(true);
    expect(select(dz, "clause-evidence")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the v6 findings-to-action export row when exports are supplied", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 1, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
      exports: {
        fixlist_md_blob: new Blob(["# fix"], { type: "text/markdown" }),
        fixlist_csv_blob: new Blob(["a,b"], { type: "text/csv" }),
        obligations_csv_blob: new Blob(["a,b"], { type: "text/csv" }),
        deadlines_ics_blob: new Blob(["BEGIN:VCALENDAR"], { type: "text/calendar" }),
        sarif_blob: new Blob(['{"version":"2.1.0"}'], { type: "application/sarif+json" }),
        html_blob: new Blob(["<!doctype html>"], { type: "text/html" }),
        fixlist_md_filename: "nda-vaulytica-fixlist.md",
        fixlist_csv_filename: "nda-vaulytica-fixlist.csv",
        obligations_csv_filename: "nda-vaulytica-obligations.csv",
        deadlines_ics_filename: "nda-vaulytica-deadlines.ics",
        sarif_filename: "nda-vaulytica.sarif.json",
        html_filename: "nda-vaulytica-report.html",
      },
    });
    const row = select(dz, "export-row")!;
    expect(row.hasAttribute("hidden")).toBe(false);
    expect(select(dz, "export-fixlist-md")!.textContent).toMatch(/Fix list \(Markdown\)/);
    expect(select(dz, "export-fixlist-csv")).not.toBeNull();
    expect(select(dz, "export-obligations-csv")).not.toBeNull();
    expect(select(dz, "export-deadlines-ics")!.textContent).toMatch(/Deadlines/);
    expect(select(dz, "export-html")!.textContent).toMatch(/HTML report/);
    expect(select(dz, "export-sarif")!.textContent).toMatch(/SARIF/);
  });

  it("hides the v6 compare row unless on_compare is supplied", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "nda.docx",
      json_filename: "nda.json",
    });
    expect(select(dz, "compare-row")!.hasAttribute("hidden")).toBe(true);
  });

  it("renders the v6 compare affordance and invokes on_compare with the chosen file", () => {
    const dz = document.createElement("div");
    const onCompare = vi.fn();
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "nda.docx",
      json_filename: "nda.json",
      on_compare: onCompare,
    });
    expect(select(dz, "compare-row")!.hasAttribute("hidden")).toBe(false);
    const input = select<HTMLInputElement>(dz, "compare-input")!;
    const file = new File(["%PDF-1.7"], "nda-v2.pdf", { type: "application/pdf" });
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    input.dispatchEvent(new Event("change"));
    expect(onCompare).toHaveBeenCalledTimes(1);
    expect(onCompare.mock.calls[0]![0].name).toBe("nda-v2.pdf");
  });

  it("renders the comparison-complete state with bucket counts and downloads", () => {
    const dz = document.createElement("div");
    const onReset = vi.fn();
    renderState(dz, {
      kind: "comparison-complete",
      base_filename: "nda-v1.pdf",
      revised_filename: "nda-v2.pdf",
      verdict: "Net improvement: more findings resolved than introduced.",
      counts: {
        resolved: { critical: 1, warning: 1, info: 0, total: 2 },
        introduced: { critical: 0, warning: 0, info: 1, total: 1 },
        unchanged: { critical: 0, warning: 2, info: 0, total: 2 },
        carried_clean_count: 940,
      },
      dkb_mismatch: false,
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "cmp.docx",
      json_filename: "cmp.json",
      on_reset: onReset,
    });
    expect(dz.getAttribute("data-state")).toBe("comparison-complete");
    expect(select(dz, "comparison-versions")!.textContent).toContain("nda-v1.pdf");
    expect(select(dz, "comparison-versions")!.textContent).toContain("nda-v2.pdf");
    expect(select(dz, "comparison-verdict")!.textContent).toContain("Net improvement");
    const counts = select(dz, "comparison-counts")!.textContent!;
    expect(counts).toMatch(/2\s*resolved/);
    expect(counts).toMatch(/1\s*introduced/);
    expect(counts).toMatch(/940/);
    expect(select(dz, "comparison-dkb-warning")!.hasAttribute("hidden")).toBe(true);
    // No clause_diff supplied → the redline line stays hidden (back-compat).
    expect(select(dz, "comparison-redline")!.hasAttribute("hidden")).toBe(true);
    select<HTMLButtonElement>(dz, "comparison-reset")!.click();
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it("comparison-complete renders a clause-level redline summary when supplied", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "comparison-complete",
      base_filename: "a.pdf",
      revised_filename: "b.pdf",
      verdict: "Mixed.",
      counts: {
        resolved: { critical: 0, warning: 0, info: 0, total: 0 },
        introduced: { critical: 0, warning: 0, info: 0, total: 0 },
        unchanged: { critical: 0, warning: 0, info: 0, total: 0 },
        carried_clean_count: 0,
      },
      dkb_mismatch: false,
      clause_diff: { added: 2, removed: 1, changed: 3, truncated: false },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "cmp.docx",
      json_filename: "cmp.json",
    });
    const redline = select(dz, "comparison-redline")!;
    expect(redline.hasAttribute("hidden")).toBe(false);
    expect(redline.textContent).toContain("3 clauses rewritten");
    expect(redline.textContent).toContain("2 added");
    expect(redline.textContent).toContain("1 removed");
  });

  it("comparison-complete redline reports no text changes for an identical body", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "comparison-complete",
      base_filename: "a.pdf",
      revised_filename: "b.pdf",
      verdict: "No change.",
      counts: {
        resolved: { critical: 0, warning: 0, info: 0, total: 0 },
        introduced: { critical: 0, warning: 0, info: 0, total: 0 },
        unchanged: { critical: 0, warning: 0, info: 0, total: 0 },
        carried_clean_count: 0,
      },
      dkb_mismatch: false,
      clause_diff: { added: 0, removed: 0, changed: 0, truncated: false },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "cmp.docx",
      json_filename: "cmp.json",
    });
    expect(select(dz, "comparison-redline")!.textContent).toContain("no clause-level text changes");
  });

  it("comparison-complete surfaces a DKB-mismatch warning when flagged", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "comparison-complete",
      base_filename: "a.pdf",
      revised_filename: "b.pdf",
      verdict: "No change to the risk surface.",
      counts: {
        resolved: { critical: 0, warning: 0, info: 0, total: 0 },
        introduced: { critical: 0, warning: 0, info: 0, total: 0 },
        unchanged: { critical: 0, warning: 0, info: 0, total: 0 },
        carried_clean_count: 10,
      },
      dkb_mismatch: true,
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "cmp.docx",
      json_filename: "cmp.json",
    });
    const warn = select(dz, "comparison-dkb-warning")!;
    expect(warn.hasAttribute("hidden")).toBe(false);
    expect(warn.textContent).toContain("different DKB versions");
  });

  it("error state renders a secondary action button and invokes it", () => {
    const dz = document.createElement("div");
    const onClick = vi.fn();
    renderState(dz, {
      kind: "error",
      message: "cross-family",
      action: { label: "Compare anyway", on_click: onClick },
    });
    const action = select<HTMLButtonElement>(dz, "error-action")!;
    expect(action.hasAttribute("hidden")).toBe(false);
    expect(action.textContent).toBe("Compare anyway");
    action.click();
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("error state hides the action button when no action is supplied", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "error", message: "boom" });
    expect(select(dz, "error-action")!.hasAttribute("hidden")).toBe(true);
  });

  it("complete-state reasoning annotates Legacy playbook + successor when playbook_deprecation is set", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      playbook_deprecation: { superseded_by: "mutual-nda-deep" },
      match_reasoning: "Selected mutual-nda.",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda.docx",
      json_filename: "nda.json",
    });
    expect(select(dz, "reasoning")!.textContent).toBe(
      "Selected mutual-nda. Legacy playbook — superseded by mutual-nda-deep.",
    );
  });

  it("complete-state reasoning annotates Legacy playbook alone when superseded_by is absent", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      playbook_deprecation: {},
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda.docx",
      json_filename: "nda.json",
    });
    expect(select(dz, "reasoning")!.textContent).toBe("Auto-selected Mutual NDA. Legacy playbook.");
  });

  it("complete-state reasoning omits the legacy annotation when playbook_deprecation is absent", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA Deep",
      match_reasoning: "Selected mutual-nda-deep.",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "x.docx",
      json_filename: "x.json",
    });
    expect(select(dz, "reasoning")!.textContent).toBe("Selected mutual-nda-deep.");
    expect(select(dz, "reasoning")!.textContent).not.toContain("Legacy");
  });

  it("download button triggers Save flow and reports status", async () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const docxBlob = new Blob(["docx-bytes"], { type: "application/octet-stream" });
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: docxBlob,
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    // Spy on anchor clicks so we can verify the synthetic anchor was
    // dispatched with the right filename attribute.
    const seen: { download: string; href: string }[] = [];
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      seen.push({ download: this.download, href: this.href });
    };
    try {
      const btn = select<HTMLButtonElement>(dz, "docx-download")!;
      btn.click();
      // saveBlob is async; let microtasks run.
      for (let i = 0; i < 5; i++) await Promise.resolve();
      expect(seen.length).toBe(1);
      expect(seen[0]?.download).toBe("nda-vaulytica.docx");
      expect(seen[0]?.href).toMatch(/^blob:/);
      // happy-dom does not expose `showSaveFilePicker`, so we exercise
      // the anchor fallback path. Status reports "Download started".
      expect(select(dz, "download-status")!.textContent).toMatch(
        /Download started: nda-vaulytica\.docx/,
      );
    } finally {
      HTMLAnchorElement.prototype.click = origClick;
      document.body.removeChild(dz);
    }
  });

  it("download flow uses File System Access API when available", async () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const docxBlob = new Blob(["docx-bytes"], { type: "application/octet-stream" });
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: docxBlob,
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    const written: BlobPart[] = [];
    let closed = false;
    (window as unknown as { showSaveFilePicker: unknown }).showSaveFilePicker = async (opts: {
      suggestedName?: string;
    }) => {
      expect(opts.suggestedName).toBe("nda-vaulytica.docx");
      return {
        createWritable: async () => ({
          write: async (data: BlobPart) => {
            written.push(data);
          },
          close: async () => {
            closed = true;
          },
        }),
      };
    };
    try {
      select<HTMLButtonElement>(dz, "docx-download")!.click();
      for (let i = 0; i < 10; i++) await Promise.resolve();
      expect(written.length).toBe(1);
      expect(closed).toBe(true);
      expect(select(dz, "download-status")!.textContent).toBe("Saved nda-vaulytica.docx");
    } finally {
      delete (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker;
      document.body.removeChild(dz);
    }
  });

  it("download flow reports empty blob and never calls click", async () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob([], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    });
    let clicked = 0;
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      clicked++;
    };
    try {
      select<HTMLButtonElement>(dz, "docx-download")!.click();
      for (let i = 0; i < 5; i++) await Promise.resolve();
      expect(clicked).toBe(0);
      expect(select(dz, "download-status")!.textContent).toMatch(/empty/);
    } finally {
      HTMLAnchorElement.prototype.click = origClick;
      document.body.removeChild(dz);
    }
  });

  it("renders v3 family chip when detection is provided in complete state", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "baa.docx",
      playbook_name: "BAA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "baa-vaulytica.docx",
      json_filename: "baa-vaulytica.json",
      v3_family: { family: "baa", label: "BAA", confidence: 0.75 },
    });
    const chip = select(dz, "v3-family")!;
    expect(chip.hidden).toBe(false);
    expect(chip.textContent).toMatch(/Detected: BAA \(0\.75\)/);
    expect(chip.getAttribute("data-confidence")).toBe("75");
    expect(chip.classList.contains("low-confidence")).toBe(false);
  });

  it("v3 family chip flags low-confidence detections with .low-confidence class (spec-v3 §60)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "borderline.docx",
      playbook_name: "DPA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_family: { family: "dpa-eu", label: "EU DPA", confidence: 0.32 },
    });
    const chip = select(dz, "v3-family")!;
    expect(chip.hidden).toBe(false);
    expect(chip.textContent).toMatch(/Detected: EU DPA \(0\.32\)/);
    expect(chip.getAttribute("data-confidence")).toBe("32");
    expect(chip.classList.contains("low-confidence")).toBe(true);
  });

  it("v3 family chip in the [0.4, 0.5) band renders normally (spec-v3 §60 faint threshold is 0.4)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "borderline.docx",
      playbook_name: "DPA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_family: { family: "dpa-eu", label: "EU DPA", confidence: 0.45 },
    });
    const chip = select(dz, "v3-family")!;
    // 0.45 is above the 0.4 faint threshold, so it must NOT be dimmed.
    expect(chip.classList.contains("low-confidence")).toBe(false);
  });

  it("hides v3 family chip when family is unknown or omitted", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
    });
    expect(select(dz, "v3-family")!.hidden).toBe(true);
  });

  it("renders compliance-frame chip row with role=switch + aria-checked reflecting v3_frames.on", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "baa.docx",
      playbook_name: "BAA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_frames: {
        available: ["HIPAA", "GDPR", "CCPA"],
        on: ["HIPAA"],
      },
    });
    const row = select(dz, "compliance-frame-chips")!;
    expect(row.hidden).toBe(false);
    const chips = row.querySelectorAll<HTMLButtonElement>('[role="switch"]');
    expect(chips).toHaveLength(3);
    expect(chips[0]!.textContent).toBe("HIPAA");
    expect(chips[0]!.getAttribute("aria-checked")).toBe("true");
    expect(chips[1]!.getAttribute("aria-checked")).toBe("false");
    expect(chips[2]!.getAttribute("aria-checked")).toBe("false");
    expect(chips[0]!.tabIndex).toBe(0);
  });

  it("compliance-frame chip toggle invokes on_frames_change with the current union", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const calls: ReadonlyArray<string>[] = [];
    renderState(dz, {
      kind: "complete",
      filename: "baa.docx",
      playbook_name: "BAA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_frames: { available: ["HIPAA", "GDPR"], on: ["HIPAA"] },
      on_frames_change: (frames) => calls.push([...frames]),
    });
    const chips = dz.querySelectorAll<HTMLButtonElement>('[role="switch"]');
    // Turn HIPAA off → empty active set.
    chips[0]!.click();
    expect(calls).toHaveLength(1);
    expect([...calls[0]!].sort()).toEqual([]);
    // Turn GDPR on → ["GDPR"].
    chips[1]!.click();
    expect(calls).toHaveLength(2);
    expect([...calls[1]!].sort()).toEqual(["GDPR"]);
    // Turn HIPAA back on → ["GDPR", "HIPAA"] (order not contracted).
    chips[0]!.click();
    expect(calls).toHaveLength(3);
    expect([...calls[2]!].sort()).toEqual(["GDPR", "HIPAA"]);
    document.body.removeChild(dz);
  });

  it("compliance-frame chip flips aria-checked on Space (keyboard a11y probe)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "complete",
      filename: "baa.docx",
      playbook_name: "BAA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_frames: { available: ["HIPAA"], on: [] },
    });
    const chip = dz.querySelector<HTMLButtonElement>('[role="switch"]')!;
    expect(chip.getAttribute("aria-checked")).toBe("false");
    chip.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true }));
    expect(chip.getAttribute("aria-checked")).toBe("true");
    chip.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
    );
    expect(chip.getAttribute("aria-checked")).toBe("false");
    document.body.removeChild(dz);
  });

  it("compliance-frame hint is rendered when v3_frames.hint is set", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "msa.docx",
      playbook_name: "MSA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
      v3_frames: {
        available: ["HIPAA"],
        on: [],
        hint: "Looking for GDPR or HIPAA coverage? Add a companion DPA or BAA.",
      },
    });
    const hint = select(dz, "compliance-frame-hint")!;
    expect(hint.hidden).toBe(false);
    expect(hint.textContent).toMatch(/Add a companion DPA or BAA/);
  });

  it("renders bundle-complete state with counts, bundle download buttons and cross-doc summary", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 3,
      counts: { critical: 4, warning: 7, info: 12 },
      cross_doc_findings: 2,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
    });
    expect(dz.getAttribute("data-state")).toBe("bundle-complete");
    expect(select(dz, "bundle-title")!.textContent).toMatch(/3 documents/);
    expect(select(dz, "counts")!.textContent).toMatch(/4/);
    expect(select(dz, "counts")!.textContent).toMatch(/7/);
    expect(select(dz, "counts")!.textContent).toMatch(/12/);
    expect(select(dz, "cross-doc-summary")!.textContent).toMatch(/2 cross-document/);
    expect(select<HTMLButtonElement>(dz, "bundle-download")!.tagName).toBe("BUTTON");
    expect(select<HTMLButtonElement>(dz, "bundle-json-download")!.tagName).toBe("BUTTON");
    // No bundle_zip_blob supplied → the "everything" link stays hidden.
    expect(select(dz, "bundle-zip-download")!.hasAttribute("hidden")).toBe(true);
    document.body.removeChild(dz);
  });

  it("bundle-complete renders the posture-coherence card when present (spec-v12 Thrust B)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
      posture_coherence: {
        counts: { aligned: 1, divergent: 1, single: 0, unstated: 0 },
        dimensions: [
          {
            dimension: "Governing law",
            coherence: "aligned",
            tiers: [
              { document: "msa.docx", tier: "ideal" },
              { document: "order.docx", tier: "ideal" },
            ],
            weakest_tier: "ideal",
            weakest_documents: ["msa.docx", "order.docx"],
          },
          {
            dimension: "Liability cap",
            coherence: "divergent",
            tiers: [
              { document: "msa.docx", tier: "ideal" },
              { document: "order.docx", tier: "below-acceptable" },
            ],
            weakest_tier: "below-acceptable",
            weakest_documents: ["order.docx"],
          },
        ],
      },
    });
    const card = select(dz, "bundle-posture-coherence")!;
    expect(card.hidden).toBe(false);
    expect(card.textContent).toMatch(/Weakest front/);
    expect(card.textContent).toMatch(/1 aligned/);
    expect(card.textContent).toMatch(/1 divergent/);
    expect(card.textContent).toMatch(/Liability cap/);
    expect(card.textContent).toMatch(/Divergent/);
    // The binding floor names the weakest rung + document.
    expect(card.textContent).toMatch(/Binding floor: below floor in order\.docx/);
    // The card never asserts which document legally governs.
    expect(card.textContent).toMatch(/does not decide which one legally governs/);
    document.body.removeChild(dz);
  });

  it("bundle-complete hides the posture-coherence card when no coherence is supplied", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
    });
    const card = select(dz, "bundle-posture-coherence")!;
    expect(card.hidden).toBe(true);
    expect(card.innerHTML).toBe("");
    document.body.removeChild(dz);
  });

  it("bundle-complete renders the production-QA card when a privilege log was present (add-production-qa-pack)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 3,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
      production_qa: {
        member_count: 4,
        bates_count: 3,
        log_present: true,
        log_warnings: [],
        findings: [
          {
            code: "PROD-001",
            severity: "warning",
            title: "Produced-set gap",
            detail: "ACME-000002 is withheld per the log but is a gap in the produced set.",
          },
        ],
        delivery_sweep: { members_scanned: 3, flags: 0, uninspectable: 0 },
        production_qa_hash: "a".repeat(64),
      },
    });
    const card = select(dz, "bundle-production-qa")!;
    expect(card.hidden).toBe(false);
    expect(card.textContent).toMatch(/Production QA/);
    expect(card.textContent).toMatch(/4 members/);
    expect(card.textContent).toMatch(/privilege log present/);
    expect(card.textContent).toMatch(/PROD-001 — Produced-set gap/);
    // The pre-production sweep summary appears (clean set → nothing flagged).
    expect(card.textContent).toMatch(/Pre-production sweep: 3 members scanned/);
    expect(card.textContent).toMatch(/nothing flagged for review/);
    // The honest scope disclaimer is always shown.
    expect(card.textContent).toMatch(/does not read in-page Bates stamps/);
    document.body.removeChild(dz);
  });

  it("bundle-complete hides the production-QA card when no privilege log was supplied", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
    });
    const card = select(dz, "bundle-production-qa")!;
    expect(card.hidden).toBe(true);
    expect(card.innerHTML).toBe("");
    document.body.removeChild(dz);
  });

  it("bundle-complete hides the compare-round row unless on_compare_round is supplied (spec-v13 Thrust B)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
    });
    expect(select(dz, "bundle-compare-row")!.hasAttribute("hidden")).toBe(true);
    document.body.removeChild(dz);
  });

  it("bundle-complete renders the compare-round affordance and invokes on_compare_round with the chosen files (spec-v13 Thrust B)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const onCompareRound = vi.fn();
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
      on_compare_round: onCompareRound,
    });
    expect(select(dz, "bundle-compare-row")!.hasAttribute("hidden")).toBe(false);
    const input = select<HTMLInputElement>(dz, "bundle-compare-input")!;
    const a = new File(["%PDF-1.7"], "msa-v2.pdf", { type: "application/pdf" });
    const b = new File(["%PDF-1.7"], "order-v2.pdf", { type: "application/pdf" });
    Object.defineProperty(input, "files", { value: [a, b], configurable: true });
    input.dispatchEvent(new Event("change"));
    expect(onCompareRound).toHaveBeenCalledTimes(1);
    expect(onCompareRound.mock.calls[0]![0].map((f: File) => f.name)).toEqual([
      "msa-v2.pdf",
      "order-v2.pdf",
    ]);
    document.body.removeChild(dz);
  });

  it("renders the bundle-comparison-complete state with the movement card + downloads (spec-v13 Thrust B)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const onReset = vi.fn();
    renderState(dz, {
      kind: "bundle-comparison-complete",
      base_document_count: 2,
      revised_document_count: 3,
      coherence_movement: {
        floor_counts: {
          improved: 0,
          regressed: 1,
          unchanged: 1,
          "newly-stated": 0,
          "now-unstated": 0,
          appeared: 0,
          disappeared: 0,
        },
        shift_counts: { fractured: 0, reconciled: 1, realigned: 0, unchanged: 1 },
        movement_hash: "abc123",
        fronts: [
          {
            dimension: "Governing law",
            base_coherence: "divergent",
            revised_coherence: "aligned",
            base_floor: "below-acceptable",
            revised_floor: "ideal",
            floor_movement: "improved",
            coherence_shift: "reconciled",
          },
          {
            dimension: "Liability cap",
            base_coherence: "divergent",
            revised_coherence: "divergent",
            base_floor: "acceptable",
            revised_floor: "below-acceptable",
            floor_movement: "regressed",
            coherence_shift: "unchanged",
          },
        ],
      },
      docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      json_blob: new Blob(["{}"], { type: "application/json" }),
      docx_filename: "vaulytica-bundle-movement.docx",
      json_filename: "vaulytica-posture-movement.json",
      on_reset: onReset,
    });
    expect(dz.getAttribute("data-state")).toBe("bundle-comparison-complete");
    expect(select(dz, "bundle-comparison-rounds")!.textContent).toMatch(
      /Baseline: 2 documents → Revised: 3 documents/,
    );
    const card = select(dz, "bundle-coherence-movement")!;
    expect(card.hidden).toBe(false);
    expect(card.textContent).toMatch(/Position drift/);
    expect(card.textContent).toMatch(/Liability cap/);
    expect(card.textContent).toMatch(/Floor regressed/);
    expect(card.textContent).toMatch(/Reconciled/);
    // The floor transition renders human-readable rung labels.
    expect(card.textContent).toMatch(/acceptable → below floor/);
    // Advisory disclaimer present, never a legal conclusion.
    expect(card.textContent).toMatch(/not a legal conclusion/);
    // Reset wires back to the empty drop zone.
    select<HTMLButtonElement>(dz, "bundle-comparison-reset")!.click();
    expect(onReset).toHaveBeenCalledTimes(1);
    document.body.removeChild(dz);
  });

  it("bundle-complete reveals the 'everything' (.zip) link when the archive blob is present (spec-v8 §25)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 1, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"], { type: "application/octet-stream" }),
      bundle_json_blob: new Blob(["{}"], { type: "application/json" }),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
      bundle_zip_blob: new Blob(["PK"], { type: "application/zip" }),
      bundle_zip_filename: "vaulytica-bundle.zip",
    });
    const zip = select(dz, "bundle-zip-download")!;
    expect(zip.hasAttribute("hidden")).toBe(false);
    expect(zip.textContent).toMatch(/Download everything \(\.zip\)/);
    document.body.removeChild(dz);
  });

  it("bundle-complete renders the cross-doc consistency toggle hidden by default (spec-v3 §62)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 3,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
    });
    const toggle = select<HTMLLabelElement>(dz, "cross-doc-toggle")!;
    const input = select<HTMLInputElement>(dz, "cross-doc-toggle-input")!;
    // Visible whenever document_count >= 2.
    expect(toggle.hidden).toBe(false);
    // Default checked (consistency on).
    expect(input.checked).toBe(true);
    // Summary shows the finding count.
    expect(select(dz, "cross-doc-summary")!.textContent).toMatch(/3 cross-document/);
  });

  it("bundle-complete toggle flips the cross-doc summary and invokes the callback (spec-v3 §62)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const onToggle = vi.fn();
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 2,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      on_consistency_toggle: onToggle,
    });
    const input = select<HTMLInputElement>(dz, "cross-doc-toggle-input")!;
    input.checked = false;
    input.dispatchEvent(new Event("change", { bubbles: true }));
    expect(select(dz, "cross-doc-summary")!.textContent).toBe(
      "Cross-document consistency disabled.",
    );
    expect(onToggle).toHaveBeenCalledWith(false);
    input.checked = true;
    input.dispatchEvent(new Event("change", { bubbles: true }));
    expect(select(dz, "cross-doc-summary")!.textContent).toMatch(/2 cross-document/);
    expect(onToggle).toHaveBeenLastCalledWith(true);
    document.body.removeChild(dz);
  });

  it("bundle-complete hides the toggle when only one document is in the bundle", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 1,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
    });
    expect(select<HTMLLabelElement>(dz, "cross-doc-toggle")!.hidden).toBe(true);
  });

  it("bundle-complete renders the Skipped list when files were rejected", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      rejected: [
        { filename: "README.md", reason: 'Vaulytica accepts .pdf and .docx — not "README.md".' },
        { filename: "scan.tiff", reason: 'Vaulytica accepts .pdf and .docx — not "scan.tiff".' },
      ],
    });
    const wrap = select(dz, "bundle-rejected")!;
    expect(wrap.hidden).toBe(false);
    const items = dz.querySelectorAll(".bundle-rejected-item");
    expect(items.length).toBe(2);
    expect(items[0]!.textContent).toMatch(/README\.md/);
    expect(items[0]!.textContent).toMatch(/Vaulytica accepts/);
    expect(items[1]!.textContent).toMatch(/scan\.tiff/);
  });

  it("bundle-complete hides the Skipped list when nothing was rejected", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
    });
    expect(select(dz, "bundle-rejected")!.hidden).toBe(true);
  });

  it("bundle-complete escapes HTML in rejected filenames/reasons", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      rejected: [{ filename: "<script>x</script>.txt", reason: "<bad>" }],
    });
    const item = dz.querySelector(".bundle-rejected-item")!;
    expect(item.innerHTML).not.toContain("<script>");
    expect(item.textContent).toMatch(/<script>x<\/script>\.txt/);
  });

  it("bundle-complete shows detected families when provided", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 3,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      detected_families: ["BAA", "EU DPA"],
    });
    const det = select(dz, "bundle-detected-families")!;
    expect(det.hidden).toBe(false);
    expect(det.textContent).toBe("Detected: BAA, EU DPA");
  });

  it("bundle-complete renders a per-doc summary card per document (spec-v3 §62)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 1, warning: 0, info: 3 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "msa.docx",
          family_label: "MSA",
          playbook_name: "MSA (Customer-Deep)",
          counts: { critical: 1, warning: 0, info: 2 },
        }),
        cardDoc({
          filename: "dpa.docx",
          playbook_name: "DPA (Controller → Processor)",
          counts: { critical: 0, warning: 0, info: 1 },
        }),
      ],
    });
    const list = select<HTMLUListElement>(dz, "multi-doc-cards")!;
    expect(list.hidden).toBe(false);
    const cards = list.querySelectorAll<HTMLLIElement>('[data-role="multi-doc-card"]');
    expect(cards.length).toBe(2);
    expect(cards[0]!.textContent).toMatch(/msa\.docx/);
    expect(cards[0]!.textContent).toMatch(/MSA \(Customer-Deep\)/);
    expect(cards[0]!.textContent).toMatch(/1 critical/);
    // Second doc has no family_label — should still render filename/playbook.
    expect(cards[1]!.textContent).toMatch(/dpa\.docx/);
    expect(cards[1]!.textContent).toMatch(/Controller/);
    // family-label line is omitted when undefined, so "·" separator absent
    // before the playbook name on that card.
    expect(cards[1]!.querySelector(".multi-doc-card-meta")?.textContent).not.toMatch(/·/);
    // Each card exposes per-doc Word + JSON download buttons with
    // aria-labels that name the document.
    const wordBtns = list.querySelectorAll<HTMLButtonElement>('[data-role="card-docx-download"]');
    const jsonBtns = list.querySelectorAll<HTMLButtonElement>('[data-role="card-json-download"]');
    expect(wordBtns.length).toBe(2);
    expect(jsonBtns.length).toBe(2);
    expect(wordBtns[0]!.getAttribute("aria-label")).toMatch(/Word.*msa\.docx/);
    expect(jsonBtns[1]!.getAttribute("aria-label")).toMatch(/JSON.*dpa\.docx/);
  });

  /**
   * A bundle is where the ingest's caveats matter MOST and where they were
   * carried least. A single dropped file has said this since the notices
   * existed; drop a folder holding a redline, a scanned PDF, or a contract
   * that is not in English, and the summary reported findings without ever
   * mentioning that one of its documents had barely been read.
   */
  it("renders each bundled document's own ingest notices on its card", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 2 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "contrato.pdf",
          playbook_name: "Mutual NDA",
          counts: { critical: 0, warning: 0, info: 1 },
          input_warnings: ["This document does not read as English — it appears to be Spanish."],
        }),
        cardDoc({
          filename: "clean.docx",
          playbook_name: "MSA",
          counts: { critical: 0, warning: 0, info: 1 },
        }),
      ],
    });
    const cards = select<HTMLUListElement>(dz, "multi-doc-cards")!.querySelectorAll<HTMLLIElement>(
      '[data-role="multi-doc-card"]',
    );
    const notices = cards[0]!.querySelector('[data-role="multi-doc-card-notices"]');
    expect(notices?.textContent).toMatch(/appears to be Spanish/);
    // The notice sits ABOVE the counts: a count read without it is read wrong.
    const html = cards[0]!.innerHTML;
    expect(html.indexOf("multi-doc-card-notices")).toBeLessThan(
      html.indexOf("multi-doc-card-counts"),
    );
    // A document the ingest read cleanly renders no line at all.
    expect(cards[1]!.querySelector('[data-role="multi-doc-card-notices"]')).toBeNull();
  });

  /**
   * One unrecognized file among ten is exactly the one a reader skims past —
   * and its counts are the ones that mean least, because only the generic
   * rules ran on it. A single dropped file has always said so above its
   * findings; a bundle showed it as a card like any other.
   */
  it("marks a bundled document whose type was not recognized", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 2 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "unknown.pdf",
          playbook_name: "Generic Fallback",
          counts: { critical: 0, warning: 0, info: 1 },
          classification_notice: "Only the always-on structural checks ran.",
        }),
        cardDoc({
          filename: "msa.docx",
          playbook_name: "MSA",
          counts: { critical: 0, warning: 0, info: 1 },
        }),
      ],
    });
    const cards = select<HTMLUListElement>(dz, "multi-doc-cards")!.querySelectorAll<HTMLLIElement>(
      '[data-role="multi-doc-card"]',
    );
    const banner = cards[0]!.querySelector('[data-role="multi-doc-card-unmatched"]');
    expect(banner?.textContent).toMatch(/Document type not recognized/);
    expect(banner?.textContent).toMatch(/always-on structural checks/);
    // Ahead of the counts, which is what it reframes.
    const html = cards[0]!.innerHTML;
    expect(html.indexOf("multi-doc-card-unmatched")).toBeLessThan(
      html.indexOf("multi-doc-card-counts"),
    );
    // A recognized document gets no banner.
    expect(cards[1]!.querySelector('[data-role="multi-doc-card-unmatched"]')).toBeNull();
  });

  it("escapes a bundled document's ingest notice", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 1,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "a.docx",
          playbook_name: "MSA",
          counts: { critical: 0, warning: 0, info: 0 },
          input_warnings: ["<img src=x onerror=alert(1)>"],
        }),
      ],
    });
    const notices = select<HTMLUListElement>(dz, "multi-doc-cards")!.querySelector(
      '[data-role="multi-doc-card-notices"]',
    )!;
    expect(notices.querySelector("img")).toBeNull();
    expect(notices.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("renders an 'Also checked' line on a bundled composite document's card (spec-v6 multi-family)", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 1, warning: 1, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "msa-with-dpa.docx",
          family_label: "MSA",
          playbook_name: "MSA (Customer-Deep)",
          counts: { critical: 1, warning: 0, info: 0 },
          secondary_families: [
            {
              playbook_name: "Data Processing Agreement (EU/UK)",
              counts: { critical: 0, warning: 1, info: 0 },
            },
          ],
        }),
        cardDoc({
          filename: "nda.docx",
          playbook_name: "Mutual NDA",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
      ],
    });
    const list = select<HTMLUListElement>(dz, "multi-doc-cards")!;
    const cards = list.querySelectorAll<HTMLLIElement>('[data-role="multi-doc-card"]');
    const secondary = cards[0]!.querySelector(".multi-doc-card-secondary");
    expect(secondary).not.toBeNull();
    expect(secondary!.textContent).toMatch(/Also checked:/);
    expect(secondary!.textContent).toMatch(/Data Processing Agreement \(EU\/UK\)/);
    expect(secondary!.textContent).toMatch(/0C · 1W · 0I/);
    // A single-family document gets no "Also checked" line.
    expect(cards[1]!.querySelector(".multi-doc-card-secondary")).toBeNull();
  });

  it("renders detection_confidence next to the family label and flags low-confidence cards", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 3,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "msa.docx",
          family_label: "MSA",
          detection_confidence: 0.83,
          playbook_name: "MSA (Customer-Deep)",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
        cardDoc({
          filename: "borderline.docx",
          family_label: "DPA",
          detection_confidence: 0.32,
          playbook_name: "DPA",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
        cardDoc({
          filename: "no-conf.docx",
          family_label: "BAA",
          playbook_name: "BAA",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
      ],
    });
    const cards = dz.querySelectorAll<HTMLLIElement>('[data-role="multi-doc-card"]');
    // High-confidence card shows (0.83) and is NOT flagged low-confidence.
    expect(cards[0]!.textContent).toMatch(/MSA\s*\(0\.83\)/);
    expect(cards[0]!.classList.contains("low-confidence")).toBe(false);
    expect(cards[0]!.querySelector(".multi-doc-card-confidence")?.textContent).toBe("(0.83)");
    // Low-confidence card gets the .low-confidence class.
    expect(cards[1]!.textContent).toMatch(/DPA\s*\(0\.32\)/);
    expect(cards[1]!.classList.contains("low-confidence")).toBe(true);
    // Card without confidence shows no (X.XX) suffix and no .low-confidence flag.
    expect(cards[2]!.querySelector(".multi-doc-card-confidence")).toBeNull();
    expect(cards[2]!.classList.contains("low-confidence")).toBe(false);
  });

  it("multi-doc card playbook label is suffixed ' (legacy)' when playbook_deprecated is true", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 3,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "old-nda.docx",
          playbook_name: "Mutual NDA",
          playbook_deprecated: true,
          counts: { critical: 0, warning: 0, info: 0 },
        }),
        cardDoc({
          filename: "new-nda.docx",
          playbook_name: "Mutual NDA (Deep)",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
        cardDoc({
          filename: "explicit-non-deprecated.docx",
          playbook_name: "BAA",
          playbook_deprecated: false,
          counts: { critical: 0, warning: 0, info: 0 },
        }),
      ],
    });
    const cards = dz.querySelectorAll<HTMLLIElement>('[data-role="multi-doc-card"]');
    expect(cards[0]!.querySelector(".multi-doc-card-playbook")!.textContent).toBe(
      "Mutual NDA (legacy)",
    );
    expect(cards[1]!.querySelector(".multi-doc-card-playbook")!.textContent).toBe(
      "Mutual NDA (Deep)",
    );
    expect(cards[2]!.querySelector(".multi-doc-card-playbook")!.textContent).toBe("BAA");
  });

  it("clicking a card download button saves that doc's per-doc blob", async () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const msaDocx = new Blob(["msa-docx"], { type: "application/octet-stream" });
    const dpaJson = new Blob(['{"x":1}'], { type: "application/json" });
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["bundle-docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "bundle.docx",
      bundle_json_filename: "bundle.json",
      documents: [
        cardDoc({
          filename: "msa.docx",
          playbook_name: "MSA",
          counts: { critical: 0, warning: 0, info: 0 },
          docx_blob: msaDocx,
          docx_filename: "msa-vaulytica.docx",
        }),
        cardDoc({
          filename: "dpa.docx",
          playbook_name: "DPA",
          counts: { critical: 0, warning: 0, info: 0 },
          json_blob: dpaJson,
          json_filename: "dpa-vaulytica.json",
        }),
      ],
    });
    const seen: { download: string }[] = [];
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      seen.push({ download: this.download });
    };
    try {
      const wordBtns = dz.querySelectorAll<HTMLButtonElement>('[data-role="card-docx-download"]');
      const jsonBtns = dz.querySelectorAll<HTMLButtonElement>('[data-role="card-json-download"]');
      wordBtns[0]!.click(); // msa Word
      jsonBtns[1]!.click(); // dpa JSON
      for (let i = 0; i < 5; i++) await Promise.resolve();
      expect(seen.map((s) => s.download)).toEqual(["msa-vaulytica.docx", "dpa-vaulytica.json"]);
      expect(select(dz, "download-status")!.textContent).toMatch(/dpa-vaulytica\.json/);
    } finally {
      HTMLAnchorElement.prototype.click = origClick;
      document.body.removeChild(dz);
    }
  });

  it("card download click does not bubble to the dropzone (no re-open picker)", () => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    const onDzClick = vi.fn();
    dz.addEventListener("click", onDzClick);
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 1,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["b"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "b.docx",
      bundle_json_filename: "b.json",
      documents: [
        cardDoc({
          filename: "a.docx",
          playbook_name: "X",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
      ],
    });
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      /* swallow */
    };
    try {
      const btn = dz.querySelector<HTMLButtonElement>('[data-role="card-docx-download"]')!;
      btn.click();
      expect(onDzClick).not.toHaveBeenCalled();
    } finally {
      HTMLAnchorElement.prototype.click = origClick;
      document.body.removeChild(dz);
    }
  });

  it("bundle-complete hides multi-doc card list when no documents provided", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
    });
    expect(select<HTMLUListElement>(dz, "multi-doc-cards")!.hidden).toBe(true);
  });

  it("multi-doc card escapes filename and playbook HTML", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 1,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
      documents: [
        cardDoc({
          filename: "evil<script>.docx",
          playbook_name: "Playbook & Co.",
          counts: { critical: 0, warning: 0, info: 0 },
        }),
      ],
    });
    const card = dz.querySelector<HTMLLIElement>('[data-role="multi-doc-card"]')!;
    // No <script> element ever lands in the DOM. Attribute values
    // (e.g. aria-label) may serialize the literal "<script>" text
    // back into HTML, but that's a payload-in-an-attribute, not a
    // tag — the parser never executes it.
    expect(card.querySelector("script")).toBeNull();
    expect(card.querySelector(".multi-doc-card-filename")!.textContent).toBe("evil<script>.docx");
    expect(card.querySelector(".multi-doc-card-meta")!.textContent).toContain("Playbook & Co.");
  });

  it("bundle-complete hides detected-families line when none provided", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "x.docx",
      bundle_json_filename: "x.json",
    });
    expect(select(dz, "bundle-detected-families")!.hidden).toBe(true);
  });

  it("bundle-complete reports 'no inconsistencies' when zero cross-doc findings", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 0, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: new Blob(["docx"]),
      bundle_json_blob: new Blob(["{}"]),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
    });
    expect(select(dz, "cross-doc-summary")!.textContent).toMatch(/No cross-document/);
  });

  it("renders error state with a message", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "error", message: "Open it in Word…" });
    expect(dz.getAttribute("data-state")).toBe("error");
    expect(select(dz, "error-message")?.textContent).toBe("Open it in Word…");
  });
});

describe("input notice — the ingest's caveats about what it read", () => {
  const complete = () =>
    ({
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
    }) as const;

  it("is hidden when the ingest had nothing to say", () => {
    const dz = document.createElement("div");
    renderState(dz, complete());
    expect(select<HTMLElement>(dz, "input-notice")!.hidden).toBe(true);
  });

  it("shows every warning the ingest produced", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      ...complete(),
      input_warnings: ["This document has tracked changes.", "OCR fallback was used."],
    });
    const el = select<HTMLElement>(dz, "input-notice")!;
    expect(el.hidden).toBe(false);
    expect(el.querySelectorAll("li")).toHaveLength(2);
    expect(el.textContent).toContain("tracked changes");
    expect(el.textContent).toContain("OCR fallback");
  });

  it("escapes the warning text", () => {
    const dz = document.createElement("div");
    renderState(dz, { ...complete(), input_warnings: ["<img src=x onerror=alert(1)>"] });
    const el = select<HTMLElement>(dz, "input-notice")!;
    expect(el.querySelector("img")).toBeNull();
    expect(el.textContent).toContain("<img");
  });
});

/**
 * Every download button hands over the file it names.
 *
 * The complete state wires **nineteen** `wire(role, blob, filename)` triples,
 * and no test had ever clicked one. A list that long, written by copy-paste,
 * fails in a way nothing else catches: the button says "Obligations (CSV)",
 * the browser saves the deadlines calendar under a `.csv` name, and every
 * assertion about rendering still passes. The repo has met the family before —
 * a `.ics` served as `text/csv` opens in a spreadsheet.
 *
 * The check is content-addressed: each blob's bytes are the name of the role
 * it belongs to, so a crossed pair cannot pass. `saveBlob` prefers the File
 * System Access API, so a fake `showSaveFilePicker` captures both halves of
 * the promise — the suggested filename and the bytes actually written.
 */
describe("the complete state's download buttons", () => {
  type Saved = { name: string; text: string };

  async function clickAndCapture(dz: HTMLElement, role: string): Promise<Saved> {
    let written: Blob | undefined;
    let suggested = "";
    (window as unknown as Record<string, unknown>).showSaveFilePicker = (opts: {
      suggestedName: string;
    }) => {
      suggested = opts.suggestedName;
      return Promise.resolve({
        createWritable: () =>
          Promise.resolve({
            write: (b: Blob) => {
              written = b;
              return Promise.resolve();
            },
            close: () => Promise.resolve(),
          }),
      });
    };
    const btn = select<HTMLButtonElement>(dz, role);
    expect(btn, `no button for role ${role}`).not.toBeNull();
    btn!.click();
    // The click handler is async; let its microtasks drain.
    await new Promise((r) => setTimeout(r, 0));
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
    expect(written, `${role} saved nothing`).toBeDefined();
    return { name: suggested, text: await written!.text() };
  }

  /** A blob whose bytes ARE its role, so a crossed wire cannot pass. */
  const b = (role: string): Blob => new Blob([role], { type: "text/plain" });

  const EXPORTS = [
    ["export-fixlist-md", "fixlist_md"],
    ["export-fixlist-csv", "fixlist_csv"],
    ["export-obligations-csv", "obligations_csv"],
    ["export-deadlines-ics", "deadlines_ics"],
    ["export-html", "html"],
    ["export-sarif", "sarif"],
    ["export-closing-checklist-md", "closing_checklist_md"],
    ["export-closing-checklist-csv", "closing_checklist_csv"],
    ["export-critical-dates-ics", "critical_dates_ics"],
    ["export-critical-dates-md", "critical_dates_md"],
    ["export-negotiation-sheet", "negotiation_sheet"],
    ["export-negotiation-md", "negotiation_posture_md"],
    ["export-negotiation-csv", "negotiation_posture_csv"],
    ["export-certificate-docx", "certificate_docx"],
    ["export-certificate-json", "certificate_json"],
    ["export-definitions-csv", "definitions_csv"],
    ["export-definitions-json", "definitions_json"],
    ["export-reviewed-docx", "reviewed_docx"],
  ] as const;

  const state = () => {
    const ex: Record<string, Blob | string> = {};
    for (const [, key] of EXPORTS) {
      ex[`${key}_blob`] = b(key);
      ex[`${key}_filename`] = `nda-${key}.out`;
    }
    return {
      kind: "complete" as const,
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 1, warning: 0, info: 0 },
      docx_blob: b("report_docx"),
      json_blob: b("report_json"),
      docx_filename: "nda-vaulytica.docx",
      json_filename: "nda-vaulytica.json",
      exports: ex as never,
    };
  };

  it("saves the report itself under its own name", async () => {
    const dz = document.createElement("div");
    renderState(dz, state());
    expect(await clickAndCapture(dz, "docx-download")).toEqual({
      name: "nda-vaulytica.docx",
      text: "report_docx",
    });
    expect(await clickAndCapture(dz, "json-download")).toEqual({
      name: "nda-vaulytica.json",
      text: "report_json",
    });
  });

  it.each(EXPORTS)("%s saves its own artifact, not a neighbour's", async (role, key) => {
    const dz = document.createElement("div");
    renderState(dz, state());
    expect(await clickAndCapture(dz, role)).toEqual({ name: `nda-${key}.out`, text: key });
  });

  it("reports an empty blob instead of saving a zero-byte file", async () => {
    const dz = document.createElement("div");
    renderState(dz, { ...state(), docx_blob: new Blob([]) });
    select<HTMLButtonElement>(dz, "docx-download")!.click();
    await new Promise((r) => setTimeout(r, 0));
    expect(select(dz, "download-status")!.textContent).toMatch(/could not save/i);
  });
});

/**
 * The two panels a reviewer acts on before a document leaves the building —
 * "Clean to send?" and "Ready to sign?" — rendered by nobody's test.
 *
 * Both carry a sentence the product depends on: the pre-disclosure card
 * promises it "never certifies the document clean," and the checklist that it
 * "does not certify the document is ready to sign." Both are presence-only and
 * must disappear when there is nothing to say, because a panel that renders
 * empty reads as a clean bill.
 *
 * And both print text taken from the analyzed document. That is the one place
 * a document's own bytes reach the page as markup if `escapeHtml` is ever
 * dropped.
 */
describe("the pre-disclosure card", () => {
  const finding = (over: Record<string, unknown> = {}) => ({
    rule_id: "HANDOFF-002",
    severity: "critical" as const,
    title: "Tracked changes remain",
    description: "The file still carries redlines from the drafting round.",
    count: 3,
    evidence: ["ins by A. Drafter", "del by B. Reviewer", "ins by A. Drafter"],
    ...over,
  });
  const state = (delivery: unknown) =>
    ({
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["d"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "a.docx",
      json_filename: "a.json",
      delivery,
    }) as never;

  it("stays hidden for a clean, inspectable document", () => {
    const dz = document.createElement("div");
    renderState(dz, state({ inspectable: true, summary: "Nothing found.", findings: [] }));
    const el = select<HTMLElement>(dz, "delivery")!;
    expect(el.hidden).toBe(true);
    expect(el.innerHTML).toBe("");
  });

  it("shows what it found, and says it does not certify the document clean", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        inspectable: true,
        summary: "3 items to clear before sending.",
        findings: [finding()],
      }),
    );
    const el = select<HTMLElement>(dz, "delivery")!;
    expect(el.hidden).toBe(false);
    expect(el.textContent).toContain("HANDOFF-002");
    expect(el.textContent).toContain("Tracked changes remain");
    expect(el.textContent).toContain("3 items to clear before sending.");
    expect(el.textContent, "the card dropped its own disclaimer").toContain(
      "never certifies the document clean",
    );
    // The worst severity present drives the heading class.
    expect(el.innerHTML).toContain("delivery-heading-critical");
  });

  it("takes its heading severity from the worst finding, not the first", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        inspectable: true,
        summary: "s",
        findings: [
          finding({ severity: "info", rule_id: "HANDOFF-009" }),
          finding({ severity: "warning", rule_id: "HANDOFF-004" }),
        ],
      }),
    );
    expect(select<HTMLElement>(dz, "delivery")!.innerHTML).toContain("delivery-heading-warning");
  });

  it("caps the evidence it lists and names the remainder exactly", () => {
    const dz = document.createElement("div");
    const evidence = Array.from({ length: 9 }, (_, i) => `redline ${i}`);
    renderState(
      dz,
      state({
        inspectable: true,
        summary: "s",
        findings: [finding({ count: 40, evidence })],
      }),
    );
    const el = select<HTMLElement>(dz, "delivery")!;
    expect(el.textContent).toContain("redline 5");
    expect(el.textContent, "the seventh item was listed past the cap").not.toContain("redline 6");
    // 40 found, 6 shown: the number said has to be the number withheld.
    expect(el.textContent).toContain("and 34 more");
  });

  it("escapes document text rather than letting it become markup", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        inspectable: true,
        summary: "s",
        findings: [finding({ evidence: ['<img src=x onerror="boom">'] })],
      }),
    );
    const el = select<HTMLElement>(dz, "delivery")!;
    expect(el.querySelector("img"), "document text became a live element").toBeNull();
    expect(el.textContent).toContain("<img src=x");
  });
});

describe("the closing checklist", () => {
  const state = (closing_checklist: unknown) =>
    ({
      kind: "complete",
      filename: "spa.docx",
      playbook_name: "Stock Purchase Agreement",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["d"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "a.docx",
      json_filename: "a.json",
      closing_checklist,
    }) as never;

  it("stays hidden when there is nothing left to resolve", () => {
    const dz = document.createElement("div");
    renderState(dz, state({ open_count: 0, items: [] }));
    const el = select<HTMLElement>(dz, "closing-checklist")!;
    expect(el.hidden).toBe(true);
    expect(el.innerHTML).toBe("");
  });

  it("groups items by category, counts each group, and says it certifies nothing", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        open_count: 3,
        items: [
          { category: "handoff", rule_id: "HANDOFF-002", label: "Clear tracked changes" },
          { category: "signature", rule_id: "EXEC-001", label: "Signature block incomplete" },
          { category: "signature", rule_id: "EXEC-004", label: "No date line", section: "12.3" },
        ],
      }),
    );
    const el = select<HTMLElement>(dz, "closing-checklist")!;
    expect(el.hidden).toBe(false);
    expect(el.textContent).toContain("3 readiness items to resolve");
    expect(el.textContent).toContain("Signatures (2)");
    expect(el.textContent).toContain("Pre-send cleanup (1)");
    expect(el.textContent).toContain("§12.3");
    expect(el.textContent, "the checklist dropped its own disclaimer").toContain(
      "does not certify the document is ready to sign",
    );
    // Fixed category order: signatures before pre-send cleanup, whatever order
    // the items arrived in.
    const html = el.innerHTML;
    expect(html.indexOf("Signatures")).toBeLessThan(html.indexOf("Pre-send cleanup"));
  });

  it("says 'item' for one and 'items' for more", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        open_count: 1,
        items: [{ category: "blank", rule_id: "BLANK-001", label: "Unfilled [insert]" }],
      }),
    );
    expect(select<HTMLElement>(dz, "closing-checklist")!.textContent).toContain(
      "1 readiness item to resolve",
    );
  });
});

/**
 * The critical-dates register — "Your calendar, computed" — is the card whose
 * output an attorney copies into a diary. Nothing rendered it.
 *
 * Two of its rules are the ones this repo has been bitten by before. A row can
 * resolve to a WINDOW rather than a single day, and a card that printed one end
 * of a window would look right and be wrong (the report once printed the LOW
 * end of a liability cap for the same reason). And a row that could NOT be
 * computed must say "Verify manually" and why — never a date, and never
 * silence, because a missing row reads as a deadline that does not exist.
 */
describe("the critical-dates register", () => {
  const row = (over: Record<string, unknown> = {}) => ({
    rule_id: "TEMP-004",
    kind: "auto_renewal_notice",
    resolved: true,
    computed_date: "2026-11-30",
    trigger: "Auto-renewal notice deadline",
    anchor: "Effective Date",
    responsible: "Customer",
    ...over,
  });
  const state = (critical_dates: unknown) =>
    ({
      kind: "complete",
      filename: "saas.docx",
      playbook_name: "SaaS Subscription",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["d"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "a.docx",
      json_filename: "a.json",
      critical_dates,
    }) as never;

  it("stays hidden when the document computes to no dates", () => {
    const dz = document.createElement("div");
    renderState(dz, state({ resolved_count: 0, unresolved_count: 0, rows: [] }));
    const el = select<HTMLElement>(dz, "critical-dates")!;
    expect(el.hidden).toBe(true);
    expect(el.innerHTML).toBe("");
  });

  it("shows the computed date with its trigger, anchor and responsible party", () => {
    const dz = document.createElement("div");
    renderState(dz, state({ resolved_count: 1, unresolved_count: 0, rows: [row()] }));
    const el = select<HTMLElement>(dz, "critical-dates")!;
    expect(el.hidden).toBe(false);
    expect(el.textContent).toContain("2026-11-30");
    expect(el.textContent).toContain("Auto-renewal notice deadline");
    expect(el.textContent).toContain("anchor: Effective Date");
    expect(el.textContent).toContain("responsible: Customer");
    expect(el.textContent).toContain("1 computed · 0 to verify manually");
    expect(el.textContent, "the register dropped its own disclaimer").toContain(
      "not a determination that a deadline is met, missed, or binding",
    );
  });

  it("prints BOTH ends of a window, not one of them", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        resolved_count: 1,
        unresolved_count: 0,
        rows: [row({ computed_date: null, window: ["2026-09-01", "2026-10-01"] })],
      }),
    );
    const text = select<HTMLElement>(dz, "critical-dates")!.textContent ?? "";
    expect(text).toContain("2026-09-01");
    expect(text, "the far end of the window was not shown").toContain("2026-10-01");
  });

  it("says 'Verify manually' and why, rather than showing a date it could not compute", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        resolved_count: 0,
        unresolved_count: 1,
        rows: [
          row({
            resolved: false,
            computed_date: null,
            reason: "The Effective Date is left blank in the document.",
          }),
        ],
      }),
    );
    const el = select<HTMLElement>(dz, "critical-dates")!;
    expect(el.textContent).toContain("Verify manually");
    expect(el.textContent).toContain("The Effective Date is left blank");
    expect(el.textContent, "an uncomputable row still showed a date").not.toContain("2026-11-30");
    expect(el.innerHTML).toContain("cd-unresolved");
  });

  it("labels an unrecognized kind rather than rendering an empty one", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({ resolved_count: 1, unresolved_count: 0, rows: [row({ kind: "not_a_known_kind" })] }),
    );
    expect(select<HTMLElement>(dz, "critical-dates")!.textContent).toContain("Deadline");
  });

  it("escapes document text in the trigger and the anchor", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        resolved_count: 1,
        unresolved_count: 0,
        rows: [row({ trigger: '<img src=x onerror="boom">', anchor: "<b>Closing</b>" })],
      }),
    );
    const el = select<HTMLElement>(dz, "critical-dates")!;
    expect(el.querySelector("img"), "document text became a live element").toBeNull();
    expect(el.querySelector("b"), "document text became markup").toBeNull();
  });
});

/**
 * The jurisdiction-overlay card, and the honest gap it has to state.
 *
 * The overlays are the state-law layer — a non-compete that is void in
 * California, a security deposit capped in one state and not another. What
 * makes this card different from the others is `uncovered_states`: when the
 * document names a state the catalog has no overlay for, the card must say so
 * in terms — "an honest coverage gap, not a clean pass" — because silence
 * there is indistinguishable from "we checked and it is fine," which is the
 * single most expensive way a compliance tool can be wrong.
 */
describe("the jurisdiction-overlay card", () => {
  const overlay = (over: Record<string, unknown> = {}) => ({
    state_name: "California",
    posture: "prohibited" as const,
    topic: "non-compete",
    headline: "Void and unenforceable",
    summary: "California voids employee non-competes except on the sale of a business.",
    recommendation: "Remove the covenant or carve California out.",
    citation: { source: "Cal. Bus. & Prof. Code § 16600", source_url: "https://example.gov/16600" },
    ...over,
  });
  const state = (jurisdiction_overlays: unknown) =>
    ({
      kind: "complete",
      filename: "employment.docx",
      playbook_name: "Employment (at-will, US)",
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: new Blob(["d"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "a.docx",
      json_filename: "a.json",
      jurisdiction_overlays,
    }) as never;

  it("stays hidden when there is neither a match nor a gap", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({ family: "non-compete", states_in_catalog: 37, matched: [], uncovered_states: [] }),
    );
    const el = select<HTMLElement>(dz, "jurisdiction-overlays")!;
    expect(el.hidden).toBe(true);
    expect(el.innerHTML).toBe("");
  });

  it("shows the state, its posture, the recommendation and a citation link", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        family: "non-compete",
        states_in_catalog: 37,
        matched: [overlay()],
        uncovered_states: [],
      }),
    );
    const el = select<HTMLElement>(dz, "jurisdiction-overlays")!;
    expect(el.hidden).toBe(false);
    expect(el.textContent).toContain("California");
    expect(el.textContent).toContain("Void and unenforceable");
    expect(el.textContent).toContain("Remove the covenant");
    expect(el.textContent).toContain("37 states covered");
    expect(el.innerHTML).toContain("overlay-prohibited");
    const link = el.querySelector("a.overlay-cite") as HTMLAnchorElement | null;
    expect(link, "the citation had no link").not.toBeNull();
    expect(link!.getAttribute("href")).toBe("https://example.gov/16600");
    // A link that opens a new tab must not hand the opener to that page.
    expect(link!.getAttribute("rel")).toContain("noopener");
  });

  it("states an uncovered state as a coverage gap, not a pass", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        family: "non-compete",
        states_in_catalog: 37,
        matched: [overlay()],
        uncovered_states: ["us-nd", "us-wy"],
      }),
    );
    const text = select<HTMLElement>(dz, "jurisdiction-overlays")!.textContent ?? "";
    expect(text).toContain("ND, WY");
    expect(text, "the gap was not stated as a gap").toContain(
      "an honest coverage gap, not a clean pass",
    );
    expect(text).toContain("those states");
  });

  it("says it in the singular for one uncovered state, and shows the gap with no matches at all", () => {
    const dz = document.createElement("div");
    renderState(
      dz,
      state({
        family: "security-deposit",
        states_in_catalog: 51,
        matched: [],
        uncovered_states: ["us-nd"],
      }),
    );
    const el = select<HTMLElement>(dz, "jurisdiction-overlays")!;
    // The gap alone is enough to show the card: a document whose only state is
    // uncovered is exactly the case that must not render as silence.
    expect(el.hidden).toBe(false);
    expect(el.textContent).toContain("ND");
    expect(el.textContent).toContain("that state");
  });
});

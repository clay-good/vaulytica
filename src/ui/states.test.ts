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
  docx_blob: Blob;
  json_blob: Blob;
  docx_filename: string;
  json_filename: string;
} {
  return {
    filename: overrides.filename,
    family_label: overrides.family_label,
    detection_confidence: overrides.detection_confidence,
    playbook_name: overrides.playbook_name,
    playbook_deprecated: overrides.playbook_deprecated,
    counts: overrides.counts,
    docx_blob: overrides.docx_blob ?? new Blob(["docx"]),
    json_blob: overrides.json_blob ?? new Blob(["{}"]),
    docx_filename: overrides.docx_filename ?? `${overrides.filename}.docx`,
    json_filename: overrides.json_filename ?? `${overrides.filename}.json`,
  };
}

describe("renderState", () => {
  it("renders empty state with the v3 §63 headline + family-mentioning sub", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "empty" });
    expect(dz.getAttribute("data-state")).toBe("empty");
    expect(dz.querySelector(".dropzone-title")?.textContent).toMatch(/Drop a PDF/);
    expect(dz.querySelector(".dropzone-title")?.textContent).toMatch(/four/);
    const sub = dz.querySelector(".dropzone-sub")!.textContent ?? "";
    // Spec-v3 §63: empty-state mentions the new families.
    expect(sub).toMatch(/BAA/);
    expect(sub).toMatch(/DPA/);
    expect(sub).toMatch(/SCC/);
    expect(sub).toMatch(/nothing is uploaded/);
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
        fixlist_md_filename: "nda-vaulytica-fixlist.md",
        fixlist_csv_filename: "nda-vaulytica-fixlist.csv",
        obligations_csv_filename: "nda-vaulytica-obligations.csv",
        deadlines_ics_filename: "nda-vaulytica-deadlines.ics",
      },
    });
    const row = select(dz, "export-row")!;
    expect(row.hasAttribute("hidden")).toBe(false);
    expect(select(dz, "export-fixlist-md")!.textContent).toMatch(/Fix list \(Markdown\)/);
    expect(select(dz, "export-fixlist-csv")).not.toBeNull();
    expect(select(dz, "export-obligations-csv")).not.toBeNull();
    expect(select(dz, "export-deadlines-ics")!.textContent).toMatch(/Deadlines/);
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
    select<HTMLButtonElement>(dz, "comparison-reset")!.click();
    expect(onReset).toHaveBeenCalledTimes(1);
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
    expect(select(dz, "reasoning")!.textContent).toBe(
      "Auto-selected Mutual NDA. Legacy playbook.",
    );
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
      expect(select(dz, "download-status")!.textContent).toMatch(/Download started: nda-vaulytica\.docx/);
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
    (window as unknown as { showSaveFilePicker: unknown }).showSaveFilePicker = async (
      opts: { suggestedName?: string },
    ) => {
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
    chip.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
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
        { filename: "README.md", reason: "Vaulytica accepts .pdf and .docx — not \"README.md\"." },
        { filename: "scan.tiff", reason: "Vaulytica accepts .pdf and .docx — not \"scan.tiff\"." },
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
    const wordBtns = list.querySelectorAll<HTMLButtonElement>(
      '[data-role="card-docx-download"]',
    );
    const jsonBtns = list.querySelectorAll<HTMLButtonElement>(
      '[data-role="card-json-download"]',
    );
    expect(wordBtns.length).toBe(2);
    expect(jsonBtns.length).toBe(2);
    expect(wordBtns[0]!.getAttribute("aria-label")).toMatch(/Word.*msa\.docx/);
    expect(jsonBtns[1]!.getAttribute("aria-label")).toMatch(/JSON.*dpa\.docx/);
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
      const wordBtns = dz.querySelectorAll<HTMLButtonElement>(
        '[data-role="card-docx-download"]',
      );
      const jsonBtns = dz.querySelectorAll<HTMLButtonElement>(
        '[data-role="card-json-download"]',
      );
      wordBtns[0]!.click(); // msa Word
      jsonBtns[1]!.click(); // dpa JSON
      for (let i = 0; i < 5; i++) await Promise.resolve();
      expect(seen.map((s) => s.download)).toEqual([
        "msa-vaulytica.docx",
        "dpa-vaulytica.json",
      ]);
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
      const btn = dz.querySelector<HTMLButtonElement>(
        '[data-role="card-docx-download"]',
      )!;
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
    expect(card.querySelector(".multi-doc-card-filename")!.textContent).toBe(
      "evil<script>.docx",
    );
    expect(card.querySelector(".multi-doc-card-meta")!.textContent).toContain(
      "Playbook & Co.",
    );
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

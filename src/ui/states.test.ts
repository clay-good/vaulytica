import { describe, expect, it } from "vitest";
import { renderState, select } from "./states.js";

describe("renderState", () => {
  it("renders empty state with the icon + sub", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "empty" });
    expect(dz.getAttribute("data-state")).toBe("empty");
    expect(dz.querySelector(".dropzone-title")?.textContent).toMatch(/Drop a PDF/);
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
    expect(chip.textContent).toMatch(/Detected: BAA/);
    expect(chip.getAttribute("data-confidence")).toBe("75");
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

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

  it("renders complete state with counts, download URLs and reasoning", () => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: "nda.docx",
      playbook_name: "Mutual NDA",
      match_reasoning: "matched on title and recipient/discloser phrasing",
      counts: { critical: 2, warning: 5, info: 11 },
      docx_url: "blob:docx",
      json_url: "blob:json",
    });
    expect(dz.getAttribute("data-state")).toBe("complete");
    const docx = select<HTMLAnchorElement>(dz, "docx-download")!;
    const json = select<HTMLAnchorElement>(dz, "json-download")!;
    expect(docx.href).toContain("blob:docx");
    expect(json.href).toContain("blob:json");
    expect(docx.getAttribute("download")).toBe("nda-vaulytica.docx");
    expect(json.getAttribute("download")).toBe("nda-vaulytica.json");
    expect(select(dz, "counts")!.textContent).toMatch(/2/);
    expect(select(dz, "counts")!.textContent).toMatch(/5/);
    expect(select(dz, "counts")!.textContent).toMatch(/11/);
    expect(select(dz, "reasoning")!.textContent).toContain("matched on title");
  });

  it("renders error state with a message", () => {
    const dz = document.createElement("div");
    renderState(dz, { kind: "error", message: "Open it in Word…" });
    expect(dz.getAttribute("data-state")).toBe("error");
    expect(select(dz, "error-message")?.textContent).toBe("Open it in Word…");
  });
});

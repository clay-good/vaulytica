/**
 * The Download section (simplify-result-downloads): at most three named files
 * up front, every other export under "Other formats", nothing removed.
 */
import { describe, expect, it } from "vitest";
import { renderState, select, type DropzoneState } from "./states.js";

const b = (s: string) => new Blob([s], { type: "text/plain" });

function exports(
  over: Partial<Extract<DropzoneState, { kind: "complete" }>["exports"] & object> = {},
) {
  return {
    fixlist_md_blob: b("m"),
    fixlist_csv_blob: b("c"),
    obligations_csv_blob: b("o"),
    deadlines_ics_blob: b("i"),
    sarif_blob: b("s"),
    html_blob: b("h"),
    fixlist_md_filename: "a.md",
    fixlist_csv_filename: "a.csv",
    obligations_csv_filename: "o.csv",
    deadlines_ics_filename: "nda - dates.ics",
    sarif_filename: "a.sarif",
    html_filename: "a.html",
    certificate_docx_blob: b("cd"),
    certificate_json_blob: b("cj"),
    certificate_docx_filename: "c.docx",
    certificate_json_filename: "c.json",
    definitions_csv_blob: b("dc"),
    definitions_json_blob: b("dj"),
    definitions_csv_filename: "d.csv",
    definitions_json_filename: "d.json",
    abstract_csv_blob: b("ac"),
    abstract_json_blob: b("aj"),
    abstract_csv_filename: "nda.abstract.csv",
    abstract_json_filename: "nda.abstract.json",
    ...over,
  };
}

function render(ex: ReturnType<typeof exports>): HTMLElement {
  const dz = document.createElement("div");
  renderState(dz, {
    kind: "complete",
    filename: "nda.docx",
    playbook_name: "Mutual NDA",
    counts: { critical: 0, warning: 1, info: 0 },
    docx_blob: b("docx"),
    json_blob: b("json"),
    docx_filename: "nda - review.docx",
    json_filename: "nda.json",
    exports: ex,
  });
  return dz;
}

/** The download buttons a reader sees once "Download" is open and "Other formats" is not. */
function upFront(dz: HTMLElement): string[] {
  return Array.from(dz.querySelectorAll<HTMLElement>('[data-role="download-primary"] li'))
    .filter((li) => !li.hidden)
    .map((li) => li.querySelector("button")!.getAttribute("data-role")!);
}

describe("the Download section", () => {
  it("offers the draft with comments, the report and the calendar for a DOCX upload", () => {
    const dz = render(
      exports({ reviewed_docx_blob: b("r"), reviewed_docx_filename: "nda - with comments.docx" }),
    );
    expect(upFront(dz)).toEqual(["export-reviewed-docx", "docx-download", "export-deadlines-ics"]);
    expect((select(dz, "download-fold") as HTMLDetailsElement).open).toBe(false);
    expect((select(dz, "other-formats") as HTMLDetailsElement).open).toBe(false);
  });

  it("leads with the report for a PDF or pasted text, and shows no disabled button", () => {
    const dz = render(exports());
    expect(upFront(dz)).toEqual(["docx-download", "export-deadlines-ics"]);
    expect(dz.querySelectorAll("button[disabled]").length).toBe(0);
  });

  it("keeps an undated calendar under Other formats", () => {
    const dz = render(exports({ deadlines_dated: false }));
    expect(upFront(dz)).toEqual(["docx-download"]);
    const cal = select(dz, "export-deadlines-ics")!;
    expect(select(dz, "other-formats")!.contains(cal)).toBe(true);
  });

  it("keeps every export reachable inside the section", () => {
    const dz = render(
      exports({
        reviewed_docx_blob: b("r"),
        reviewed_docx_filename: "r.docx",
        closing_checklist_md_blob: b("x"),
        closing_checklist_md_filename: "x.md",
        closing_checklist_csv_blob: b("x"),
        closing_checklist_csv_filename: "x.csv",
        critical_dates_ics_blob: b("x"),
        critical_dates_ics_filename: "x.ics",
        critical_dates_md_blob: b("x"),
        critical_dates_md_filename: "x.md",
        negotiation_posture_md_blob: b("x"),
        negotiation_posture_md_filename: "x.md",
        negotiation_posture_csv_blob: b("x"),
        negotiation_posture_csv_filename: "x.csv",
        negotiation_sheet_blob: b("x"),
        negotiation_sheet_filename: "x.html",
      }),
    );
    const fold = select(dz, "download-fold")!;
    const roles = [
      "docx-download",
      "json-download",
      "export-reviewed-docx",
      "export-deadlines-ics",
      "export-fixlist-md",
      "export-fixlist-csv",
      "export-obligations-csv",
      "export-html",
      "export-sarif",
      "export-certificate-docx",
      "export-certificate-json",
      "export-definitions-csv",
      "export-definitions-json",
      "export-abstract-csv",
      "export-abstract-json",
      "export-closing-checklist-md",
      "export-closing-checklist-csv",
      "export-critical-dates-ics",
      "export-critical-dates-md",
      "export-negotiation-md",
      "export-negotiation-csv",
      "export-negotiation-sheet",
    ];
    for (const role of roles) {
      const el = select(dz, role);
      expect(el, role).not.toBeNull();
      expect(fold.contains(el!), role).toBe(true);
      expect(el!.hidden, role).toBe(false);
    }
  });

  it("puts the key terms under Other formats, and hides them when not built", () => {
    const dz = render(exports());
    const csv = select(dz, "export-abstract-csv")!;
    expect(select(dz, "other-formats")!.contains(csv)).toBe(true);
    expect(upFront(dz)).not.toContain("export-abstract-csv");
    const none = render(exports({ abstract_csv_blob: undefined, abstract_json_blob: undefined }));
    expect(select(none, "export-abstract-csv")!.hidden).toBe(true);
    expect(select(none, "export-abstract-json")!.hidden).toBe(true);
  });
});

describe("the bundle's Download section", () => {
  const bundle = (over: Record<string, unknown> = {}) => {
    const dz = document.createElement("div");
    renderState(dz, {
      kind: "bundle-complete",
      document_count: 2,
      counts: { critical: 0, warning: 1, info: 0 },
      cross_doc_findings: 0,
      bundle_docx_blob: b("docx"),
      bundle_json_blob: b("{}"),
      bundle_docx_filename: "vaulytica-bundle.docx",
      bundle_json_filename: "vaulytica-bundle.json",
      ...over,
    } as DropzoneState);
    return dz;
  };
  const shown = (dz: HTMLElement) =>
    Array.from(dz.querySelectorAll<HTMLElement>(".download-primary li"))
      .filter((li) => !li.hidden)
      .map((li) => li.querySelector("button")!.getAttribute("data-role")!);

  it("offers the inventory up front, its JSON under Other formats", () => {
    const dz = bundle({
      bundle_zip_blob: b("zip"),
      bundle_zip_filename: "vaulytica-bundle.zip",
      inventory_csv_blob: b("csv"),
      inventory_csv_filename: "vaulytica-inventory.csv",
      inventory_json_blob: b("json"),
      inventory_json_filename: "vaulytica-inventory.json",
    });
    expect(shown(dz)).toEqual([
      "bundle-download",
      "bundle-zip-download",
      "bundle-inventory-download",
    ]);
    const json = select(dz, "bundle-inventory-json-download")!;
    expect(json.hidden).toBe(false);
    expect(select(dz, "other-formats")!.contains(json)).toBe(true);
  });

  it("hides both when no inventory was built", () => {
    const dz = bundle();
    expect(shown(dz)).toEqual(["bundle-download"]);
    expect(select(dz, "bundle-inventory-json-download")!.hidden).toBe(true);
  });
});

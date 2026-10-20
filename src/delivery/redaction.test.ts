/**
 * Redaction integrity — HANDOFF-006, HANDOFF-007, HANDOFF-008
 * (add-redaction-integrity-scan).
 *
 * Each fixture hides a sentinel no other fixture uses, so the masking
 * assertion — no export contains the covered words — is a plain grep.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readContainer, maskShape } from "./container.js";
import { deriveHandoffFindings } from "./handoff.js";
import { scanDelivery } from "./index.js";
import { SEC_EXHIBIT_FAMILIES } from "./sec-exhibit.js";
import { buildDocx, documentXml } from "./_fixtures.js";

const run = (rPr: string, text: string): string =>
  `<w:r><w:rPr>${rPr}</w:rPr><w:t xml:space="preserve">${text}</w:t></w:r>`;
const para = (inner: string, pPr = ""): string =>
  `<w:p>${pPr ? `<w:pPr>${pPr}</w:pPr>` : ""}${inner}</w:p>`;
const docx = (...paragraphs: string[]): ArrayBuffer =>
  buildDocx({ document: documentXml(paragraphs.join("")) });

function pdf(body: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(`%PDF-1.7\n${body}\ntrailer\n<< >>\n%%EOF\n`);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

describe("HANDOFF-007 — text hidden by color in a DOCX", () => {
  it("finds black text on a black highlight, and reports its shape only", () => {
    const facts = readContainer(
      docx(
        para(
          run("", "The purchase price is ") +
            run('<w:highlight w:val="black"/>', "QUILLON 4417") +
            run("", "."),
        ),
      ),
      "docx",
      "",
    );
    expect(facts.redactions).toEqual([
      {
        kind: "docx-run",
        reason: "text in its own highlight color (black)",
        location: "paragraph 1",
        masked_shape: "xxxxxxx ####",
      },
    ]);
  });

  it("finds white text on the white page and text in its own shading", () => {
    const facts = readContainer(
      docx(
        para(run('<w:color w:val="FFFFFF"/>', "MARROWBY")),
        para(
          run(
            '<w:color w:val="000000"/><w:shd w:val="clear" w:color="auto" w:fill="000000"/>',
            "TESSELK",
          ),
        ),
        para(run('<w:color w:val="1F1F1F"/>', "VANTOLE"), '<w:shd w:val="clear" w:fill="1F1F1F"/>'),
      ),
      "docx",
      "",
    );
    expect(facts.redactions?.map((r) => [r.location, r.reason])).toEqual([
      ["paragraph 1", "white text on the white page"],
      ["paragraph 2", "text in its own shading color (#000000)"],
      ["paragraph 3", "text in its own shading color (#1F1F1F)"],
    ]);
  });

  it("does not report text a reader can see", () => {
    const facts = readContainer(
      docx(
        // An ordinary highlight.
        para(run('<w:highlight w:val="yellow"/>', "visible on yellow")),
        // Automatic color on dark shading: Word draws it white, so it is read.
        para(run('<w:shd w:val="clear" w:fill="000000"/>', "white on black, automatically")),
        // A black highlight over nothing but spaces hides no words.
        para(run('<w:highlight w:val="black"/>', "   ")),
        para(run("", "plain text")),
      ),
      "docx",
      "",
    );
    expect(facts.redactions).toBeUndefined();
  });

  it("joins consecutive covered runs in one paragraph into one redaction", () => {
    const hl = '<w:highlight w:val="black"/>';
    const facts = readContainer(docx(para(run(hl, "ORBEN ") + run(hl, "KASTRIL"))), "docx", "");
    expect(facts.redactions).toHaveLength(1);
    expect(facts.redactions?.[0]?.masked_shape).toBe("xxxxx xxxxxxx");
  });

  it("derives a critical finding that cites the shape, never the words", () => {
    const facts = readContainer(
      docx(para(run('<w:highlight w:val="black"/>', "QUILLON 4417"))),
      "docx",
      "",
    );
    const finding = deriveHandoffFindings(facts).find((f) => f.rule_id === "HANDOFF-007");
    expect(finding?.severity).toBe("critical");
    expect(finding?.evidence[0]).toContain("xxxxxxx ####");
    expect(JSON.stringify(finding)).not.toMatch(/QUILLON|4417/);
  });
});

describe("HANDOFF-006 — a PDF redaction mark that was never applied", () => {
  it("reports an unapplied /Redact annotation", () => {
    const facts = readContainer(
      pdf("1 0 obj\n<< /Type /Annot /Subtype /Redact /Rect [10 10 90 20] >>\nendobj"),
      "pdf",
      "",
    );
    expect(facts.redactions).toEqual([
      {
        kind: "pdf-redact-annotation",
        reason: "a redaction mark that was never applied",
        location: "annotation 1",
      },
    ]);
    const finding = deriveHandoffFindings(facts).find((f) => f.rule_id === "HANDOFF-006");
    expect(finding?.severity).toBe("critical");
  });

  it("reports nothing for a PDF without one", () => {
    const facts = readContainer(
      pdf("1 0 obj\n<< /Type /Annot /Subtype /Highlight /Rect [1 1 2 2] >>\nendobj"),
      "pdf",
      "",
    );
    expect(facts.redactions).toBeUndefined();
  });
});

describe("HANDOFF-008 — omission markers without the SEC first-page statement", () => {
  const MARKED =
    "SUPPLY AGREEMENT\n\nThe price is [***] per unit, payable as set out in Schedule [***].";
  const LEGEND =
    "Certain identified information has been excluded from this exhibit because it is both not material and is the type that the registrant treats as private or confidential. Omissions are marked [***].\n\n";

  const run008 = (text: string, secExhibit: boolean) =>
    deriveHandoffFindings(readContainer(new ArrayBuffer(0), "paste", text), [], {
      text,
      secExhibit,
    }).find((f) => f.rule_id === "HANDOFF-008");

  it("warns when an SEC exhibit marks omissions and its first page has no statement", () => {
    const finding = run008(MARKED, true);
    expect(finding?.severity).toBe("warning");
    expect(finding?.count).toBe(2);
    expect(finding?.evidence[1]).toMatch(/not found: .*not material/);
  });

  it("is silent when the statement is on the first page", () => {
    expect(run008(LEGEND + MARKED, true)).toBeUndefined();
  });

  it("is silent outside an SEC exhibit, and when nothing is marked", () => {
    expect(run008(MARKED, false)).toBeUndefined();
    expect(run008("SUPPLY AGREEMENT\n\nThe price is $4.00 per unit.", true)).toBeUndefined();
  });

  it("brings an SEC-exhibit type into scope by routing, and anything by assertion", async () => {
    const report = (playbookId?: string, secExhibit?: boolean) =>
      scanDelivery({
        bytes: new ArrayBuffer(0),
        source: "paste",
        text: MARKED,
        ...(playbookId ? { playbookId } : {}),
        ...(secExhibit ? { secExhibit } : {}),
      });
    const has008 = (r: Awaited<ReturnType<typeof report>>) =>
      r.findings.some((f) => f.rule_id === "HANDOFF-008");
    expect(has008(await report("manufacturing-supply-agreement"))).toBe(true);
    expect(has008(await report("lease-residential-us"))).toBe(false);
    expect(has008(await report("lease-residential-us", true))).toBe(true);
  });

  it("holds its type list equal to the EDGAR routing labels", () => {
    const labels = JSON.parse(
      readFileSync(join(process.cwd(), "corpus", "routing", "labels.json"), "utf8"),
    ) as Array<{ exact?: string; acceptable?: string[] }>;
    const fromLabels = new Set(
      labels.flatMap((l) => [l.exact, ...(l.acceptable ?? [])]).filter(Boolean),
    );
    expect([...SEC_EXHIBIT_FAMILIES].sort()).toEqual([...fromLabels].sort());
  });
});

describe("the masking invariant", () => {
  it("no serialized delivery report carries a covered word", async () => {
    const SENTINELS = ["QUILLON", "MARROWBY", "TESSELK"];
    const bytes = docx(
      para(run('<w:highlight w:val="black"/>', "QUILLON")),
      para(run('<w:color w:val="FFFFFF"/>', "MARROWBY")),
      para(run('<w:shd w:val="clear" w:fill="000000"/><w:color w:val="000000"/>', "TESSELK")),
    );
    const report = await scanDelivery({ bytes, source: "docx", text: "" });
    expect(report.findings.some((f) => f.rule_id === "HANDOFF-007")).toBe(true);
    const serialized = JSON.stringify(report);
    for (const s of SENTINELS) expect(serialized).not.toContain(s);
  });

  it("masks letters and digits in any script, keeping spacing", () => {
    expect(maskShape("Ab 12 Éé ٣")).toBe("xx ## xx #");
  });

  it("leaves a document with no redaction byte-identical (no `redactions` key)", async () => {
    const plain = await scanDelivery({
      bytes: docx(para(run("", "Nothing hidden here."))),
      source: "docx",
      text: "Nothing hidden here.",
    });
    expect(plain.findings).toEqual([]);
    const facts = readContainer(docx(para(run("", "Nothing hidden here."))), "docx", "");
    expect("redactions" in facts).toBe(false);
  });
});

describe("HANDOFF-007 — theme colors", () => {
  const THEME =
    '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:themeElements><a:clrScheme name="Office">' +
    '<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>' +
    '<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>' +
    '<a:dk2><a:srgbClr val="44546A"/></a:dk2><a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>' +
    '<a:accent1><a:srgbClr val="4472C4"/></a:accent1>' +
    "</a:clrScheme></a:themeElements></a:theme>";
  const themed = (theme: string | undefined, ...paragraphs: string[]): ArrayBuffer =>
    buildDocx({ document: documentXml(paragraphs.join("")), ...(theme ? { theme } : {}) });
  const facts = (bytes: ArrayBuffer) => readContainer(bytes, "docx", "");

  it("reads white-on-white written as a theme color with no hex", () => {
    const f = facts(
      themed(
        THEME,
        para(
          run("", "The fee is ") + run('<w:color w:themeColor="background1"/>', "TAMBRIEL 3301"),
        ),
      ),
    );
    expect(f.redactions?.map((r) => r.reason)).toEqual(["white text on the white page"]);
    expect(JSON.stringify(f)).not.toContain("TAMBRIEL");
  });

  it("reads theme text on theme shading of the same slot", () => {
    const f = facts(
      themed(
        THEME,
        para(
          run(
            '<w:color w:val="000000" w:themeColor="text1"/><w:shd w:val="clear" w:color="auto" w:fill="000000" w:themeFill="text1"/>',
            "TAMBRIEL 3302",
          ),
        ),
      ),
    );
    expect(f.redactions).toHaveLength(1);
  });

  it("paints the theme color, not the stated fallback, as Word does", () => {
    // Stated black, themed background1 (white): on the white page it is invisible.
    const f = facts(
      themed(
        THEME,
        para(run('<w:color w:val="000000" w:themeColor="background1"/>', "TAMBRIEL 3303")),
      ),
    );
    expect(f.redactions).toHaveLength(1);
  });

  it("does not guess a tinted theme color, or one with no theme to read, and says so", () => {
    const tinted = facts(
      themed(THEME, para(run('<w:color w:themeColor="text1" w:themeTint="80"/>', "TAMBRIEL 3304"))),
    );
    expect(tinted.redactions).toBeUndefined();
    expect(tinted.note).toMatch(/1 run uses a theme color .* not checked for text hidden by color/);
    const noTheme = facts(
      themed(undefined, para(run('<w:color w:themeColor="background1"/>', "TAMBRIEL 3305"))),
    );
    expect(noTheme.redactions).toBeUndefined();
    expect(noTheme.note).toMatch(/theme color/);
  });

  it("leaves ordinary theme-colored text alone", () => {
    const f = facts(
      themed(THEME, para(run('<w:color w:themeColor="accent1"/>', "Visible heading"))),
    );
    expect(f.redactions).toBeUndefined();
    expect(f.note ?? "").not.toMatch(/theme color/);
  });
});

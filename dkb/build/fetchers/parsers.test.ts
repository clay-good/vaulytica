import { describe, expect, it } from "vitest";
import {
  parseEdgarSearchHits,
  parseUslmXml,
  parseEcfrXml,
  parsePublicLawXml,
  parseCommonPaperMarkdown,
  parseCuadRows,
  parseLedgarRows,
  ulcActToStatute,
  ULC_ACTS,
} from "./index.js";

describe("parseEdgarSearchHits", () => {
  it("turns each hit into a classifier-example record keyed by file type", () => {
    const fixture = JSON.stringify({
      hits: {
        total: { value: 2 },
        hits: [
          {
            _id: "0001",
            _source: {
              ciks: ["0000320193"],
              display_names: ["Apple Inc."],
              form: "10-K",
              file_type: "EX-10.1",
              file_date: "2025-09-30",
            },
          },
          {
            _id: "0002",
            _source: {
              ciks: ["0000789019"],
              display_names: ["Microsoft Corp."],
              form: "10-Q",
              file_type: "EX-2.1",
              file_date: "2025-07-31",
            },
          },
        ],
      },
    });
    const records = parseEdgarSearchHits(fixture);
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({
      kind: "classifier-example",
      data: { id: "edgar/0001", category: "edgar-ex10" },
    });
    expect(records[1]).toMatchObject({
      kind: "classifier-example",
      data: { id: "edgar/0002", category: "edgar-ex2" },
    });
  });
});

describe("parseUslmXml", () => {
  it("extracts each <section> with citation and excerpt", () => {
    const xml = `<?xml version="1.0"?>
      <code>
        <section>
          <num>§ 2</num>
          <heading>Validity, irrevocability, and enforcement of agreements to arbitrate</heading>
          <content>A written provision in any maritime transaction or a contract evidencing a transaction…</content>
        </section>
      </code>`;
    const out = parseUslmXml(xml, 9, "2026-05-12T00:00:00Z");
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe("usc-9-2");
    expect(out[0]?.citation).toBe("9 U.S.C. § 2");
    expect(out[0]?.canonical_url).toContain("title9-section2");
    expect(out[0]?.excerpt).toContain("Validity");
  });

  it("skips sections without a <num>", () => {
    const xml = `<?xml version="1.0"?>
      <code><section><heading>Untitled</heading></section></code>`;
    expect(parseUslmXml(xml, 11, "2026-05-12T00:00:00Z")).toHaveLength(0);
  });
});

describe("parseEcfrXml", () => {
  it("extracts DIV8 sections as CFR records", () => {
    const xml = `<?xml version="1.0"?>
      <CFR>
        <DIV8 N="240.10b-5">
          <HEAD>§ 240.10b-5 Employment of manipulative and deceptive devices.</HEAD>
          <P>It shall be unlawful for any person…</P>
        </DIV8>
      </CFR>`;
    const out = parseEcfrXml(xml, 17, "2026-05-12T00:00:00Z");
    expect(out[0]?.citation).toBe("17 C.F.R. § 240.10b-5");
    expect(out[0]?.canonical_url).toContain("title-17/section-240.10b-5");
  });
});

describe("parsePublicLawXml", () => {
  it("yields citation 'Pub. L. No. 118-N' per publiclaw element", () => {
    const xml = `<?xml version="1.0"?>
      <root>
        <publiclaw congress="118" num="42">
          <title>An Act to do something specific.</title>
        </publiclaw>
      </root>`;
    const out = parsePublicLawXml(xml, "2026-05-12T00:00:00Z");
    expect(out[0]?.citation).toBe("Pub. L. No. 118-42");
    expect(out[0]?.canonical_url).toContain("PLAW-118publ42");
  });
});

describe("parseCommonPaperMarkdown", () => {
  it("splits on H2 and emits one clause per heading", () => {
    const md = `# Mutual NDA\n\n## Confidentiality\nRecipient shall protect.\n\n## Term\nThis Agreement is effective for two years.\n`;
    const out = parseCommonPaperMarkdown(
      md,
      "mutual-nda",
      "https://raw.githubusercontent.com/CommonPaper/Mutual-NDA/main/README.md",
      "2026-05-12T00:00:00Z",
      "CC-BY-4.0",
      "https://creativecommons.org/licenses/by/4.0/",
    );
    expect(out).toHaveLength(2);
    expect(out[0]?.category).toBe("confidentiality");
    expect(out[1]?.category).toBe("term");
    expect(out[0]?.source.attribution).toContain("CC BY 4.0");
  });
});

describe("parseCuadRows", () => {
  it("turns CUAD answer rows into classifier examples", () => {
    const fixture = JSON.stringify({
      rows: [
        {
          row_idx: 7,
          row: {
            question: "Highlight the parts related to 'Governing Law'.",
            answers: { text: ["This Agreement is governed by the laws of Delaware."] },
          },
        },
        {
          row_idx: 8,
          row: {
            question: "Highlight 'Anti-Assignment'.",
            answers: { text: [] },
          },
        },
      ],
    });
    const out = parseCuadRows(fixture);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      kind: "classifier-example",
      data: { category: "governing-law" },
    });
  });
});

describe("parseLedgarRows", () => {
  it("uses ClassLabel names when available", () => {
    const fixture = JSON.stringify({
      features: [{ name: "label", type: { _type: "ClassLabel", names: ["governing-law", "term"] } }],
      rows: [
        { row_idx: 0, row: { text: "Governed by Delaware.", label: 0 } },
        { row_idx: 1, row: { text: "Two-year term.", label: 1 } },
      ],
    });
    const out = parseLedgarRows(fixture);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ data: { category: "governing-law" } });
    expect(out[1]).toMatchObject({ data: { category: "term" } });
  });

  it("falls back to string labels when no ClassLabel is supplied", () => {
    const fixture = JSON.stringify({
      rows: [{ row_idx: 9, row: { text: "x", label: "Custom Label" } }],
    });
    const out = parseLedgarRows(fixture);
    expect(out[0]).toMatchObject({ data: { category: "custom-label" } });
  });
});

describe("ulcActToStatute / ULC_ACTS", () => {
  it("ships at least UETA and UCC Article 2", () => {
    const ids = ULC_ACTS.map((a) => a.id);
    expect(ids).toContain("ueta");
    expect(ids).toContain("ucc-article-2");
  });

  it("ulcActToStatute builds the statute record stub", () => {
    const stat = ulcActToStatute(ULC_ACTS[0]!, "2026-05-12T00:00:00Z", "Some excerpt text");
    expect(stat.id.startsWith("ulc-")).toBe(true);
    expect(stat.jurisdiction).toBe("us-federal");
    expect(stat.retrieved_at).toBe("2026-05-12T00:00:00Z");
    expect(stat.excerpt).toBe("Some excerpt text");
  });
});

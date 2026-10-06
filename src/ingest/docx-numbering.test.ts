import { describe, expect, it } from "vitest";
import {
  AlignmentType,
  Document,
  HeadingLevel,
  LevelFormat,
  Packer,
  Paragraph,
  TextRun,
} from "docx";
import { numberingLabels } from "./docx-numbering.js";
import { ingestDocxBuffer } from "./docx.js";
import { forEachParagraph, forEachSection } from "../extract/walk.js";

// A contract numbered the way Word numbers one: the numbers live in the list
// definition, not in the text, and a numbered HEADING reaches mammoth's HTML
// with no number at all.
async function wordNumbered(): Promise<ArrayBuffer> {
  const heading = (text: string, level: number) =>
    new Paragraph({
      text,
      heading: level === 0 ? HeadingLevel.HEADING_1 : HeadingLevel.HEADING_2,
      numbering: { reference: "articles", level },
    });
  const item = (text: string) =>
    new Paragraph({ children: [new TextRun(text)], numbering: { reference: "items", level: 0 } });
  const body = (text: string) => new Paragraph({ children: [new TextRun(text)] });
  const doc = new Document({
    numbering: {
      config: [
        {
          reference: "articles",
          levels: [
            {
              level: 0,
              format: LevelFormat.UPPER_ROMAN,
              text: "Article %1",
              alignment: AlignmentType.START,
            },
            {
              level: 1,
              format: LevelFormat.DECIMAL,
              text: "Section %1.%2",
              alignment: AlignmentType.START,
              isLegalNumberingStyle: true,
            },
          ],
        },
        {
          reference: "items",
          levels: [
            {
              level: 0,
              format: LevelFormat.LOWER_LETTER,
              text: "(%1)",
              alignment: AlignmentType.START,
            },
          ],
        },
      ],
    },
    sections: [
      {
        children: [
          heading("Definitions", 0),
          body("Capitalized terms have their defined meanings."),
          heading("Services", 0),
          heading("Scope", 1),
          body("Provider shall:"),
          item("design the system;"),
          item("deliver it."),
          heading("Fees", 1),
          body("Customer shall pay as set out in Section 2.1."),
        ],
      },
    ],
  });
  const buf = await Packer.toBuffer(doc);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

describe("numberingLabels — Word's automatic numbering, as Word shows it", () => {
  it("renders each level's format and a legal-style label", async () => {
    const labels = numberingLabels(await wordNumbered());
    expect(labels.get("Definitions")).toEqual(["Article I"]);
    expect(labels.get("Services")).toEqual(["Article II"]);
    expect(labels.get("Scope")).toEqual(["Section 2.1"]);
    expect(labels.get("Fees")).toEqual(["Section 2.2"]);
    expect(labels.get("design the system;")).toEqual(["(a)"]);
    expect(labels.get("deliver it.")).toEqual(["(b)"]);
  });
});

describe("ingestDocxBuffer — a numbered heading keeps its number", () => {
  it("writes the label into the heading and the list item", async () => {
    const tree = (await ingestDocxBuffer(await wordNumbered())).tree;
    const headings: string[] = [];
    forEachSection(tree, (s) => headings.push(s.heading));
    expect(headings).toEqual([
      "Article I Definitions",
      "Article II Services",
      "Section 2.1 Scope",
      "Section 2.2 Fees",
    ]);
    const paragraphs: string[] = [];
    forEachParagraph(tree, (p) => paragraphs.push(p.text));
    expect(paragraphs).toContain("(a) design the system;");
  });
});

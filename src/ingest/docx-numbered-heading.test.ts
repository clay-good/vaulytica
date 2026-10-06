import { describe, expect, it } from "vitest";
import { detectNumberedHeading } from "./docx.js";

// A DOCX often types its numbered headings as plain (bold) paragraphs; the
// ingest promotes them by shape. Run against every heading-bearing specimen
// rendered as a DOCX, the shape test missed every heading with a comma and
// promoted street addresses instead, and the outline rules reported sections
// "missing" that were present and sections 1400 and 440 that were addresses.
describe("detectNumberedHeading", () => {
  it.each([
    ["1. INVENTORY, PLACEMENTS, AND IMPRESSIONS", 2],
    ["4. Compliance with Laws, Rules, and Regulations", 2],
    ["3.2 Invoicing and Payment", 3],
    ["12 Definitions", 2],
  ])("promotes %s", (text, level) => {
    expect(detectNumberedHeading(text)).toEqual({ level });
  });

  it.each([
    "1400 Preston Road, Suite 620",
    "440 North Wells Street, Suite 720",
    "77 Mill Brook Road",
    "2210 West Fulton Street",
    "Chicago, Illinois 60654",
    "1. The Buyer shall pay. the balance",
  ])("leaves %s as body text", (text) => {
    expect(detectNumberedHeading(text)).toBeNull();
  });
});

describe("a plain-typed numbered heading among styled siblings", () => {
  it("takes its siblings' level instead of nesting under a neighbour", async () => {
    const { Document, HeadingLevel, Packer, Paragraph } = await import("docx");
    const { ingestDocxBuffer } = await import("./docx.js");
    const doc = new Document({
      sections: [
        {
          children: [
            new Paragraph({ text: "WELCOME", heading: HeadingLevel.HEADING_1 }),
            new Paragraph({ text: "1. Purpose and Scope" }),
            new Paragraph({ text: "This handbook is not a contract." }),
            new Paragraph({
              text: "2. Changes to This Handbook.",
              heading: HeadingLevel.HEADING_1,
            }),
            new Paragraph({ text: "The Company may change this handbook." }),
            new Paragraph({ text: "3. Hours of Work" }),
            new Paragraph({ text: "Employees record their time." }),
          ],
        },
      ],
    });
    const buf = await Packer.toBuffer(doc);
    const { tree } = await ingestDocxBuffer(
      buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer,
    );
    const top = tree.sections.map((s) => s.heading);
    expect(top).toEqual(
      expect.arrayContaining([
        "1. Purpose and Scope",
        "2. Changes to This Handbook.",
        "3. Hours of Work",
      ]),
    );
  });
});

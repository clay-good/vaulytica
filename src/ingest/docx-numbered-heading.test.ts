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

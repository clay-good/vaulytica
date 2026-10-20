/**
 * The two readings of one redline (add-redline-two-sided-analysis).
 */
import { describe, expect, it } from "vitest";
import { buildDocx, documentXml, REDLINE } from "../delivery/_fixtures.js";
import { ingestDocxBuffer } from "./docx.js";
import { collectRevisionTexts, rejectedDocumentXml } from "./docx-revisions.js";
import type { DocumentTree } from "./types.js";

const text = (tree: DocumentTree): string => {
  const out: string[] = [];
  const walk = (ss: DocumentTree["sections"]) => {
    for (const s of ss) {
      if (s.heading) out.push(s.heading);
      for (const p of s.paragraphs) out.push(p.runs.map((r) => r.text).join(""));
      walk(s.children);
    }
  };
  walk(tree.sections);
  return out.join("\n");
};

describe("the rejected reading of a redline", () => {
  it("is the draft as it stood: deletions back, insertions gone", async () => {
    const bytes = buildDocx({ document: REDLINE });
    const accepted = await ingestDocxBuffer(bytes);
    const rejected = await ingestDocxBuffer(bytes, { revisions: "rejected" });
    expect(text(accepted.tree)).toContain("indemnify Buyer against all losses without limit");
    expect(text(accepted.tree)).not.toContain("capped at the fees");
    expect(text(accepted.tree)).toContain("within sixty days");

    expect(text(rejected.tree)).toContain("capped at the fees paid in the prior twelve months");
    expect(text(rejected.tree)).not.toContain("without limit");
    expect(text(rejected.tree)).toContain("within thirty days");
    // The moved sentence is where it started, once.
    expect(text(rejected.tree)).toMatch(/3\. Notices\. Notices are effective on receipt\./);
    expect(text(rejected.tree).match(/effective on receipt/g)).toHaveLength(1);
  });

  it("is the same bytes, and says which reading it is", async () => {
    const bytes = buildDocx({ document: REDLINE });
    const accepted = await ingestDocxBuffer(bytes);
    const rejected = await ingestDocxBuffer(bytes, { revisions: "rejected" });
    expect(rejected.sha256).toBe(accepted.sha256);
    expect(accepted.warnings.join(" ")).toMatch(/as if every change were ACCEPTED/);
    expect(rejected.warnings.join(" ")).toMatch(/every change REJECTED/);
  });

  it("reads a document without tracked changes the same either way", async () => {
    const bytes = buildDocx({
      document: documentXml(`<w:p><w:r><w:t>Vendor shall perform.</w:t></w:r></w:p>`),
    });
    const a = await ingestDocxBuffer(bytes);
    const b = await ingestDocxBuffer(bytes, { revisions: "rejected" });
    expect(b.tree).toEqual(a.tree);
    expect(b.warnings).toEqual(a.warnings);
  });
});

describe("rejectedDocumentXml", () => {
  it("leaves no revision element behind", () => {
    const out = rejectedDocumentXml(REDLINE);
    expect(out).not.toMatch(
      /<w:(?:ins|del|moveFrom|moveTo)\b|<\/w:(?:ins|del|moveFrom|moveTo)>|w:delText/,
    );
    // ...and no tag it did not mean to touch.
    expect(rejectedDocumentXml('<w:tblBorders><w:insideH w:val="single"/></w:tblBorders>')).toBe(
      '<w:tblBorders><w:insideH w:val="single"/></w:tblBorders>',
    );
  });

  it("leaves an element never closed as written, and stays linear", () => {
    expect(rejectedDocumentXml('<w:p><w:ins w:author="X"><w:r><w:t>a</w:t>')).toBe(
      '<w:p><w:ins w:author="X"><w:r><w:t>a</w:t>',
    );
    const open = '<w:ins w:author="X">'.repeat(20_000);
    const t = performance.now();
    rejectedDocumentXml(open);
    expect(performance.now() - t).toBeLessThan(2_000);
  });
});

describe("collectRevisionTexts", () => {
  it("reads each change's kind, author and text, and skips the empty markers", () => {
    const revs = collectRevisionTexts(REDLINE);
    expect(revs).toContainEqual({
      kind: "insertion",
      author: "Opposing Counsel",
      text: "Supplier shall indemnify Buyer against all losses without limit.",
    });
    expect(revs).toContainEqual({
      kind: "deletion",
      author: "Opposing Counsel",
      text: "Each party's total liability is capped at the fees paid in the prior twelve months.",
    });
    // The move counts on both sides; the paragraph-mark marker carries no text.
    expect(
      revs.filter((r) => r.text === "Notices are effective on receipt.").map((r) => r.kind),
    ).toEqual(["insertion", "deletion"]);
    expect(revs.every((r) => r.text.trim().length > 0)).toBe(true);
  });

  it("decodes entities and keeps an authorless change without an author", () => {
    expect(collectRevisionTexts('<w:ins w:id="1"><w:r><w:t>A &amp; B</w:t></w:r></w:ins>')).toEqual(
      [{ kind: "insertion", text: "A & B" }],
    );
  });
});

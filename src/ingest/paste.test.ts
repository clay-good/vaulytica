import { describe, expect, it } from "vitest";
import { ingestPaste } from "./paste.js";
import { forEachParagraph } from "../extract/walk.js";

describe("ingestPaste", () => {
  it("produces a single-section tree from a plain paragraph", async () => {
    const r = await ingestPaste("Hello world.\n\nAnother paragraph.");
    expect(r.source).toBe("paste");
    expect(r.tree.sections).toHaveLength(1);
    expect(r.tree.sections[0]!.paragraphs).toHaveLength(2);
    expect(r.warnings[0]).toMatch(/pasted text loses/i);
  });

  it("detects ATX headings", async () => {
    const r = await ingestPaste("# Title\n\nSome body.\n\n## Sub\n\nMore body.");
    expect(r.tree.sections).toHaveLength(1);
    expect(r.tree.sections[0]!.heading).toBe("Title");
    expect(r.tree.sections[0]!.children).toHaveLength(1);
    expect(r.tree.sections[0]!.children[0]!.heading).toBe("Sub");
    expect(r.tree.sections[0]!.children[0]!.level).toBe(2);
  });

  it("detects Setext headings (=== for H1, --- for H2)", async () => {
    const r = await ingestPaste(
      "Big Title\n===========\n\nBody.\n\nSubsection\n----------\n\nMore.",
    );
    expect(r.tree.sections[0]!.heading).toBe("Big Title");
    expect(r.tree.sections[0]!.children[0]!.heading).toBe("Subsection");
    expect(r.tree.sections[0]!.children[0]!.level).toBe(2);
  });

  it("keeps a sentence followed by a rule of dashes in the scannable paragraph stream", async () => {
    // A clause line followed by a `---` separator must NOT be promoted to a
    // Setext heading — headings leave the paragraph stream and escape every
    // paragraph-based rule, a silent false negative. The rule line is dropped
    // as a visual separator; the clause stays a paragraph.
    const r = await ingestPaste(
      "Executive shall not compete with the Company for two years.\n------------------------\nThe remainder is standard.",
    );
    const paras: string[] = [];
    forEachParagraph(r.tree, (p) => paras.push(p.text));
    expect(paras).toContain("Executive shall not compete with the Company for two years.");
    // The dashes are dropped, not folded into the clause text.
    expect(paras.some((t) => t.includes("---"))).toBe(false);
    // Nothing was promoted to a heading.
    const headings: string[] = [];
    const walk = (secs: typeof r.tree.sections): void =>
      secs.forEach((s) => {
        if (s.heading) headings.push(s.heading);
        walk(s.children);
      });
    walk(r.tree.sections);
    expect(headings).toEqual([]);
  });

  it("computes a deterministic sha256 over the input text", async () => {
    const a = await ingestPaste("identical");
    const b = await ingestPaste("identical");
    expect(a.sha256).toEqual(b.sha256);
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("counts words", async () => {
    const r = await ingestPaste("one two three four");
    expect(r.word_count).toBe(4);
  });
});

/**
 * An ingest owes a caveat to a document it could read NOTHING out of.
 *
 * A zero-byte file used to come back with a full analysis and no mention of
 * being empty: `word_count: 0`, and three findings telling the reader the
 * document has no parties identified, no Effective Date and no defined terms.
 * Every one is true of nothing at all, and the only caveat it carried was the
 * generic "pasted text loses structure" note.
 *
 * The findings are deliberately left alone — a presence rule firing on a
 * document with no legal content is documented behaviour — and what was
 * missing is the ingest saying what it read, which is the ingest's whole job.
 */
describe("ingestPaste — a file with no readable text", () => {
  it("warns when the paste is empty", async () => {
    const r = await ingestPaste("");
    expect(r.word_count).toBe(0);
    expect(r.warnings.some((w) => w.startsWith("No readable text was found"))).toBe(true);
  });

  it("warns when the paste is only whitespace and punctuation", async () => {
    const r = await ingestPaste("\n\n   \t\n");
    expect(r.word_count).toBe(0);
    expect(r.warnings.some((w) => w.startsWith("No readable text was found"))).toBe(true);
  });

  it("says nothing of the kind for a document that has text", async () => {
    const r = await ingestPaste("AGREEMENT\n\nProvider shall deliver the Services.\n");
    expect(r.word_count).toBeGreaterThan(0);
    expect(r.warnings.some((w) => w.startsWith("No readable text was found"))).toBe(false);
  });

  it("tells the reader the findings are about an empty document", async () => {
    const r = await ingestPaste("");
    const w = r.warnings.find((x) => x.startsWith("No readable text was found"))!;
    // The sentence has to say what it MEANS for the report, not just report a
    // number — a reader who sees "0 words" still reads the findings below it.
    expect(w).toContain("about an empty document");
    expect(w).toContain("scanned image");
  });
});

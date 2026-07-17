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

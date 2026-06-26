import { describe, expect, it } from "vitest";
import { ingestPaste } from "./paste.js";

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

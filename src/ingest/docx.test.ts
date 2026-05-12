import { describe, expect, it } from "vitest";
import { parseDocxHtml } from "./docx.js";

describe("parseDocxHtml", () => {
  it("uses the first heading as the top section heading", () => {
    const tree = parseDocxHtml("<h1>Agreement</h1><p>Body.</p>");
    expect(tree.sections).toHaveLength(1);
    expect(tree.sections[0]!.heading).toBe("Agreement");
    expect(tree.sections[0]!.level).toBe(1);
    expect(tree.sections[0]!.paragraphs).toHaveLength(1);
  });

  it("nests h2 under h1", () => {
    const tree = parseDocxHtml(
      "<h1>Top</h1><p>p1</p><h2>Sub</h2><p>p2</p>",
    );
    expect(tree.sections).toHaveLength(1);
    const top = tree.sections[0]!;
    expect(top.heading).toBe("Top");
    expect(top.paragraphs).toHaveLength(1);
    expect(top.children).toHaveLength(1);
    expect(top.children[0]!.heading).toBe("Sub");
    expect(top.children[0]!.level).toBe(2);
  });

  it("collects inline bold/italic/underline formatting hints", () => {
    const tree = parseDocxHtml("<h1>H</h1><p>plain <strong>bold</strong> <em>italic</em>.</p>");
    const runs = tree.sections[0]!.paragraphs[0]!.runs;
    const bold = runs.find((r) => r.text === "bold");
    const italic = runs.find((r) => r.text === "italic");
    expect(bold?.formatting?.bold).toBe(true);
    expect(italic?.formatting?.italic).toBe(true);
  });

  it("renders unordered list items as paragraphs with a bullet prefix", () => {
    const tree = parseDocxHtml("<h1>H</h1><ul><li>one</li><li>two</li></ul>");
    const paragraphs = tree.sections[0]!.paragraphs;
    expect(paragraphs).toHaveLength(2);
    expect(paragraphs[0]!.runs[0]!.text).toContain("•");
    expect(paragraphs[1]!.runs[0]!.text).toContain("•");
  });

  it("renders table rows as pipe-joined paragraphs", () => {
    const tree = parseDocxHtml(
      "<h1>H</h1><table><tr><td>A</td><td>B</td></tr><tr><td>1</td><td>2</td></tr></table>",
    );
    const lines = tree.sections[0]!.paragraphs.map((p) =>
      p.runs.map((r) => r.text).join(""),
    );
    expect(lines.some((l) => l.includes("A | B"))).toBe(true);
    expect(lines.some((l) => l.includes("1 | 2"))).toBe(true);
  });
});

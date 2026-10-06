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
    const tree = parseDocxHtml("<h1>Top</h1><p>p1</p><h2>Sub</h2><p>p2</p>");
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
    const lines = tree.sections[0]!.paragraphs.map((p) => p.runs.map((r) => r.text).join(""));
    expect(lines.some((l) => l.includes("A | B"))).toBe(true);
    expect(lines.some((l) => l.includes("1 | 2"))).toBe(true);
  });
});

describe("parseDocxHtml — Word's automatic numbering", () => {
  const paragraphsOf = (html: string): string[] => {
    const out: string[] = [];
    const walk = (sections: ReturnType<typeof parseDocxHtml>["sections"]): void => {
      for (const s of sections) {
        for (const p of s.paragraphs) out.push(p.runs.map((r) => r.text).join(""));
        walk(s.children);
      }
    };
    walk(parseDocxHtml(html).sections);
    return out;
  };

  it("continues the count across body text, and numbers each sub-clause", () => {
    // mammoth starts a new <ol> after every interrupting paragraph, and nests a
    // sub-clause list inside its parent's <li>.
    expect(
      paragraphsOf(
        "<ol><li>Definitions.</li></ol><p>Terms have their defined meanings.</p>" +
          "<ol><li>Services.<ol><li>Provider shall perform the Services.</li><li>Provider shall meet the service levels.</li></ol></li></ol>" +
          "<ol><li>Fees.</li></ol>",
      ),
    ).toEqual([
      "1. Definitions.",
      "Terms have their defined meanings.",
      "2. Services.",
      "2.1 Provider shall perform the Services.",
      "2.2 Provider shall meet the service levels.",
      "3. Fees.",
    ]);
  });

  it("continues a sub-clause list that an interruption wrapped in an empty bullet", () => {
    // mammoth's shape for a level-2 item after a body paragraph.
    expect(
      paragraphsOf(
        "<ol><li>Covered Claims.<ol><li>Each party agrees to arbitrate.</li></ol></li></ol>" +
          "<p>(a) a claim of sexual harassment</p>" +
          "<ul><li><ol><li>Employee may also file with an agency.</li></ol></li></ul>" +
          "<ol><li>Class Actions.<ol><li>Claims are arbitrated individually.</li></ol></li></ol>",
      ),
    ).toEqual([
      "1. Covered Claims.",
      "1.1 Each party agrees to arbitrate.",
      "(a) a claim of sexual harassment",
      "1.2 Employee may also file with an agency.",
      "2. Class Actions.",
      "2.1 Claims are arbitrated individually.",
    ]);
  });

  it("restarts the count at an exhibit", () => {
    expect(
      paragraphsOf(
        "<ol><li>Services.</li><li>Fees.</li></ol><h1>EXHIBIT A</h1><ol><li>Scope.</li></ol>",
      ),
    ).toContain("1. Scope.");
  });
});

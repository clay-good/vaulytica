import type { DocumentTree, IngestResult, Paragraph, Section } from "./types.js";
import { countWords, normalize } from "./normalize.js";
import { sha256Hex } from "./hash.js";

/**
 * Ingest a raw text string. Pasted text has lost its document structure, so
 * we reconstruct as much as we reasonably can:
 *
 * - paragraphs are separated by blank lines (one or more `\n` in a row);
 * - headings are detected by Markdown-style `#` prefix (`# H1`, `## H2`, ...)
 *   *or* by an underline of `=` / `-` characters on the following line
 *   (Setext-style: `===` → H1, `---` → H2);
 * - everything else is body text within the current section.
 *
 * The result always has at least one section (the root, level 1, with an
 * empty heading) so that downstream extractors never need to special-case
 * an empty tree.
 */
export async function ingestPaste(text: string): Promise<IngestResult> {
  const warnings: string[] = [];
  warnings.push(
    "Pasted text loses document structure; rules that depend on heading levels or DOCX styles may be skipped.",
  );

  const tree = buildTreeFromText(text);
  const normalized = normalize(tree);

  return {
    tree: normalized,
    source: "paste",
    word_count: countWords(normalized),
    sha256: await sha256Hex(text),
    warnings,
  };
}

function buildTreeFromText(text: string): DocumentTree {
  // Split on lone line breaks but keep them so we can detect blank-line breaks.
  const lines = text.replace(/\r\n?/g, "\n").split("\n");

  // Root section accumulates paragraphs that appear before any heading.
  const root: Section = { id: "", heading: "", level: 1, paragraphs: [], children: [] };
  const sections: Section[] = [root];

  // Stack of (section, level) so that pushing a new heading nests properly.
  const stack: Section[] = [root];

  let currentParaLines: string[] = [];
  const flushParagraph = (): void => {
    if (currentParaLines.length === 0) return;
    const joined = currentParaLines.join(" ").trim();
    currentParaLines = [];
    if (!joined) return;
    const target = stack[stack.length - 1]!;
    const p: Paragraph = {
      id: "",
      runs: [{ id: "", text: joined, start: 0, end: 0 }],
    };
    target.paragraphs.push(p);
  };

  const pushSection = (heading: string, level: number): void => {
    flushParagraph();
    while (stack.length > 1 && stack[stack.length - 1]!.level >= level) {
      stack.pop();
    }
    const parent = stack[stack.length - 1]!;
    const section: Section = { id: "", heading, level, paragraphs: [], children: [] };
    if (parent === root && parent.paragraphs.length === 0 && parent.heading === "") {
      // Promote: the first heading replaces the synthetic root so the tree
      // doesn't carry an empty-string heading at level 1 unnecessarily.
      sections.length = 0;
      sections.push(section);
      stack.length = 0;
      stack.push(section);
    } else if (parent === root) {
      sections.push(section);
      stack.push(section);
    } else {
      parent.children.push(section);
      stack.push(section);
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    const trimmed = line.trim();

    // Setext heading: previous line is text, this line is === or ---
    if (currentParaLines.length === 1 && /^=+$/.test(trimmed) && trimmed.length >= 3) {
      const headingText = currentParaLines[0]!.trim();
      currentParaLines = [];
      pushSection(headingText, 1);
      continue;
    }
    if (currentParaLines.length === 1 && /^-+$/.test(trimmed) && trimmed.length >= 3) {
      const headingText = currentParaLines[0]!.trim();
      currentParaLines = [];
      pushSection(headingText, 2);
      continue;
    }

    // ATX heading: starts with one or more `#`
    const atx = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(trimmed);
    if (atx) {
      pushSection(atx[2]!, atx[1]!.length);
      continue;
    }

    if (trimmed.length === 0) {
      flushParagraph();
      continue;
    }
    currentParaLines.push(trimmed);
  }
  flushParagraph();

  // If the root section ended up empty, drop it.
  if (sections.length > 1 && sections[0] === root && root.paragraphs.length === 0) {
    sections.shift();
  }

  return { type: "document", sections };
}

import type { DocumentTree, Section } from "../ingest/types.js";
import type { SectionOutline, SectionOutlineNode } from "./types.js";

/**
 * Build a {@link SectionOutline} from a normalized {@link DocumentTree}.
 * The outline mirrors the tree's structure but also extracts a `numbered_label`
 * for sections whose heading starts with a numbered or article-style prefix.
 *
 * Patterns recognized:
 * - `1.`, `1.1`, `1.1.1`, … (dotted decimal)
 * - `Article I`, `Article II`, …, `Article XXIII` (roman)
 * - `Section 4` / `§ 4`
 */

const NUMBER_PREFIX =
  /^\s*(?:(\d+(?:\.\d+)*)\.?|(?:Article\s+([IVXLCDM]+|\d+))|(?:Section\s+(\d+(?:\.\d+)*))|§\s*(\d+(?:\.\d+)*))\b/i;

export function extractSections(tree: DocumentTree): SectionOutline {
  const by_id: Record<string, SectionOutlineNode> = {};

  const walk = (sections: Section[]): SectionOutlineNode[] =>
    sections.map((s) => {
      const label = extractNumberedLabel(s.heading);
      const node: SectionOutlineNode = {
        id: s.id,
        heading: s.heading,
        level: s.level,
        numbered_label: label,
        children: walk(s.children),
      };
      by_id[s.id] = node;
      return node;
    });

  const nodes = walk(tree.sections);
  return { nodes, by_id };
}

function extractNumberedLabel(heading: string): string | undefined {
  const m = NUMBER_PREFIX.exec(heading);
  if (!m) return undefined;
  if (m[1]) return m[1];
  if (m[2]) return `Article ${m[2].toUpperCase()}`;
  if (m[3]) return m[3];
  if (m[4]) return m[4];
  return undefined;
}

/**
 * Flatten the outline to a list, document order. Useful for cross-reference
 * resolution and structural integrity checks.
 */
export function flattenOutline(outline: SectionOutline): SectionOutlineNode[] {
  const out: SectionOutlineNode[] = [];
  const walk = (nodes: SectionOutlineNode[]): void => {
    for (const n of nodes) {
      out.push(n);
      walk(n.children);
    }
  };
  walk(outline.nodes);
  return out;
}

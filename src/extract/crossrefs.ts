import type { DocumentTree } from "../ingest/types.js";
import type { CrossRef, SectionOutline } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Resolve every "Section 4.2" / "Article III" / "§ 12(b)" reference
 * against the outline. Anything that does not resolve is flagged with
 * `unresolved: true` for STRUCT-007 to surface.
 *
 * Romans are accepted up to a reasonable bound and converted to integers
 * for matching against the outline's numbered labels.
 */

const REF_RE =
  /\b(?:Section|Sections|Article|Articles|Exhibit|Schedule|Attachment|§§?)\s+([0-9]+(?:\.[0-9]+)*(?:\([a-z]\))?|[IVXLCDM]+)/gi;

export function extractCrossRefs(
  tree: DocumentTree,
  outline: SectionOutline,
): CrossRef[] {
  const refs: CrossRef[] = [];
  const labelIndex = buildLabelIndex(outline);

  forEachParagraph(tree, (ctx) => {
    REF_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REF_RE.exec(ctx.text)) !== null) {
      const label = (m[1] ?? "").replace(/\(.*\)$/, "");
      const normalized = normalizeLabel(label);
      const resolved = normalized ? labelIndex.get(normalized) : undefined;
      refs.push({
        raw_text: m[0],
        resolved_id: resolved,
        unresolved: resolved === undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });

  return refs;
}

function buildLabelIndex(outline: SectionOutline): Map<string, string> {
  const map = new Map<string, string>();
  for (const node of Object.values(outline.by_id)) {
    if (node.numbered_label) {
      const norm = normalizeLabel(node.numbered_label);
      if (norm) map.set(norm, node.id);
    }
  }
  return map;
}

function normalizeLabel(label: string): string | undefined {
  if (!label) return undefined;
  if (/^[IVXLCDM]+$/i.test(label)) {
    const n = romanToInt(label.toUpperCase());
    return n ? `article:${n}` : undefined;
  }
  if (label.toLowerCase().startsWith("article ")) {
    const tail = label.slice(8).trim();
    if (/^[IVXLCDM]+$/i.test(tail)) {
      const n = romanToInt(tail.toUpperCase());
      return n ? `article:${n}` : undefined;
    }
    if (/^\d+$/.test(tail)) return `article:${tail}`;
  }
  if (/^[0-9]+(?:\.[0-9]+)*$/.test(label)) return `section:${label}`;
  return undefined;
}

function romanToInt(s: string): number | null {
  const vals: Record<string, number> = { I: 1, V: 5, X: 10, L: 50, C: 100, D: 500, M: 1000 };
  let total = 0;
  let prev = 0;
  for (let i = s.length - 1; i >= 0; i -= 1) {
    const v = vals[s[i]!];
    if (v === undefined) return null;
    if (v < prev) total -= v;
    else total += v;
    prev = v;
  }
  return total > 0 ? total : null;
}

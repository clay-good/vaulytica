/**
 * The paragraph walk the proofreading rules share (add-proofreading-pack):
 * every operative paragraph, the first hit, and how many there were. A
 * proofreading flag is about the document's own mechanics, so it quotes only
 * the document and asserts nothing about the law.
 */
import type { RuleContext } from "../../finding.js";
import type { DocPosition } from "../../../extract/types.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { isNonOperative } from "../_helpers.js";

export type ProofHit = { text: string; detail: string; position: DocPosition };

/** Every hit `find` reports, in document order. `find` returns the offset and a detail. */
export function scanParagraphs(
  ctx: RuleContext,
  find: (text: string) => Array<{ at: number; length: number; detail: string }>,
): ProofHit[] {
  const hits: ProofHit[] = [];
  forEachParagraph(ctx.tree, (p) => {
    if (isNonOperative(p.text)) return;
    for (const h of find(p.text)) {
      hits.push({
        text: p.text,
        detail: h.detail,
        position: {
          section_id: p.section.id,
          paragraph_id: p.paragraph.id,
          start: p.start + h.at,
          end: p.start + h.at + h.length,
        },
      });
    }
  });
  return hits;
}

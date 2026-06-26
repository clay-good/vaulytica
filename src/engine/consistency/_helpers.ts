/**
 * Shared helpers for consistency rules.
 *
 * `kindOf` classifies a document by playbook id into one of the {@link DocKind}
 * buckets. `findByKind` returns the first document of a given kind (rules
 * that need a unique match must check). `fullText` flattens a document tree
 * to a single string for whole-document scanning.
 */

import type { ConsistencyDocument, DocKind } from "./types.js";
import type { ParagraphContext } from "../../extract/walk.js";
import { forEachParagraph } from "../../extract/walk.js";

export function kindOf(doc: ConsistencyDocument): DocKind {
  const p = doc.playbook_id.toLowerCase();
  if (p === "sow" || p.startsWith("sow-")) return "sow";
  if (p.startsWith("msa-") || p === "msa-general") return "msa";
  if (p.startsWith("baa")) return "baa";
  if (p.startsWith("dpa-") || p === "dpa" || p.startsWith("scc-")) {
    return "dpa";
  }
  if (p.includes("nda")) return "nda";
  return "other";
}

export function findByKind(
  documents: readonly ConsistencyDocument[],
  kind: DocKind,
): ConsistencyDocument | undefined {
  return documents.find((d) => kindOf(d) === kind);
}

export function hasAllKinds(
  documents: readonly ConsistencyDocument[],
  required: readonly DocKind[],
): boolean {
  return required.every((k) => documents.some((d) => kindOf(d) === k));
}

export function fullText(doc: ConsistencyDocument): string {
  const parts: string[] = [];
  forEachParagraph(doc.tree, (p) => {
    if (p.section.heading) parts.push(p.section.heading);
    parts.push(p.text);
  });
  return parts.join("\n");
}

/**
 * Find the first paragraph whose own text — or the section heading that
 * contains it — matches `pattern`. Matching the heading too is necessary
 * because anchors like "Scope of Services" frequently live in the heading
 * while the operative text is in the paragraph below.
 */
export function findParagraph(doc: ConsistencyDocument, pattern: RegExp): ParagraphContext | null {
  let hit: ParagraphContext | null = null;
  forEachParagraph(doc.tree, (p) => {
    if (hit) return;
    if (pattern.test(p.text)) {
      hit = p;
      return;
    }
    const heading = p.section.heading;
    if (heading && pattern.test(heading)) hit = p;
  });
  return hit;
}

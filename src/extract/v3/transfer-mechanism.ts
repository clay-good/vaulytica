/**
 * v3 cross-border transfer language detector (spec-v3.md §20).
 *
 * Scans for canonical phrases, classifies the asserted mechanism, locates the
 * supporting text (annex, attachment, hyperlink, by-reference, recital-only).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  TransferMechanismKind,
  TransferMechanismLocation,
  TransferMechanismReference,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

type MechanismPattern = { kind: TransferMechanismKind; rx: RegExp };

const PATTERNS: MechanismPattern[] = [
  { kind: "scc-module-1", rx: /\b(?:SCC[s]?\s+Module\s+(?:1|One)|Module\s+(?:1|One)\b[^\n]{0,80}?Standard Contractual Clauses)/i },
  { kind: "scc-module-2", rx: /\b(?:SCC[s]?\s+Module\s+(?:2|Two)|Module\s+(?:2|Two)\b[^\n]{0,80}?Standard Contractual Clauses)/i },
  { kind: "scc-module-3", rx: /\b(?:SCC[s]?\s+Module\s+(?:3|Three)|Module\s+(?:3|Three)\b[^\n]{0,80}?Standard Contractual Clauses)/i },
  { kind: "scc-module-4", rx: /\b(?:SCC[s]?\s+Module\s+(?:4|Four)|Module\s+(?:4|Four)\b[^\n]{0,80}?Standard Contractual Clauses)/i },
  { kind: "scc-unspecified", rx: /\bStandard Contractual Clauses\b|\bEU SCCs?\b|\bSCCs?\b(?!\s*Module)/i },
  { kind: "uk-idta", rx: /\bInternational Data Transfer Agreement\b|\bIDTA\b/i },
  { kind: "uk-addendum", rx: /\bUK Addendum\b|\bInternational Data Transfer Addendum\b/i },
  { kind: "swiss-addendum", rx: /\bSwiss Addendum\b/i },
  { kind: "adequacy-decision", rx: /\badequacy decision\b/i },
  { kind: "binding-corporate-rules", rx: /\bBinding Corporate Rules\b|\bBCRs?\b/i },
  { kind: "article-49-derogation", rx: /\bArticle\s*49\b|\bArt\.\s*49\b/i },
  { kind: "data-privacy-framework", rx: /\bData Privacy Framework\b|\bDPF\b/i },
];

function inferLocation(text: string): TransferMechanismLocation {
  const t = text.toLowerCase();
  if (/\bannex\b|\bschedule\b|\bexhibit\b/.test(t)) return "annex";
  if (/\battachment\b/.test(t) || /\battached hereto\b/.test(t)) return "attachment";
  if (/https?:\/\//.test(text)) return "hyperlink";
  if (/\bincorporated by reference\b|\bby reference\b/.test(t)) return "by-reference";
  if (/\bwhereas\b|\brecital[s]?\b/.test(t)) return "recital-only";
  return "inline";
}

export function extractTransferMechanisms(
  tree: DocumentTree,
): TransferMechanismReference[] {
  const seen = new Set<string>();
  const out: TransferMechanismReference[] = [];
  forEachParagraph(tree, (ctx) => {
    for (const p of PATTERNS) {
      const m = p.rx.exec(ctx.text);
      if (!m) continue;
      const key = `${p.kind}|${ctx.paragraph.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        kind: p.kind,
        raw_text: m[0],
        location: inferLocation(ctx.text),
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });
  // Suppress unspecified-SCC when a more-specific module matched in the same paragraph.
  const moreSpecificParas = new Set<string>();
  for (const r of out) {
    if (r.kind.startsWith("scc-module-")) moreSpecificParas.add(r.position.paragraph_id ?? "");
  }
  const filtered = out.filter(
    (r) => r.kind !== "scc-unspecified" || !moreSpecificParas.has(r.position.paragraph_id ?? ""),
  );
  filtered.sort((a, b) =>
    a.position.start !== b.position.start
      ? a.position.start - b.position.start
      : a.kind < b.kind
        ? -1
        : a.kind > b.kind
          ? 1
          : 0,
  );
  return filtered;
}

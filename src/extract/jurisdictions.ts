import type { DocumentTree } from "../ingest/types.js";
import type { JurisdictionReference } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Extract governing-law, venue, and arbitration-seat references.
 *
 * The DKB jurisdiction table is consulted for normalization, but it is
 * passed in by the caller (so this extractor stays a pure function over
 * `(tree, dkbLookup)`). When no DKB is available — for example during the
 * very first prototype runs before the DKB scaffolding lands — pass an
 * empty function and `jurisdiction_id` will be `undefined` everywhere.
 */

const GOV_LAW =
  /\b(governed\s+by\s+(?:and\s+construed\s+(?:in\s+accordance\s+with\s+)?)?the\s+laws?\s+of\s+(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?))(?=[.,;)]|\s+(?:without|excluding|and|regardless)|$)/gi;

const VENUE =
  /\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue|jurisdiction\s+and\s+venue|sole\s+and\s+exclusive\s+(?:venue|jurisdiction|forum))\b[^.;)]{0,80}?(?:shall\s+(?:be|lie)|is|lies|shall\s+rest|will\s+be)\s+(?:in|with|within)?\s*(?:any\s+|the\s+|a\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)/gi;
const VENUE_SIMPLE =
  /\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue)\b[^.;)]{0,80}?\s+(?:shall\s+be|is|lies|will\s+be)\s+(?:in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|$)/gi;

const ARBITRATION_SEAT =
  /\b(?:seat\s+of\s+arbitration|arbitration\s+(?:shall\s+take\s+place|shall\s+be\s+(?:seated|conducted))\s+in)\s+([A-Z][A-Za-z\s&\-,]+?)(?=[.,;)]|\s+under|\s+pursuant|$)/gi;

export type DkbLookup = (raw: string) => string | undefined;

export function extractJurisdictions(
  tree: DocumentTree,
  lookup: DkbLookup = () => undefined,
): JurisdictionReference[] {
  const out: JurisdictionReference[] = [];

  forEachParagraph(tree, (ctx) => {
    runRegex(GOV_LAW, ctx.text, (m) => {
      const raw = (m[2] ?? "").trim();
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    const seenVenue = new Set<string>();
    runRegex(VENUE, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      if (!raw) return;
      const key = `${m.index}:${raw.toLowerCase()}`;
      if (seenVenue.has(key)) return;
      seenVenue.add(key);
      out.push({
        clause_kind: "venue",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    runRegex(VENUE_SIMPLE, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      if (!raw) return;
      const key = `${m.index}:${raw.toLowerCase()}`;
      if (seenVenue.has(key)) return;
      seenVenue.add(key);
      out.push({
        clause_kind: "venue",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    runRegex(ARBITRATION_SEAT, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      out.push({
        clause_kind: "arbitration-seat",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
  });

  return out;
}

function runRegex(
  re: RegExp,
  text: string,
  fn: (m: RegExpExecArray) => void,
): void {
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) fn(m);
}

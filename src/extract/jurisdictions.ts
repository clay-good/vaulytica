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
/**
 * The dominant forum-selection formulation carries no "venue"/"forum" token:
 * "all disputes … shall be resolved/brought/litigated (exclusively) in the
 * state and federal courts located in New York County". Its absence made
 * CHOICE-003 fire "no venue clause" on textbook forum clauses and blinded
 * the law/venue-mismatch rules (audit).
 */
const VENUE_RESOLVED_IN =
  /\b(?:disputes?|claims?|actions?|proceedings?|litigation)\b[^.;)]{0,120}?\bshall\s+be\s+(?:resolved|brought|litigated|adjudicated|heard|instituted)\s+(?:exclusively\s+)?(?:in|before)\s+(?:any\s+|the\s+|a\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)/gi;

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
      const tail = ctx.text.slice(m.index + m[0].length);
      // A DISCLAIMED governing law ("shall NOT be governed by the laws of
      // California, but rather … Delaware") must not be reported as the chosen
      // law — asserting a jurisdiction the contract explicitly rejects is a
      // confident false statement, and downstream jurisdiction-consistency
      // rules rely on this fact directly. When the match is negated, drop the
      // rejected jurisdiction and instead capture the "rather/instead by the
      // laws of X" jurisdiction the clause actually selects, if stated.
      if (isNegatedGovLaw(ctx.text, m.index)) {
        const actual = detectAlternativeLaw(tail);
        if (actual) {
          out.push({
            clause_kind: "governing-law",
            jurisdiction_id: lookup(actual),
            raw_text: actual,
            position: posInParagraph(ctx, m.index, m.index + m[0].length),
          });
        }
        return;
      }
      // Exception / fallback structure: capture the jurisdiction this
      // clause yields to on the primary record (precedence is explicit)
      // rather than emitting a second, equal governing-law record.
      const fallback = detectFallback(tail);
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        ...(fallback ? { fallback_jurisdiction: fallback } : {}),
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
    runRegex(VENUE_RESOLVED_IN, ctx.text, (m) => {
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

/**
 * Detect an exception/fallback jurisdiction in the text following a
 * governing-law clause: "…, except … the laws of Texas"; "…, provided
 * that if such courts lack jurisdiction, then New York". Bounded to the
 * clause tail so it does not reach into the next sentence.
 */
function detectFallback(tail: string): string | undefined {
  const window = tail.slice(0, 200);
  const m =
    /\b(?:except|provided\s+that|otherwise|failing\s+which|if\s+such\s+courts?\b[^.;]*?(?:then|,))\b[^.;]*?\b(?:the\s+)?(?:laws?\s+of\s+|courts?\s+of\s+|then\s+)(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)/.exec(
      window,
    );
  return m?.[1]?.trim() || undefined;
}

/**
 * True when a "governed by the laws of …" match at `matchIndex` is negated by
 * a preceding "not" / "never" / "in no event" in the same clause (bounded to
 * the ~40 chars before the match, cut at the last sentence break, allowing a
 * few intervening words like "shall not be governed", "is not governed").
 */
function isNegatedGovLaw(text: string, matchIndex: number): boolean {
  const raw = text.slice(Math.max(0, matchIndex - 40), matchIndex);
  const clause = raw.split(/[.;]\s/).pop() ?? raw;
  return /\b(?:not|never|no\s+event)\b(?:\s+\w+){0,3}\s*$/i.test(clause);
}

/**
 * In the tail after a negated governing-law clause, capture the jurisdiction
 * the clause actually selects: "…, but rather by the laws of Delaware",
 * "instead governed by the laws of New York". Bounded to the clause tail.
 */
function detectAlternativeLaw(tail: string): string | undefined {
  const m =
    /\b(?:rather|instead)\b[^.;]{0,60}?\bthe\s+laws?\s+of\s+(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+(?:without|excluding|and|regardless)|$)/.exec(
      tail,
    );
  return m?.[1]?.trim() || undefined;
}

function runRegex(re: RegExp, text: string, fn: (m: RegExpExecArray) => void): void {
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) fn(m);
}

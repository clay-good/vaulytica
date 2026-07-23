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

/**
 * Every US state plus DC, as a regex alternation. Exported because the rules
 * that reason about whether a venue is domestic need the same list — a
 * partial one silently reclassifies the states it omits as foreign.
 */
export const US_STATE_PATTERN =
  "Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\\s+Hampshire|New\\s+Jersey|New\\s+Mexico|New\\s+York|North\\s+Carolina|North\\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\\s+Island|South\\s+Carolina|South\\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\\s+Virginia|Wisconsin|Wyoming|District\\s+of\\s+Columbia";

/**
 * A venue clause names a COURTHOUSE, and a courthouse sits in a city: "the
 * state or federal courts located in Wilmington, Delaware". Every venue
 * pattern stops its capture at that comma, so the venue was recorded as
 * "Wilmington" — a name no governing-law clause ever uses. Each rule that
 * reconciles law against venue then reported a mismatch the document does not
 * contain: on the corpus's minimal-PASS MSA (Delaware law, Wilmington courts)
 * that was four simultaneous false findings, one of them calling Wilmington a
 * "foreign venue without standard enforceability treaty".
 *
 * When the document names the state — or, for a foreign forum, the country —
 * immediately after the locality, that is the venue's jurisdiction, so record
 * it. "Dublin, Ireland" resolves to Ireland for the same reason: the treaty
 * that makes a foreign judgment enforceable is a country's, never a city's.
 */
const COUNTRY_PATTERN =
  "United\\s+States|Canada|Mexico|United\\s+Kingdom|England(?:\\s+and\\s+Wales)?|Scotland|Wales|Ireland|Germany|France|Japan|Australia|New\\s+Zealand|Singapore|Hong\\s+Kong|China|India|Brazil|Spain|Italy|Netherlands|Switzerland|South\\s+Korea|Sweden|Israel|Norway|Belgium|Austria|Denmark|Finland|Portugal|Poland|Luxembourg";

const JURISDICTION_AFTER_LOCALITY = new RegExp(
  `^\\s*,\\s*(?:the\\s+(?:State|Commonwealth)\\s+of\\s+)?(${US_STATE_PATTERN}|${COUNTRY_PATTERN})\\b`,
  "i",
);

/**
 * `governed by … the laws of X`.
 *
 * The commas matter: the textbook clause is written both ways, and "governed
 * by**,** and construed in accordance with**,** the laws of the Republic of
 * Ireland" matched nothing — so CHOICE-001 reported "Vaulytica did not find a
 * governing-law clause" on a document whose Governing Law section says
 * precisely that. `the Republic of` needs naming too, or the capture keeps
 * the descriptor and "Republic of Ireland" never reconciles against an
 * "Ireland" venue.
 */
const SOVEREIGN_PREFIX = String.raw`the\s+(?:State|Commonwealth|Republic|Kingdom|Province)\s+of\s+|the\s+`;
const GOV_LAW = new RegExp(
  String.raw`\b(governed\s+by\s*,?\s*(?:and\s+construed\s+(?:in\s+accordance\s+with\s*,?\s*)?)?the\s+laws?\s+of\s+(?:${SOVEREIGN_PREFIX})?([A-Z][A-Za-z\s&-]+?))(?=[.,;)]|\s+(?:without|excluding|and|regardless)|$)`,
  "gi",
);

/**
 * The other half of the same clause, written as a statement rather than a
 * command: "The governing law of this Addendum **is** the law of England and
 * Wales" — the UK IDTA's own wording, and eight corpus fixtures were told
 * they had no governing-law clause because of it.
 */
const GOV_LAW_IS = new RegExp(
  String.raw`\bgoverning\s+law\b(?:\s+of\s+[^.;)]{0,60}?)?\s+(?:is|shall\s+be|will\s+be)\s+(?:the\s+laws?\s+of\s+)?(?:${SOVEREIGN_PREFIX})?([A-Z][A-Za-z&-]+(?:\s+(?:and\s+)?[A-Z][A-Za-z&-]+){0,3})`,
  "gi",
);

const VENUE = new RegExp(
  String.raw`\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue|jurisdiction\s+and\s+venue|sole\s+and\s+exclusive\s+(?:venue|jurisdiction|forum))\b(?:\([0-9]+\)|[^.;)]){0,80}?(?:shall\s+(?:be|lie)|is|lies|shall\s+rest|will\s+be)\s+(?:in|with|within)?\s*(?:any\s+|the\s+|a\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);
const VENUE_SIMPLE =
  /\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue)\b[^.;)]{0,80}?\s+(?:shall\s+be|is|lies|will\s+be)\s+(?:in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|$)/gi;
/**
 * The dominant forum-selection formulation carries no "venue"/"forum" token:
 * "all disputes … shall be resolved/brought/litigated (exclusively) in the
 * state and federal courts located in New York County". Its absence made
 * CHOICE-003 fire "no venue clause" on textbook forum clauses and blinded
 * the law/venue-mismatch rules (audit).
 *
 * Each slot below was too narrow for drafting the corpus actually contains,
 * and every miss became CHOICE-003 asserting "The document does not state
 * where disputes must be brought" about a document with a forum-selection
 * clause — a false absence, the worst thing this tool can say:
 *   - the noun: "Any **disagreement** concerning this Policy …", "Any
 *     **controversy**, claim, or dispute …";
 *   - the run-up: a recital of what the clause covers ("arising out of,
 *     related to, or in connection with these Clauses, including any matter
 *     concerning their validity, interpretation, performance, breach, or
 *     termination") runs past 120 characters;
 *   - the verb: "shall be **commenced** exclusively before …";
 *   - the preposition: "shall be resolved **by** the courts of France";
 *   - the court: "before the **competent** courts located in Dublin".
 */
const DISPUTE_NOUN = String.raw`disputes?|claims?|actions?|proceedings?|litigation|controvers(?:y|ies)|disagreements?|suits?`;
const FORUM_VERB = String.raw`resolved|brought|litigated|adjudicated|heard|instituted|commenced|filed|maintained|tried|venued|determined`;
const COURT_ADJECTIVE = String.raw`competent\s+|appropriate\s+|proper\s+|applicable\s+`;
// The run-up window between the dispute noun and its forum verb excludes ")"
// so a list marker never bridges two clauses — but that also broke on the
// numeric parenthetical ordinary drafting puts there: "Any dispute not
// resolved within thirty (30) days shall be resolved in the … courts" was
// reported as having no venue clause. A digits-only parenthetical is a day
// count, never a clause boundary, so it is admitted as a unit.
const RUNUP = String.raw`(?:\([0-9]+\)|[^.;)])`;
const VENUE_RESOLVED_IN = new RegExp(
  String.raw`\b(?:${DISPUTE_NOUN})\b${RUNUP}{0,200}?\bshall\s+be\s+(?:${FORUM_VERB})\s+(?:exclusively\s+|solely\s+|finally\s+)?(?:in|before|by)\s+(?:any\s+|the\s+|a\s+)?(?:${COURT_ADJECTIVE})?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?(?:${COURT_ADJECTIVE})?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);

/**
 * The other dominant forum formulation names no dispute and no "shall be
 * resolved" verb — the parties simply consent to a court's jurisdiction: "the
 * parties consent to the exclusive jurisdiction of the state and federal
 * courts located in New York County, New York", "each party irrevocably
 * submits to the jurisdiction of the courts of England and Wales". None of the
 * verb-driven patterns above match it, so CHOICE-003 reported "no venue
 * clause" on a document whose forum clause is one of the most common ones
 * written.
 */
const VENUE_CONSENT = new RegExp(
  String.raw`\b(?:consent|submit|agree|attorn)\w*\s+(?:[^.;)]{0,40}?\s+)?to\s+the\s+(?:${COURT_ADJECTIVE}|exclusive\s+|non-?exclusive\s+|personal\s+|sole\s+|general\s+)*jurisdiction\s+(?:and\s+venue\s+)?of\s+(?:any\s+|the\s+|a\s+)?(?:${COURT_ADJECTIVE})?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?(?:${COURT_ADJECTIVE})?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);

const ARBITRATION_SEAT =
  /\b(?:seat\s+of\s+arbitration|arbitration\s+(?:shall\s+take\s+place|shall\s+be\s+(?:seated|conducted))\s+in)\s+([A-Z][A-Za-z\s&\-,]+?)(?=[.,;)]|\s+under|\s+pursuant|$)/gi;

export type DkbLookup = (raw: string) => string | undefined;

/**
 * "England and Wales" is the one jurisdiction name that contains the clause
 * connector every capture stops at ("and", or the comma-free `\s+and\b`
 * lookahead), so both the governing-law and the venue captures truncated it
 * to "England" — which CHOICE-005's treaty list does not know, and which
 * reads as a mismatch against the full name extracted by the other clause.
 * A capture ending in "England" whose tail continues " and Wales" is the
 * compound name, not a connector.
 */
function extendEnglandAndWales(
  text: string,
  raw: string,
  end: number,
): { raw: string; end: number } {
  const m = /^\s+and\s+Wales\b/.exec(text.slice(end));
  if (m && /(^|\s)England$/i.test(raw)) {
    return { raw: `${raw} and Wales`, end: end + m[0].length };
  }
  return { raw, end };
}

export function extractJurisdictions(
  tree: DocumentTree,
  lookup: DkbLookup = () => undefined,
): JurisdictionReference[] {
  const out: JurisdictionReference[] = [];

  const seenGovLaw = new Set<string>();

  forEachParagraph(tree, (ctx) => {
    runRegex(GOV_LAW, ctx.text, (m) => {
      const ext = extendEnglandAndWales(ctx.text, (m[2] ?? "").trim(), m.index + m[0].length);
      const raw = ext.raw;
      const tail = ctx.text.slice(ext.end);
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
      // A clause that describes its law by formula and then names it —
      // "governed by the law of the European Union Member State in which the
      // data exporter is established, namely France" — has stated France. The
      // description alone matches no venue clause ever written, so reporting
      // it as the governing law made the SCC's own France forum read as a
      // law/venue mismatch.
      const named = detectNamedJurisdiction(tail);
      seenGovLaw.add((named ?? raw).toLowerCase());
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(named ?? raw),
        raw_text: named ?? raw,
        ...(fallback ? { fallback_jurisdiction: fallback } : {}),
        position: posInParagraph(ctx, m.index, ext.end),
      });
    });
    runRegex(GOV_LAW_IS, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      // The `i` flag makes `[A-Z]` match any letter, so require the
      // capitalization a jurisdiction name always carries — otherwise "The
      // governing law of this Addendum is determined by …" registers
      // "determined" as the law.
      if (!/^[A-Z]/.test(raw)) return;
      if (seenGovLaw.has(raw.toLowerCase())) return;
      seenGovLaw.add(raw.toLowerCase());
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    const seenVenue = new Set<string>();
    const recordVenue = (m: RegExpExecArray): void => {
      const ext = extendEnglandAndWales(ctx.text, (m[1] ?? "").trim(), m.index + m[0].length);
      const captured = ext.raw;
      if (!captured) return;
      const end = ext.end;
      const jurisdiction = JURISDICTION_AFTER_LOCALITY.exec(ctx.text.slice(end))?.[1];
      const raw = jurisdiction ? jurisdiction.replace(/\s+/g, " ") : captured;
      const key = `${m.index}:${raw.toLowerCase()}`;
      if (seenVenue.has(key)) return;
      seenVenue.add(key);
      out.push({
        clause_kind: "venue",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, end),
      });
    };
    runRegex(VENUE, ctx.text, recordVenue);
    runRegex(VENUE_SIMPLE, ctx.text, recordVenue);
    runRegex(VENUE_RESOLVED_IN, ctx.text, recordVenue);
    runRegex(VENUE_CONSENT, ctx.text, recordVenue);
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
 * The concrete jurisdiction a descriptive governing-law clause goes on to
 * name: "…the Member State in which the data exporter is established, **namely
 * France**". Anchored to the start of the clause tail so a jurisdiction named
 * later in the sentence for some other reason is not mistaken for the law.
 */
function detectNamedJurisdiction(tail: string): string | undefined {
  const m =
    /^\s*,?\s*(?:namely|i\.e\.,?|that\s+is,?|specifically)\s+(?:the\s+)?([A-Z][A-Za-z\s&-]*?)(?=[.,;)]|$)/.exec(
      tail,
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

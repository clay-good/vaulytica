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
// A manner adverb routinely sits between "governed" and "by" — "governed
// exclusively by", "governed solely by" — and the rigid "governed\s+by" token
// dropped the whole clause, so CHOICE-001 reported "no governing-law clause" on
// a document that plainly names one. The adverb is optional and does not change
// the clause's meaning, so this only widens what matches. `under` joins `by` as
// the preposition — "governed under the laws of X" is the same clause as
// "governed by the laws of X".
const GOVERNED_BY = String.raw`governed\s+(?:(?:exclusively|solely|only|entirely)\s+)?(?:by|under)`;
// The intervening doublet — "governed by, and construed in accordance with, the
// laws of X" / "governed by, and enforced under, the laws of X". The second
// verb+preposition sits between the first verb and "the laws of"; without this
// optional clause the anchor never reached "the laws of" and the whole
// governing-law clause was read as absent.
const GOV_LAW_DOUBLET = String.raw`(?:and\s+(?:construed|enforced|interpreted|governed)\s+(?:in\s+accordance\s+with|under|by)\s*,?\s*)?`;
const GOV_LAW = new RegExp(
  String.raw`\b((?:${GOVERNED_BY}|controlled\s+by|(?:interpreted|construed|resolved)\s+(?:under|in\s+accordance\s+with)|subject\s+to|determined\s+(?:under|by|in\s+accordance\s+with))\s*,?\s*${GOV_LAW_DOUBLET}the\s+(?:substantive\s+|internal\s+|domestic\s+|local\s+|applicable\s+)*laws?\s+of\s+(?:${SOVEREIGN_PREFIX})?([A-Z][A-Za-z\s&-]+?))(?=[.,;)]|\s+(?:without|excluding|and|regardless)|$)`,
  "gi",
);

/**
 * The other half of the same clause, written as a statement rather than a
 * command: "The governing law of this Addendum **is** the law of England and
 * Wales" — the UK IDTA's own wording, and eight corpus fixtures were told
 * they had no governing-law clause because of it. The elliptical "**that of**"
 * variant — "The governing law shall be that of the State of Texas", where
 * "that" stands in for "the law" — is accepted too; without it the capture
 * began on the lowercase "that" and the clause read as absent.
 */
const GOV_LAW_IS = new RegExp(
  String.raw`\bgoverning\s+law\b(?:\s+of\s+[^.;)]{0,60}?)?\s+(?:is|shall\s+be|will\s+be)\s+(?:that\s+of\s+)?(?:the\s+laws?\s+of\s+)?(?:${SOVEREIGN_PREFIX})?([A-Z][A-Za-z&-]+(?:\s+(?:and\s+)?[A-Z][A-Za-z&-]+){0,3})`,
  "gi",
);

/**
 * The compact adjectival form: "governed by Ohio law", "governed by California
 * law", "construed under New York law". It names the jurisdiction as an
 * adjective on the word "law" rather than "the laws OF X", so neither pattern
 * above matched it and CHOICE-001 reported "no governing-law clause" on a
 * clause that plainly states one. The capture is one to three Title-case words
 * before the literal "law"; the `/^[A-Z]/` guard in the consumer rejects the
 * lowercase non-jurisdictions this would otherwise reach ("applicable law",
 * "federal law", "such law").
 */
const GOV_LAW_ADJECTIVAL = new RegExp(
  String.raw`\b(?:${GOVERNED_BY}|(?:construed|interpreted)\s+(?:under|in\s+accordance\s+with))\s+(?:${SOVEREIGN_PREFIX})?([A-Z][A-Za-z&-]+(?:\s+[A-Z][A-Za-z&-]+){0,2})\s+law\b`,
  "gi",
);
// The subject-first adjectival form: "Georgia law governs this Agreement",
// "California law shall apply". Gated to a recognized US state or country so
// "applicable/federal/such law governs" does not register.
const GOV_LAW_ADJ_SUBJECT = new RegExp(
  String.raw`\b(${US_STATE_PATTERN}|${COUNTRY_PATTERN})\s+law\s+(?:governs?|applies|controls?|shall\s+(?:govern|apply|control))\b`,
  "gi",
);

/**
 * The subject-first governing-law clause: "The laws of the State of Texas shall
 * govern this Agreement", "The laws of Delaware apply". The verb follows the
 * jurisdiction, so the "governed by … the laws of X" patterns above never saw
 * it and CHOICE-001 reported a false absence. Gated to a recognized US state or
 * country so "the laws of physics/God/war" do not register as a jurisdiction.
 */
const GOV_LAW_SUBJECT_FIRST = new RegExp(
  String.raw`\bthe\s+(?:substantive\s+|internal\s+|domestic\s+|local\s+|applicable\s+)*laws?\s+of\s+(?:the\s+(?:State|Commonwealth)\s+of\s+)?(${US_STATE_PATTERN}|${COUNTRY_PATTERN})\b[^.;)]{0,20}?\s+(?:shall\s+)?(?:govern|appl(?:y|ies)|control)\b`,
  "gi",
);

const VENUE = new RegExp(
  String.raw`\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue|jurisdiction\s+and\s+venue|sole\s+and\s+exclusive\s+(?:venue|jurisdiction|forum))\b(?:\([0-9]+\)|[^.;)]){0,80}?(?:shall\s+(?:be|lie)|is|lies|shall\s+rest|will\s+be)\s+(?:exclusively\s+|solely\s+|only\s+|proper(?:ly)?\s+)*(?:in|with|within)?\s*(?:any\s+|the\s+|a\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);
/**
 * The courts-first venue clause: "the state and federal courts located in San
 * Francisco, California shall have exclusive jurisdiction". The forum verb
 * follows the courts, so the venue patterns that lead on "venue/forum … shall
 * be … courts" missed it. The locality is captured; recordVenue reads the
 * state after the comma.
 *
 * Two shapes the original pattern missed:
 *   - The locality is a bare jurisdiction with NO trailing "City, State" comma
 *     ("courts located in Delaware shall have exclusive jurisdiction", "courts
 *     sitting in New York County shall have venue"). The capture could only end
 *     at punctuation, so with the forum verb directly after the locality it ran
 *     past it, swallowed "shall have …", and the forward lookahead then failed —
 *     the whole clause went unread. The locality now also ends before a "shall
 *     have" / "have" forum verb, so the comma-less form reads. (The comma form
 *     is unchanged: the comma still terminates the capture first.)
 *   - The "of the State of" preposition ("the courts of the State of California
 *     shall have exclusive jurisdiction") alongside "located in" / "sitting in".
 *     Gated to "of the State/Commonwealth of <Name>", so "courts of competent
 *     jurisdiction" / "courts of Appeals" (no State-of scaffold) are not swept in.
 */
const VENUE_COURTS_FIRST = new RegExp(
  String.raw`\b(?:the\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+the\s+(?:State|Commonwealth)\s+of\s+)([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+(?:shall\s+have|have)\b|$)(?=[^.]{0,60}?\b(?:shall\s+have|have)\s+(?:exclusive\s+)?(?:jurisdiction|venue))`,
  "gi",
);
// "shall lie" is as common as "shall be" for a venue clause — "venue for any
// proceeding shall lie in Franklin County, Ohio" — so include it. The locality
// ("Franklin County") is captured and recordVenue then reads the state after
// the comma via JURISDICTION_AFTER_LOCALITY, so the venue records as "Ohio".
// The run-up window between a venue/dispute anchor and its forum verb excludes
// ")" so a list marker never bridges two clauses — but that also broke on the
// numeric parenthetical ordinary drafting puts there: "Any dispute not
// resolved within thirty (30) days shall be resolved in the … courts" was
// reported as having no venue clause. A digits-only parenthetical is a day
// count, never a clause boundary, so it is admitted as a unit. Shared by
// VENUE_SIMPLE and VENUE_RESOLVED_IN (and inlined in VENUE) — VENUE_SIMPLE
// carried the bare `[^.;)]` window until an audit found it failing on
// "Venue for any dispute not resolved within thirty (30) days shall be in
// Franklin County, Ohio", which its own comment names as its target shape.
const RUNUP = String.raw`(?:\([0-9]+\)|[^.;)])`;
const VENUE_SIMPLE = new RegExp(
  String.raw`\b(?:venue|forum|exclusive\s+jurisdiction|exclusive\s+venue)\b${RUNUP}{0,80}?\s+(?:shall\s+(?:be|lie)|is|lies|will\s+be)\s+(?:proper\s+)?(?:in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|$)`,
  "gi",
);
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
const DISPUTE_NOUN = String.raw`disputes?|claims?|actions?|proceedings?|litigation|controvers(?:y|ies)|disagreements?|suits?|lawsuits?`;
const FORUM_VERB = String.raw`resolved|brought|litigated|adjudicated|heard|instituted|commenced|filed|maintained|tried|venued|determined`;
const COURT_ADJECTIVE = String.raw`competent\s+|appropriate\s+|proper\s+|applicable\s+`;
// A forum clause often names the court type before "Court(s)": "the Superior
// Court of California", "the Circuit Court of Cook County". The qualifier sits
// between the article and the "Court" token, so it is admitted as an optional
// prefix to the "courts?" token in the forum patterns.
const COURT_NAME = String.raw`(?:Superior\s+|Supreme\s+|District\s+|Circuit\s+|Chancery\s+|Commercial\s+|County\s+|Municipal\s+)?`;
// The forum verb is frequently a doublet — "filed AND maintained", "brought
// AND prosecuted", "commenced AND litigated" — and the adverb slot carries
// "only" ("brought only in") as readily as "exclusively", so both are admitted.
// The forum verb is also reached through a CONJOINED governing-law verb, which
// is how a great many single-sentence "governing law and forum" clauses are
// written: "Any dispute … **will be governed by Ohio law and resolved**
// exclusively in the state or federal courts sitting in Franklin County,
// Ohio". The doublet slot above required the two verbs to be adjacent
// ("filed and maintained"), so the intervening "by Ohio law" broke it, and
// "governed" is not — and must not become — a forum verb in its own right.
// Admitting a bounded run before the "and" reads the real shape while still
// requiring a genuine forum verb, the "in/before/by … courts" scaffold, and a
// capitalized place after it.
const FORUM_VERB_LEAD_IN = String.raw`(?:\w+${RUNUP}{0,40}?\s+and\s+)?`;
const VENUE_RESOLVED_IN = new RegExp(
  String.raw`\b(?:${DISPUTE_NOUN})\b${RUNUP}{0,200}?\b(?:shall|must|will|may)\s+(?:be\s+${FORUM_VERB_LEAD_IN}(?:${FORUM_VERB})(?:\s+and\s+(?:${FORUM_VERB}))?|take\s+place|proceed|lie)\s+(?:exclusively\s+|solely\s+|finally\s+|only\s+)?(?:in|before|by)\s+(?:any\s+|the\s+|a\s+)?(?:${COURT_ADJECTIVE})?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?(?:${COURT_ADJECTIVE})?${COURT_NAME}courts?\s+(?:of\s+competent\s+jurisdiction\s+)?(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
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
// "the" before the jurisdiction adjectives is optional ("consents to personal
// jurisdiction …"), and the clause reads "jurisdiction OF the courts" OR
// "jurisdiction IN the courts".
const VENUE_CONSENT = new RegExp(
  String.raw`\b(?:consent|submit|agree|attorn|subject)\w*\s+(?:[^.;)]{0,40}?\s+)?to\s+(?:the\s+)?(?:${COURT_ADJECTIVE}|exclusive\s+|non-?exclusive\s+|personal\s+|sole\s+|general\s+)*jurisdiction\s+(?:and\s+venue\s+)?(?:of|in)\s+(?:any\s+|the\s+|a\s+)?(?:${COURT_ADJECTIVE})?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?(?:${COURT_ADJECTIVE})?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);
// "The parties agree to venue in Harris County, Texas" — venue selected as the
// object of "agree/consent/submit to venue in", with no "shall be … courts".
const VENUE_AGREE_IN = new RegExp(
  String.raw`\b(?:agree|consent|submit|stipulat)\w*\s+(?:[^.;)]{0,30}?\s+)?to\s+(?:exclusive\s+|proper\s+)?venue\s+in\s+(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|$)`,
  "gi",
);

/**
 * The inverted forum-selection formulation puts the COURT first: "the Court
 * of Chancery of the State of Delaware shall be the sole and exclusive forum
 * for any derivative action …" — the standard Delaware exclusive-forum bylaw.
 * Every pattern above expects the forum token or dispute noun BEFORE the
 * court, so the clause's venue went unextracted — and VENUE_SIMPLE's
 * case-insensitive capture instead grabbed the lowercase text after "shall
 * be", reporting the venue as "the sole and exclusive forum for any
 * derivative action" (a foreign venue, per CHOICE-005, with no treaty).
 */
const VENUE_SUBJECT = new RegExp(
  String.raw`\b(?:Court\s+of\s+Chancery\s+of\s+|(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?${COURT_NAME}courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+))(?:[A-Z][A-Za-z\s&.-]+?,\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)\s+(?:shall\s+be|is|are|will\s+be|shall\s+constitute)\s+the\s+(?:sole\s+|and\s+|exclusive\s+)+(?:forum|venue)\b`,
  "g",
);

/**
 * The forum is also selected by WAIVING objection to it: "each party waives any
 * objection to venue in the courts of Cook County, Illinois", "the parties
 * waive any objection to the laying of venue in the state courts of Dallas
 * County, Texas". The clause fixes the forum as surely as an affirmative
 * consent, but names no dispute and no "shall be … forum" verb, so every
 * pattern above missed it and CHOICE-003 read the document as forum-silent.
 */
const VENUE_WAIVE_OBJECTION = new RegExp(
  String.raw`\bwaiv\w+\s+(?:any\s+|all\s+)?objections?\s+(?:[^.;)]{0,30}?\s+)?to\s+(?:the\s+)?(?:laying\s+of\s+)?venue\s+(?:in|of)\s+(?:any\s+|the\s+|a\s+)?(?:state\s+(?:and|or)\s+federal\s+|federal\s+(?:and|or)\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+(?:in|within)\s+|sitting\s+(?:in|within)\s+|of\s+|in\s+|within\s+)?(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+and\b|$)`,
  "gi",
);

// The seat is captured AFTER its connector ("shall be", "in") so the location
// name — not "shall be London" — lands in the capture group. The `i` flag is
// needed for the case-varying keywords, so the explicit connector, rather than
// a case-sensitive anchor, is what makes the capture begin at the seat.
// The named administering institutions. Anchoring the "administered by … in X"
// form on one of these keeps an ordinary "conducted … in New York" prose out —
// only a clause that names a real arbitral body records a seat.
const ARB_PROVIDER = String.raw`AAA|JAMS|ICC|ICDR|LCIA|SIAC|HKIAC|CIETAC|SCC|DIS|CPR|American\s+Arbitration\s+Association|International\s+Chamber\s+of\s+Commerce|International\s+Centre\s+for\s+Dispute\s+Resolution|London\s+Court\s+of\s+International\s+Arbitration`;

const ARBITRATION_SEAT = new RegExp(
  String.raw`\b(?:` +
    // noun-first: "the seat/place/situs (, or legal place,) of (the) arbitration shall be (in) X"
    String.raw`(?:legal\s+)?(?:seat|place|situs)(?:\s*,\s*or\s+(?:legal\s+)?place\s*,)?\s+of\s+(?:the\s+)?arbitration\s+(?:shall\s+be|is|will\s+be)\s+(?:in\s+)?` +
    String.raw`|` +
    // verb-first: "(the) (arbitral) arbitration/tribunal shall take place/be seated/conducted/held/sit in X"
    String.raw`(?:the\s+)?(?:arbitral\s+)?(?:arbitration|tribunal)\s+(?:shall|will|must)\s+(?:take\s+place\s+in|be\s+(?:seated|conducted|held)\s+in|sit\s+in)\s+` +
    String.raw`|` +
    // institution-first: "administered by JAMS in X", "before the ICC in X",
    // "under the ICC Rules in X" — the named arbitral body fixes the clause as an
    // arbitration seat, so the locality after "in"/"at" is the seat.
    String.raw`(?:administered|conducted|held|resolved|settled|before|under)\s+(?:by\s+|the\s+)?(?:the\s+)?(?:${ARB_PROVIDER})\b(?:\s+(?:rules|arbitration))?\s+(?:in|at)\s+` +
    String.raw`)([A-Z][A-Za-z\s&\-]+?)(?=[.,;)]|\s+under|\s+pursuant|$)`,
  "gi",
);

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
    /**
     * Paragraph offsets where a law was captured out of a negated clause's
     * tail — the restated clause's own GOV_LAW match starts there too.
     */
    const altLawOffsets = new Set<number>();
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
          // The selected law is recorded from the REJECTED clause's tail, so
          // when that tail restates the verb — "shall not be governed by the
          // laws of California, but shall instead be governed by the laws of
          // Delaware" — the very next GOV_LAW match records Delaware a second
          // time. Remember WHERE the selected law was read from, so only that
          // one restated clause is skipped below. Keying on the name instead
          // would drop any later clause in the paragraph naming the same
          // jurisdiction — an ancillary exhibit's own governing-law sentence
          // is a real, separate clause and must still record.
          altLawOffsets.add(ext.end + actual.offset);
          out.push({
            clause_kind: "governing-law",
            jurisdiction_id: lookup(actual.raw),
            raw_text: actual.raw,
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
      if (altLawOffsets.has(m.index + m[0].lastIndexOf(raw))) return;
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
    runRegex(GOV_LAW_ADJECTIVAL, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      // Same guards as GOV_LAW_IS: the `i` flag makes `[A-Z]` match any
      // letter, so require a real capitalized jurisdiction name, and drop a
      // disclaimed selection ("not governed by California law").
      if (!/^[A-Z]/.test(raw)) return;
      if (isNegatedGovLaw(ctx.text, m.index)) return;
      if (seenGovLaw.has(raw.toLowerCase())) return;
      seenGovLaw.add(raw.toLowerCase());
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    runRegex(GOV_LAW_SUBJECT_FIRST, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      if (!/^[A-Z]/.test(raw)) return;
      if (isNegatedGovLaw(ctx.text, m.index)) return;
      if (seenGovLaw.has(raw.toLowerCase())) return;
      seenGovLaw.add(raw.toLowerCase());
      out.push({
        clause_kind: "governing-law",
        jurisdiction_id: lookup(raw),
        raw_text: raw,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    });
    runRegex(GOV_LAW_ADJ_SUBJECT, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      if (!/^[A-Z]/.test(raw)) return;
      if (isNegatedGovLaw(ctx.text, m.index)) return;
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
      // The `i` flag makes `[A-Z]` match any letter, so require the
      // capitalization a jurisdiction name always carries — otherwise "shall
      // be the sole and exclusive forum for any derivative action" registers
      // the lowercase clause tail as the venue.
      if (!/^[A-Z]/.test(captured)) return;
      // A venue captured with the state name embedded — "Court of Chancery of
      // the State of Delaware" leaves "Chancery of the State of Delaware" in
      // the capture because "Chancery" blocks the pattern's "the State of"
      // consumption — names its jurisdiction after "State/Commonwealth of".
      // Reduce it to the bare state so a Delaware-Chancery forum matches
      // Delaware governing law instead of reading as a different jurisdiction
      // (CHOICE-004/009/012). A clean capture ("Delaware") has no such tail and
      // is left untouched.
      const stateOfTail = /(?:State|Commonwealth)\s+of\s+([A-Z][A-Za-z\s&-]+?)\s*$/.exec(captured);
      const normalizedCapture = stateOfTail?.[1] ? stateOfTail[1].trim() : captured;
      const end = ext.end;
      const jurisdiction = JURISDICTION_AFTER_LOCALITY.exec(ctx.text.slice(end))?.[1];
      const raw = jurisdiction ? jurisdiction.replace(/\s+/g, " ") : normalizedCapture;
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
    runRegex(VENUE_COURTS_FIRST, ctx.text, recordVenue);
    runRegex(VENUE_RESOLVED_IN, ctx.text, recordVenue);
    runRegex(VENUE_CONSENT, ctx.text, recordVenue);
    runRegex(VENUE_AGREE_IN, ctx.text, recordVenue);
    runRegex(VENUE_SUBJECT, ctx.text, recordVenue);
    runRegex(VENUE_WAIVE_OBJECTION, ctx.text, recordVenue);
    runRegex(ARBITRATION_SEAT, ctx.text, (m) => {
      const raw = (m[1] ?? "").trim();
      // The pattern needs the `i` flag for its case-varying keywords, which
      // also weakens the capture's leading `[A-Z]` to "any letter" — so the
      // institution-first branch happily took the lowercase word after "in"
      // in "administered by the ICC in accordance with the ICC Rules…" and
      // recorded "accordance with the ICC Rules of Arbitration then in force"
      // as a seat. Every other consumer in this file re-checks the capital
      // for exactly this reason; this one did not.
      //
      // The article is allowed before the capital. A bare `^[A-Z]` also threw
      // away every seat that idiomatically carries one — "the seat of
      // arbitration shall be the Netherlands", "shall be seated in the Hague"
      // — turning a real seat clause into no seat at all, which is the more
      // dangerous direction of the two.
      if (!/^(?:the\s+)?[A-Z]/.test(raw)) return;
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
 * a preceding "not" / "never" / "in no event" / "under no circumstances" in
 * the same clause (cut at the last sentence break, allowing a few intervening
 * words like "shall not be governed", "is not governed").
 *
 * Two things widened here, because a disclaimed law was being recorded as the
 * agreement's actual governing law — the exact failure this guard exists to
 * prevent. The lookback was ~40 chars, which is shorter than the negation
 * phrase itself in "shall under no circumstances whatsoever be governed by",
 * so the negation sat just outside the window. And an interposed comma
 * parenthetical — "shall not, under any circumstances, be governed by the laws
 * of California" — pushed the negation past the 3-word adjacency budget.
 *
 * The adjacency budget is what keeps this from over-suppressing, so it is
 * deliberately NOT relaxed: the interposed clause is allowed only when it is
 * set off by commas immediately after the negation. An unrelated negation
 * earlier in the same sentence ("Although the Company is not incorporated in
 * Delaware, this Agreement is governed by the laws of Delaware") still does
 * not match, because its words are neither comma-set-off at the negation nor
 * within the word budget.
 */
function isNegatedGovLaw(text: string, matchIndex: number): boolean {
  const raw = text.slice(Math.max(0, matchIndex - 90), matchIndex);
  const clause = raw.split(/[.;]\s/).pop() ?? raw;
  return /\b(?:not|never|no\s+(?:event|circumstances?))\b(?:\s*,[^,.;]{0,60},)?(?:\s+\w+){0,3}\s*$/i.test(
    clause,
  );
}

/**
 * In the tail after a negated governing-law clause, capture the jurisdiction
 * the clause actually selects: "…, but rather by the laws of Delaware",
 * "instead governed by the laws of New York". Bounded to the clause tail.
 */
function detectAlternativeLaw(tail: string): { raw: string; offset: number } | undefined {
  const m =
    /\b(?:rather|instead)\b[^.;]{0,60}?\bthe\s+laws?\s+of\s+(?:the\s+(?:State|Commonwealth)\s+of\s+)?([A-Z][A-Za-z\s&-]+?)(?=[.,;)]|\s+(?:without|excluding|and|regardless)|$)/.exec(
      tail,
    );
  const raw = m?.[1]?.trim();
  if (!m || !raw) return undefined;
  // The offset identifies the clause this law was read out of, so the caller
  // can skip that one restated clause without keying on the name.
  return { raw, offset: m.index + m[0].lastIndexOf(raw) };
}

function runRegex(re: RegExp, text: string, fn: (m: RegExpExecArray) => void): void {
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) fn(m);
}

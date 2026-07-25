import type { Rule, RuleContext, Finding } from "../../finding.js";
import { findStatuteCitation, makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";

// A signature-block label is followed by a colon ("By:") or an underscore fill
// line ("By ____"). WITHOUT that anchor the bare words "by" / "date" / "title"
// occur constantly as ordinary prose ("passes by that date", "Title to the
// Goods"), which counted as signature signals and SILENTLY SUPPRESSED the
// critical "no signature block" finding on documents that have none.
const SIG_LINE = /^\s*(?:By|Name|Title|Date|Signed|Print(?:ed)?\s+Name)\b\s*(?::|_)/im;
const SIG_TOKEN = /\b(?:By|Name|Title|Date|Signature|Signed|Authorized\s+Signatory)\b\s*:/i;
const EXHIBIT_HEADING = /\b(?:exhibit|schedule|attachment|appendix|annex|annexure)\b/i;

// The attestation formula that introduces every executed signature page. An
// individual party signs with a bare typed name — no "By:/Name:/Title:"
// labels — so a contract between a company and a person can carry exactly ONE
// anchored token, and the two-token floor called its executed signature page
// missing. The formula is never ordinary prose, so it counts as one signal
// (once); a document with the recital but no signature line at all still
// fires.
const ATTESTATION =
  /\bin\s+witness\s+whereof\b|\bthe\s+parties\s+(?:have\s+(?:executed|signed)|hereto\s+have\s+(?:executed|signed))\b/i;

// A conformed signature ("/s/ Jane Smith") is an executed signature even with
// no "By:/Name:/Title:" labels — bylaws, board consents, and court filings
// sign this way, and the label-anchored tokens alone read a certified set of
// bylaws as unsigned (a critical false positive on a well-formed document).
const CONFORMED_SIG = /^\s*\/s\/\s+\S/m;
// A signature line that names its signatory by office rather than by a
// "By:/Name:/Title:" grid — "____________ Jordan Ellis, Director". Board /
// member / partner consents, resolutions, and certificates sign this way: an
// underscore rule followed by a person's name and a signatory office. The
// label-anchored tokens alone read such a consent as unsigned (a critical
// false positive). "/s/" is already covered by CONFORMED_SIG, so this matches
// only the underscore form to avoid double-counting the same line.
const OFFICE_SIG_LINE =
  /_{4,}\s*[A-Z][A-Za-z.'’-]+(?:\s+[A-Z][A-Za-z.'’-]+){0,3},?\s+(?:Director|President|Vice\s+President|Secretary|Treasurer|Chief\s+[A-Za-z]+\s+Officer|CEO|CFO|COO|CTO|Manager|Managing\s+Member|Member|Trustee|General\s+Partner|Partner|(?:Sole\s+)?Incorporator|Testat(?:or|rix)|Principal|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant|Authorized\s+Signatory|Its\b)\b/g;
// A standalone signatory office on a signature line — "____ Notary Public",
// "____ Witness", "____ Testator" — with no personal name attached.
const STANDALONE_SIGNATORY_ROLE =
  /_{4,}\s*(?:\/s\/\s*)?(?:Notary\s+Public|Notary|Witness|Affiant|Declarant|Testat(?:or|rix)|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant)\b/i;

/**
 * True if a paragraph is a bare-name signature line: an underscore rule
 * followed by the printed name of a known signatory party ("____ Alexandra
 * Reyes"), or a standalone "Notary Public" / "Witness" line. Requiring an
 * actual extracted party name (or explicit role) keeps a genuine
 * "____ [Insert Name]" placeholder from counting as a signature.
 */
function isBareNameSignatureLine(text: string, partyNames: string[]): boolean {
  if (STANDALONE_SIGNATORY_ROLE.test(text)) return true;
  if (!/_{6,}/.test(text)) return false;
  const after = text.replace(/_{6,}/g, " ").replace(/\/s\//g, " ").trim();
  if (!after) return false;
  // "____ Signature of Subject" / "____ Print Name of Witness" — the label
  // form a consent, affidavit, or application signs with.
  if (/^(?:signature|signed|print(?:ed)?\s+name)\s+(?:of|by)\b/i.test(after)) return true;
  const lower = after.toLowerCase();
  return partyNames.some((n) => {
    // Strip a role parenthetical the extractor may attach —
    // 'Karen Whitfield (the "Petitioner")' — before comparing to the printed
    // signature name.
    const nl = n
      .toLowerCase()
      .replace(/\s*\(.*$/, "")
      .trim();
    if (nl.length < 4) return false;
    return lower === nl || lower.startsWith(`${nl},`) || lower.startsWith(`${nl} `);
  });
}
// The secretary's certification formula that closes bylaws and resolutions.
// Deliberately narrow ("certified as adopted", "certify that the foregoing")
// so an amendment clause's "may be adopted by the Board" is not a signal.
const CERTIFICATION = /\bcertified\s+as\s+adopted\b|\bcertif(?:y|ies)\s+that\s+the\s+foregoing\b/i;

// A governance instrument's dated adoption recital — "Adopted by the Board of
// Directors on August 15, 2026" — IS its execution: committee charters and
// policies are adopted by resolution, not signed by parties, and demanding a
// By:/Name: block of one is a critical false positive. The DATE is required,
// so an amendment clause's undated "may be adopted by the Board" never counts.
const DATED_ADOPTION =
  /\badopted\s+by\s+the\s+board(?:\s+of\s+directors)?\s+(?:on|as\s+of)\s+[A-Z][a-z]+\s+\d{1,2},\s+\d{4}/i;

// A delivery instrument — disclosure schedules, closing certificates,
// officer's certificates — is DELIVERED pursuant to a parent agreement, not
// signed by counterparties; the delivery recital is its execution context.
// The window admits periods ("delivered by Tidewater Analytics, Inc. (the
// 'Seller') pursuant to …" carries an entity abbreviation) and blocks only
// semicolons, so the recital's own punctuation cannot defeat it.
const DELIVERY_RECITAL =
  /\bare\s+delivered\s+by\b[^;]{0,120}?\b(?:pursuant\s+to|in\s+connection\s+with)\b|\bis\s+delivered\s+(?:pursuant\s+to|in\s+connection\s+with)\b/i;

// A PUBLISHED notice (cookie notice, privacy policy, terms page) is issued,
// not signed — its "Last updated: <date>" line is the publication stamp that
// stands in for execution. Deliberately narrow to the revision-stamp wording:
// "Effective Date:" appears on plenty of signed contracts, and accepting it
// would silence the critical finding on a genuinely unsigned agreement.
const PUBLICATION_STAMP =
  /\blast\s+(?:updated|revised|modified|amended)\s*:?\s*[A-Z][a-z]+\s+\d{1,2},\s+\d{4}/i;

/**
 * STRUCT-003 — Signature block present (critical).
 *
 * Looks for a canonical `By: ___ Name: ___ Title: ___ Date: ___`
 * pattern anywhere in the document, with two complementary searches:
 *
 *   1. Inside the "execution / signatures / signature page" sections
 *      if any such section heading exists.
 *   2. Otherwise in the last 40% of body paragraphs *that are not part
 *      of an exhibit/schedule/attachment/appendix/annex section*. Real
 *      contracts routinely have exhibits after the signature page, so
 *      the previous "last 15% of paragraphs" heuristic produced a
 *      critical false positive on every well-formed contract with
 *      attached schedules.
 *
 * Two qualifying lines (e.g., `By:` AND `Name:`, or `By:` AND `Date:`)
 * are required to fire a "present" verdict, so a stray "Name:" inside
 * a notice clause doesn't satisfy the check.
 */
export const rule: Rule = {
  id: "STRUCT-003",
  version: "1.13.0",
  name: "Signature block present",
  category: "structural",
  default_severity: "critical",
  description:
    "Verifies the document contains a signature block (with exhibits / schedules after it tolerated). Cites UETA § 7 and ESIGN 15 U.S.C. § 7001 for legal background.",
  dkb_citations: ["stat-ueta-section-7", "stat-15-usc-7001"],

  check(ctx: RuleContext): Finding | null {
    type P = { start: number; text: string; sectionId: string; inExhibit: boolean };
    const paragraphs: P[] = [];
    // The printed names of the signatories, for the bare-name signature line a
    // personal / estate instrument uses ("____ Alexandra Reyes").
    const partyNames = ctx.extracted.parties
      .map((p) => p.name)
      .filter((n): n is string => typeof n === "string" && n.trim().length >= 4);
    const exhibitSectionIds = new Set<string>();
    forEachSection(ctx.tree, (s) => {
      if (EXHIBIT_HEADING.test(s.heading)) exhibitSectionIds.add(s.id);
    });
    forEachParagraph(ctx.tree, (p) => {
      paragraphs.push({
        start: p.start,
        text: p.text,
        sectionId: p.section.id,
        inExhibit: exhibitSectionIds.has(p.section.id),
      });
    });
    if (paragraphs.length === 0) return null;

    const countSigSignals = (slice: P[]): number => {
      let signals = 0;
      let attested = false;
      let certified = false;
      for (const p of slice) {
        const text = p.text;
        if (!attested && ATTESTATION.test(text)) {
          attested = true;
          signals += 1;
        }
        if (CONFORMED_SIG.test(text)) signals += 1;
        OFFICE_SIG_LINE.lastIndex = 0;
        const officeSigs = text.match(OFFICE_SIG_LINE);
        if (officeSigs) signals += officeSigs.length;
        // A bare-name signature line — an underscore rule followed by the
        // printed name of a known party, or a standalone "Notary Public" /
        // "Witness" line — is how a prenup, will, or affidavit is signed.
        if (isBareNameSignatureLine(text, partyNames)) signals += 1;
        if (!certified && CERTIFICATION.test(text)) {
          certified = true;
          signals += 1;
        }
        // Self-sufficient: a dated adoption recital is the complete
        // execution of an adopted instrument; a delivery recital is the
        // complete execution context of a delivered one.
        if (
          !certified &&
          (DATED_ADOPTION.test(text) || DELIVERY_RECITAL.test(text) || PUBLICATION_STAMP.test(text))
        ) {
          certified = true;
          signals += 2;
        }
        // Count distinct sig tokens in the paragraph; a single
        // paragraph can carry the full table row "By: ___ Name: ___".
        const m = text.match(/\b(By|Name|Title|Date|Signature|Signed|Authorized\s+Signatory)\b/gi);
        if (!m) continue;
        const distinct = new Set(m.map((t) => t.toLowerCase().replace(/\s+/g, " ")));
        if (SIG_LINE.test(text) || SIG_TOKEN.test(text)) signals += distinct.size;
      }
      return signals;
    };

    // Strategy 1: a dedicated execution / signatures section anywhere
    // in the document. If found and it has ≥2 signature tokens, pass.
    const execSectionParas = paragraphs.filter((p) => isInExecutionSection(ctx, p.sectionId));
    if (execSectionParas.length > 0 && countSigSignals(execSectionParas) >= 2) return null;

    // Strategy 2: last 40% of non-exhibit paragraphs. Allow exhibits
    // to live after the signature page — that's normal contract shape.
    const body = paragraphs.filter((p) => !p.inExhibit);
    if (body.length > 0) {
      const cutoff = Math.floor(body.length * 0.6);
      const tail = body.slice(cutoff);
      if (countSigSignals(tail) >= 2) return null;
    }

    // Strategy 3: anywhere in the document, ≥2 tokens within a 12-paragraph
    // window. Covers compact / unconventional layouts.
    for (let i = 0; i < paragraphs.length; i++) {
      const window = paragraphs.slice(i, i + 12);
      if (countSigSignals(window) >= 2) return null;
    }

    const last = (paragraphs.filter((p) => !p.inExhibit).slice(-1)[0] ??
      paragraphs[paragraphs.length - 1])!;
    const citations = [
      findStatuteCitation(ctx.dkb, "stat-ueta-section-7"),
      findStatuteCitation(ctx.dkb, "stat-15-usc-7001"),
    ].filter((s): s is NonNullable<typeof s> => Boolean(s));

    return makeFinding({
      rule,
      title: "No signature block detected",
      description: "The end of this Agreement does not contain the standard signature pattern.",
      excerptText: last.text.slice(0, 160),
      explanation:
        "A contract without identifiable signatures may be unenforceable or invalid. Electronic signatures are permitted under ESIGN and state UETA equivalents, but the document must still record the parties' consent to be bound — typically via a 'By / Name / Title / Date' block.",
      recommendation:
        "Add a signature block for each party with lines for By, Name, Title, and Date. Electronic-signature platforms like DocuSign produce this automatically.",
      position: {
        section_id: last.sectionId,
        start: last.start,
        end: last.start + last.text.length,
      },
      source_citations: citations,
    });
  },
};

const EXECUTION_HEADING = /\b(?:in\s+witness\s+whereof|signatures?|execution|signature\s+page)\b/i;

function isInExecutionSection(ctx: RuleContext, sectionId: string): boolean {
  let inSection = false;
  forEachSection(ctx.tree, (s) => {
    if (s.id === sectionId && EXECUTION_HEADING.test(s.heading)) inSection = true;
  });
  return inSection;
}

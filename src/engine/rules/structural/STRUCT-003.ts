import type { Rule, RuleContext, Finding } from "../../finding.js";
import { findStatuteCitation, makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";
import { isIncorporatedExhibit } from "../_helpers.js";

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
// "/s/ Name" at a line start OR right after a label ("By: /s/ Jane Smith",
// "Authorized Representative: /s/ Margaret Hale" on an ACORD certificate) —
// or after the comma of the valediction it follows ("Respectfully submitted,
// /s/ Dana Reyes"). That last case is not a stylistic variant: pasted and
// plain-text ingest joins the lines of a block with SPACES, so a signature
// laid out on three lines arrives as one paragraph and a line-start anchor
// can never reach the "/s/".
//
// The anchor is that the character before the mark is not a word character,
// which is the whole of the URL guard ("example.com/s/thing", where the mark
// is glued to one). Listing the punctuation that may precede it instead ("^",
// ":", ",", ".") left out the commonest thing of all: a SPACE. An 83(b)
// election dated on the line above its conformed signature arrives as "…
// Dated: July 15, 2026 /s/ Elena Marie Vasquez" once its blank lines are
// gone, and reported itself unsigned at `critical`.
//
// Case-INSENSITIVE: an all-caps instrument signs "/S/ MARTIN R. ODEGAARD",
// and old-form guaranties, bonds, and powers of attorney are set in capitals
// throughout.
const CONFORMED_SIG = /(?:^|[^\w/])\s*\/s\/\s+\S/im;
// An E-SIGNATURE PLATFORM ARTIFACT is an executed signature. A contract signed
// through DocuSign, Adobe Sign, or Dropbox Sign carries the platform's stamp
// on every page of the executed copy, and the signature itself is a typed name
// beside a timestamp — "By: Dana Reyes (Aug 4, 2026 14:02 EDT)" — with no
// "Name:"/"Title:" grid beneath it. That is ONE weak token against a
// two-token floor, so the executed copy of an enormous share of modern
// contracts reported "No signature block detected" at `critical`. The stamp is
// never ordinary prose, so it is self-sufficient, like a conformed "/s/".
const ESIGN_ARTIFACT =
  /\bDocuSign\s+Envelope\s+ID\b|\bAdobe\s+(?:Acrobat\s+)?Sign\b|\bDropbox\s+Sign\b|\bHelloSign\b|\bPandaDoc\b|\bSignNow\b|\bElectronically\s+signed\s+by\b|\be-?signed\s+by\b|\bSigned\s+by:\s*\S/i;
// A signature line that names its signatory by office rather than by a
// "By:/Name:/Title:" grid — "____________ Jordan Ellis, Director". Board /
// member / partner consents, resolutions, and certificates sign this way: an
// underscore rule followed by a person's name and a signatory office. The
// label-anchored tokens alone read such a consent as unsigned (a critical
// false positive). "/s/" is already covered by CONFORMED_SIG, so this matches
// only the underscore form to avoid double-counting the same line.
const OFFICE_SIG_LINE =
  /_{4,}\s*[A-Z][A-Za-z.'’-]+(?:\s+[A-Z][A-Za-z.'’-]+){0,3},?\s+(?:Director|President|Vice\s+President|Secretary|Treasurer|Chief\s+[A-Za-z]+\s+Officer|CEO|CFO|COO|CTO|Manager|Managing\s+Member|Member|Trustee|General\s+Partner|Partner|(?:Sole\s+)?Incorporator|Testat(?:or|rix)|Principal|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant|Trustee|Grantor|Settlor|Authorized\s+Signatory|Its\b)\b/g;
// A standalone signatory office on a signature line — "____ Notary Public",
// "____ Witness", "____ Testator" — with no personal name attached.
//
// The judicial offices are here because a COURT ORDER is signed by an office
// and never by a name: a QDRO, a consent judgment, and a stipulated order all
// close with "SO ORDERED … _____________ Justice of the Supreme Court", and
// without them every one of them reported "No signature block detected" at
// `critical`. The `_{4,}` prefix is what keeps the words safe: "the Court"
// and "the Clerk" appear in ordinary prose constantly, and never after a
// signature rule.
const STANDALONE_SIGNATORY_ROLE =
  /_{4,}\s*(?:\/s\/\s*)?(?:Notary\s+Public|Notary|Witness|Affiant|Declarant|Testat(?:or|rix)|Execut(?:or|rix)|Personal\s+Representative|Attorney-in-Fact|Patient|Participant|Judge|Justice|Magistrate(?:\s+Judge)?|Chief\s+Judge|Referee|Hearing\s+Officer|Administrative\s+Law\s+Judge|Clerk(?:\s+of\s+(?:the\s+)?Court)?)\b/i;

// A template / field-label token that must NOT appear in a string accepted as
// a printed personal name — "____ Company Name", "____ Insert Party" are
// placeholders, not signatures. (Parity with STRUCT-013.)
const NON_NAME_TOKEN =
  /\b(?:Name|Date|Address|City|State|Zip|Country|Title|Code|Number|Amount|Value|Reference|Period|Term|Field|Information|Details|Description|Phone|Email|Sum|Fee|Rate|Price|Insert|Sign|Signature|Print(?:ed)?|Company|Corporation|Entity|Party|Here|TBD|TBA)\b/i;
const HONORIFIC_PREFIX =
  /^(?:Dr|Mr|Mrs|Ms|Mx|Prof(?:essor)?|Hon|Rev|Sir|Dame|Fr|Sr|Capt|Col|Gen|Lt|Sgt|Rabbi|Pastor|Judge)\.?\s+/i;

/**
 * True if `s` is a bare printed personal name — 2–4 Title-Case words, each with
 * a lowercase tail, no field-label token, honorific stripped. (Parity with
 * STRUCT-013 so a unilateral instrument whose sole signatory is named only in
 * the block — "____ Gregory Halstead" on a seller non-compete — is recognized.)
 */
function isPersonalName(s: string): boolean {
  const t = s.replace(/,.*$/, "").trim().replace(HONORIFIC_PREFIX, "");
  if (NON_NAME_TOKEN.test(t)) return false;
  return /^[A-Z][a-z]+(?:\s+[A-Z][a-z.'’-]+){1,3}$/.test(t);
}

/**
 * True if a paragraph is a bare-name signature line: an underscore rule
 * followed by the printed name of a known signatory party ("____ Alexandra
 * Reyes"), a clean personal name even if not an extracted party
 * ("____ Gregory Halstead"), or a standalone "Notary Public" / "Witness" line.
 * Requiring an extracted party, a clean personal name, or an explicit role
 * keeps a genuine "____ [Insert Name]" placeholder from counting as a signature.
 */
function isBareNameSignatureLine(text: string, partyNames: string[]): boolean {
  if (STANDALONE_SIGNATORY_ROLE.test(text)) return true;
  if (!/_{6,}/.test(text)) return false;
  // Each segment that FOLLOWS an underscore rule, rather than the paragraph
  // with its rules blanked out. A release's signature page lays out four
  // rules and four labels, and once its blank lines are gone they arrive as
  // one paragraph — so a label anchored at the paragraph's start could only
  // ever see the first of them, and the release reported itself unsigned at
  // `critical`. Splitting on the rules reads each line the same way whether
  // it arrived alone or joined to its neighbours.
  const segments = text
    .split(/_{6,}/)
    .slice(1)
    .map((seg) => seg.replace(/\/s\//g, " ").trim())
    .filter((seg) => seg.length > 0);
  if (segments.length === 0) return false;
  for (const seg of segments) {
    // "____ Signature of Subject" / "____ Print Name of Witness" — the label
    // form a consent, affidavit, or application signs with.
    if (/^(?:signature|signed|print(?:ed)?\s+name)\s+(?:of|by)\b/i.test(seg)) return true;
    if (isPersonalName(seg)) return true;
    const lower = seg.toLowerCase();
    const named = partyNames.some((n) => {
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
    if (named) return true;
  }
  return false;
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
//
// A policy is APPROVED or RATIFIED at least as often as it is "adopted", and
// by a committee at least as often as by the full board — an acceptable-use
// policy headed "Approved by the Board of Directors on August 15, 2026" drew
// the critical finding until the verb set matched the way boards actually
// minute the act.
const DATED_ADOPTION =
  // An engineering, security, or records policy is adopted by an OFFICER, not
  // by the board — "Adopted by the Chief Technology Officer on March 9,
  // 2026" — and demanding a board resolution of one is the same critical
  // false positive the board form was added to answer.
  /\b(?:adopted|approved|ratified)\s+by\s+the\s+(?:board(?:\s+of\s+directors)?|(?:audit|compensation|nominating|governance|risk|executive|finance)\s+committee|chief\s+\w+\s+officer|general\s+counsel|president|c[eftoi]o)\s+(?:on|as\s+of)\s+[A-Z][a-z]+\s+\d{1,2},\s+\d{4}/i;

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
// "Last reviewed" belongs beside "last updated": a policy, a register, and a
// standing notice all stamp the REVIEW rather than the edit, and it is the
// same publication stamp under a different verb.
// A POLICY is ADOPTED, not signed. "Adopted by the Board of Directors on
// February 18, 2026" names the BODY that executed it and the date it did so,
// which is a corporate policy's whole execution — there is no signature block
// on a records-retention policy or an audit committee charter, and reporting
// one as unsigned is a `critical` with no answer.
//
// Narrow to an adopting BODY plus a date, deliberately: a bare "Effective
// Date: …" appears on plenty of signed contracts, and the note on
// `PUBLICATION_STAMP` above records why accepting that alone would silence the
// finding on a genuinely unsigned agreement.
const ADOPTION_RECITAL =
  /\b(?:adopted|approved|ratified|issued|authorized)\s+by\s+(?:the\s+)?[^.\n]{0,60}?\b(?:board|committee|council|trustees|directors|shareholders|stockholders|members|general\s+counsel|chief\s+\w+\s+officer)\b[^.\n]{0,40}?\b(?:on|effective|as\s+of|dated)\s+(?:[A-Z][a-z]+\s+\d{1,2},\s+\d{4}|\d{4}-\d{2}-\d{2})/;

const PUBLICATION_STAMP =
  /\blast\s+(?:updated|revised|modified|amended|reviewed)\s*:?\s*[A-Z][a-z]+\s+\d{1,2},\s+\d{4}/i;

// A formal valediction opening a line — "Very truly yours,", "Sincerely,",
// "Respectfully submitted," — is the execution of CORRESPONDENCE (a demand
// letter, a cease-and-desist, an opinion letter): the signer's name follows
// the closing, not a By:/underscore block.
//
// What follows the closing must be the end of the line OR a capitalized word,
// which is the signer's name. Requiring end-of-line ALONE (the first form of
// this pattern) meant the closing had to be alone on its line, and on the
// paste and plain-text path it never is: that ingest joins the lines of a
// block with spaces, so "Very truly yours, / Dana Reyes / Reyes & Hall LLP"
// arrives as one paragraph and every pasted letter reported itself unsigned,
// at `critical`.
//
// The capital-letter requirement keeps a mid-prose "Respectfully submitted,
// this motion should be granted" out, and it has to be applied OUTSIDE the
// case-insensitive match: `[A-Z]` under `i` matches a lowercase letter too, so
// spelling it inside the pattern admitted exactly the prose it was written to
// exclude.
const LETTER_CLOSING_WORDS =
  /^\s*(?:very\s+truly\s+yours|sincerely(?:\s+yours)?|respectfully(?:\s+submitted|\s+yours)?|yours\s+(?:truly|faithfully|sincerely)|best\s+regards|warm\s+regards|kind\s+regards|cordially)\s*,?[ \t]*/i;

/** True when a line of `text` is a valediction followed by nothing or by a name. */
function hasLetterClosing(text: string): boolean {
  for (const line of text.split("\n")) {
    const m = LETTER_CLOSING_WORDS.exec(line);
    if (!m) continue;
    const rest = line.slice(m[0].length);
    if (rest === "" || /^[A-Z]/.test(rest)) return true;
  }
  return false;
}

// A click-wrap / browse-wrap acceptance — "By installing or using the Software,
// you agree to be bound by this EULA", "By accessing the Service you accept
// these Terms" — is how an online agreement (EULA, terms of service) is
// executed: acceptance is by conduct, not a signature block.
const CLICKWRAP_ACCEPTANCE =
  /\bby\s+(?:installing|using|accessing|clicking|downloading|continuing|registering|signing\s+up|checking)[^.]{0,90}?\byou\s+(?:agree|accept|consent|acknowledge)\b/i;

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
/** A document that expressly disclaims being a contract. */
const DISCLAIMS_CONTRACT =
  /\b(?:is|are)\s+not\s+(?:intended\s+(?:to\s+be|as)\s+)?(?:a\s+)?(?:legally\s+binding\s+)?contracts?\b|\bdoes\s+not\s+(?:create|constitute|confer)\s+(?:any\s+)?(?:contractual|binding)\s+(?:rights?|obligations?|relationship)/i;

function documentText(ctx: RuleContext): string {
  const parts: string[] = [];
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const section of sections) {
      for (const p of section.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(section.children);
    }
  };
  walk(ctx.tree.sections);
  return parts.join(" ");
}

export const rule: Rule = {
  id: "STRUCT-003",
  version: "1.31.0",
  name: "Signature block present",
  category: "structural",
  default_severity: "critical",
  description:
    "Verifies the document contains a signature block (with exhibits / schedules after it tolerated). Cites UETA § 7 and ESIGN 15 U.S.C. § 7001 for legal background.",
  dkb_citations: ["stat-ueta-section-7", "stat-15-usc-7001"],

  check(ctx: RuleContext): Finding | null {
    // A document that says it is not a contract does not have a signature
    // block, and is not defective for lacking one. "This Handbook is not a
    // contract of employment and does not create contractual rights of any
    // kind" is the first substantive sentence of nearly every employee
    // handbook, and it is there precisely because nobody signs it — the
    // acknowledgment of receipt is a separate page. Reporting the absent
    // signature block at `critical` is a finding with no answer: adding one
    // would contradict the disclaimer.
    //
    // Self-declaring, so it needs no playbook to be attached to, and it
    // matches nothing in the corpus.
    if (DISCLAIMS_CONTRACT.test(documentText(ctx))) return null;
    // An exhibit / schedule / annex that says it is incorporated into a named
    // parent instrument is signed WITH that instrument, on the parent's
    // signature page. A FAR flowdown exhibit dropped in on its own drew this
    // finding at `critical` for a signature block it is not supposed to have.
    if (isIncorporatedExhibit(ctx)) return null;
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
      for (const [i, p] of slice.entries()) {
        const text = p.text;
        // A signature line and the name under it are ONE construct, and
        // whether they arrive as one paragraph or two is a fact about the
        // file, not about the document: a DOCX styles them separately, and so
        // does any text laid out with a blank line between every line. The
        // affordance tests read the rule together with what FOLLOWS it, so
        // "______" over "Priya Venkataraman, Secretary" is recognized as the
        // signature it is. The weak By:/Name:/Title: token count still reads
        // one paragraph, so a stray label in the next one cannot manufacture a
        // signature block out of nothing.
        const withNext = `${text} ${slice[i + 1]?.text ?? ""}`.trim();
        if (!attested && ATTESTATION.test(text)) {
          attested = true;
          signals += 1;
        }
        // A conformed "/s/ Name" is an unambiguous signature affordance, and a
        // court filing (a brief, a motion) or an e-signed letter is executed by
        // that single line alone — so it is self-sufficient (+2), like the
        // bare-name / office-signature lines, not a weak token needing a second.
        if (CONFORMED_SIG.test(text)) signals += 2;
        if (ESIGN_ARTIFACT.test(text)) signals += 2;
        // An office-signature line ("____ Eleanor Harper, Settlor and Trustee",
        // "____ Jordan Ellis, Director") is an unambiguous affordance, and a
        // unilateral instrument (a trust declaration, a certificate) carries
        // exactly one — so each is self-sufficient (×2), like the bare-name
        // line below.
        OFFICE_SIG_LINE.lastIndex = 0;
        const officeSigs = text.match(OFFICE_SIG_LINE) ?? withNext.match(OFFICE_SIG_LINE);
        if (officeSigs) signals += officeSigs.length * 2;
        // A bare-name signature line — an underscore rule followed by the
        // printed name of a known party, a standalone "Notary Public" /
        // "Witness" line, or a "Signature of <role>" label — is an
        // unambiguous signature affordance. A UNILATERAL instrument (a PIIA,
        // affidavit, or acknowledgment) is signed by ONE party, so a single
        // such line must satisfy the check; it is self-sufficient (+2) like a
        // dated-adoption recital, unlike the weak By/Name/Title tokens that
        // need corroboration.
        if (
          isBareNameSignatureLine(text, partyNames) ||
          isBareNameSignatureLine(withNext, partyNames)
        ) {
          signals += 2;
        }
        if (!certified && CERTIFICATION.test(text)) {
          certified = true;
          signals += 1;
        }
        // Self-sufficient: a dated adoption recital is the complete
        // execution of an adopted instrument; a delivery recital is the
        // complete execution context of a delivered one.
        if (
          !certified &&
          (DATED_ADOPTION.test(text) ||
            DELIVERY_RECITAL.test(text) ||
            PUBLICATION_STAMP.test(text) ||
            ADOPTION_RECITAL.test(text) ||
            hasLetterClosing(text) ||
            CLICKWRAP_ACCEPTANCE.test(text))
        ) {
          certified = true;
          signals += 2;
        }
        // Count distinct sig tokens in the paragraph; a single
        // paragraph can carry the full table row "By: ___ Name: ___".
        //
        // A COVER BLOCK is not a signature block. "Prepared for: … Prepared
        // by: … Date prepared: …" at the top of a broker's summary yields the
        // tokens "by" and "date" in one paragraph, which was enough to reach
        // the two-token floor and stand the check down on an unsigned
        // document. The labels are stripped before counting, so a real "By:"
        // on a signature line still counts.
        const counted = text.replace(
          /\b(?:prepared|compiled)\s+(?:by|for)\b|\bdate\s+(?:prepared|of\s+issue)\b|\beffective\s+date\b|\bdate\s+of\s+th(?:is|e)\s+\w+/gi,
          " ",
        );
        const m = counted.match(
          /\b(By|Name|Title|Date|Signature|Signed|Authorized\s+Signatory)\b/gi,
        );
        if (!m) continue;
        const distinct = new Set(m.map((t) => t.toLowerCase().replace(/\s+/g, " ")));
        if (SIG_LINE.test(counted) || SIG_TOKEN.test(counted)) signals += distinct.size;
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

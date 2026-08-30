/**
 * Deterministic playbook matcher (spec §19, build step 8).
 *
 * The matcher scores the document against every playbook's
 * `match_features` and returns the highest-scoring playbook. If no
 * playbook scores above {@link MATCH_THRESHOLD}, the fallback id
 * (`generic-fallback`) is returned. All matching is case-insensitive
 * and substring-based on whitespace-normalized text.
 *
 * Scoring is referentially transparent: no randomness, no time, no IO.
 */

import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";
import {
  GENERIC_FALLBACK_ID,
  MATCH_THRESHOLD,
  MATCH_WEIGHTS,
  type Playbook,
  type PlaybookMatchAlternative,
  type PlaybookMatchResult,
} from "./types.js";

/**
 * The title-ish corpus the playbook matcher scores `title_keywords` against.
 *
 * `matchPlaybook` documents this as "the first heading plus the preamble
 * paragraph". The pipeline had been passing only the first section's
 * heading, with `?? file.name` as the fallback — and `??` catches null and
 * undefined, not the **empty string** the tree builder actually produces for
 * a document with no styled heading. Every plain-text or pasted document,
 * and every DOCX whose title is bold body text rather than a Heading style,
 * therefore reached the matcher with an empty title.
 *
 * The consequence was silent and large: title keywords are the single
 * biggest contributor to a playbook score (0.3, against 0.2 per
 * distinguishing phrase), so a document that names itself in its first line
 * lost that entire signal. A short, unambiguous engagement letter scored
 * 0.4 and fell to `generic-fallback`; the same text with the title seen
 * scores 0.7 and routes correctly.
 *
 * The preamble is capped because it is a *title* corpus, not a body one:
 * an unbounded first paragraph would let an incidental mention of another
 * family's title keyword outrank the document's own name.
 */
export const TITLE_PREAMBLE_CHARS = 240;

/**
 * How far into the document a letter's subject line may sit and still be
 * read as its title. A letter reaches its "Re:" line only after the
 * letterhead, the date, a delivery legend, and the recipient's address
 * block — several paragraphs, but always near the top. The bound keeps a
 * "Re:" appearing deep in the body (a quoted piece of correspondence, an
 * exhibit) from being mistaken for the document's own subject.
 */
export const TITLE_SUBJECT_SCAN_PARAGRAPHS = 12;

/**
 * A letter states its title in its subject line, not in a heading.
 *
 * `titleCorpus` reads the first heading plus the first paragraph, which is
 * right for a document whose name is at the top — and exactly wrong for a
 * letter, whose first paragraph is the sender's letterhead. A reservation-
 * of-rights letter reached the matcher as "Meridian Casualty Insurance
 * Company Claims Department 4400 Harbor Point Drive", matched no title
 * keyword of any playbook, scored 0.4 on two distinguishing phrases, and
 * fell to `generic-fallback` — while the line the drafter wrote to say what
 * the document IS, "Re: Reservation of Rights — Claim No. …", was never
 * looked at. Every letter-shaped family has the same hole: the WARN notice,
 * the demand letter, the litigation hold, the preliminary lien notice, the
 * termination-of-representation letter.
 *
 * "Re:" and "Subject:" are the conventions; "In re:" is the caption form.
 * The test is anchored to the start of the paragraph so a mid-sentence
 * "with respect to" or a defined term ending in "re" cannot trigger it.
 */
const SUBJECT_LINE = /^\s*(?:re|subject|in\s+re)\s*:\s*(\S.*)$/is;

/**
 * The same subject line, inside a MEMO HEADER BLOCK.
 *
 * An internal memorandum states its title in "RE:" like a letter, but puts it
 * at the bottom of a four-line block:
 *
 *   TO:    All employees of the Commercial Lending Group
 *   FROM:  Deirdre Salazar, General Counsel
 *   DATE:  July 6, 2026
 *   RE:    Litigation Hold Notice — Ridgeway Partners LLC v. Broadmoor …
 *
 * Pasted and plain-text ingest joins the lines of a block with spaces, so the
 * whole header arrives as ONE paragraph beginning "TO:" — and {@link
 * SUBJECT_LINE}, anchored to the start of the paragraph, never reaches the
 * "RE:". A litigation hold notice scored 0.4 and fell to `generic-fallback`,
 * where it was told at `critical` that it has no signature block. Every memo
 * -shaped family has the hole: the litigation hold, the internal escalation,
 * the compliance advisory.
 *
 * Anchored on a preceding memo field label, so a mid-sentence "with respect
 * to" or a defined term ending in "re" still cannot trigger it.
 */
const MEMO_HEADER_SUBJECT = /^\s*(?:to|from|date|cc|bcc)\s*:[\s\S]{0,400}?\bre\s*:\s*(\S[^\n]*)/i;

/**
 * The document's first lines, in order, bounded and trimmed.
 *
 * A section's heading is emitted ahead of its paragraphs because a filing's
 * caption may arrive either way: pasted or plain text puts the court line in
 * the first paragraph, while a DOCX that styles it reaches the tree as a
 * heading. Both are the document's first line, and the caption walk has to
 * see it in both shapes.
 */
function leadingLines(
  sections: readonly {
    heading?: string;
    paragraphs: readonly { runs: readonly { text: string }[] }[];
  }[],
): string[] {
  const out: string[] = [];
  const push = (text: string): boolean => {
    if (out.length >= TITLE_SUBJECT_SCAN_PARAGRAPHS) return false;
    out.push(text.trim());
    return true;
  };
  for (const section of sections) {
    const heading = (section.heading ?? "").trim();
    if (heading.length > 0 && !push(heading)) return out;
    for (const paragraph of section.paragraphs) {
      if (!push(paragraph.runs.map((r) => r.text).join(""))) return out;
    }
  }
  return out;
}

/**
 * The subject line as a FALLBACK, found anywhere in the opening block.
 *
 * Both readers above are anchored to the start of a paragraph, and a letter's
 * "Re:" line is only at the start of one when the ingest happens to split it
 * there. Text copied out of a PDF keeps its line breaks and loses its blank
 * lines, so the letterhead, the addressee, the "Re:" line, and the salutation
 * arrive as ONE paragraph — and an offer letter whose subject line says
 * "Re: Offer of Employment — Director, Assay Development" lost it.
 *
 * "Re" is matched case-SENSITIVELY and must be followed by a colon, which is
 * what keeps it off "more:", "therefore:", and an ordinary mid-sentence word.
 * The capture stops at the salutation or the first sentence break, so it takes
 * the subject and not the letter.
 */
const SUBJECT_ANYWHERE = /(?:^|[\s\n])Re\s*:\s*([^\n]{1,120}?)(?=\s+Dear\b|\s*[.;]|$)/;

function subjectLine(
  sections: readonly {
    heading?: string;
    paragraphs: readonly { runs: readonly { text: string }[] }[];
  }[],
): string {
  const lines = leadingLines(sections);
  for (const text of lines) {
    const m = SUBJECT_LINE.exec(text) ?? MEMO_HEADER_SUBJECT.exec(text);
    if (m) return m[1]!.trim().slice(0, TITLE_PREAMBLE_CHARS);
  }
  for (const text of lines) {
    const m = SUBJECT_ANYWHERE.exec(text);
    if (m) return m[1]!.trim().slice(0, TITLE_PREAMBLE_CHARS);
  }
  return "";
}

/**
 * A negotiated agreement wears its legends above its title.
 *
 * "EXECUTION VERSION", "CONFIDENTIAL", "PRIVILEGED AND CONFIDENTIAL —
 * ATTORNEY WORK PRODUCT", "DRAFT — FOR DISCUSSION PURPOSES ONLY": these sit on
 * the first line of a very large share of real deal documents, and the
 * preamble the matcher read was therefore the legend. A **mutual** NDA
 * carrying "EXECUTION VERSION" over "MUTUAL NON-DISCLOSURE AGREEMENT" routed
 * to `unilateral-nda` — the mutual playbook's title keyword never hit, and the
 * unilateral one won on "the Disclosing Party" / "the Receiving Party", which
 * a mutual NDA uses too because each party is both.
 *
 * A legend is recognized as a WHOLE line built only of legend tokens and
 * separators, so a title that merely contains one of the words is untouched:
 * "CONFIDENTIALITY AGREEMENT" is a title, "CONFIDENTIAL" is a legend.
 *
 * A restrictive-securities legend hides it the same way, and is a different
 * shape: not a stamp but a whole uppercase SENTENCE. "THIS NOTE AND THE
 * SECURITIES ISSUABLE UPON CONVERSION HEREOF HAVE NOT BEEN REGISTERED UNDER
 * THE SECURITIES ACT OF 1933 …" opens essentially every note, warrant, SAFE,
 * and stock certificate. It cost a genuine convertible promissory note its
 * routing: `promissory-note` matched the title keyword "note" — from the word
 * "NOTE" inside the legend — while "CONVERTIBLE PROMISSORY NOTE", the line
 * below it, was never read, so every conversion check (valuation cap,
 * discount, qualified financing, change-of-control premium) was skipped. A
 * document title is short and carries no sentence-ending period; a legend
 * paragraph is long and does, so that is the test, and it is applied only to
 * uppercase text so an ordinary mixed-case preamble is untouched.
 *
 * A bare container marker — "EXHIBIT A", "SCHEDULE 1", "ANNEX B" — hides the
 * title the same way, and an agreement attached as an exhibit is one of the
 * commonest things a reviewer drops in. It is dropped only when the marker and
 * its designator are the WHOLE line: "EXHIBIT A — FORM OF MUTUAL NDA" carries
 * the title and is kept. No playbook's title keywords begin with one of these
 * words, so nothing loses a signal.
 */
const LEGEND_TOKEN =
  /execution\s+(?:version|copy)|conformed\s+copy|final\s+(?:version|form)|drafts?|confidential(?:ity)?|privileged|proprietary|trade\s+secrets?|attorney[-\s]work[-\s]product|attorney[-\s]client\s+privileged?|work\s+product|for\s+(?:discussion|settlement|negotiation)\s+purposes\s+only|subject\s+to\s+(?:protective\s+order|review|contract|revision)|confidential\s+treatment\s+requested|do\s+not\s+(?:copy|distribute|file)|not\s+for\s+distribution/;
const LEGEND_LINE = new RegExp(
  String.raw`^[\s\-–—*|/[\]()]*(?:(?:${LEGEND_TOKEN.source})[\s\-–—*|/,;:[\]()]*(?:and[\s\-–—*|/,;:]*)?)+$`,
  "i",
);

/**
 * Longest an uppercase, sentence-punctuated line may be and still be read as a
 * title rather than a legend paragraph. Real titles run well under this even
 * when they are long ("AMENDED AND RESTATED LIMITED LIABILITY COMPANY
 * OPERATING AGREEMENT"), and they do not end in a period.
 */
const LEGEND_SENTENCE_CHARS = 120;

function isLegendSentence(line: string): boolean {
  return (
    line.length > LEGEND_SENTENCE_CHARS &&
    /[.;]$/.test(line) &&
    /[A-Z]/.test(line) &&
    line === line.toUpperCase()
  );
}

const CONTAINER_MARKER =
  /^(?:exhibit|schedule|annex|appendix|attachment)\s+[A-Za-z0-9][A-Za-z0-9.-]*[\s.:—–-]*$/i;

/** Drop the leading legend lines so the document's own title is first. */
function dropLegends(lines: readonly string[]): string[] {
  let i = 0;
  while (
    i < lines.length &&
    (lines[i]!.length === 0 ||
      LEGEND_LINE.test(lines[i]!) ||
      CONTAINER_MARKER.test(lines[i]!) ||
      isLegendSentence(lines[i]!))
  )
    i += 1;
  return lines.slice(i);
}

/**
 * A court filing names itself BELOW its caption.
 *
 * The first paragraph of a filing is the court ("IN THE UNITED STATES
 * DISTRICT COURT FOR THE NORTHERN DISTRICT OF ILLINOIS"), followed by the
 * party block, the docket number, and the judge — and only then the line that
 * says what the document is. So the preamble the matcher reads is the name of
 * a courthouse, which is identical for a complaint, an answer, a motion to
 * compel, and a set of interrogatory responses.
 *
 * The cost is the same as the letterhead's: a defendant's responses and
 * objections to interrogatories matched no title keyword, scored 0.6 on
 * "plaintiff", "venue", and "jury" — three words every filing contains — and
 * routed to `complaint`, which then reported at `critical` that the document
 * had no jurisdictional statement, no demand for relief, and no jury demand.
 * It is a discovery response. It is not supposed to have any of them.
 *
 * The caption's shape is a strong convention, so the scaffolding is skipped
 * rather than the title guessed: a party name (an uppercase line ending in a
 * comma), a bare role designation, and the docket/judge line are each
 * recognizable, and the first paragraph that is none of them is the filing's
 * title. Engaged only when the document opens on a court line, so nothing that
 * is not a filing is touched.
 */
const CAPTION_COURT = /^[^.]{0,160}\bcourt\b[^.]{0,80}$/i;
// The trailing guard is a negative lookahead, not `\b`: a line holding the
// bare versus mark — "v." — ends on a period, and `\b` needs a word character
// on one side of the position, so the commonest caption line there is never
// matched. It only shows when each line is its own paragraph, which is what a
// double-spaced filing gives; a Washington set of interrogatories then handed
// the matcher "v." as its title.
const CAPTION_ROLE =
  /^\s*(?:v\.|vs\.|-v-|plaintiffs?|defendants?|petitioners?|respondents?|appellants?|appellees?|movants?|debtors?|intervenors?|claimants?|cross-?(?:claimants?|defendants?)|third-?party\s+(?:plaintiffs?|defendants?))(?![A-Za-z])[\s,.:;)-]*$/i;
// The court block's venue line. Federal practice puts a "FOR THE" in front of
// it — "FOR THE NORTHERN DISTRICT OF ILLINOIS" — which the bare one-word lead
// could not read, so a Rule 26(f) joint report re-routed to `litigation-hold`
// the moment its court block arrived as three paragraphs instead of one.
//
// STATE practice writes it half a dozen
// ways: "IN AND FOR KING COUNTY", "COUNTY OF LOS ANGELES", "PARISH OF
// ORLEANS", "THIRD JUDICIAL DISTRICT". None of them names a "court" and none
// is a party line, so the walk stopped on the venue and handed the matcher a
// county as the filing's title — which is exactly what a Washington set of
// interrogatories does the moment each of its lines is its own paragraph.
const CAPTION_COURT_DIVISION =
  /^\s*(?:for\s+the\s+)?(?:[A-Za-z]+\s+){0,3}(?:district|circuit)\s+of\b|\bdivision\s*$|^\s*in\s+and\s+for\b|^\s*(?:the\s+)?(?:county|parish|borough|city|state|commonwealth)\s+of\b|\b(?:county|parish)\s*$|^\s*[A-Za-z]+\s+judicial\s+(?:district|circuit)\b/i;
const CAPTION_DOCKET =
  /\b(?:case|civil\s+action|index|docket|cause|file)\s+no\b|\bhon\.|\bjudge\b/i;
/**
 * The docket line written BARE, which is how most state courts write it:
 * "No. 26-2-04188-1 SEA". The qualifier the pattern above requires — "Case
 * No.", "Civil Action No." — is federal practice and a minority of state
 * practice. A Washington set of interrogatories stopped the caption walk on
 * its own docket line.
 *
 * A number must follow, and the walk is engaged only under a court line, so a
 * title beginning with the word "No" is untouched.
 */
const CAPTION_BARE_DOCKET = /^\s*nos?\.\s*\d/i;
/**
 * A party-role designation closing a side of the caption — ", Defendants." —
 * wherever it sits in a one-paragraph caption.
 */
const ROLE_DESIGNATION =
  /,?\s*(?:plaintiffs?|defendants?|petitioners?|respondents?|appellants?|appellees?|movants?|debtors?|intervenors?|claimants?)\s*[.,;]/i;

/**
 * The docket number or the judge's line, wherever it sits.
 *
 * A judge's name is Title Case and a filing's title is not, so the name run
 * requires a lowercase second letter: without it, "Hon. Marisol Aguirre-Vance
 * JOINT INITIAL STATUS" was swallowed whole and the title lost its first three
 * words. Splitting on it
 * leaves the filing's title as the last segment when a whole caption arrives
 * as one paragraph.
 */
const DOCKET_LINE = /(?:(?:case|civil\s+action|index|docket|cause|file)\s+)?nos?\.\s*\S+/i;

/**
 * The judge's line. Case-SENSITIVE, and deliberately: the name run is
 * `[A-Z][a-z]` so it stops at a filing's ALL-CAPS title. Under the `i` flag
 * `[A-Z]` matches a lowercase letter too, so "Hon. Marisol Aguirre-Vance
 * JOINT INITIAL" was swallowed whole and the title lost its first two words.
 */
const JUDGE_LINE =
  /[Hh]on(?:orable)?\.?\s+(?:[A-Z][a-z][\w.'’-]*\s*){1,4}|[Mm]agistrate\s+[Jj]udge\s+(?:[A-Z][a-z][\w.'’-]*\s*){1,4}/;

/** A docket number trailing the party block on the same line. */
const TRAILING_DOCKET =
  /\s*\b(?:(?:case|civil\s+action|index|docket|cause|file)\s+)?nos?\.\s*\d[\w.-]*(?:\s+[A-Z0-9-]{1,8})*\s*$/i;
/**
 * The caption's party block arriving as ONE paragraph, which is what happens
 * whenever the ingest does not give each line its own: "HOLLIS MARINE SUPPLY,
 * INC., Plaintiff, v. CASCADE PORT SERVICES, LLC, Defendant." The role test
 * above is anchored at the START of a line and cannot see a block that merely
 * ENDS on one, so the walk handed the matcher both parties' names as the
 * filing's title.
 *
 * The COMMA before the role is what makes it the caption's and not a title's:
 * "PLAINTIFF'S FIRST SET OF INTERROGATORIES TO DEFENDANT" ends on the same
 * word and names the document, and skipping it lost the title all over again.
 */
const CAPTION_PARTY_BLOCK =
  /,\s*(?:plaintiffs?|defendants?|petitioners?|respondents?|appellants?|appellees?|movants?|debtors?|intervenors?|claimants?|cross-?(?:claimants?|defendants?)|third-?party\s+(?:plaintiffs?|defendants?))\s*[.,;:)\s-]*$/i;

function captionTitle(paragraphs: readonly string[]): string {
  // The DOCKET NUMBER sits above the court in an appellate caption — a
  // Supreme Court petition opens "No. 26-1147" and names the court on the
  // next line. Requiring the court on the FIRST line threw the whole caption
  // away, and a petition for a writ of certiorari, whose own title keyword is
  // exactly that phrase, fell to `generic-fallback`.
  let head = 0;
  while (head < paragraphs.length && head < 2 && CAPTION_BARE_DOCKET.test(paragraphs[head]!)) {
    head += 1;
  }
  if (head >= paragraphs.length || !CAPTION_COURT.test(paragraphs[head]!)) return "";
  for (const text of paragraphs.slice(head + 1)) {
    if (text.length === 0) continue;
    if (CAPTION_ROLE.test(text)) continue;
    // A caption that arrived as ONE paragraph carries the docket and the judge
    // MID-line, with the filing's title after them: "… Defendant. Case No.
    // 1:26-cv-04412 Hon. Marisol Aguirre-Vance JOINT INITIAL STATUS REPORT AND
    // RULE 26(f) DISCOVERY PLAN". Skipping the whole line because it mentions
    // a docket threw the title away with it, and a Rule 26(f) report re-routed
    // to `litigation-hold` the moment its blank lines went.
    // Split on the docket AND on a party-role designation: a one-paragraph
    // caption can carry the parties on either side of the docket, and taking
    // only what follows the docket handed the matcher a defendant's name.
    const afterDocket =
      (text.split(DOCKET_LINE).pop() ?? "")
        .split(JUDGE_LINE)
        .pop()
        ?.split(ROLE_DESIGNATION)
        .pop()
        ?.trim() ?? "";
    if (
      afterDocket !== text &&
      afterDocket.length >= 12 &&
      /^[A-Z]/.test(afterDocket) &&
      !CAPTION_ROLE.test(afterDocket) &&
      !afterDocket.endsWith(",")
    ) {
      return afterDocket.slice(0, TITLE_PREAMBLE_CHARS);
    }
    if (CAPTION_DOCKET.test(text) || CAPTION_BARE_DOCKET.test(text)) continue;
    // The docket sits on the same LINE as the party block whenever the ingest
    // does not separate them — "… LLC, Defendant. No. 26-2-04188-1 SEA" — so
    // the party-block test, which reads the end of the line, has to see past
    // it. Only the scaffolding tests read the trimmed form; the title returned
    // is always the line as written.
    const withoutDocket = text.replace(TRAILING_DOCKET, "").trim();
    if (CAPTION_PARTY_BLOCK.test(withoutDocket) || CAPTION_ROLE.test(withoutDocket)) continue;
    // The court block runs over several lines — "UNITED STATES DISTRICT COURT"
    // / "NORTHERN DISTRICT OF CALIFORNIA" / "SAN FRANCISCO DIVISION" — and only
    // the first names a "court". When each line is its own paragraph the walk
    // stopped on the district line and handed the matcher a venue as the
    // filing's title.
    if (CAPTION_COURT_DIVISION.test(text)) continue;
    // A party name in the caption block. The test used to also require the
    // line to be entirely uppercase, which a caption with more than one party
    // on a side is not: "CORVUS SYSTEMS CORPORATION and MARISOL ANDRADE,"
    // carries a lowercase "and", so the walk stopped there and handed the
    // matcher the defendants' names as the filing's title. A stipulated
    // protective order captioned that way routed to `mutual-nda` at 0.9 and
    // was told it had no governing law, no liability cap, no IP allocation,
    // and no termination-for-cause clause. It is a court order.
    //
    // The comma alone is the test now: a document's title never ends in one,
    // and a party line, a role designation, and an entity descriptor ("ACME
    // CORP., a Delaware corporation,") all do. The walk is engaged only under
    // a court line, and skipping every line still lands on the first line that
    // is not caption scaffolding — the title.
    if (text.endsWith(",")) continue;
    // A party line CONTINUED onto the next line — "CORVUS SYSTEMS CORPORATION
    // and" / "MARISOL ANDRADE," — carries the conjunction instead of the
    // comma, so the comma test above lets it through and the walk hands the
    // matcher a defendant's name as the filing's title. No document title ends
    // in "and".
    if (/\b(?:and|&)\s*$/i.test(text)) continue;
    return text.slice(0, TITLE_PREAMBLE_CHARS);
  }
  return "";
}

/**
 * Longest a line may be and still read as a title rather than a sentence.
 */
const TITLE_LINE_CHARS = 120;

/**
 * A RECORDED instrument names itself below the recorder's block.
 *
 * Every deed, deed of trust, easement, lien, and release that goes to a county
 * recorder opens on the same scaffolding — who asked for the recording, where
 * to mail the instrument back, an escrow or parcel number, and the reserved
 * white space:
 *
 *   Recording requested by and when recorded return to:
 *   Ashfield Title Company, 1900 Wazee Street, Suite 500, Denver, CO 80202
 *   Space above this line for recorder's use
 *   GENERAL WARRANTY DEED
 *
 * The matcher read the title-company address as the document's title. A
 * general warranty deed — the commonest recorded instrument there is — matched
 * no title keyword of any playbook, scored 0.2, and fell to
 * `generic-fallback`, so not one of the deed checks ran on it. This is the
 * sixth shape of the same defect the letterhead, the court caption, the
 * execution stamp, the exhibit marker, and the securities legend each had.
 *
 * Like the caption walk, it is engaged only when the document OPENS on a
 * recording line, and it skips only lines it can recognize as scaffolding —
 * the recorder's reserved space and anything address-shaped — before taking
 * the first title-shaped line as the instrument's name.
 */
const RECORDING_HEADER =
  /^\s*(?:(?:when\s+)?recorded?\s*[,:]?\s*(?:please\s+)?return\s+to|recording\s+requested\s+by|after\s+recording\s*,?\s*(?:please\s+)?return\s+to|mail\s+(?:tax\s+statements?|recorded\s+\w+)\s+to|prepared\s+by\s+and\s+return\s+to)\b/i;
const RECORDER_RESERVED_SPACE =
  /space\s+(?:above|below)\s+this\s+line|for\s+recorder'?s?\s+use|reserved\s+for\s+(?:the\s+)?recorder/i;
const ADDRESS_SHAPED =
  /\b\d{5}(?:-\d{4})?\b|\b(?:street|st\.|avenue|ave\.|road|rd\.|drive|dr\.|boulevard|blvd\.|suite|ste\.|floor|parkway|pkwy|lane|highway|hwy)\b|\bp\.?\s?o\.?\s+box\b|\battn\b|\bescrow\s+(?:no|number)\b|\bapn\b|\b(?:assessor'?s?\s+)?parcel\s+(?:no|number|id)\b/i;

/**
 * The recorder's INDEX fields, which sit in the same block as the return-to
 * address: "Reference number of related document: 20190412000733",
 * "Auditor's File No. 9812440", "Recording No. 2026-0041188". None carries a
 * ZIP or a street suffix, so the address test cannot see them, and a
 * Washington quitclaim deed whose lines each had their own paragraph stopped
 * the walk on one of them and fell to `generic-fallback`.
 */
const RECORDER_INDEX_FIELD =
  /\b(?:reference|recording|document|instrument|(?:auditor|clerk|recorder)'?s?\s+file|tax\s+parcel|folio)\s+(?:no|nos|number|numbers|id)\b/i;

function recordedInstrumentTitle(paragraphs: readonly string[]): string {
  if (paragraphs.length === 0 || !RECORDING_HEADER.test(paragraphs[0]!)) return "";
  // The block must be PASSED before the title is taken. Where each line of the
  // return-to address is its own paragraph, the first title-shaped line is the
  // title company's NAME — "Ashfield Title Company" carries no ZIP and no
  // street suffix, so nothing else here recognizes it — and a general warranty
  // deed was handed its escrow agent as its own name. An address line or the
  // recorder's reserved space is what marks the end of the block, and every
  // recorded instrument has at least one.
  let passedBlock = false;
  for (const text of paragraphs.slice(1)) {
    if (text.length === 0) continue;
    if (RECORDING_HEADER.test(text)) continue;
    if (
      RECORDER_RESERVED_SPACE.test(text) ||
      ADDRESS_SHAPED.test(text) ||
      RECORDER_INDEX_FIELD.test(text)
    ) {
      passedBlock = true;
      continue;
    }
    if (!passedBlock) continue;
    if (titleShaped(text)) return text.slice(0, TITLE_PREAMBLE_CHARS);
    return "";
  }
  return "";
}

/**
 * True if `line` is shaped like a document title: short, two or more words,
 * no sentence-ending punctuation, and set in caps or Title Case. Used to
 * decide whether the line UNDER the preamble is the document's own name or
 * the first sentence of its body.
 */
function titleShaped(line: string | undefined): boolean {
  if (!line) return false;
  const t = line.trim();
  if (t.length === 0 || t.length > TITLE_LINE_CHARS) return false;
  if (/[.;:,]$/.test(t)) return false;
  // A document's title is not a street address. "Ashfield Title Company, 1900
  // Wazee Street, Suite 500, Denver, Colorado 80202" is Title Case throughout,
  // carries no terminal punctuation, and reads as a title to every other test
  // here — and it is the line directly above the name of every recorded
  // instrument and below the letterhead of every letter.
  if (ADDRESS_SHAPED.test(t)) return false;
  const words = t.split(/\s+/);
  if (words.length < 2) return false;
  if (!/[A-Za-z]/.test(t)) return false;
  if (t === t.toUpperCase()) return true;
  // Title Case: every word of three or more letters starts capitalized.
  return words.every((w) => w.length < 3 || !/^[a-z]/.test(w));
}

export function titleCorpus(
  tree: {
    sections: readonly {
      heading?: string;
      paragraphs: readonly { runs: readonly { text: string }[] }[];
    }[];
  },
  fallback: string,
): string {
  const first = tree.sections[0];
  const heading = (first?.heading ?? "").trim();
  const paragraphs = (first?.paragraphs ?? []).slice(0, TITLE_SUBJECT_SCAN_PARAGRAPHS).map((p) =>
    p.runs
      .map((r) => r.text)
      .join("")
      .trim(),
  );
  const stripped = dropLegends(paragraphs);
  const preamble = (stripped[0] ?? "").slice(0, TITLE_PREAMBLE_CHARS);
  // A document's identity is sometimes TWO lines: a header naming the
  // instrument that governs it, and below that the document's own name.
  // Every equity award carries the shape — "HALCYON INSTRUMENTS, INC. 2026
  // EQUITY INCENTIVE PLAN" above "NOTICE OF STOCK OPTION GRANT" — and the
  // header is not a legend to drop, because the Plan document itself opens on
  // the identical line. Read on one line, a grant notice routed to
  // `equity-incentive-plan` and was checked against the Plan's compliance
  // matrix: it was told at `critical` that it stated no share reserve, and at
  // `warning` that it stated no evergreen, no capitalization adjustment, no
  // change-in-control treatment, no amendment triggers, and no clawback hook.
  // Those are provisions of the Plan. A grant notice has none of them and is
  // not supposed to.
  //
  // Only a title-SHAPED second line is taken, so an ordinary agreement whose
  // second paragraph is body prose contributes nothing.
  // A RUN of title-shaped lines, not just one. The identity can be three lines
  // deep — "HALCYON INSTRUMENTS, INC." / "2026 EQUITY INCENTIVE PLAN" /
  // "NOTICE OF STOCK OPTION GRANT" — and it arrives that way whenever the
  // ingest gives each line its own paragraph, which is what a document with no
  // blank lines does. Reading only the second line lost the grant notice's own
  // name and routed it to the Plan.
  const subtitleLines: string[] = [];
  for (let i = 1; i <= 2; i += 1) {
    if (!titleShaped(stripped[i])) break;
    subtitleLines.push(stripped[i]!.slice(0, TITLE_PREAMBLE_CHARS));
  }
  const subtitle = subtitleLines.join(" ");
  const subject = subjectLine(tree.sections);
  const caption = captionTitle(dropLegends(leadingLines(tree.sections)));
  const recorded = recordedInstrumentTitle(dropLegends(leadingLines(tree.sections)));
  const parts = [heading, preamble, subtitle, subject, caption, recorded].filter(
    (p) => p.length > 0,
  );
  return parts.length > 0 ? parts.join(" ") : fallback;
}

export type MatchInput = {
  /**
   * A title-ish corpus drawn from the document — typically the first
   * heading plus the preamble paragraph. Title-keyword features are
   * matched against this string, case-insensitively.
   */
  title?: string;
  /**
   * Distinguishing-phrase and negative-feature features are matched
   * against this whole-document text. If absent, the matcher falls
   * back to the title.
   */
  body_text?: string;
};

type ScoredPlaybook = {
  playbook: Playbook;
  /** Raw additive score before clamping; used for ranking. */
  raw_score: number;
  /** Score clamped to [0, 1] for external display. */
  score: number;
  matched_title_keywords: string[];
  matched_required_clauses: string[];
  matched_distinguishing_phrases: string[];
  matched_negative_features: string[];
};

/**
 * Pick the best playbook for the document.
 *
 * Weights per spec §26 step 8:
 *  - title keyword match: +0.3 each
 *  - required clause match: +0.4 each
 *  - distinguishing phrase match: +0.2 each
 *  - negative feature match: -0.1 each
 *
 * Each contribution is normalized by the count of that feature type on
 * the playbook so a playbook with many required clauses does not
 * automatically outscore one with few. The final score is bounded to
 * [0, 1] after summation, then compared to {@link MATCH_THRESHOLD}.
 *
 * Ties are broken lexicographically by playbook id for determinism.
 */
/**
 * Longest feature string still treated as an ACRONYM for matching purposes.
 * "psa", "eula", "g701", "daca" are the forms a document actually prints; a
 * longer string is a phrase, and a phrase's substring match is what lets
 * "conflicts of interest" find "Conflicts of Interest Policy".
 */
const ACRONYM_MAX_LENGTH = 5;

/**
 * Match a feature string against a corpus.
 *
 * Features are matched as plain substrings, which is right for a phrase and
 * wrong for an acronym: `change-order` listed **"co"**, which appears inside
 * "Company", "Contract", "Counsel", and "Cost", so it collected a title
 * keyword's 0.3 from almost any document. The same shape sits in "sig"
 * (inside "assignment", "signature"), "spa" (inside "space"), "apa" (inside
 * "apartment"), "ccr" (inside "accrue"), and "safe" (inside "safeguard" and
 * "safe harbor") — a class the catalog acquired one acronym at a time.
 *
 * A short feature is therefore matched on word boundaries. "CO" standing
 * alone in a change order's title still matches; "Company" no longer does.
 */
/**
 * Drop apostrophes so a feature and the document can be compared.
 *
 * Two things defeat a plain substring match, and both are invisible:
 *
 *  - **Word writes the CURLY apostrophe.** Thirty catalog features carry the
 *    straight one — "investors' rights agreement", "attorneys' eyes only",
 *    "finder's fee", "defendant's answer" — and none of them can match a DOCX,
 *    which spells it U+2019. `apostrophe-tolerance.test.ts` has fenced the
 *    RECOGNIZER regexes against this since it was found there; the catalog's
 *    features are plain strings and were never swept.
 *  - **The possessive is optional in the drafter's own spelling.** California's
 *    lien statute and the statutory notice it prescribes both write "mechanics
 *    lien"; Texas writes "mechanic's lien". Only one of the two could match.
 *
 * Removing the apostrophe entirely settles both: "mechanic's" and "mechanics"
 * normalize to the same token, and the curly and straight spellings do too.
 */
function stripApostrophes(text: string): string {
  return text.replace(/['’‘\u02BC]/g, "").replace(/[\u2010-\u2015]/g, "-");
}

/**
 * The three spellings of a compound a drafter may use, precomputed once for
 * the whole corpus.
 *
 * The hyphen is optional in legal English and every family carries at least
 * one compound that is written all three ways: "non-disclosure agreement",
 * "nondisclosure agreement", "non disclosure agreement"; "anti-money-
 * laundering policy" and "anti-money laundering policy"; "attorney-in-fact"
 * and "attorney in fact"; "by-laws" and "bylaws". A hundred and thirty-six
 * catalog features carry a hyphen, and each could match exactly one of the
 * three.
 *
 * Spaces are never removed — only hyphens are — so no comparison can join two
 * words that the document keeps apart. That is what keeps a feature like "a
 * lien" from matching "alien".
 */
type Corpus = { plain: string; noHyphen: string; spaced: string };

function buildCorpus(text: string): Corpus {
  const plain = stripApostrophes(text);
  return {
    plain,
    noHyphen: plain.replace(/-/g, ""),
    spaced: plain.replace(/-/g, " "),
  };
}

function matchesIn(corpus: Corpus, feature: string): boolean {
  const needle = stripApostrophes(feature.toLowerCase());
  if (needle.length === 0) return false;
  const variants: Array<[string, string]> = [
    [corpus.plain, needle],
    [corpus.noHyphen, needle.replace(/-/g, "")],
    [corpus.spaced, needle.replace(/-/g, " ")],
  ];
  for (const [hay, pin] of variants) {
    if (pin.length === 0) continue;
    if (pin.length > ACRONYM_MAX_LENGTH || !/^[a-z0-9][a-z0-9.-]*$/.test(pin)) {
      if (hay.includes(pin)) return true;
      continue;
    }
    const escaped = pin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:^|[^a-z0-9])${escaped}(?![a-z0-9])`, "i").test(hay)) return true;
  }
  return false;
}

/**
 * Exported for `apostrophe-tolerance.test.ts`, which sweeps the whole shipped
 * catalog for a feature that cannot match its own spelling. The guard has to
 * probe the comparison itself: a one-feature document scores below the routing
 * threshold, so the match result names no features to assert on.
 */
export function matchesFeature(corpusRaw: string, feature: string): boolean {
  return matchesIn(buildCorpus(corpusRaw), feature);
}

/**
 * Ranking tolerance for {@link matchPlaybook}. Scores are sums of decimal
 * tenths, so anything below this is float noise, not a difference.
 */
const SCORE_EPSILON = 1e-9;

export function matchPlaybook(
  extracted: ExtractedData,
  classified: ClassifiedParagraph[],
  available: readonly Playbook[],
  input: MatchInput = {},
): PlaybookMatchResult {
  const title = buildCorpus((input.title ?? "").toLowerCase());
  const body = buildCorpus((input.body_text ?? input.title ?? "").toLowerCase());
  const present_categories = new Set(classified.map((c) => c.category));
  const defined_terms = new Set(extracted.definitions.entries.map((e) => e.term.toLowerCase()));

  const scored: ScoredPlaybook[] = available.map((playbook) => {
    const f = playbook.match_features;

    const matched_title_keywords = f.title_keywords.filter((kw) => matchesIn(title, kw));
    const matched_required_clauses = f.required_clauses.filter(
      (cat) => present_categories.has(cat) || defined_terms.has(cat.toLowerCase()),
    );
    const matched_distinguishing_phrases = f.distinguishing_phrases.filter((p) =>
      matchesIn(body, p),
    );
    const matched_negative_features = f.negative_features.filter((n) => matchesIn(body, n));

    // Per-match additive scoring, with each feature category capped so
    // playbooks with many keywords don't auto-dominate playbooks with
    // few. Title and required-clause contributions cap at 2x their
    // weight; distinguishing phrases cap at 3x to reward several
    // independent textual hits.
    const tkw_score = Math.min(
      matched_title_keywords.length * MATCH_WEIGHTS.title_keyword,
      MATCH_WEIGHTS.title_keyword * 2,
    );
    // ONE required clause, not two.
    //
    // `required_clauses` are classifier CATEGORIES — "term",
    // "termination-for-cause", "indemnification", "confidentiality-obligation",
    // "ip-ownership" — and the generic commercial families list three apiece.
    // Any agreement with a confidentiality section, a term, and a statement of
    // work therefore collected 0.8 for them, which is the largest single block
    // in the score and enough on its own to beat a specialised family that
    // matched its own title and three phrases of its own register.
    //
    // That is how `independent-contractor` took an FTC endorsement agreement,
    // `consulting-agreement` and then `mutual-nda`, `msa-general` and `sow`
    // took a joint development agreement, and `msa-general` took a copyright
    // licence — each fixed by hand, one negative feature at a time, before the
    // cause was measured.
    //
    // Lowering the cap to one was run against the whole suite: all 166
    // specimens still route to the family they are pinned to, all 365 golden
    // fixtures are unchanged, and 10,284 tests pass. The second required
    // clause was contributing nothing correct anywhere — it only let a generic
    // family outbid a specific one.
    const req_score = Math.min(
      matched_required_clauses.length * MATCH_WEIGHTS.required_clause,
      MATCH_WEIGHTS.required_clause * 1,
    );
    const dist_score = Math.min(
      matched_distinguishing_phrases.length * MATCH_WEIGHTS.distinguishing_phrase,
      MATCH_WEIGHTS.distinguishing_phrase * 3,
    );
    const neg_penalty = matched_negative_features.length * MATCH_WEIGHTS.negative_feature;

    const raw = tkw_score + req_score + dist_score + neg_penalty;
    const score = clamp(raw, 0, 1);

    return {
      playbook,
      raw_score: raw,
      score,
      matched_title_keywords,
      matched_required_clauses,
      matched_distinguishing_phrases,
      matched_negative_features,
    };
  });

  scored.sort((a, b) => {
    // Compare scores at display precision, not at IEEE-754 precision.
    //
    // The weights are decimal tenths, and three distinguishing phrases
    // (0.2 × 3 = 0.6000000000000001) are not equal to two title keywords
    // (0.3 × 2 = 0.6). A trademark coexistence agreement therefore lost to
    // `mutual-nda-deep` — which matched "each party", "either party",
    // "irreparable harm" — by one part in 10^16, and every tiebreak below
    // was unreachable in exactly the cases it was written for. Both scores
    // were reported to the user as 0.6.
    if (Math.abs(b.raw_score - a.raw_score) > SCORE_EPSILON) return b.raw_score - a.raw_score;
    // Tiebreak 1: prefer non-deprecated over deprecated. Lets a
    // `*-deep` successor outrank its legacy v2 sibling when both
    // score identically.
    const aDep = a.playbook.deprecated === true;
    const bDep = b.playbook.deprecated === true;
    if (aDep !== bDep) return aDep ? 1 : -1;
    // Tiebreak 2: prefer the family the document's TITLE named.
    //
    // A trademark coexistence agreement tied `mutual-nda-deep` at 0.6 — the
    // coexistence family on two title keywords, the NDA family on four
    // phrases every bilateral agreement carries ("each party", "either
    // party", "injunctive relief", "irreparable harm") — and lost the tie to
    // the alphabet. It was then audited as a mutual NDA and reported nine
    // critical omissions, every one of them a clause no coexistence
    // agreement has.
    //
    // The title is the document saying what it is. When two families score
    // the same, the one that read the title is the better guess.
    if (b.matched_title_keywords.length !== a.matched_title_keywords.length) {
      return b.matched_title_keywords.length - a.matched_title_keywords.length;
    }
    // Tiebreak 3: lexicographic id for determinism.
    return a.playbook.id.localeCompare(b.playbook.id, "en");
  });

  const top = scored[0];
  const alternatives: PlaybookMatchAlternative[] = scored.slice(1, 4).map((s) => ({
    playbook_id: s.playbook.id,
    confidence: round3(s.score),
    raw_confidence: round3(s.raw_score),
  }));

  if (!top || top.playbook.id === GENERIC_FALLBACK_ID || top.score < MATCH_THRESHOLD) {
    return {
      playbook_id: GENERIC_FALLBACK_ID,
      confidence: top ? round3(top.score) : 0,
      raw_confidence: top ? round3(top.raw_score) : 0,
      alternatives: top
        ? scored
            .slice(0, 3)
            .filter((s) => s.playbook.id !== GENERIC_FALLBACK_ID)
            .map((s) => ({
              playbook_id: s.playbook.id,
              confidence: round3(s.score),
              raw_confidence: round3(s.raw_score),
            }))
        : [],
      reasoning: buildFallbackReasoning(top),
    };
  }

  return {
    playbook_id: top.playbook.id,
    confidence: round3(top.score),
    raw_confidence: round3(top.raw_score),
    alternatives,
    reasoning: buildReasoning(top),
  };
}

function clamp(n: number, lo: number, hi: number): number {
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function buildReasoning(s: ScoredPlaybook): string {
  const parts: string[] = [];
  parts.push(`Selected ${s.playbook.id} (score ${round3(s.score)}).`);
  if (s.matched_title_keywords.length > 0) {
    parts.push(`Title matched: ${quote(s.matched_title_keywords)}.`);
  }
  if (s.matched_required_clauses.length > 0) {
    parts.push(`Required clauses present: ${quote(s.matched_required_clauses)}.`);
  }
  if (s.matched_distinguishing_phrases.length > 0) {
    parts.push(`Distinguishing phrases: ${quote(s.matched_distinguishing_phrases)}.`);
  }
  if (s.matched_negative_features.length > 0) {
    parts.push(`Negative features penalized: ${quote(s.matched_negative_features)}.`);
  }
  return parts.join(" ");
}

function buildFallbackReasoning(top: ScoredPlaybook | undefined): string {
  if (!top) {
    return `No playbooks supplied; using ${GENERIC_FALLBACK_ID}.`;
  }
  if (top.playbook.id === GENERIC_FALLBACK_ID) {
    return `Top-scoring entry is the fallback itself (${round3(top.score)}); using ${GENERIC_FALLBACK_ID}.`;
  }
  return `Best score was ${top.playbook.id} at ${round3(top.score)}, below the ${MATCH_THRESHOLD} threshold; using ${GENERIC_FALLBACK_ID}.`;
}

function quote(items: string[]): string {
  return items.map((i) => `"${i}"`).join(", ");
}

import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { borrowsParentVocabulary } from "../_helpers.js";

/**
 * STRUCT-006 — Used-but-never-defined capitalized terms (warning).
 *
 * Lists Title-Case multi-word phrases used in the body but not in the
 * defined-term list. Party names and a small set of common words are
 * filtered out by the extractor.
 */
/**
 * The incorporation-by-reference clause: capitalized terms not defined in THIS
 * document take their meanings from a named parent one. Both halves are
 * required, and the gap between them is bounded to a single sentence.
 */
const INCORPORATES_DEFINITIONS =
  /\b(?:capitali[sz]ed|defined)\s+terms?\b[^.]{0,120}?\bnot\s+(?:otherwise\s+)?defined\b[^.]{0,120}?\b(?:have|has|(?:shall|will|must)\s+have|(?:shall|will|must)\s+bear|are\s+given)\s+the\s+(?:respective\s+)?meanings?\b/i;

function documentText(ctx: RuleContext): string {
  const parts: string[] = [];
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(s.children);
    }
  };
  walk(ctx.tree.sections);
  return parts.join(" ");
}

/**
 * A public OFFICE is not a defined term.
 *
 * "before me, the undersigned Notary Public", "sworn before a Commissioner of
 * Deeds", "recorded with the Register of Deeds": every acknowledgment,
 * affidavit, and recorded instrument names the officer before whom it was
 * taken, in Title Case, and none of them defines the office — the state does.
 * A Louisiana Act of Cash Sale was told that "Notary Public" is a term it
 * forgot to define.
 */
/**
 * How far into the opening line to look for the document's own name. Long
 * enough for "ACTION BY WRITTEN CONSENT OF THE BOARD OF DIRECTORS OF
 * THISTLEDOWN ROBOTICS, INC.", short enough that a document with no heading
 * and a body paragraph first cannot suppress terms from its own prose.
 */
const TITLE_SCAN_CHARS = 140;

/**
 * An INTERNAL FUNCTION is a department, not a defined term.
 *
 * Every policy names the team that administers it — "report it to Trade
 * Compliance", "escalate to Information Security", "the People team
 * investigates" — in Title Case, and no policy stops to define its own org
 * chart. An export control policy was told that "Trade Compliance" is a term
 * it forgot to define, in the paragraph that tells employees to call them.
 *
 * Anchored on the FUNCTION word at the end of the phrase, so an ordinary
 * defined term is untouched: nothing calls a defined term "Trade Compliance".
 */
const INTERNAL_FUNCTION =
  /\b(?:compliance|legal|finance|accounting|engineering|security|procurement|operations|marketing|payroll|treasury|audit|human\s+resources|people\s+(?:team|operations))$/i;

const PUBLIC_OFFICE =
  /^(?:notary\s+public|justice\s+of\s+the\s+peace|commissioner\s+of\s+deeds|clerk\s+of\s+(?:the\s+)?court|register\s+of\s+deeds|recorder\s+of\s+deeds|county\s+(?:clerk|recorder)|secretary\s+of\s+state|attorney\s+general|clerk\s+of\s+the\s+circuit\s+court)$/i;

/**
 * A person the document introduces by their relationship to the declarant.
 *
 * "I appoint my husband, Thomas Aurelio Harper, as Executor"; "I give my
 * grandmother's pearl brooch to my daughter, Nadia Harper Okonkwo". A will,
 * trust, power of attorney, or guardianship designation names the people it
 * benefits and appoints, and none of them is a PARTY — the only party is the
 * declarant — so the party-name subtraction below could not reach them, and a
 * well-drafted will was told that its executor and its residuary beneficiary
 * are Title-Case terms it forgot to define. A person's name is never a defined
 * term, and the appositive is how the document says it is a person.
 *
 * Anchored on the relationship word immediately before the name, so an
 * ordinary defined term introduced in the same shape ("the Purchase Price")
 * is untouched: nothing calls a defined term "my daughter".
 */
const PERSONAL_APPOSITIVE = String.raw`(?:my|our|his|her|their|the)\s+(?:late\s+)?(?:husband|wife|spouse|son|daughter|child|children|stepson|stepdaughter|mother|father|parent|brother|sister|sibling|grandson|granddaughter|grandchild|niece|nephew|aunt|uncle|cousin|partner|friend|executor|executrix|administrator|trustee|co-trustee|successor\s+trustee|guardian|conservator|attorney-in-fact|agent|personal\s+representative|beneficiary)\s*,\s*`;

function isNamedPerson(documentBody: string, term: string): boolean {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`${PERSONAL_APPOSITIVE}${escaped}\\b`, "i").test(documentBody);
}

/**
 * A JOB TITLE is not a defined term.
 *
 * An offer letter is written in Title Case throughout about the one thing it
 * exists to offer — "the position of Staff Mechanical Engineer", "You will be
 * a Staff Mechanical Engineer reporting to …" — and it was told that Staff
 * Mechanical Engineer is a term it forgot to define. There is no drafting
 * change that answers it: a letter cannot define the job it is offering
 * without writing 'the position of Staff Mechanical Engineer (the "Staff
 * Mechanical Engineer")'.
 *
 * The introduction is the test, not a vocabulary list — job titles are
 * unbounded, and the phrases below are how an EMPLOYMENT document says the
 * Title-Case run that follows is the job. An ordinary defined term introduced
 * the same way does not exist: nothing reads "the position of the Purchase
 * Price".
 *
 * A bare "as" is deliberately not one of them. It reads "as Settlor and
 * initial Trustee", "shall serve as Successor Trustee", "as Escrow Agent" —
 * every fiduciary role in every estate and escrow instrument — and admitting
 * it stood down the check on four revocable-trust fixtures.
 */
const POSITION_INTRODUCTION = String.raw`(?:the\s+(?:position|role|title|job|post)\s+of|(?:employed|hired|engaged|promoted|appointed)\s+(?:as|to)\s+(?:an?\s+|the\s+)?|you\s+will\s+be\s+(?:an?\s+|the\s+)?)`;

function isJobTitle(documentBody: string, term: string): boolean {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`${POSITION_INTRODUCTION}\\s*${escaped}\\b`, "i").test(documentBody);
}

export const rule: Rule = {
  id: "STRUCT-006",
  version: "1.8.0",
  name: "Used-but-never-defined capitalized terms",
  category: "structural",
  default_severity: "warning",
  description: "Reports Title-Case multi-word phrases that are used in the body but never defined.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // A document that imports its definitions is not missing them.
    //
    // "Capitalized terms used and not defined in this Amendment have the
    // meanings given in the Lease" is the standard incorporation clause, and
    // it appears in every amendment, addendum, statement of work, side letter,
    // and order form — documents whose whole point is that the parent defines
    // the vocabulary. A third amendment to an office lease was told that Base
    // Rent, Base Year, Proportionate Share, Fair Market Rental Value, and
    // Security Deposit were undefined, in a document whose Section 1 says
    // exactly where they are defined. Every one of those is a false
    // accusation, and there is no drafting change that would answer it short
    // of restating the parent lease.
    //
    // The clause is recognized on its two load-bearing halves — capitalized
    // terms not defined HERE, and their meanings given THERE — so an ordinary
    // sentence that merely mentions defined terms does not disable the check.
    // A document that RATIFIES a named parent takes its vocabulary from it just
    // as squarely as one that says so in a definitions clause. A construction
    // change order closes with "Except as expressly modified here, all terms of
    // the Contract dated June 3, 2025 remain in full force and effect" and was
    // told that Contract Sum and Contract Time — the two terms the AIA contract
    // it modifies exists to define — are terms it forgot to define.
    if (INCORPORATES_DEFINITIONS.test(documentText(ctx)) || borrowsParentVocabulary(ctx))
      return null;
    // A party's defined ROLE is introduced in the preamble exactly like any
    // other defined term — `… the individual or entity accepting this EULA
    // ("End User")` — so the body's later use of "End User" is defined, not
    // undefined. Matching party NAMES alone reported those roles as never
    // defined.
    const partyNames = new Set(
      ctx.extracted.parties.flatMap((p) => [
        p.name.toLowerCase(),
        ...(p.role ? [p.role.toLowerCase()] : []),
      ]),
    );
    // A candidate that is a word-boundary prefix of a party's name is that
    // party, colloquially shortened — "Halewood Media" for the party
    // "Halewood Media LLC" (TITLE_CASE_PHRASE cannot include the all-caps
    // suffix) — never an undefined term.
    const body = documentText(ctx);
    // The heading, or — when the ingest gives an unstyled document none, which
    // is what every pasted or plain-text document gets — the opening line.
    // Reading `sections[0].heading` alone found the empty string and
    // suppressed nothing on exactly the documents that need it.
    const firstSection = ctx.tree.sections[0];
    const headingText = (firstSection?.heading ?? "").trim();
    const openingLine = (firstSection?.paragraphs[0]?.runs ?? [])
      .map((r) => r.text)
      .join("")
      .trim();
    const title = (headingText.length > 0 ? headingText : openingLine)
      .slice(0, TITLE_SCAN_CHARS)
      .toLowerCase();
    const candidates = ctx.extracted.definitions.undefined_capitalized.filter((e) => {
      const lower = e.term.toLowerCase();
      if (partyNames.has(lower)) return false;
      for (const name of partyNames) {
        if (name.startsWith(`${lower} `)) return false;
      }
      // A person the document names by their relationship to the declarant is
      // a person, not a term the drafter forgot to define.
      if (isNamedPerson(body, e.term)) return false;
      // A public office is defined by the state, not by this document.
      if (PUBLIC_OFFICE.test(e.term.trim())) return false;
      // The job the document offers is a role, not a term it forgot to define.
      if (isJobTitle(body, e.term)) return false;
      // An internal function is a department, not a defined term.
      if (INTERNAL_FUNCTION.test(e.term.trim())) return false;
      // The document's OWN NAME is not a term it forgot to define. Every
      // instrument refers to itself in Title Case throughout — "this Written
      // Consent", "this Guaranty", "this Tolling Agreement" — and the name is
      // established by the heading at the top of the page, not by a
      // definitions section. An action by written consent of the board was
      // told that "Written Consent" is an undefined term, in a document
      // titled ACTION BY WRITTEN CONSENT. There is no drafting change that
      // answers it: a document cannot define its own title without saying
      // "this Written Consent (this "Written Consent")".
      if (title.includes(e.term.toLowerCase())) return false;
      return true;
    });
    if (candidates.length === 0) return null;

    const first = candidates[0]!;
    const list = candidates
      .slice(0, 12)
      .map((c) => c.term)
      .join(", ");
    const extra = candidates.length > 12 ? `, …(${candidates.length - 12} more)` : "";
    return makeFinding({
      rule,
      title: `Undefined Title-Case terms: ${candidates.length}`,
      description: `Used but not defined: ${list}${extra}.`,
      excerptText: first.term,
      explanation:
        "Title-Case phrases in a contract usually signal a defined term. When they aren't defined, readers must guess at the intended meaning. Either define them or use lowercase if the term is intended in its ordinary sense.",
      recommendation:
        "Add a definition for each genuinely defined term, or change the casing if the phrase is being used in its ordinary sense.",
      position: first.positions[0] ?? { section_id: "", start: 0, end: 0 },
      source_citations: [],
    });
  },
};

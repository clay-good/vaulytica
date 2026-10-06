import type { Rule, RuleContext, Finding } from "../../finding.js";
import {
  allMatches,
  emit,
  firstParagraphMatch,
  MODAL_QUALIFIER,
  OBLIGATION_MODAL,
} from "../_helpers.js";
import { forEachSection } from "../../../extract/walk.js";
import { isStatutoryDandOIndemnity } from "./RISK-015.js";
import { truncate } from "../../text.js";

const PROCEDURE = [
  // The notice element is stated with the VERB at least as often as the noun
  // — "we will notify you of any such claim", "Buyer shall promptly notify
  // Seller of any claim for which it seeks indemnification". A noun-only
  // pattern reported this element missing on an indemnity that spells the
  // obligation out. Anchored on a claim word inside the sentence, so an
  // unrelated "notify the other party of a change of address" in the same
  // section is not read as the claims-notice term.
  [
    "notice",
    // The claim word can come first: "… any third-party claim that the Work
    // infringes …, provided that Client promptly notifies Contractor".
    /prompt(?:ly)?\s+notice|written\s+notice|\bnotice\s+of\s+(?:any|the|such|each)\b|\bnotif(?:y|ies|ied)\b[^.]{0,80}?\b(?:claim|demand|action|proceeding|suit)\b|\b(?:claim|demand|action|proceeding|suit)\b[^.]{0,160}?\bprompt(?:ly)?\s+notif(?:y|ies|ied)\b|\b(?:indemnified|indemnitee)\b[^.]{0,60}?\bnotif(?:y|ies)\b[^.;,]{0,60}?\bprompt(?:ly)?\b/i,
  ],
  // "defense control" must be tied to the defense/claim — a bare "sole control"
  // matched an unrelated clause ("sole control over its own systems") and
  // wrongly reported this element as present.
  [
    "defense control",
    // "duty to defend" and "defend … with counsel …" articulate which party
    // conducts the defense just as much as "control of the defense" — an
    // indemnity that spells out the defense obligation and counsel selection
    // was wrongly reported as missing this element.
    // The BRITISH spelling is the one a UK or Commonwealth indemnity uses, and
    // this repo already reads "licence" beside "license" for the same reason.
    // "gives Contractor control of the defence" is the textbook clause and was
    // reported as an indemnity missing its defence-control element.
    // The determiner varies: "allow the indemnifying party to control ITS
    // defense" is the same element, and a venue rental agreement that said so
    // was told its indemnity named no one to control the defense.
    // The indemnitee's right to "participate at its own expense" is the
    // other half of the same term: the indemnitor conducts the defense.
    /(?:sole\s+|exclusive\s+)?control\s+(?:of|over)\s+(?:the|its|their|such|any\s+such)\s+(?:defen[cs]e|claim|litigation|proceeding|action)|control\s+(?:the|its|their|such)\s+defen[cs]e|(?:assume|conduct)\s+(?:the\s+)?defen[cs]e|duty\s+to\s+defend|defend[^.]{0,50}\bcounsel\b|\bparticipate\b[^.;]{0,40}?\bat\s+(?:its|their)\s+own\s+(?:cost|expense)/i,
  ],
  // "shall not settle any claim in a manner that imposes liability on the
  // indemnified party without the indemnified party's prior written consent"
  // puts ~110 chars between "settle" and "consent". Bound the run to one
  // sentence ([^.]) — where a co-occurring settle/consent is always the
  // settlement-consent term — and accept either order.
  //
  // APPROVAL IS CONSENT. "amounts paid in settlement approved by Provider" and
  // "no settlement without the indemnitor's prior written approval" are the
  // ordinary way half of technology indemnities write this term, and reading
  // only the word "consent" reported an indemnity that plainly contains it as
  // missing it — the failure direction that matters for a presence rule, since
  // its false positive is a confident accusation about a clause the document
  // has. Found by the clean-document method on a complete SaaS agreement.
  [
    "settlement consent",
    /settl\w*[^.]{0,160}(?:consent|approv\w*)|(?:consent|approv\w*)[^.]{0,120}settl/i,
  ],
] as const;

// An operative indemnity promise, as distinct from a passing reference. A
// SOW that incorporates "the MSA's … indemnification … provisions" by
// reference contains no indemnity clause of its own — auditing that
// cross-reference for defense-control and settlement-consent mechanics
// accused a correctly drafted document of an incomplete clause it never
// purported to contain.
const OPERATIVE_INDEMNITY = new RegExp(
  `\\b(?:${OBLIGATION_MODAL}|hereby)${MODAL_QUALIFIER}(?:(?:further|also|fully|jointly\\s+and\\s+severally|at\\s+all\\s+times)\\s+)?(?:defend,?\\s+)?indemnif|\\bindemnifies\\b|\\bindemnification\\s+by\\b`,
  "i",
);

const CLAUSE_NUMBER = /^\s*(?:(?:article|section|clause)\s+)?(\d+(?:\.\d+)*)\.?\s+\S/i;
// "Notice" only as "Notice and …" / "Notice of …": a general "Notices;
// Counterparts" clause is not the claims procedure.
const PROCEDURE_TITLE =
  /\b(?:defen[cs]e|defend|procedur\w*|claims?|indemni\w*|third[- ]party|settle\w*|cooperat\w*|notice\s+(?:and|of)\b)/i;
/**
 * The clause's title: the run-in "9.2 Indemnification Procedure." →
 * "Indemnification Procedure", or a heading line's own text.
 */
const clauseTitle = (p: string): string =>
  /^\s*(?:(?:article|section|clause)\s+)?[\d.]*\s*([^.]{0,80})(?:\.|$)/i.exec(p)?.[1] ?? "";

/**
 * The indemnity paragraph and the paragraphs that belong to it: its own
 * sub-clauses ("9.1" → "9.1.1"), unnumbered continuation paragraphs, and any
 * clause whose title names the procedure ("9.2 Indemnification Procedure",
 * "4. DEFENSE AND COOPERATION") with its own continuation. Any other clause
 * ("9.2 Amendments", "ARTICLE 10") closes the run until such a title reopens it.
 */
function clauseRun(paras: string[], start: number): string[] {
  const own = CLAUSE_NUMBER.exec(paras[start]!)?.[1];
  const out = [paras[start]!];
  let open = true;
  for (let i = start + 1; i < paras.length; i++) {
    const p = paras[i]!;
    const n = CLAUSE_NUMBER.exec(p)?.[1];
    if (n && !(own && n.startsWith(`${own}.`))) open = PROCEDURE_TITLE.test(clauseTitle(p));
    if (open) out.push(p);
  }
  return out;
}

/** RISK-011 — Indemnity procedure clause present (info). */
export const rule: Rule = {
  id: "RISK-011",
  version: "1.7.0",
  name: "Indemnity procedure clause",
  category: "risk-allocation",
  default_severity: "info",
  description:
    "Verifies the indemnity includes notice, defense-control, and settlement-consent procedural elements.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // The indemnity's OWN clause, not its first mention: a credit agreement
    // says "indemnify" in its breakage-costs clause (§2.8) long before §9.1
    // "Indemnification". A pasted document is often one section, which hid
    // this; the same agreement as a DOCX audited §2 and reported the §9
    // procedure missing. A paragraph titled "Indemnification" / "Supplier
    // Indemnity" leads, else the first
    // mention as before.
    const indem =
      allMatches(
        ctx,
        /^\s*(?:\d+(?:\.\d+)*\.?\s+)?(?:[A-Z][\w'’-]*\s+){0,2}Indemni(?:ty|fication|ties)\b/,
      )[0] ?? firstParagraphMatch(ctx, /\bindemnif/i);
    if (!indem) return null;
    // The first match is often the SECTION HEADING ("7. INDEMNIFICATION"),
    // and testing the procedure regexes against a heading declared every
    // element missing while they sat one paragraph below — with the excerpt
    // anchored to the heading (audit). Evaluate the whole containing
    // section, and anchor to its first substantive indemnity paragraph.
    // Searched at every depth: a DOCX nests its numbered headings, and a
    // top-level lookup found nothing, so the rule audited one paragraph and
    // reported the "6.3 Procedure" paragraph's notice, defense control and
    // settlement consent all missing.
    let section: (typeof ctx.tree.sections)[number] | undefined;
    forEachSection(ctx.tree, (s) => {
      if (!section && s.id === indem.position.section_id) section = s;
    });
    const paraText = (p: { runs: { text: string }[] }): string =>
      p.runs.map((r) => r.text).join("");
    // Plus any section whose HEADING names the procedure: a hold-harmless
    // agreement puts notice and defense in "4. Defense and Cooperation", a
    // clause of its own. Pasted text is often one section and saw it anyway;
    // a DOCX, where it is a sibling section, did not.
    const procedureSections: string[] = [];
    forEachSection(ctx.tree, (s) => {
      if (
        s !== section &&
        /\b(?:defen[cs]e|procedur\w*|claims?|notices?|indemni\w*)\b/i.test(s.heading ?? "")
      )
        procedureSections.push(s.heading ?? "", ...s.paragraphs.map(paraText));
    });
    // The CLAUSE, not the whole section, when the section is not itself the
    // indemnity: pasted text is often one section for the whole document, and
    // a revolving credit agreement's §9.1 indemnity — defense control and
    // settlement consent, no claims notice — passed on "three Business Days'
    // prior written notice" in §8.2 Voluntary Termination. The DOCX reading,
    // where §9 was the section, said so.
    const paras = section?.paragraphs.map(paraText) ?? [];
    const start = paras.indexOf(indem.text);
    const clause =
      section && start >= 0 && !/\bindemni/i.test(section.heading ?? "")
        ? clauseRun(paras, start)
        : paras;
    const sectionText = section
      ? [section.heading ?? "", ...clause, ...procedureSections].join("\n")
      : indem.text;
    // No operative promise anywhere in the containing section means the match
    // was a passing reference (an incorporation of a parent agreement's
    // indemnity, a liability-cap carve-out) — there is no clause to audit.
    if (!OPERATIVE_INDEMNITY.test(sectionText)) return null;
    // Statutory D&O indemnification (bylaws/charter) is not a commercial
    // indemnity clause; demanding defense-control and settlement-consent
    // mechanics of DGCL § 145 language audits the wrong instrument.
    if (isStatutoryDandOIndemnity(sectionText)) return null;
    // Likewise the fiduciary-protection indemnity every escrow agreement and
    // indenture gives its neutral agent ("Buyer and Seller shall jointly and
    // severally indemnify and hold harmless the Escrow Agent") — the agent's
    // protection is good-faith reliance and ministerial duties, not
    // commercial claims-procedure mechanics.
    //
    // The verb string is "indemnify, DEFEND, and hold harmless" at least as
    // often as the two-verb form, and the adjacent pattern could not reach
    // past the inserted word: an M&A escrow agreement whose Section 9 reads
    // "Buyer and the Sellers, jointly and severally, shall indemnify, defend,
    // and hold harmless the Escrow Agent" was audited as a commercial
    // indemnity and told it controls no defense and requires no settlement
    // consent — of the clause that protects the neutral stakeholder.
    if (
      /\bindemnify\b[^.;]{0,60}?\bhold\s+(?:harmless\s+)?the\s+(?:escrow\s+agent|trustee|administrative\s+agent|collateral\s+agent|paying\s+agent|depositary|custodian)\b/i.test(
        sectionText,
      )
    ) {
      return null;
    }
    const missing = PROCEDURE.filter(([, re]) => !re.test(sectionText)).map(([n]) => n);
    if (missing.length === 0) return null;
    const substantive = clause.find((t) => /\bindemnif/i.test(t) && t.length > 60);
    return emit(ctx, rule, {
      title: `Indemnity procedural elements missing: ${missing.join(", ")}`,
      description: `Indemnity clause appears to be missing: ${missing.join(", ")}.`,
      excerpt: truncate(substantive ?? indem.text, 280),
      explanation:
        "A complete indemnity clause specifies (a) the timeline and form for notice of a claim, (b) which party controls defense, and (c) whether settlement requires consent.",
      position: substantive
        ? { section_id: indem.position.section_id, start: 0, end: 0 }
        : indem.position,
    });
  },
};

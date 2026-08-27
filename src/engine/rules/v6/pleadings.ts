/**
 * v6 pack C — pleadings (spec-v46.md §7).
 *
 * Two families, checked against the pleading rules. Namespace: `PLDG`.
 *
 * The line these checks hold is the same one the filing-format pack holds:
 * they read **form**, never merit. Whether a complaint states a plausible
 * claim, whether an affirmative defense is available, whether a Rule 9(b)
 * allegation is particular *enough* — all of those are the drafter's
 * judgment. What a deterministic tool can see is whether the pleading does
 * the structural things the rules require of every pleading: allege the
 * basis of jurisdiction, number its paragraphs, respond to each averment,
 * demand relief, carry a Rule 11 signature.
 */

import type { Rule } from "../../finding.js";
import { pack, frcp, localRule, practice } from "./_helpers.js";

const C = "pleadings";

const COMPLAINT = pack("complaint", C, [
  {
    id: "PLDG-001",
    name: "Caption naming the court and all parties",
    cite: frcp("10(a)", "form of pleadings — caption and names of parties"),
    pat: [
      /(in\s+the\s+(united\s+states\s+)?(district|superior|circuit|supreme|county)\s+court|court\s+of\s+(common\s+pleas|chancery))/i,
      /(plaintiff|petitioner)/i,
    ],
    all: true,
    why: "Rule 10(a) requires a caption with the court's name, a title naming all parties, a file number, and a Rule 7(a) designation. The complaint is the one pleading that must name every party in the title.",
    fix: "Add the full caption with the court, the complete party title, the case number field, and the pleading designation.",
    sev: "critical",
  },
  {
    id: "PLDG-002",
    name: "Short and plain statement of the grounds for jurisdiction",
    cite: frcp("8(a)(1)", "claim for relief — grounds for the court's jurisdiction"),
    pat: [
      /jurisdiction/i,
      /(28\s+u\.?s\.?c\.?\s*§?\s*13[23]\d|diversity|federal\s+question|amount\s+in\s+controversy|supplemental\s+jurisdiction)/i,
    ],
    all: true,
    why: "Rule 8(a)(1) requires a short and plain statement of the grounds for jurisdiction. Federal courts raise subject-matter jurisdiction on their own, and a complaint that does not plead it invites a sua sponte dismissal before anyone reaches the merits.",
    fix: "Plead the jurisdictional basis with its statute, and for diversity, plead each party's citizenship and the amount in controversy.",
    sev: "critical",
  },
  {
    id: "PLDG-003",
    name: "Venue allegation",
    cite: frcp("12(b)(3)", "defenses — improper venue"),
    pat: [
      /venue/i,
      /(28\s+u\.?s\.?c\.?\s*§?\s*1391|proper\s+in\s+this\s+district|substantial\s+part\s+of\s+the\s+events|resides\s+in\s+this)/i,
    ],
    all: true,
    why: "Venue is waivable but a Rule 12(b)(3) motion is cheap to make and expensive to answer. Pleading the venue basis forecloses it at the outset.",
    fix: "Plead venue with the statute and the facts that satisfy it — the events, the property, or the defendant's residence.",
  },
  {
    id: "PLDG-004",
    // 1.0.1 — the `m` flag on the numbered-paragraph recognizer used to be
    // dropped when the pillars were conjoined, so this column read only the
    // very start of the document (`v5/_pack.ts`).
    ver: "1.0.1",
    name: "Numbered paragraphs limited to a single set of circumstances",
    cite: frcp("10(b)", "form of pleadings — paragraphs and separate statements"),
    pat: [
      /^\s*\d+\.\s/m,
      /(count\s+(one|i\b|1)|first\s+(cause\s+of\s+action|claim)|claim\s+for\s+relief)/i,
    ],
    all: true,
    why: "Rule 10(b) requires numbered paragraphs each limited as far as practicable to a single set of circumstances, and separate counts where doing so promotes clarity. Unnumbered narrative cannot be answered paragraph by paragraph as Rule 8(b) requires.",
    fix: "Number every paragraph sequentially and separate each claim into its own count with its own heading.",
    sev: "critical",
  },
  {
    id: "PLDG-005",
    name: "Rule 9(b) particularity for fraud or mistake",
    cite: frcp("9(b)", "pleading special matters — fraud or mistake"),
    pat: [
      /(fraud|misrepresent|mistake|conceal)/i,
      /(on\s+or\s+about\s+\w+\s+\d{1,2}|specifically\s+(stated|alleged)|who,?\s+what,?\s+when|the\s+following\s+statements?\s+(were|was)\s+made)/i,
    ],
    all: true,
    why: "Rule 9(b) requires the circumstances of fraud or mistake to be stated with particularity — the who, what, when, where, and how. Generalized fraud allegations are the most commonly dismissed pleading defect in federal practice.",
    fix: "For each fraud-based claim, plead the speaker, the statement, the date and place, the content, and why it was false.",
    when: [/(fraud|fraudulent|misrepresent|mistake|conceal|false\s+statement)/i],
    sev: "critical",
  },
  {
    id: "PLDG-006",
    name: "Demand for relief",
    cite: frcp("8(a)(3)", "claim for relief — demand for the relief sought"),
    pat: [
      /(wherefore|prayer\s+for\s+relief|demand(s)?\s+judgment|requests?\s+that\s+(this|the)\s+court)/i,
      /(damages|injunctive|declaratory|costs|attorneys['’]?\s+fees|such\s+other\s+(and\s+further\s+)?relief)/i,
    ],
    all: true,
    why: "Rule 8(a)(3) requires a demand for the relief sought. A default judgment cannot exceed what the demand asked for, so an omitted or narrow prayer caps the case before it starts.",
    fix: "Add a prayer for relief enumerating every remedy sought, with a catch-all for such other and further relief as the court deems just.",
    sev: "critical",
  },
  {
    id: "PLDG-007",
    name: "Rule 11 signature block",
    cite: frcp("11(a)", "signing pleadings, motions, and other papers"),
    pat: [
      /(\/s\/|respectfully\s+submitted|signature)/i,
      /(attorney|counsel\s+for|bar\s+no|address|telephone|e-?mail)/i,
    ],
    all: true,
    why: "Rule 11(a) requires every pleading to be signed by at least one attorney of record with the signer's address, email, and telephone number, and the court must strike an unsigned paper unless it is promptly corrected.",
    fix: "Add the signature block with the signing attorney's name, bar number, address, telephone number, and email.",
    sev: "critical",
  },
  {
    id: "PLDG-008",
    name: "Jury demand where a jury is wanted",
    cite: frcp("38(b)", "right to a jury trial — demand"),
    pat: [/jury/i, /(demand|trial\s+by\s+jury|hereby\s+demands?)/i],
    all: true,
    why: "Rule 38(b) requires a written jury demand served no later than 14 days after the last pleading directed to the issue; failing to serve it waives the jury trial under Rule 38(d). It is the easiest right in civil procedure to lose by omission.",
    fix: "Add a jury demand on the face of the complaint (and note it in the caption where local rules require), or record the deliberate decision to try the case to the bench.",
    sev: "critical",
  },
]);

const ANSWER = pack("answer", C, [
  {
    id: "PLDG-009",
    name: "Caption and pleading designation",
    cite: frcp("10(a)", "form of pleadings — caption"),
    pat: [
      /(in\s+the\s+(united\s+states\s+)?(district|superior|circuit|supreme|county)\s+court|court\s+of\s+(common\s+pleas|chancery))/i,
      /(answer|case\s+no|civil\s+action\s+no|docket)/i,
    ],
    all: true,
    why: "Rule 10(a) permits the answer to name only the first party on each side, but it must carry the court, the file number, and the Rule 7(a) designation.",
    fix: "Add the caption with the court, the case number, and the designation of the pleading.",
    sev: "critical",
  },
  {
    id: "PLDG-010",
    name: "Response to each numbered allegation",
    cite: frcp("8(b)(1)(B)", "defenses; admissions and denials — admit or deny the allegations"),
    pat: [
      /(admit|deny|denies)/i,
      /(paragraph\s+\d|each\s+(and\s+every\s+)?allegation|the\s+allegations\s+(of|in)\s+paragraph)/i,
    ],
    all: true,
    why: "Rule 8(b)(1)(B) requires the answer to admit or deny the allegations asserted against it, and Rule 8(b)(6) deems an allegation admitted if not denied. A paragraph left unanswered is a fact conceded.",
    fix: "Respond to each numbered paragraph by number, and confirm no paragraph of the complaint is left unaddressed.",
    sev: "critical",
  },
  {
    id: "PLDG-011",
    name: "Rule 8(b)(5) lack-of-knowledge formulation",
    cite: frcp("8(b)(5)", "defenses; admissions and denials — lacking knowledge or information"),
    pat: [
      /(lack|without)\s+(sufficient\s+)?(knowledge|information)/i,
      /(form\s+a\s+belief|belief\s+as\s+to\s+the\s+truth|on\s+that\s+basis\s+denies|therefore\s+denies)/i,
    ],
    all: true,
    why: "Rule 8(b)(5) permits a lack-of-knowledge response that 'has the effect of a denial' only in the statutory form: lacking knowledge or information sufficient to form a belief about the truth of the allegation. Loose paraphrases have been treated as admissions.",
    fix: "Use the Rule 8(b)(5) formulation exactly, and add the resulting denial.",
    when: [/(lack|without)\s+(sufficient\s+)?(knowledge|information)/i],
    sev: "critical",
  },
  {
    id: "PLDG-012",
    name: "Affirmative defenses pleaded",
    cite: frcp("8(c)(1)", "defenses; admissions and denials — affirmative defenses"),
    pat: [
      /affirmative\s+defense/i,
      /(statute\s+of\s+limitations|waiver|estoppel|release|failure\s+to\s+state|laches|assumption\s+of\s+risk|first\s+affirmative)/i,
    ],
    all: true,
    why: "Rule 8(c)(1) lists nineteen defenses that must be affirmatively pleaded in responding to a pleading; a defense omitted from the answer is generally waived. This is the single largest irreversible risk in drafting an answer.",
    fix: "Plead every applicable Rule 8(c)(1) defense, each separately stated and numbered, with enough factual content to give notice.",
    sev: "critical",
  },
  {
    id: "PLDG-013",
    name: "Rule 12(b) defenses preserved",
    cite: frcp("12(h)(1)", "waiving and preserving certain defenses"),
    pat: [
      /(12\(b\)|personal\s+jurisdiction|improper\s+venue|insufficient\s+(process|service))/i,
      /(reserve|preserve|does\s+not\s+waive|asserted\s+(herein|in\s+this\s+answer))/i,
    ],
    all: true,
    why: "Rule 12(h)(1) waives personal jurisdiction, venue, and process defenses if omitted from the first Rule 12 response. They cannot be raised later, whatever their merit.",
    fix: "Assert any available Rule 12(b)(2)-(5) defense in the answer itself, since a later motion cannot revive it.",
    when: [/(12\(b\)|personal\s+jurisdiction|improper\s+venue|insufficient\s+(process|service))/i],
    sev: "critical",
  },
  {
    id: "PLDG-014",
    name: "Prayer for relief",
    cite: practice("answer-prayer", "the answer's demand for relief"),
    pat: [
      /(wherefore|prays?|requests?\s+that\s+(this|the)\s+court)/i,
      /(dismiss|judgment\s+in\s+(its|their|defendant['’]?s?)\s+favor|take\s+nothing|costs|attorneys['’]?\s+fees)/i,
    ],
    all: true,
    why: "The answer's prayer is where the defendant asks for dismissal, costs, and fees. Omitting it does not waive much, but it does leave the court without a stated request to grant.",
    fix: "Add a prayer asking that plaintiff take nothing, that the action be dismissed with prejudice, and for costs and fees as available.",
  },
  {
    id: "PLDG-015",
    name: "Rule 11 signature block",
    cite: frcp("11(a)", "signing pleadings, motions, and other papers"),
    pat: [
      /(\/s\/|respectfully\s+submitted|signature)/i,
      /(attorney|counsel\s+for|bar\s+no|address|telephone|e-?mail)/i,
    ],
    all: true,
    why: "Rule 11(a) applies to the answer exactly as to the complaint, and an unsigned answer must be struck unless promptly corrected.",
    fix: "Add the signature block with the signing attorney's name, bar number, address, telephone number, and email.",
    sev: "critical",
  },
  {
    id: "PLDG-016",
    name: "Certificate of service",
    cite: frcp("5(d)(1)(B)", "serving and filing — certificate of service"),
    pat: [
      /certificate\s+of\s+service/i,
      /(served|cm\/ecf|electronic\s+filing|e-?mail|method\s+of\s+service)/i,
    ],
    all: true,
    why: "Even where CM/ECF serves registered parties automatically, most local rules still require the certificate, and any party served outside the system must be shown.",
    fix: "Add a certificate of service naming every party served, the method for each, and the date.",
  },
]);

/** Local-rule caveat used by the pleading pack's own documentation. */
export const PLEADING_LOCAL_RULE_NOTE = localRule(
  "pleadings",
  "caption format, paragraph numbering, jury-demand placement, and certificate-of-service practice",
);

export const PLEADING_RULES: readonly Rule[] = [...COMPLAINT, ...ANSWER];

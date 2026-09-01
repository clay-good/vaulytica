import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/**
 * The trigger a wind-down clause opens with. Requiring the bare "upon
 * termination" missed the form the corpus actually writes — "Upon expiration
 * **or** termination of this BAA, Business Associate shall … return … or
 * destroy all PHI" — so the rule reported "The contract does not state what
 * happens upon termination" about a clause that states it.
 */
// "(effective) date of" tolerated between the lead-in and the noun — "upon the
// effective date of termination", "on the date of expiration" — so the trigger
// still leads a wind-down consequence in that common phrasing.
// The preposition is AFTER as often as ON: "Within thirty (30) days AFTER
// expiration or termination, Recipient shall destroy all copies" is the
// standard data-return clause, and an on/upon-only trigger read it as no
// effect-of-termination clause at all.
/**
 * "END" — and its siblings "conclusion" and "completion" — are triggers too.
 * An internship agreement whose §7.3 is titled Effect and reads "On the end of
 * the internship for any reason, Sections 4, 5, 7.3, and 8 continue in effect,
 * the Intern returns Company property …" was told it does not state what
 * happens upon termination, because the trigger noun had to be "termination"
 * or "expiration". The trigger is conjunctive with a CONSEQUENCE verb, so an
 * ordinary "on the end of each month" does not satisfy it on its own.
 */
// The trigger is as often a WHEN-clause with a VERB as a prepositional phrase
// with a noun. "Unredeemed points are forfeited WHEN THE PROGRAM ENDS" states
// the effect of termination exactly as plainly as "upon termination of the
// program, unredeemed points are forfeited" — and only the second was read, so
// a set of loyalty terms whose sections 7 and 8 say what happens to the points
// was told it says nothing. The verb forms are bounded to a short subject run
// so the clause cannot reach across a sentence.
//
// "if" is deliberately NOT a connector here. Widening to it let a severance
// clause — "IF the Company ENDS employment without Cause, the Company will pay
// twelve months of base salary, conditioned on a signed RELEASE" — satisfy the
// check on the noun "release" in the consequence list, which is a coincidence
// and not a statement of what happens on termination.
const TERMINATION_NOUN = String.raw`expiration|expiry|termination|cessation|end|conclusion|completion`;
const TERMINATION_VERB = String.raw`ends?|ended|terminates?|terminated|expires?|expired|ceases?|ceased|concludes?|concluded`;
const TERMINATION_TRIGGER = String.raw`(?:(?:(?:up)?on|after|following)\s+(?:the\s+)?(?:any\s+|such\s+)?(?:(?:effective\s+)?date\s+of\s+)?(?:${TERMINATION_NOUN})(?:\s+or\s+(?:${TERMINATION_NOUN}))?|(?:when|once)\s+(?:the\s+|this\s+|your\s+)?(?:\w+\s+){0,2}?(?:${TERMINATION_VERB})\b)`;

/**
 * What the clause says happens. "delete" and "export" belong here: a modern
 * data clause returns data by exporting it, and the SaaS corpus writes
 * "Customer shall have thirty (30) days to export all Customer Data".
 * "surrender" is the canonical lease wind-down consequence — "Upon expiration
 * or termination, Tenant shall surrender the Premises" is a commercial lease's
 * effect-of-termination clause, and its absence made the rule report none.
 * "survive"/"survival" is the paradigmatic effect-of-termination statement —
 * this rule's own explanation names "the rights and obligations that survive"
 * as the first thing such a clause spells out, yet a bare survival clause
 * ("Sections 3-7 shall survive termination of this Agreement") was reported as
 * having no effect-of-termination clause at all.
 */
// "release" in the ACTIVE voice — "Factor shall release its security interest
// and file a termination statement", "Lender shall release the collateral" —
// which the passive "is/are released" branch below could not read. It is a
// consequence only when it follows a termination trigger inside one sentence,
// so a settlement's "mutual release of claims" is untouched.
// A ground lease's consequence is that TITLE VESTS: "On expiration or
// earlier termination of this Lease, title to the Improvements VESTS IN
// Landlord automatically … and Tenant shall DELIVER the Improvements in
// good condition." Neither verb was in the list, nor was TRANSFER — "On
// expiration or termination, Supplier shall ... TRANSFER the manufacturing
// process and all Customer-owned tooling" — so the clause that is the
// whole economic point of the lease read as no effect-of-termination clause
// at all. Both are only consequences when they follow a termination trigger
// inside one sentence, which is what keeps "Landlord shall deliver
// possession" and an equity vesting schedule out.
// Each verb tolerates its third-person and past forms. Several did not:
// `return`, `destroy`, `delete`, `purge`, `transition`, `export`, `refund` and
// `discontinue` were listed bare, so "the Intern RETURNS Company property" —
// the plainest consequence a contract can state — did not match, while
// "shall return" did. Which form a drafter reaches for is a choice about the
// subject, not about the clause.
const CONSEQUENCE = String.raw`ceases?|ceased|returns?|returned|destroys?|destroyed|deletes?|deleted|purges?|purged|transitions?|transitioned|exports?|exported|refunds?|refunded|reverts?|reverted|vests?\s+in|deliver(?:s|ed)?|conveys?|conveyed|transfers?|transferred|discontinues?|discontinued|surrenders?|surrendered|releas(?:e|es|ed)|wind[\s-]down|forfeit(?:s|ed|ure)?|disable[sd]?`;

/**
 * Either order, within one sentence. A consequence drafted BEFORE its trigger
 * ("Processing shall cease upon termination of the MSA") is ordinary drafting,
 * and a forward-only scan reads it as absent; the old `[\s\S]{0,200}` window
 * had the opposite failing, crossing sentence boundaries to borrow a verb from
 * an unrelated clause.
 */
/**
 * One sentence, but a section cross-reference is not a sentence boundary. The
 * windows here were `[^.]`, and a survival clause naming its own sections —
 * "On the end of the internship for any reason, Sections 4, 5, 7.3, and 8
 * continue in effect, the Intern returns Company property" — stops the window
 * dead at the period in "7.3", so the consequence verb four words later is
 * never reached and the clause reads as absent. A period followed by a DIGIT
 * is a decimal or a subsection number, never the end of a sentence.
 */
const SAME_SENTENCE = String.raw`(?:[^.]|\.(?=\d))`;

const EFFECT_OF_TERMINATION = new RegExp(
  String.raw`\b(?:effect|consequences)\s+of\s+termination\b` +
    `|\\b${TERMINATION_TRIGGER}\\b${SAME_SENTENCE}{0,220}\\b(?:${CONSEQUENCE})\\b` +
    // The plainest consequence there is, and one the noun list did not hold:
    // "On termination, the Tolling Period ENDS and any applicable limitations
    // period RESUMES running." Admitted only AFTER the trigger, never before
    // it — "This Agreement ends upon expiration of the Initial Term" defines a
    // term, it does not state what termination does.
    `|\\b${TERMINATION_TRIGGER}\\b${SAME_SENTENCE}{0,220}\\b(?:ends?|ended|expires?|lapses?|resumes?|is\\s+released|are\\s+released|becomes?\\s+(?:void|null))\\b` +
    `|\\b(?:${CONSEQUENCE})\\b${SAME_SENTENCE}{0,120}\\b${TERMINATION_TRIGGER}\\b` +
    // "Customer shall pay for all Services performed … through the
    // termination date" — the pay-for-work-performed wind-down consequence
    // states what happens on termination without the "upon termination"
    // trigger the branches above require. The full phrase is unambiguous;
    // "pay" is deliberately NOT added to CONSEQUENCE (a failure-to-pay
    // termination TRIGGER would then read as an effect clause).
    String.raw`|\bpay\b${SAME_SENTENCE}{0,160}\bthrough\s+the\s+(?:date\s+of\s+termination|termination\s+date|effective\s+date\s+of\s+termination)\b` +
    // "If Buyer terminates for Seller's material breach, the earnest deposit
    // shall be returned" — the conditional form states a termination
    // consequence with no "upon termination" trigger at all.
    // `\w*` on the consequence: the conditional form conjugates its verb
    // ("the deposit shall be returnED") and a bare \b-wrapped stem rejects
    // every inflection.
    String.raw`|\bif\s+${SAME_SENTENCE}{0,80}?\bterminat(?:es|ed)\b${SAME_SENTENCE}{0,160}?\b(?:${CONSEQUENCE})\w*` +
    // The purchase-agreement form pairs the termination VERB with the
    // consequence in one sentence and no "(up)on" noun trigger — "the Buyer
    // may terminate this Agreement, in which case the Earnest Money is
    // refunded", "may terminate … and receive a refund". The verb takes the
    // AGREEMENT as its object (not "terminate any employee who fails to
    // return property", which is a firing clause, not a wind-down), and a
    // bare "terminate this Agreement for convenience" with no consequence
    // word still fails this branch and correctly reports none.
    String.raw`|\bterminat(?:es?|ed|ing)\s+(?:this\s+|the\s+)(?:Agreement|Lease|Contract|SOW|Note|Order)\b${SAME_SENTENCE}{0,120}?\b(?:${CONSEQUENCE})\w*` +
    // An explicit consequence CONNECTOR, which names the effect without naming
    // the agreement. "Either party may terminate the Tolling Period on thirty
    // days' written notice, AFTER WHICH the limitations period resumes
    // running" is the plainest effect-of-termination sentence a tolling
    // agreement can write, and every branch above missed it: the object is a
    // defined term rather than "this Agreement", and "after which" is not a
    // termination TRIGGER, which has to lead with "after TERMINATION".
    //
    // "after which" / "whereupon" / "at which point" following a termination
    // verb states a consequence by construction — that is what the words do —
    // so this branch needs no agreement-object restriction. The consequence
    // list is the same one the trigger branches use, plus the intransitive
    // verbs a suspended right takes when it comes back.
    String.raw`|\bterminat(?:e|es|ed|ing|ion)\b${SAME_SENTENCE}{0,160}?\b(?:after\s+which|whereupon|at\s+which\s+(?:point|time))\b${SAME_SENTENCE}{0,120}?\b(?:${CONSEQUENCE}|ends?|ended|resumes?|resumed|expires?|lapses?|reverts?)\w*` +
    // A survival clause is the paradigmatic effect-of-termination statement —
    // "Sections 3 through 7 shall survive termination of this Agreement." It
    // takes termination as a bare object of "survive", not "UPON termination",
    // so the trigger branches above (which require the "(up)on" lead-in) never
    // matched it. This branch pairs the survive verb / "survival" heading with
    // a nearby termination or expiration reference — in EITHER order, since a
    // ToS commonly writes "Upon termination, … Sections 4, 8 and 10 survive"
    // with the trigger first. The reverse direction is anchored on the
    // termination/expiration noun (not "this Agreement", which is too common)
    // to avoid stitching an unrelated "survive" to the clause.
    String.raw`|\bsurviv(?:e|es|al)\b${SAME_SENTENCE}{0,60}\b(?:termination|expiration|expiry|this\s+Agreement)\b` +
    String.raw`|\b(?:termination|expiration|expiry)\b${SAME_SENTENCE}{0,80}\bsurviv(?:e|es|al)\b` +
    // The accrued-obligations / savings statement is a paradigmatic effect-of-
    // termination clause with no wind-down verb — "Termination shall not
    // relieve either party of obligations accrued …", "termination … without
    // prejudice to any other rights or remedies".
    String.raw`|\btermination\b${SAME_SENTENCE}{0,60}?\b(?:shall|will|does)\s+not\s+(?:relieve|affect|release|discharge|waive)\b` +
    String.raw`|\btermination\b${SAME_SENTENCE}{0,80}?\bwithout\s+prejudice\s+to\b` +
    // "Following termination, the parties shall have no further obligations" —
    // the no-further-obligations savings statement, and "Upon termination,
    // outstanding amounts become immediately due and payable" — the payment-
    // acceleration effect. Both are anchored to a nearby "termination" so a
    // plain payment term ("invoices are due and payable Net 30") stays inert.
    String.raw`|\btermination\b${SAME_SENTENCE}{0,80}?\bno\s+further\s+(?:obligations?|liabilit(?:y|ies)|rights|duties)\b` +
    String.raw`|\btermination\b${SAME_SENTENCE}{0,80}?\b(?:immediately\s+)?due\s+and\s+payable\b` +
    // "Upon such termination, the Owner may complete the Work … and the
    // Contractor shall be liable for any costs …" — a construction / services
    // termination-for-cause states its consequence with a party + modal, and
    // its verbs ("complete", "be liable for") are deliberately NOT in
    // CONSEQUENCE (a "fails to complete" TRIGGER would then read as an effect).
    // "Upon SUCH termination" (the demonstrative pointing back at the specific
    // termination just described) reliably introduces the consequence, so a
    // modal within a short window is a safe, specific effect signal.
    String.raw`|\b(?:up)?on\s+such\s+(?:termination|expiration|expiry|cancellation)\b${SAME_SENTENCE}{0,40}\b(?:shall|may|will|must)\b` +
    // An ENTITY agreement (LLC / partnership) winds down by DISSOLUTION, not
    // "termination": "Upon dissolution, the Partnership's assets shall be applied
    // first to creditors, then to the Partners" is the effect-of-termination
    // clause in entity form. "dissolution" is not among the termination triggers
    // above, so an entity agreement that states its wind-down read as having
    // none. A bare dissolution TRIGGER with no wind-down consequence ("the
    // Company shall dissolve upon consent") does not match — the wind-down verb
    // (apply / distribute / wind up / liquidate) must follow.
    String.raw`|\b(?:up)?on\s+(?:the\s+)?dissolution\b${SAME_SENTENCE}{0,140}\b(?:appl(?:y|ied)|distribut\w+|wind(?:ing)?[\s-]?up|wound\s+up|liquidat\w+)\b` +
    // The construction / services termination-FOR-DEFAULT remedy states its
    // effect in the same clause as the termination: "the Owner may terminate
    // this Agreement for default and complete the Work by other means, and the
    // Contractor shall be liable for the resulting costs". The "Upon such
    // termination … modal" branch above only catches the separate-sentence
    // form; this catches the one-clause form. "for default/cause" is the
    // discriminator, and "complete the Work" / "liable for … costs" the effect —
    // neither verb is in CONSEQUENCE (a "fails to complete" trigger must not read
    // as an effect), so the for-default qualifier is required.
    String.raw`|\bterminat\w+\b${SAME_SENTENCE}{0,80}?\bfor\s+(?:default|cause)\b${SAME_SENTENCE}{0,120}?\b(?:complete\s+(?:the\s+)?work|liable\s+for\b${SAME_SENTENCE}{0,40}?\bcosts?)\b` +
    // "Buyer may terminate this order for convenience on written notice, in
    // which case Buyer pays for conforming goods delivered and Seller's
    // reasonable unavoidable costs" — a purchase order states the effect with
    // the connective "in which case" and a verb none of the branches above
    // admit ("pays for goods delivered" is not a wind-down verb, and "pay" is
    // deliberately outside CONSEQUENCE so a failure-to-pay TRIGGER cannot read
    // as an effect). The connective is doing the work here: "in which case"
    // introduces a consequence and nothing else, so pairing it with a
    // termination word in the same sentence is specific without needing to
    // enumerate the consequence verb at all.
    String.raw`|\bterminat(?:e|es|ed|ing|ion)\b${SAME_SENTENCE}{0,120}?\bin\s+which\s+case\b`,
  "i",
);

/** TERM-005 — Effect of termination clause present (warning). */
export const rule: Rule = {
  id: "TERM-005",
  version: "1.20.0",
  name: "Effect of termination clause",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract explains what happens upon termination.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    if (firstParagraphMatch(ctx, EFFECT_OF_TERMINATION)) return null;
    return emit(ctx, rule, {
      title: "No effect-of-termination clause detected",
      description: "The contract does not state what happens upon termination.",
      excerpt: "(no effect-of-termination clause)",
      explanation:
        "An effect-of-termination clause spells out the rights and obligations that survive, the return or destruction of materials, and the wind-down rules.",
      recommendation:
        'Add an effect-of-termination clause: what is owed for work already performed, what each party returns or deletes, which licences continue, and which sections survive — naming them by number, not "the provisions that by their nature survive".',
      position: topPosition(ctx),
    });
  },
};

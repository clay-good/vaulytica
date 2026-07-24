import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/**
 * The trigger a wind-down clause opens with. Requiring the bare "upon
 * termination" missed the form the corpus actually writes — "Upon expiration
 * **or** termination of this BAA, Business Associate shall … return … or
 * destroy all PHI" — so the rule reported "The contract does not state what
 * happens upon termination" about a clause that states it.
 */
const TERMINATION_TRIGGER = String.raw`(?:up)?on\s+(?:the\s+)?(?:any\s+)?(?:expiration|expiry|termination|cessation)(?:\s+or\s+(?:expiration|expiry|termination|cessation))?`;

/**
 * What the clause says happens. "delete" and "export" belong here: a modern
 * data clause returns data by exporting it, and the SaaS corpus writes
 * "Customer shall have thirty (30) days to export all Customer Data".
 * "surrender" is the canonical lease wind-down consequence — "Upon expiration
 * or termination, Tenant shall surrender the Premises" is a commercial lease's
 * effect-of-termination clause, and its absence made the rule report none.
 */
const CONSEQUENCE = String.raw`ceases?|cease|return|destroy|delete|purge|transition|export|refund|revert|discontinue|surrenders?|wind[\s-]down`;

/**
 * Either order, within one sentence. A consequence drafted BEFORE its trigger
 * ("Processing shall cease upon termination of the MSA") is ordinary drafting,
 * and a forward-only scan reads it as absent; the old `[\s\S]{0,200}` window
 * had the opposite failing, crossing sentence boundaries to borrow a verb from
 * an unrelated clause.
 */
const EFFECT_OF_TERMINATION = new RegExp(
  String.raw`\b(?:effect|consequences)\s+of\s+termination\b` +
    `|\\b${TERMINATION_TRIGGER}\\b[^.]{0,220}\\b(?:${CONSEQUENCE})\\b` +
    `|\\b(?:${CONSEQUENCE})\\b[^.]{0,120}\\b${TERMINATION_TRIGGER}\\b` +
    // "Customer shall pay for all Services performed … through the
    // termination date" — the pay-for-work-performed wind-down consequence
    // states what happens on termination without the "upon termination"
    // trigger the branches above require. The full phrase is unambiguous;
    // "pay" is deliberately NOT added to CONSEQUENCE (a failure-to-pay
    // termination TRIGGER would then read as an effect clause).
    String.raw`|\bpay\b[^.]{0,160}\bthrough\s+the\s+(?:date\s+of\s+termination|termination\s+date|effective\s+date\s+of\s+termination)\b` +
    // "If Buyer terminates for Seller's material breach, the earnest deposit
    // shall be returned" — the conditional form states a termination
    // consequence with no "upon termination" trigger at all.
    // `\w*` on the consequence: the conditional form conjugates its verb
    // ("the deposit shall be returnED") and a bare \b-wrapped stem rejects
    // every inflection.
    String.raw`|\bif\s+[^.]{0,80}?\bterminat(?:es|ed)\b[^.]{0,160}?\b(?:${CONSEQUENCE})\w*`,
  "i",
);

/** TERM-005 — Effect of termination clause present (warning). */
export const rule: Rule = {
  id: "TERM-005",
  version: "1.3.0",
  name: "Effect of termination clause",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract explains what happens upon termination.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, EFFECT_OF_TERMINATION)) return null;
    return emit(ctx, rule, {
      title: "No effect-of-termination clause detected",
      description: "The contract does not state what happens upon termination.",
      excerpt: "(no effect-of-termination clause)",
      explanation:
        "An effect-of-termination clause spells out the rights and obligations that survive, the return or destruction of materials, and the wind-down rules.",
      position: topPosition(ctx),
    });
  },
};

import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, excerptWindow, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-015 — Waiver of non-waivable Article 9 debtor protections (critical,
 * dark-patterns).
 *
 * U.C.C. § 9-602 lists the debtor protections a security agreement **may not
 * waive**: the breach-of-the-peace limit on self-help repossession (§ 9-609),
 * the commercial-reasonableness standard for disposition (§ 9-610(b)), the
 * notification of disposition (§§ 9-611 to 9-614), the right to redeem the
 * collateral (§ 9-623), and the deficiency calculation (§§ 9-625 to 9-626). A
 * clause purporting to waive them is void as to those rights, and the finance
 * party that relies on it can lose its deficiency entirely.
 *
 * The gap this closes: BNK-143 is a PRESENCE check for "default, acceleration,
 * and disposition of collateral", and it finds the words "default" and
 * "repossess" in exactly the clause that waives the protections — so an
 * equipment finance lease saying the lessor may "repossess the Equipment
 * without notice or legal process" and that the lessee "waives any right to
 * notice, hearing, or redemption" satisfied it and drew no finding at all.
 * BNK-143's own `why` says the protections "apply whatever the contract says";
 * nothing said so to the reader. A presence check reading an unlawful waiver
 * as compliance is a new shape of the express-denial defect, and the answer is
 * a rule that reports the waiver rather than a suppression on the rule the
 * waiver satisfied.
 *
 * The saving language a careful form carries — "except as prohibited by
 * applicable law", "to the extent permitted by law", "subject to Article 9" —
 * does not fire: with it the waiver reaches only what may be waived, which is
 * the whole point of the sentence.
 */

/**
 * The waiver and its object, in ONE construction.
 *
 * The first form of this rule looked for a waiver anywhere in the paragraph
 * and a protection word anywhere in the 200 characters after it, and reported
 * an ordinary non-waiver clause — "no delay in exercising a remedy waives it"
 * — on an existing specimen, because a later sentence in the same paragraph
 * carried the noun. **The waived object has to be the protection**, so the
 * window is the sentence and it runs from the verb to the noun.
 *
 * The window admits a period only when a digit follows it: the sentence's own
 * full stop is what bounds the match, and a decimal inside a dollar amount is
 * not that. Bare "notice" is deliberately NOT an object here — notice of
 * default is waivable in plenty of contexts, and § 9-602's subject is notice
 * of the DISPOSITION. A clause that waives notice along with the hearing or
 * the redemption right still fires, on those.
 */
const WAIVES_PROTECTION = new RegExp(
  String.raw`\b(?:waives?|waiving|(?:shall|will)\s+have\s+no\s+right\s+to)\b(?:[^;.]|\.(?=\d)){0,80}?` +
    String.raw`\b(?:notice\s+of\s+(?:sale|disposition|intended\s+disposition)|right\s+of\s+redemption` +
    String.raw`|redemption|redeem\b|hearing|commercially\s+reasonabl\w*|deficiency` +
    String.raw`|breach\s+of\s+the\s+peace)\b`,
  "i",
);

/** The secured party reserving the remedy without the process the law requires. */
const WITHOUT_PROCESS =
  /\b(?:repossess|retake|take\s+possession\s+of|dispose\s+of|sell)\b[^;.]{0,80}?\bwithout\b[^;.]{0,40}?\b(?:notice|demand|(?:legal|judicial|court)\s+process|court\s+order|hearing)\b/i;

/**
 * The carve-out that keeps the clause inside what the law allows.
 *
 * Two of these are not generic saving language but the statute itself, and an
 * existing specimen supplied both: § 9-609(b)(2) permits repossession without
 * judicial process precisely WHEN it happens "without a breach of the peace",
 * so a clause that states the condition is quoting the rule rather than
 * escaping it — and a disposition made "in a commercially reasonable manner as
 * Article 9 of the Uniform Commercial Code requires" names the article by its
 * full title, which a pattern expecting "in accordance with Article 9" misses.
 * Reporting either as an unlawful waiver would be a false accusation on the
 * compliant drafting.
 */
const SAVED_BY_LAW =
  /\b(?:except\s+as\s+(?:otherwise\s+)?(?:prohibited|required|provided)\s+by\s+(?:applicable\s+)?law|to\s+the\s+extent\s+(?:not\s+prohibited|permitted)\s+by\s+(?:applicable\s+)?law|subject\s+to\s+(?:the\s+requirements\s+of\s+)?(?:applicable\s+law|article\s+9|the\s+uniform\s+commercial\s+code)|as\s+permitted\s+by\s+(?:applicable\s+)?law|in\s+accordance\s+with\s+(?:applicable\s+law|article\s+9)|without\s+(?:a\s+)?breach\s+of\s+the\s+peace|article\s+9\s+of\s+the\s+uniform\s+commercial\s+code)\b/i;

export const rule: Rule = {
  id: "DARK-015",
  version: "1.0.0",
  name: "Waiver of non-waivable Article 9 debtor protections",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects a security agreement or finance lease purporting to waive the debtor protections U.C.C. § 9-602 makes non-waivable — notice of disposition, commercial reasonableness, the right to redeem, the deficiency calculation, or the breach-of-the-peace limit on self-help repossession.",
  dkb_citations: [],
  applies_to_playbooks: [
    "equipment-finance-agreement",
    "equipment-lease",
    "security-agreement",
    "loan-agreement",
    "revolving-credit-agreement",
    "sba-loan-agreement",
  ],
  check(ctx: RuleContext): Finding | null {
    const hit =
      firstParagraphMatch(ctx, WAIVES_PROTECTION) ?? firstParagraphMatch(ctx, WITHOUT_PROCESS);
    if (!hit) return null;
    if (SAVED_BY_LAW.test(hit.text)) return null;
    return emit(ctx, rule, {
      title: "Waiver of non-waivable Article 9 protections",
      description: hit.match[0].trim().slice(0, 200),
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "U.C.C. § 9-602 lists the debtor protections a security agreement may not waive: the breach-of-the-peace limit on self-help repossession (§ 9-609), commercial reasonableness of the disposition (§ 9-610(b)), notification of the disposition (§§ 9-611 to 9-614), the right to redeem the collateral (§ 9-623), and the deficiency calculation (§§ 9-625 to 9-626). A clause purporting to waive them is void as to those rights, and a secured party that repossesses or sells in reliance on it risks losing its deficiency altogether.",
      recommendation:
        'Remove the waiver, or confine it to what § 9-602 permits — "except as prohibited by applicable law" / "subject to the requirements of Article 9" — and state that repossession and disposition will comply with the notice and commercial-reasonableness requirements.',
      position: hit.position,
    });
  },
};

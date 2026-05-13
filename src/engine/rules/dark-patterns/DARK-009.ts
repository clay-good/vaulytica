import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-009 — Unilateral amendment by posting to a URL (warning,
 * dark-patterns).
 *
 * Dark pattern: vendor reserves the right to change the contract by
 * posting a new version on its website. Continued use of the service
 * is deemed acceptance. This shifts the burden of monitoring the
 * agreement to the customer in perpetuity and renders the original
 * negotiated terms effectively meaningless. Common in consumer-facing
 * SaaS ToS but also creeps into B2B SaaS contracts where it has no
 * legitimate place.
 *
 * The FTC has criticized "post-and-pray" amendment in
 * `Klocek v. Gateway, 104 F. Supp. 2d 1332` and subsequent enforcement
 * actions, and California's Auto-Renewal Law / FTC Click-to-Cancel
 * Rule (16 CFR § 425) require affirmative consent for material
 * changes. Best practice: material changes require signed amendment;
 * minor / non-material changes may be effected by written notice
 * with a defined objection / opt-out window.
 *
 * Detection: trigger phrases "modify / amend / change / update" the
 * "Agreement / terms / Service" by "posting / publishing / making
 * available" at / on a URL / website / portal, with implicit
 * acceptance by continued use.
 */
export const rule: Rule = {
  id: "DARK-009",
  version: "1.0.0",
  name: "Unilateral amendment by posting",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Detects clauses that let one party change the agreement by posting a new version online, with implicit acceptance by continued use.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    // Pattern A: "Vendor may modify/amend the Agreement by posting…"
    const a = firstParagraphMatch(
      ctx,
      /\b(?:Vendor|Provider|Company|Licensor|Customer|Operator|we|we\s+reserve\s+the\s+right\s+to)\s*(?:may|reserves?\s+the\s+right\s+to|shall\s+have\s+the\s+right\s+to)?\s*(?:modify|amend|change|update|revise|alter)\b[\s\S]{0,160}\b(?:terms?|agreement|service|policy|policies|conditions)\b[\s\S]{0,160}\b(?:post(?:ing)?|publish(?:ing)?|making\s+available|made\s+available|upload(?:ing)?|placing)\b[\s\S]{0,80}\b(?:website|site|portal|url|link|page|online|on\s+its\s+(?:website|site|portal)|at\s+(?:the\s+)?url)\b/i,
    );
    if (a) {
      return emit(ctx, rule, {
        title: "Unilateral amendment by posting to a URL",
        description: a.match[0],
        excerpt: a.text.slice(Math.max(0, a.match.index - 30), a.match.index + 320),
        explanation:
          "Allowing one party to change the contract by posting a new version on a website shifts the entire burden of monitoring the agreement to the other party in perpetuity, and renders the originally negotiated terms effectively meaningless. The FTC has called out 'post-and-pray' amendment in enforcement actions, and California's auto-renewal law plus the FTC's Click-to-Cancel rule (16 CFR § 425) require affirmative consent for material changes. Courts also sometimes refuse to enforce such clauses on illusory-contract grounds.",
        recommendation:
          "Restrict unilateral amendment to immaterial / non-substantive changes effected by written notice (email + at least 30 days) with a defined objection / opt-out right. Material changes — pricing, scope, liability, data use — must require a signed amendment or affirmative click-through consent.",
        position: a.position,
      });
    }

    // Pattern B: "continued use … constitutes acceptance" + amendment
    // language elsewhere in the paragraph. Often used as the closing
    // sentence of the amendment-by-posting block.
    const b = firstParagraphMatch(
      ctx,
      /\b(?:modif(?:y|ied)|amend(?:ed)?|chang(?:e|ed)|updat(?:e|ed)|revis(?:e|ed))\b[\s\S]{0,200}\bcontinued\s+(?:use|access)\b[\s\S]{0,120}\b(?:constitut\w+|deem\w+|signif\w+|will\s+be|shall\s+be)[\s\S]{0,40}(?:acceptance|consent|agreement|assent|binding)\b/i,
    );
    if (b) {
      return emit(ctx, rule, {
        title: "Continued-use-as-acceptance amendment clause",
        description: b.match[0],
        excerpt: b.text.slice(Math.max(0, b.match.index - 30), b.match.index + 320),
        explanation:
          "A clause that deems continued use of the service to be acceptance of unilateral amendments has been criticized as illusory: the party 'consenting' has no real notice and no real ability to refuse without disrupting their business. FTC guidance and courts increasingly require affirmative consent for material contract changes.",
        recommendation:
          "Require affirmative consent (signed amendment or click-through) for material changes. Continued-use-as-acceptance is acceptable only for non-substantive changes after meaningful written notice and an opt-out window.",
        position: b.position,
      });
    }
    return null;
  },
};

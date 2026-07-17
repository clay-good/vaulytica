import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * PERS-005 — Non-compete clause present (warning, personnel).
 *
 * Surfaces any non-compete / covenant-not-to-compete clause. The
 * spec's playbook for `employment-at-will-us` and similar contexts
 * expects this surface because non-compete enforceability varies
 * sharply by jurisdiction:
 *
 *   - California: void per Bus. & Prof. Code § 16600 (with narrow
 *     exceptions tied to sale of a business).
 *   - North Dakota / Oklahoma / Minnesota: largely unenforceable.
 *   - Washington: narrow (RCW 49.62 income threshold).
 *   - Texas: enforceable only under Bus. & Com. Code § 15.50.
 *   - Federal: the FTC's January 2024 final rule banning most
 *     non-competes was vacated nationwide in 2024 (Ryan LLC v.
 *     FTC, N.D. Tex.) but the policy direction remains hot.
 *
 * Always-warn so a human reviewer evaluates against the controlling
 * jurisdiction's enforceability bucket from the DKB.
 */
export const rule: Rule = {
  id: "PERS-005",
  version: "1.0.0",
  name: "Non-compete clause present",
  category: "personnel",
  default_severity: "warning",
  description:
    "Surfaces non-compete / covenant-not-to-compete language so a reviewer can audit against the controlling jurisdiction's enforceability rules.",
  dkb_citations: ["stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:non[-\s]?compete|covenant\s+not\s+to\s+compete|shall\s+not\s+(?:directly\s+or\s+indirectly\s+)?compete|agrees?\s+not\s+to\s+(?:directly\s+or\s+indirectly\s+)?engage\s+in\s+(?:any\s+)?(?:business|activity)\s+(?:that\s+)?compet)/i,
    );
    if (!hit) return null;
    // Suppress a DISCLAIMER of a non-compete ("nothing shall be construed as a
    // covenant not to compete", "does not contain a non-compete") — but NOT the
    // operative covenant itself ("Executive shall not compete"), whose "not" is
    // the restriction, not a disclaimer. The generic negation helper can't tell
    // these apart, so this rule checks disclaimer markers specifically.
    if (
      /\bconstrued\s+(?:as|to)\b|\b(?:does|shall|will)\s+not\s+(?:contain|include|impose|create|constitute|be\s+deemed)\b|for\s+the\s+avoidance\s+of\s+doubt[\s\S]{0,80}\bnothing\b|\bnothing\b[\s\S]{0,80}\bconstrued\b|\bno\s+(?:non[-\s]?compete|covenant\s+not\s+to\s+compete|restrictive\s+covenant)\b/i.test(
        hit.text,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "Non-compete clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "Non-compete clauses have sharply divergent enforceability by jurisdiction. California prohibits them outright (Bus. & Prof. Code § 16600); Washington imposes income thresholds; Texas requires consideration and a reasonable geographic / temporal scope under Bus. & Com. Code § 15.50; the FTC's nationwide ban was vacated in 2024 but the regulatory environment remains active. A non-compete that's standard in one state may be void in another.",
      recommendation:
        "Confirm the controlling jurisdiction's enforceability bucket (use the DKB jurisdiction record). If the controlling state voids non-competes, either delete the clause or convert to a narrower non-solicitation. If the clause is enforceable, audit the duration, geographic scope, and consideration provided.",
      position: hit.position,
    });
  },
};

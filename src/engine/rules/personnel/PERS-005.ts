import type { Rule, RuleContext, Finding } from "../../finding.js";
import { allMatches, describesCovenantElsewhere, emit, excerptWindow } from "../_helpers.js";

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
  version: "1.4.0",
  name: "Non-compete clause present",
  category: "personnel",
  default_severity: "warning",
  description:
    "Surfaces non-compete / covenant-not-to-compete language so a reviewer can audit against the controlling jurisdiction's enforceability rules.",
  dkb_citations: ["stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    // Scan EVERY hit, not just the first. A document that opens with an
    // incoming-obligations representation and imposes a real covenant later
    // would otherwise be silenced by the disclaimer test running against the
    // wrong paragraph.
    const hits = allMatches(
      ctx,
      // "non-competition" (the dominant section-heading spelling) is added — the
      // old `non[-\s]?compete` matched "non-compete" but not "non-competition".
      // The bare covenant verb is also written "WILL not compete" / "AGREES NOT
      // TO compete", not only "shall not compete".
      /\b(?:non[-\s]?compet(?:e|ition)|covenant\s+not\s+to\s+compete|(?:shall|will)\s+not\s+(?:directly\s+or\s+indirectly\s+)?compete|agrees?\s+not\s+to\s+(?:directly\s+or\s+indirectly\s+)?compete|agrees?\s+not\s+to\s+(?:directly\s+or\s+indirectly\s+)?engage\s+in\s+(?:any\s+)?(?:business|activity)\s+(?:that\s+)?compet|shall\s+not[^.;]{0,60}?\b(?:own|manage|operate|control|be\s+employed\s+by|participate\s+in)\b[^.;]{0,120}?\bcompeting\s+business)/i,
    );
    // Suppress a DISCLAIMER of a non-compete ("nothing shall be construed as a
    // covenant not to compete", "does not contain a non-compete") — but NOT the
    // operative covenant itself ("Executive shall not compete"), whose "not" is
    // the restriction, not a disclaimer. The generic negation helper can't tell
    // these apart, so this rule checks disclaimer markers specifically.
    //
    // A drag-along's PROTECTION is a third shape, and it is the mirror of the
    // covenant: "no Stockholder is required to accept a covenant not to
    // compete" is a promise that none will be imposed, and it was reported as
    // a non-compete clause present.
    //
    // The INCOMING-OBLIGATIONS representation is the other shape, and it is in
    // essentially every offer letter and employment agreement: "you represent
    // that you are not subject to any employment, confidentiality,
    // non-competition, or other agreement that would prevent you from
    // accepting this position". That is a promise the candidate is NOT bound
    // by someone else's covenant — the opposite of imposing one — and it was
    // reported as a non-compete clause present, at `warning`, on a letter that
    // contains none.
    const DISCLAIMED =
      /\bconstrued\s+(?:as|to)\b|\b(?:does|shall|will)\s+not\s+(?:contain|include|impose|create|constitute|be\s+deemed)\b|for\s+the\s+avoidance\s+of\s+doubt[\s\S]{0,80}\bnothing\b|\bnothing\b[\s\S]{0,80}\bconstrued\b|\bno\s+(?:non[-\s]?compet(?:e|ition)|covenant\s+not\s+to\s+compete|restrictive\s+covenant)\b|\b(?:are|is|am)\s+not\s+(?:subject\s+to|bound\s+by|a\s+party\s+to)\b|\bnot\s+(?:subject\s+to|bound\s+by|a\s+party\s+to)\s+any\b|\b(?:no|not)\s+[^.;]{0,50}?\brequired\s+to\s+(?:accept|sign|execute|enter\s+into|agree\s+to)\b/i;
    const hit = hits.find(
      (h) => !DISCLAIMED.test(h.text) && !describesCovenantElsewhere(h.text, h.match.index),
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Non-compete clause present",
      description: hit.match[0],
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "Non-compete clauses have sharply divergent enforceability by jurisdiction. California prohibits them outright (Bus. & Prof. Code § 16600); Washington imposes income thresholds; Texas requires consideration and a reasonable geographic / temporal scope under Bus. & Com. Code § 15.50; the FTC's nationwide ban was vacated in 2024 but the regulatory environment remains active. A non-compete that's standard in one state may be void in another.",
      recommendation:
        "Confirm the controlling jurisdiction's enforceability bucket (use the DKB jurisdiction record). If the controlling state voids non-competes, either delete the clause or convert to a narrower non-solicitation. If the clause is enforceable, audit the duration, geographic scope, and consideration provided.",
      position: hit.position,
    });
  },
};

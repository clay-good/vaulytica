import type { Rule, RuleContext, Finding } from "../../finding.js";
import { describesCovenantElsewhere, emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/**
 * How long the covenant runs — "for a period of two (2) years", "for
 * twenty-four (24) months", "for 18 months after the Closing".
 */
const DURATION =
  /\bfor\s+(?:a\s+period\s+of\s+)?(?:[a-z-]+\s+)?\(?\d{1,3}\)?\s*(?:year|month|week|day)s?\b|\b\(?\d{1,3}\)?\s*(?:year|month)s?\s+(?:after|from|following)\b/i;

/**
 * Where it reaches — a radius, a named state or county, a defined Territory,
 * or the whole world.
 */
const GEOGRAPHY =
  /\bwithin\s+(?:a\s+)?(?:[a-z-]+\s+)?\(?\d{1,4}\)?\s*[- ]?miles?\b|\b(?:in|within|throughout)\s+the\s+(?:State|Commonwealth|County|City|Province)\s+of\s+[A-Z][A-Za-z]+|\bin\s+the\s+Territory\b|\bworldwide\b|\banywhere\s+in\s+the\s+(?:world|United\s+States)\b|\bin\s+the\s+United\s+States\b/;

/**
 * PERS-001 — Non-compete SCOPE (info).
 *
 * PERS-005 reports that a non-compete is present, at `warning`, with the
 * jurisdiction analysis. This rule and that one were emitting the same title —
 * "Non-compete clause present" — over the same span on three specimens: one
 * drafting fact, reported twice in the same words.
 *
 * What this rule adds, and what its own description has always promised, is
 * the SCOPE: how long the covenant runs and where it reaches. When it can read
 * neither, it says so as a prompt rather than repeating the other rule's words.
 */
export const rule: Rule = {
  id: "PERS-001",
  version: "1.3.0",
  name: "Non-compete present",
  category: "personnel",
  default_severity: "info",
  description: "Detects non-compete; surfaces geographic and temporal scope.",
  dkb_citations: ["stat-16-cfr-910", "stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      // The dominant non-compete forms carried none of the original tokens and
      // went undetected (audit): the bare "Employee shall not compete", the
      // noun "non-competition" (the old `\bnon[- ]compete\b` stopped at the
      // word boundary and missed the "-ition" ending), and the "engage in a
      // business that competes" object. `non[- ]?compet(?:e|ition)` admits
      // non-compete / noncompete / non-competition while still excluding
      // "non-competitive" (bids, pricing). The negation the covenant itself
      // carries ("shall NOT compete") sits INSIDE each match, so the
      // unnegated-window guard only suppresses a genuine disclaimer ("this is
      // NOT a non-compete") — not the covenant.
      /\bnon[- ]?compet(?:e|ition)\b|\bcovenant\s+not\s+to\s+compete\b|\b(?:shall|will|agrees?)\s+not[,\s]+(?:to[,\s]+)?(?:directly\s+or\s+indirectly[,\s]+)?compete\b|\bshall\s+not[^.;]{0,80}?\b(?:own|manage|operate|control|engage\s+in|carry\s+on|be\s+employed\s+by|work\s+for|render\s+services?|participate\s+in)\b[^.;]{0,120}?\b(?:(?:competing|competitive)\s+(?:business|enterprise|activit\w*|venture|firm|company)|business\s+that\s+competes)\b/i,
      50,
      // A covenant the document merely DESCRIBES — "the non-competition
      // covenants each of you will sign" in a conflict-waiver letter — is not
      // one this document imposes.
      (paragraph, index) => describesCovenantElsewhere(paragraph, index),
    );
    if (!hit) return null;
    // The PARAGRAPH, not the enclosing sentence: the trigger matches the
    // section heading — "9.1 Non-Competition." — whose own sentence ends at
    // the period, so the scope stated in the sentence beneath it was invisible.
    const clause = hit.text;
    const duration = DURATION.exec(clause)?.[0]?.trim();
    const geography = GEOGRAPHY.exec(clause)?.[0]?.trim();
    const scope = [duration, geography].filter(Boolean).join(", ");
    // When the scope cannot be read the finding is a PROMPT, not an
    // accusation: the trigger matches the section HEADING ("14. Covenant Not
    // to Compete.") as readily as the covenant, and the scope is then in the
    // paragraph beneath it, which this rule does not see. Saying "no stated
    // scope" would be wrong as often as right.
    return emit(ctx, rule, {
      title: scope
        ? `Non-compete scope: ${scope}`
        : "Non-compete clause — check scope and enforceability",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Non-competes are unenforceable in some jurisdictions (e.g., California, Bus. & Prof. Code § 16600). The FTC's 2024 rule that would have banned most worker non-competes (16 C.F.R. Part 910) was set aside nationwide in Ryan LLC v. FTC (N.D. Tex. Aug. 20, 2024) and never took effect — the FTC dismissed its appeals in September 2025 — so enforceability turns on state law, with the FTC retaining only case-by-case FTC Act § 5 enforcement. Verify against the governing-law jurisdiction.",
      position: hit.position,
    });
  },
};

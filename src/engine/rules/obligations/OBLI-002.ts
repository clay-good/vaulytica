import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/**
 * An obligation whose action is DISCLAIMED — "Vendor shall **not have any
 * reciprocal indemnification obligation**". The extractor records the obligor
 * and the action verbatim, so counting it as that party bearing the obligation
 * inverts the clause's meaning and hides the very asymmetry this rule exists to
 * report.
 */
const NEGATED_ACTION = /^(?:not|never)\b/i;

/**
 * The obligations that are mutual by default, each with the name a reader
 * would use for it. The label is not decoration: the finding's title and
 * excerpt used to interpolate the pattern itself, so every OBLI-002 finding
 * this tool has ever emitted read "Asymmetric obligation under
 * '\bconfidential'" and "Obligation kind matching /\bconfidential/i" —
 * engine internals printed at an attorney.
 */
const RECIPROCAL_PATTERNS = [
  { label: "confidentiality", pattern: /\bconfidential/i },
  { label: "indemnification", pattern: /\bindemnif/i },
  { label: "representations", pattern: /\brepresentation/i },
  { label: "warranties", pattern: /\bwarrant/i },
] as const;

/** OBLI-002 — Reciprocity asymmetry (info). */
export const rule: Rule = {
  id: "OBLI-002",
  version: "1.0.0",
  name: "Reciprocity asymmetry",
  category: "obligations",
  default_severity: "info",
  description: "For typically-mutual obligations, flags when only one party bears the obligation.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const parties = ctx.extracted.parties;
    if (parties.length < 2) return null;
    // Obligations name the party by whichever surface form the drafter used,
    // and contracts overwhelmingly write the ROLE ("Employee shall …", "the
    // Company shall …") rather than the legal name. Matching on `name` alone
    // silently dropped every role-phrased obligor, so a genuinely one-sided
    // clause went unreported whenever the document used its own defined roles.
    const partySet = new Set(
      parties.flatMap((p) => [p.name.toLowerCase(), ...(p.role ? [p.role.toLowerCase()] : [])]),
    );
    for (const { label, pattern } of RECIPROCAL_PATTERNS) {
      const seenObligors = new Set<string>();
      for (const o of ctx.extracted.obligations) {
        if (!pattern.test(o.action)) continue;
        if (NEGATED_ACTION.test(o.action.trim())) continue;
        const o2 = o.obligor.toLowerCase().trim();
        if (partySet.has(o2)) seenObligors.add(o2);
      }
      if (seenObligors.size === 1 && partySet.size >= 2) {
        return emit(ctx, rule, {
          title: `Asymmetric ${label} obligation`,
          description: `Only ${[...seenObligors][0]} bears this typically-mutual obligation.`,
          excerpt: `${label} obligation`,
          explanation:
            "Obligations like confidentiality, indemnity, and representations are usually mutual. A one-sided version is sometimes intentional but worth confirming.",
          position: topPosition(ctx),
        });
      }
    }
    return null;
  },
};

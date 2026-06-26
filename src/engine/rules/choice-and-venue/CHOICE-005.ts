import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

const NY_CONVENTION_PARTIES =
  /\b(?:United\s+States|Canada|Mexico|United\s+Kingdom|Germany|France|Japan|Australia|Singapore|Hong\s+Kong|China|India|Brazil|Spain|Italy|Netherlands|Switzerland|South\s+Korea|Sweden|Ireland|Israel|UAE|Norway|Belgium|Austria|Denmark|Finland|Portugal|Poland|England\s+and\s+Wales)\b/i;

/** CHOICE-005 — Foreign venue without enforceability treaty (warning). */
export const rule: Rule = {
  id: "CHOICE-005",
  version: "1.0.0",
  name: "Foreign venue without enforceability treaty",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags non-US venues outside the New York / Hague convention common list.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const venue = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "venue");
    if (!venue) return null;
    if (
      /\b(?:state|federal|United\s+States|Delaware|New\s+York|California|Texas|Florida|Illinois|Massachusetts|Washington|Georgia|Pennsylvania|D\.?C\.?)\b/i.test(
        venue.raw_text,
      )
    )
      return null;
    if (NY_CONVENTION_PARTIES.test(venue.raw_text)) return null;
    return emit(ctx, rule, {
      title: `Foreign venue without standard enforceability treaty: ${venue.raw_text}`,
      description: `Venue: ${venue.raw_text}.`,
      excerpt: venue.raw_text,
      explanation:
        "Enforcing a US judgment in a jurisdiction outside the New York or Hague convention can be expensive and uncertain. Confirm a clear path to enforcement exists.",
      position: venue.position,
    });
  },
};

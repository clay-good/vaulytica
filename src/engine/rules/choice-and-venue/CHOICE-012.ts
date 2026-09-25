import type { Rule, RuleContext, Finding } from "../../finding.js";
import { rule as CHOICE_004 } from "./CHOICE-004.js";
import { emit } from "../_helpers.js";

/**
 * CHOICE-012 — Governing-law / venue jurisdiction mismatch (warning).
 *
 * Fires when the document selects one jurisdiction as the governing
 * law but a different jurisdiction as the venue / exclusive forum.
 * The combination is enforceable in many jurisdictions but is almost
 * always a drafting error rather than a deliberate choice: a litigant
 * filing in the venue jurisdiction's courts must brief the other
 * jurisdiction's law (a question of law under Fed. R. Civ. P. 44.1, and
 * judicially noticed for sister states), adding cost and giving the local
 * judge an unfamiliar legal framework to apply. The result
 * is unpredictable and slow.
 *
 * Detection: the jurisdictions extractor produces a `governing-law`
 * entry and one or more `venue` entries. We compare the normalized
 * jurisdiction labels; if they differ on a meaningful axis (state /
 * country) the rule fires. Federal-vs-state references for the same
 * state (e.g., "federal courts located in Delaware" + "laws of
 * Delaware") are NOT flagged — that's the conventional pairing.
 *
 * Real-world example caught by this rule: the user's
 * Sample_MSA_Northwind_Acme document selected Delaware law (§14.1)
 * and New York courts (§14.2) — two unrelated jurisdictions chosen
 * by mistake.
 */
export const rule: Rule = {
  id: "CHOICE-012",
  version: "1.2.0",
  name: "Governing-law / venue jurisdiction mismatch",
  category: "choice-and-venue",
  default_severity: "warning",
  description:
    "Fires when the governing-law selection names a different jurisdiction than the venue / exclusive-forum selection.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // ONE law/venue split, ONE finding. CHOICE-004 owns it; this rule keeps
    // only the cases CHOICE-004 does not report. The three used to fire
    // together and disagree — "almost always a drafting accident" beside
    // "usually deliberate" — in comments on one clause.
    if (CHOICE_004.check(ctx) !== null) return null;
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    if (!gov) return null;
    const venues = ctx.extracted.jurisdictions.filter((j) => j.clause_kind === "venue");
    if (venues.length === 0) return null;

    const govNorm = normalizeJurisdiction(gov.raw_text);
    if (!govNorm) return null;
    const mismatched = venues.find((v) => {
      const vNorm = normalizeJurisdiction(v.raw_text);
      return vNorm && vNorm !== govNorm;
    });
    if (!mismatched) return null;

    return emit(ctx, rule, {
      title: `Governing law (${gov.raw_text}) and venue (${mismatched.raw_text}) name different jurisdictions`,
      description: `Governing law is ${gov.raw_text}; venue / exclusive jurisdiction is ${mismatched.raw_text}.`,
      excerpt: `${gov.raw_text} → ${mismatched.raw_text}`,
      explanation:
        "When the governing-law and venue clauses name different jurisdictions, the court hearing the dispute must apply another jurisdiction's law. Federal courts decide foreign-country law as a question of law (Fed. R. Civ. P. 44.1), and state courts routinely take judicial notice of sister-state law; a law/forum split adds cost and unpredictability. The mismatch is almost always a drafting accident — one side copy-pasted from a different template — rather than a deliberate strategic choice.",
      recommendation:
        "Align governing law and venue to the same jurisdiction unless the mismatch is deliberate and documented. If deliberate, add a brief explanation in the choice-of-law section noting the rationale (typical use case: a neutral arbitral seat with a different governing law).",
      position: mismatched.position,
    });
  },
};

/**
 * Map a free-form jurisdiction label to a normalized comparison key.
 * Drops "the State of" / "the Commonwealth of" prefixes, strips
 * leading articles, lowercases, and collapses common state-name
 * variants. Returns `undefined` for empty input so the rule can
 * defer to the next venue if available.
 */
function normalizeJurisdiction(raw: string): string | undefined {
  const trimmed = raw
    .toLowerCase()
    // Drop venue-prefix noise the extractor sometimes captures as part
    // of the raw_text on the simple-regex fallback path.
    .replace(
      /^the\s+(?:state\s+and\s+federal\s+|federal\s+and\s+state\s+|state\s+|federal\s+)?courts?\s+(?:located\s+in\s+|sitting\s+in\s+|of\s+|in\s+)?/,
      "",
    )
    .replace(/^the\s+/, "")
    .replace(/\b(?:state|commonwealth)\s+of\s+/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!trimmed) return undefined;
  // Common shorthand and abbreviation normalizations.
  const ALIAS: Record<string, string> = {
    del: "delaware",
    "del.": "delaware",
    ny: "new york",
    "n.y.": "new york",
    ca: "california",
    cal: "california",
    "cal.": "california",
    tex: "texas",
    "tex.": "texas",
    mass: "massachusetts",
    "mass.": "massachusetts",
    uk: "united kingdom",
    "england and wales": "england",
  };
  return ALIAS[trimmed] ?? trimmed;
}

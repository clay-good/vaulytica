import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { CURRENCY_TOKEN } from "../../../extract/amounts.js";

/** RISK-010 — Insurance requirement levels (info). */
export const rule: Rule = {
  id: "RISK-010",
  version: "1.2.0",
  name: "Insurance requirement levels",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces insurance requirement amounts and types.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `[^.;\n]` so the dollar amount must be in the SAME sentence as the
      // coverage type — otherwise an unrelated figure (e.g. the contract price
      // in the next sentence) was reported as the coverage minimum. The type
      // list covered only four lines; a services / construction contract also
      // states umbrella / excess, workers' comp, auto, employer's / products /
      // D&O / EPLI / property limits, and abbreviates CGL / E&O / D&O — all
      // previously unsurfaced. Ambiguous heads are anchored to an insurance
      // word ("umbrella LIABILITY/POLICY/COVERAGE") so an "umbrella clause of
      // $5,000" is not read as a coverage limit.
      // Abbreviations carry a `(?![-\w])` guard so "CGL-2026-447821" (a policy
      // number on a certificate of insurance) is not read as a coverage type.
      // The amount was the dollar GLYPH alone, and an international contract
      // states its minimum "USD 2,000,000 per occurrence" or "€5.000.000".
      // `src/extract/amounts.ts` has read the ISO codes and the other symbols
      // since it was written; the rule layer had its own narrower spelling
      // (v1.2.0).
      new RegExp(
        String.raw`\b(?:commercial\s+general\s+liability|(?:CGL|E&O|D&O|EPLI)(?![-\w])|professional\s+liability|errors\s+and\s+omissions|cyber\s+liability|umbrella\s+(?:liability|insurance|policy|coverage)|excess\s+liability|workers['’]?\s+comp(?:ensation)?|(?:commercial\s+)?auto(?:mobile)?\s+liability|employer['’]?s?\s+liability|products?\s+liability|directors['’]?\s+and\s+officers['’]?|employment\s+practices\s+liability|property\s+insurance)\b[^.;\n]{0,160}?(?:` +
          CURRENCY_TOKEN +
          String.raw`)\s*([\d,]+)`,
        "i",
      ),
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Insurance requirements stated",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 320),
      explanation:
        "Insurance levels should match the deal size and risk. Common minimums are $1M per occurrence CGL and $2M E&O for services contracts.",
      position: hit.position,
    });
  },
};

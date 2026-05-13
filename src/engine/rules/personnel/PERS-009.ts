import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";
import type { DocPosition } from "../../../extract/types.js";

/**
 * PERS-009 — Long non-solicit duration (warning, personnel).
 *
 * Detects non-solicit / no-hire clauses with a duration that exceeds
 * the consensus-reasonable bound. PERS-002 fires "info" on the
 * presence of any non-solicit; PERS-009 escalates to "warning" when
 * the duration extends past 12 months — the most commonly cited
 * outer bound for enforceability across US states. Durations of 24
 * months or more are flagged with stronger language: California
 * Bus. & Prof. Code § 16600 / § 16600.5 voids most non-solicits
 * regardless of duration; New York courts disfavor non-solicits
 * longer than 12 months absent a strong showing of legitimate
 * business interest (e.g., *BDO Seidman v. Hirshberg*, 712 N.E.2d
 * 1220); Massachusetts G.L. c. 149 § 24L caps at 12 months for
 * post-employment restrictions on individuals.
 *
 * Detection: a paragraph carrying non-solicit / no-hire / no-poach
 * language AND a duration expressed in months / years. Two thresholds:
 *
 *   - 13–23 months → "exceeds the typical 12-month bound"
 *   - ≥ 24 months → "well beyond the consensus enforceable window"
 */

// Conservative non-solicit gates. We do a cheap "is there a relevant
// signal at all?" check (NON_SOLICIT_KEYWORD) then a small set of
// non-overlapping patterns to confirm. Splitting like this avoids
// the catastrophic-backtracking risk of a single mega-alternation
// where multiple branches share a `(?:to\s+)?solicit` tail.
const NON_SOLICIT_KEYWORD = /\b(?:solicit|no[- ]hire|no[- ]poach)\b/i;
const NON_SOLICIT_NEGATIVES = [
  /\bnon[- ]solicit(?:ation)?\b/i,
  /\b(?:shall|may|will|agrees?)\s+not\s+solicit\b/i,
  /\bnot\s+to\s+solicit\b/i,
  /\bno[- ]hire\b/i,
  /\bno[- ]poach\b/i,
];

// Conservative duration regex — avoids backtracking by keeping the
// quantifier tree shallow. Matches either a bare number / spelled-out
// number, then optional "(NN)" gloss, then the unit.
const DURATION_RE =
  /\b(\d{1,3}|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fifteen|eighteen|twenty(?:-(?:one|two|three|four))?|thirty(?:-six)?)\s*(?:\(\d{1,3}\)\s*)?(year|years|month|months)\b/i;

const NUM_WORDS: Record<string, number> = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, fifteen: 15, eighteen: 18,
  twenty: 20, "twenty-one": 21, "twenty-two": 22, "twenty-three": 23, "twenty-four": 24,
  thirty: 30, "thirty-six": 36,
};

function durationToMonths(amount: string, unit: string): number | null {
  const cleaned = amount.toLowerCase().replace(/\s+/g, "-");
  let n: number | null = null;
  if (/^\d+$/.test(cleaned)) n = Number(cleaned);
  else if (cleaned in NUM_WORDS) n = NUM_WORDS[cleaned]!;
  if (n == null) return null;
  return /year/i.test(unit) ? n * 12 : n;
}

export const rule: Rule = {
  id: "PERS-009",
  version: "1.0.0",
  name: "Long non-solicit duration",
  category: "personnel",
  default_severity: "warning",
  description:
    "Flags non-solicit / no-hire clauses lasting longer than 12 months; escalates the description when the duration is ≥ 24 months.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Hit = { months: number; raw: string; text: string; position: DocPosition; matchIndex: number };
    let hit: Hit | null = null;
    forEachParagraph(ctx.tree, (p) => {
      if (hit) return;
      const text = p.text;
      if (!NON_SOLICIT_KEYWORD.test(text)) return;
      // Confirm a negative-obligation framing.
      let negFound = false;
      for (const re of NON_SOLICIT_NEGATIVES) {
        if (re.test(text)) {
          negFound = true;
          break;
        }
      }
      if (!negFound) return;
      // Find the first long-enough duration.
      const re = new RegExp(DURATION_RE.source, DURATION_RE.flags + "g");
      re.lastIndex = 0;
      let dm: RegExpExecArray | null;
      while ((dm = re.exec(text)) !== null) {
        const months = durationToMonths(dm[1] ?? "", dm[2] ?? "");
        if (months == null || months <= 12) continue;
        hit = {
          months,
          raw: dm[0],
          text,
          position: {
            section_id: p.section.id,
            paragraph_id: p.paragraph.id,
            start: p.start + dm.index,
            end: p.start + dm.index + dm[0].length,
          },
          matchIndex: dm.index,
        };
        return;
      }
    });
    if (!hit) return null;
    const h: Hit = hit;
    const tier = h.months >= 24 ? "well beyond" : "exceeds";
    return emit(ctx, rule, {
      title: `Non-solicit duration ${h.months} months ${tier} the consensus 12-month bound`,
      description: `${h.raw} — non-solicit duration ${h.months} months`,
      excerpt: h.text.slice(Math.max(0, h.matchIndex - 20), h.matchIndex + 280),
      explanation:
        h.months >= 24
          ? "Non-solicit durations of 24 months or longer are routinely struck down or narrowed by US courts. California Bus. & Prof. Code §§ 16600 / 16600.5 voids most non-solicits regardless of duration; Massachusetts G.L. c. 149 § 24L caps individual post-employment restrictions at 12 months; New York courts (e.g., *BDO Seidman v. Hirshberg*) require a strong legitimate-business-interest showing for anything past 12 months. A 24+ month restriction is unlikely to be enforced as written."
          : "Non-solicit durations longer than 12 months are increasingly disfavored. The consensus enforceable window across US states is 12 months, with California (Bus. & Prof. Code §§ 16600 / 16600.5) voiding most non-solicits entirely. A 13–23 month restriction is likely to be narrowed by a reviewing court to 12 months or less.",
      recommendation:
        "Reduce the non-solicit duration to 12 months or less, or split into (i) a 12-month post-engagement non-solicit, and (ii) a longer non-solicit limited to specific individuals with a documented legitimate business interest. Consider whether the clause is enforceable at all under California law if any party is California-based.",
      position: h.position,
    });
  },
};

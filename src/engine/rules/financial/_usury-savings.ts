/**
 * A usury SAVINGS clause caps the rate it states at the legal limit: "the lesser
 * of eighteen percent (18%) per year and the maximum rate permitted by
 * applicable law", or "one percent (1%) per month or the maximum rate permitted
 * by law, whichever is less". The stated figure cannot exceed what the law
 * allows, so a rule that compares it with a usury line must not accuse it.
 *
 * FIN-004 and FIN-009 share this so they cannot disagree about it; EQT-012
 * carries the same idea in its `exclude_if`.
 */
const SAVINGS =
  /\b(?:maximum|highest)\s+(?:lawful\s+|legal\s+)?(?:rate|amount)\s+(?:of\s+interest\s+)?(?:permitted|allowed|permissible)\b|\b(?:maximum|highest)\s+lawful\s+rate\b|\blawful\s+maximum\b/i;

/**
 * Whether the clause holding a matched rate is a savings clause. Reads from the
 * match to the end of its sentence — a decimal point is not a sentence end —
 * because the cap follows the rate ("… 18% per year and the maximum rate …").
 */
export function isUsurySavingsClause(paragraph: string, matchIndex: number): boolean {
  const rest = paragraph.slice(matchIndex);
  const sentence = /^(?:[^.]|\.(?=\d))*/.exec(rest)?.[0] ?? rest;
  return SAVINGS.test(sentence);
}

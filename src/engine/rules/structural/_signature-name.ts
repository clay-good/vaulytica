/**
 * The printed personal name under a signature line — ONE owner.
 *
 * STRUCT-003 (is there a signature block?) and STRUCT-013 (is this rule an
 * unfilled placeholder?) each carried a byte-identical copy of this test and
 * its two vocabularies, and a fix to one did not reach the other: STRUCT-013
 * learned in 9.738.0 that an individual signs over "Name / Date: <filled>",
 * and STRUCT-003 reported a climbing-gym release unsigned for the same line
 * until 9.762.0.
 *
 * The letters are UNICODE and a word may carry an internal capital: the
 * ASCII `[A-Z][a-z]+` form rejected "José García", "Zoë Müller", "Siobhan
 * O'Brien", "Ian McDonald" and "Anneke Achebe-Lindström" — every one a real
 * signatory, each reported at `critical` as a placeholder or a missing
 * signature. A word still needs a lowercase letter (so "TBD" is not a name)
 * unless it is an initial ("K.").
 */

/** A template / field-label token that is never part of a printed name. */
export const NON_NAME_TOKEN =
  /\b(?:Name|Date|Address|City|State|Zip|Country|Title|Code|Number|Amount|Value|Reference|Period|Term|Field|Information|Details|Description|Phone|Email|Sum|Fee|Rate|Price|Insert|Sign|Signature|Print(?:ed)?|Company|Corporation|Entity|Party|Here|TBD|TBA)\b/i;

/** A courtesy / professional title stripped before the name test. */
export const HONORIFIC_PREFIX =
  /^(?:Dr|Mr|Mrs|Ms|Mx|Prof(?:essor)?|Hon|Rev|Sir|Dame|Fr|Sr|Capt|Col|Gen|Lt|Sgt|Rabbi|Pastor|Judge)\.?\s+/i;

const NAME_WORD = String.raw`\p{Lu}(?:\.|[\p{L}'’-]*\p{Ll}[\p{L}'’.-]*)`;
const PERSONAL_NAME = new RegExp(String.raw`^${NAME_WORD}(?:\s+${NAME_WORD}){1,3}$`, "u");

/**
 * True if `s` is a bare printed personal name — 2–4 name words, no field-label
 * token. A trailing ", Role" clause and a leading honorific come off first.
 */
export function isPersonalName(s: string): boolean {
  const t = s.replace(/,.*$/, "").trim().replace(HONORIFIC_PREFIX, "");
  if (NON_NAME_TOKEN.test(t)) return false;
  return PERSONAL_NAME.test(t);
}

/**
 * The text under a rule with a FILLED-IN date caption removed — "Daniel K.
 * Osei Date: July 15, 2026" → "Daniel K. Osei". Requires the colon: a "Date:"
 * field, never a surname.
 */
export function withoutFilledDate(s: string): string {
  return s.replace(/\s+Dated?\s*:\s*[^_]*$/i, "").trim();
}

/**
 * Syllables in an English word (add-readability-measure, task 1).
 *
 * A fixed, versioned rule set plus a short exception list, so a change to the
 * counter is visible as a version change, never silent. The rules are the
 * usual vowel-group count with the corrections English spelling needs: a
 * silent final "e", "-es" and "-ed" that add no syllable except after the
 * sounds that make them one ("boxes", "dated"), a final consonant + "le"
 * ("article"), and the vowel pairs that split ("pe-ri-od", "ma-te-ri-al").
 *
 * Measured against the committed reference list in `syllables-reference.ts`
 * (frequent words of the specimen corpus, counted from dictionary
 * syllabification); the accuracy is asserted in `syllables.test.ts`.
 */
export const SYLLABLE_COUNTER_VERSION = "1";

/** Words the rules get wrong, with their dictionary count. */
const EXCEPTIONS: Readonly<Record<string, number>> = {
  business: 2,
  every: 2,
  being: 2,
  ohio: 3,
  area: 3,
  idea: 3,
  create: 2,
  created: 3,
  creates: 2,
  agreeing: 3,
  science: 2,
  quiet: 2,
  poem: 2,
  real: 1,
  people: 2,
  one: 1,
  once: 1,
  some: 1,
  come: 1,
  done: 1,
  none: 1,
  gone: 1,
  give: 1,
  have: 1,
  live: 1,
  move: 1,
  above: 2,
  whose: 1,
  where: 1,
  there: 1,
  here: 1,
  were: 1,
  are: 1,
  wednesday: 2,
  hereunder: 3,
  thereunder: 3,
  hereinafter: 4,
};

/** Vowel pairs read as two syllables ("pe-ri-od", "ma-te-ri-al", "o-ri-ent", "pi-o-neer"). */
const SPLIT_PAIR = /(?:ia|io|iu|eo|ua|uo|ie(?=r$|st$))/g;

/** The syllables in one word; 0 for something with no letters. */
export function syllables(word: string): number {
  const w = word
    .toLowerCase()
    .replace(/['’]s$/, "")
    .replace(/[^a-z]/g, "");
  if (!w) return 0;
  const known = EXCEPTIONS[w];
  if (known !== undefined) return known;
  // "any", "many": a vowel, a consonant, then "y" is two; "why", "toy" one.
  if (w.length <= 3) return /^[aeiou][^aeiouy]y$/.test(w) ? 2 : 1;
  // A "here-", "there-", "where-" compound is its parts: "here·of", "there·under".
  const compound = /^(here|there|where)([a-z]{2,})$/.exec(w);
  if (compound && compound[2] !== "s") return 1 + syllables(compound[2]!);
  let core = w;
  // A final "-es"/"-ed"/"-e" is silent unless the stem needs a vowel to say it.
  if (/(?:[sxz]|ch|sh|g|c)es$/.test(core)) core = core.slice(0, -1);
  else if (/[^aeiouy]es$/.test(core)) core = core.slice(0, -2);
  else if (/[td]ed$/.test(core)) core = core.slice(0, -2) + "a";
  else if (/[^aeiouy]ed$/.test(core)) core = core.slice(0, -2);
  else if (/[^aeiouy]le$/.test(core)) core = core.slice(0, -2) + "al";
  else if (/[^aeiouy]e$/.test(core)) core = core.slice(0, -1);
  // A silent "e" before a suffix: "state·ment", "like·ly".
  core = core.replace(/([^aeiouy])e(ment|ly|ful|ness|less)$/, "$1$2");
  core = core.replace(/^y/, "");
  // A "y" between vowels is a consonant: "bu·yer", "em·ploy·ee", "pay·a·ble".
  core = core.replace(/([aeiou])y(?=[aeiou])/g, "$1-");
  const groups = core.match(/[aeiouy]+/g)?.length ?? 0;
  // A pair that splits adds one, except where the "i" is part of "-tion"/"-cial"/"-cian".
  const splits = (
    core.replace(/(?:ti|ci|si|xi)(?:on|al|an|ous|ent|ence|a)/g, "-").match(SPLIT_PAIR) ?? []
  ).length;
  return Math.max(1, groups + splits);
}

/** Syllables in a run of words. */
export function countSyllables(words: readonly string[]): number {
  let n = 0;
  for (const w of words) n += syllables(w);
  return n;
}

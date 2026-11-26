/**
 * Raw jurisdiction text → `us-XX` id. The one resolver.
 *
 * This is the lookup `extractAll` has always accepted and no caller ever
 * supplied (`wire-jurisdiction-id-resolution`). While `jurisdiction_id` was
 * `undefined` on every entry the product produced, each consumer that needed
 * it grew its own normalization instead: this map lived in `state-overlays.ts`
 * under a docstring that said "runtime extraction does not populate
 * `jurisdiction_id` … so this map is the resolver", `CHOICE-012` carries a
 * comparison-key normalizer, and `custom-interpreter.ts` strips law affixes off
 * raw text. 🚨 **A dead field does not stay dead; it gets worked around.** It
 * lives here now so the extractor can fill the field and the consumers can read
 * it.
 *
 * Coverage is the 50 states plus DC, and nothing else. A name outside the map
 * returns `undefined` — the honest-N/A path. `England and Wales`, `Ireland` and
 * `United States` are real extracted values that resolve to no state id, and a
 * governing-law clause stating a FORMULA ("the jurisdiction where the Equipment
 * is located") names no jurisdiction to resolve at all.
 */

/**
 * 🚨 This map's key set is asserted against `US_STATE_PATTERN` in
 * `jurisdiction-ids.test.ts`. That list is the extractor's own idea of which
 * states exist, written independently of this one, and its docstring already
 * warns that a partial list "silently reclassifies the states it omits as
 * foreign". Two hand-maintained state lists that are never compared will drift;
 * the comparison is what makes adding a state to one of them fail loudly.
 */
const STATE_NAME_TO_ID: ReadonlyMap<string, string> = new Map(
  (
    [
      ["alabama", "al"],
      ["alaska", "ak"],
      ["arizona", "az"],
      ["arkansas", "ar"],
      ["california", "ca"],
      ["colorado", "co"],
      ["connecticut", "ct"],
      ["delaware", "de"],
      ["district of columbia", "dc"],
      ["florida", "fl"],
      ["georgia", "ga"],
      ["hawaii", "hi"],
      ["idaho", "id"],
      ["illinois", "il"],
      ["indiana", "in"],
      ["iowa", "ia"],
      ["kansas", "ks"],
      ["kentucky", "ky"],
      ["louisiana", "la"],
      ["maine", "me"],
      ["maryland", "md"],
      ["massachusetts", "ma"],
      ["michigan", "mi"],
      ["minnesota", "mn"],
      ["mississippi", "ms"],
      ["missouri", "mo"],
      ["montana", "mt"],
      ["nebraska", "ne"],
      ["nevada", "nv"],
      ["new hampshire", "nh"],
      ["new jersey", "nj"],
      ["new mexico", "nm"],
      ["new york", "ny"],
      ["north carolina", "nc"],
      ["north dakota", "nd"],
      ["ohio", "oh"],
      ["oklahoma", "ok"],
      ["oregon", "or"],
      ["pennsylvania", "pa"],
      ["rhode island", "ri"],
      ["south carolina", "sc"],
      ["south dakota", "sd"],
      ["tennessee", "tn"],
      ["texas", "tx"],
      ["utah", "ut"],
      ["vermont", "vt"],
      ["virginia", "va"],
      ["washington", "wa"],
      ["west virginia", "wv"],
      ["wisconsin", "wi"],
      ["wyoming", "wy"],
    ] as const
  ).map(([name, abbr]) => [name, `us-${abbr}`]),
);

/** The jurisdiction names this resolver knows, for the drift guard. */
export function resolvableJurisdictionNames(): readonly string[] {
  return [...STATE_NAME_TO_ID.keys()];
}

/**
 * Resolve raw jurisdiction text to a `us-XX` id, or `undefined`.
 *
 * Satisfies `DkbLookup`, so it can be handed straight to `extractAll`. The
 * governing-law extractor already strips leading articles, but a venue or
 * arbitration-seat capture may still arrive as "the State of Delaware" or
 * "Delaware law", so the affixes are trimmed defensively here. Punctuation is
 * dropped rather than split on: a courthouse capture ("Wilmington, Delaware")
 * carries a city, which is not a state name and correctly resolves to nothing —
 * narrowing to the trailing word would invent a state the clause did not name.
 */
export function resolveJurisdictionId(raw: string): string | undefined {
  const cleaned = raw
    .toLowerCase()
    .replace(/\b(the\s+)?(state|commonwealth)\s+of\s+/g, "")
    .replace(/\s+laws?$/, "")
    .replace(/[^a-z\s]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return STATE_NAME_TO_ID.get(cleaned);
}

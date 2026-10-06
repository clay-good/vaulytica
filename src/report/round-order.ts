/**
 * Round order read from file names (spec-v16/v17 Part XVI).
 *
 * A round archive saved as `round1.coherence.json`, `round2…`, `round10…` is
 * ordered by the numbers its names carry, compared as numbers: `round2`
 * precedes `round10`, where a lexical sort would put `round10` second and
 * silently reorder the deal. The order is inferred only when the names state
 * it — a name with no number, or two names carrying the same number
 * (`round-1`, `round-01`), leaves it unknowable, and the archive is refused
 * rather than guessed.
 *
 * One policy for both surfaces: the CLI's directory walker and the browser's
 * dropped rounds.
 */

/** The file name a saved coherence artifact carries. */
export const ROUND_ARTIFACT = /\.coherence\.json$/i;

/** The numbers in a file name, leading zeros dropped: the key round order is read from. */
function roundKey(name: string): string {
  return (name.match(/\d+/g) ?? []).map((d) => String(Number(d))).join(".");
}

export type RoundOrder<T> = { ok: true; items: T[] } | { ok: false; reason: string };

/** `items` in round order by `name`, or the reason the names do not determine it. */
export function orderRounds<T>(items: T[], name: (item: T) => string): RoundOrder<T> {
  const unnumbered = items.map(name).filter((n) => roundKey(n) === "");
  if (unnumbered.length > 0) {
    return {
      ok: false,
      reason: `cannot infer round order — ${unnumbered.join(", ")} carries no round number`,
    };
  }
  const seen = new Map<string, string>();
  for (const n of items.map(name)) {
    const twin = seen.get(roundKey(n));
    if (twin) {
      return {
        ok: false,
        reason: `cannot infer round order — ${twin} and ${n} carry the same round number`,
      };
    }
    seen.set(roundKey(n), n);
  }
  return {
    ok: true,
    items: [...items].sort((a, b) => name(a).localeCompare(name(b), "en", { numeric: true })),
  };
}

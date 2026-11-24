/**
 * `npm run authority:drift` — re-read every mandated text at its official
 * source and report whether its wording still matches the committed passage.
 *
 * Scheduled/on-demand only, like `citation:check --reachability`: it opens
 * sockets, so it never runs per-commit and is never imported by `src/`. The
 * per-commit half (every row's digest matches its own text) is in
 * `drift.test.ts` and needs no network.
 *
 * Exit codes: 0 when every passage is unchanged, 1 when any has drifted or
 * could not be found. A drift is a real signal — the yardstick `TEXT-001`
 * measures against has moved — so it fails the scheduled build rather than
 * printing a warning nobody reads.
 */
import { committedDigests, compareAgainstSource, type DriftVerdict } from "./drift.js";

/** Bounded fetch; a scheduled tool may use a clock and a timeout. */
async function readSource(url: string, timeoutMs = 30_000): Promise<string> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { "user-agent": "Vaulytica authority-drift (vaulytica.com)" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function main(): Promise<void> {
  const rows = committedDigests();
  const verdicts: DriftVerdict[] = [];
  // One request per distinct source, not per variant: § 433.2(a) and (b) are
  // two passages in one section.
  const bodies = new Map<string, string | Error>();
  for (const url of new Set(rows.map((r) => r.source_url))) {
    try {
      bodies.set(url, await readSource(url));
    } catch (err) {
      bodies.set(url, err instanceof Error ? err : new Error(String(err)));
    }
  }
  for (const row of rows) {
    const body = bodies.get(row.source_url)!;
    if (body instanceof Error) {
      verdicts.push({
        key: row.key,
        status: "not-found",
        detail: `could not read ${row.source_url}: ${body.message}`,
      });
      continue;
    }
    verdicts.push(compareAgainstSource(row, body));
  }

  const byKey = new Map(rows.map((r) => [r.key, r]));
  for (const v of verdicts) {
    const row = byKey.get(v.key)!;
    const mark = v.status === "unchanged" ? "ok  " : v.status === "drifted" ? "DRIFT" : "MISS";
    process.stdout.write(`${mark} ${row.citation} ${row.where} (read ${row.retrieved_at})\n`);
    if (v.status !== "unchanged") process.stdout.write(`      ${v.detail}\n`);
  }

  const bad = verdicts.filter((v) => v.status !== "unchanged");
  process.stdout.write(`\n${verdicts.length - bad.length}/${verdicts.length} passages unchanged\n`);
  if (bad.length > 0) {
    process.stdout.write(
      "A drifted passage means the text TEXT-001 measures against is no longer the text the\n" +
        "authority prints. Re-read the section at its official source, update the row and its\n" +
        "retrieved_at, and regenerate the goldens.\n",
    );
    process.exitCode = 1;
  }
}

await main();

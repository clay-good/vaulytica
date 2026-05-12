/**
 * DKB version helpers. Versions take the form `vYYYY-MM-DD-<commit>`
 * (e.g. `v2026-05-11-a1b2c3d`). The build pipeline also accepts the
 * special prefix `v0.0.x-` for hand-authored starters that predate the
 * automated pipeline.
 */

export type ParsedDkbVersion = {
  /** Year, month, day. `null` for starter (`v0.0.x`) versions. */
  date: { year: number; month: number; day: number } | null;
  /** Suffix after the date — usually a git short-hash. */
  suffix: string;
  raw: string;
};

const DATED = /^v(\d{4})-(\d{2})-(\d{2})-(.+)$/;
const STARTER = /^v0\.0\.\d+-(.+)$/;

export function parseDkbVersion(raw: string): ParsedDkbVersion | null {
  const dated = DATED.exec(raw);
  if (dated) {
    return {
      date: { year: +dated[1]!, month: +dated[2]!, day: +dated[3]! },
      suffix: dated[4]!,
      raw,
    };
  }
  const starter = STARTER.exec(raw);
  if (starter) {
    return { date: null, suffix: starter[1]!, raw };
  }
  return null;
}

/**
 * Compare two parsed versions. Starters (`date === null`) are always
 * considered older than dated versions. Among dated versions, ordering
 * is by date; suffixes are compared lexicographically as a tiebreaker.
 *
 * Returns negative if `a < b`, 0 if equal, positive if `a > b`.
 */
export function compareDkbVersions(a: string, b: string): number {
  const pa = parseDkbVersion(a);
  const pb = parseDkbVersion(b);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;
  if (pa.date && !pb.date) return 1;
  if (!pa.date && pb.date) return -1;
  if (pa.date && pb.date) {
    if (pa.date.year !== pb.date.year) return pa.date.year - pb.date.year;
    if (pa.date.month !== pb.date.month) return pa.date.month - pb.date.month;
    if (pa.date.day !== pb.date.day) return pa.date.day - pb.date.day;
  }
  return pa.suffix < pb.suffix ? -1 : pa.suffix > pb.suffix ? 1 : 0;
}

export function isValidDkbVersion(raw: string): boolean {
  return parseDkbVersion(raw) !== null;
}

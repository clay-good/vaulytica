/**
 * What the report endpoint writes, and for how long (spec-v53 §5).
 *
 * The database is the smallest interface D1 offers that this needs, so the
 * tests can run the real migration through SQLite and exercise the same SQL.
 */

import type { Report } from "./validate.js";

/** The slice of Cloudflare D1 this Worker uses. */
export type Statement = {
  bind(...values: unknown[]): Statement;
  run(): Promise<{ meta: { changes: number } }>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
};
export type Database = { prepare(sql: string): Statement };

/** Ceilings are constants in code, not configuration. */
export const LIMITS = {
  /** Accepted reports per reporter per day. */
  reporterAccepted: 5,
  /** Accepted reports per day in total. */
  totalAccepted: 200,
  /** Verified attempts per reporter per day, accepted or not. */
  reporterAttempts: 20,
  /** Verified attempts per day in total. */
  totalAttempts: 1000,
} as const;

/** Every report is deleted after this many days. */
export const RETENTION_DAYS = 30;

const DAY_MS = 86_400_000;
export const dayOf = (now: Date): string => now.toISOString().slice(0, 10);

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Who sent a report, for one day and for counting only: a keyed hash of the
 * day and the IP. The raw IP is never written, the key cannot be reversed
 * without the secret, and it changes at midnight UTC.
 */
export async function reporterKey(ip: string, secret: string, day: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${day}|${ip}`)));
}

/** The same report twice is one row. */
export async function dedupeKey(report: Report): Promise<string> {
  const canonical = JSON.stringify([
    report.kind,
    report.rule_id,
    report.rule_version,
    report.engine_version,
    report.dkb_version,
    report.document_type,
    report.near_family,
    report.note,
  ]);
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
}

/** Delete every report older than the retention period, and stale counters. */
export async function purgeExpired(db: Database, now: Date): Promise<number> {
  const cutoff = new Date(now.getTime() - RETENTION_DAYS * DAY_MS).toISOString();
  const gone = await db.prepare("DELETE FROM finding_reports WHERE created_at < ?").bind(cutoff).run();
  const day = dayOf(new Date(now.getTime() - 2 * DAY_MS));
  await db.prepare("DELETE FROM report_reporter_days WHERE day < ?").bind(day).run();
  await db.prepare("DELETE FROM report_days WHERE day < ?").bind(day).run();
  return gone.meta.changes;
}

type Counts = { attempts: number; accepted: number };

async function counts(db: Database, day: string, reporter: string): Promise<[Counts, Counts]> {
  const mine = await db
    .prepare("SELECT attempts, accepted FROM report_reporter_days WHERE day = ? AND reporter = ?")
    .bind(day, reporter)
    .first<Counts>();
  const all = await db
    .prepare("SELECT attempts, accepted FROM report_days WHERE day = ?")
    .bind(day)
    .first<Counts>();
  const none = { attempts: 0, accepted: 0 };
  return [mine ?? none, all ?? none];
}

async function bump(db: Database, day: string, reporter: string, column: "attempts" | "accepted") {
  // `column` is one of two literals above, never input.
  await db
    .prepare(
      `INSERT INTO report_reporter_days (day, reporter, ${column}) VALUES (?, ?, 1)
       ON CONFLICT (day, reporter) DO UPDATE SET ${column} = ${column} + 1`,
    )
    .bind(day, reporter)
    .run();
  await db
    .prepare(
      `INSERT INTO report_days (day, ${column}) VALUES (?, 1)
       ON CONFLICT (day) DO UPDATE SET ${column} = ${column} + 1`,
    )
    .bind(day)
    .run();
}

export type Stored = "stored" | "duplicate" | "limited";

/**
 * Count the attempt, and store the report unless a ceiling is reached or it
 * is already here. Retention runs first, so an old row never outlives its
 * thirty days because the cron missed a night.
 */
export async function storeReport(
  db: Database,
  report: Report,
  reporter: string,
  now: Date,
  newId: () => string = () => crypto.randomUUID(),
): Promise<Stored> {
  await purgeExpired(db, now);
  const day = dayOf(now);
  const [mine, all] = await counts(db, day, reporter);
  if (mine.attempts >= LIMITS.reporterAttempts || all.attempts >= LIMITS.totalAttempts) {
    return "limited";
  }
  await bump(db, day, reporter, "attempts");
  if (mine.accepted >= LIMITS.reporterAccepted || all.accepted >= LIMITS.totalAccepted) {
    return "limited";
  }
  const inserted = await db
    .prepare(
      `INSERT OR IGNORE INTO finding_reports
         (id, created_at, kind, rule_id, rule_version, engine_version, dkb_version,
          document_type, near_family, note, dedupe_key)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      newId(),
      now.toISOString(),
      report.kind,
      report.rule_id,
      report.rule_version,
      report.engine_version,
      report.dkb_version,
      report.document_type,
      report.near_family,
      report.note,
      await dedupeKey(report),
    )
    .run();
  if (inserted.meta.changes === 0) return "duplicate";
  await bump(db, day, reporter, "accepted");
  return "stored";
}

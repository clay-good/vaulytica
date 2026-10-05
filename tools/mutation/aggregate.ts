/**
 * Combine the per-shard Stryker reports into one mutation score and apply the
 * `break` floor from stryker.config.json.
 *
 * The weekly mutation job outgrew one runner: complete runs took 95 minutes on
 * 2026-09-07, and after `obligations.ts` tripled in size every run from
 * 2026-09-14 on hit the 180-minute job limit and reported `cancelled` — four
 * weeks with no score at all. The workflow now mutates the modules in parallel
 * shards, and this script is the one place the aggregate is decided.
 *
 * Stryker's score: (killed + timeout) / (killed + timeout + survived + no
 * coverage). Compile and runtime errors and ignored mutants count on neither
 * side, as in Stryker itself.
 *
 * A module with no report means a shard did not finish (the runner went away,
 * or a shard hit its own time limit). That says nothing about the suite, so it
 * is reported as incomplete and does not fail the job — the same rule the
 * single-job workflow applied to a signal death. Scoring the shards that did
 * finish against the floor would compare a different module set to a baseline
 * measured over all of them.
 *
 *   npx tsx tools/mutation/aggregate.ts <reports-dir>
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

type MutantStatus =
  | "Killed"
  | "Survived"
  | "NoCoverage"
  | "Timeout"
  | "CompileError"
  | "RuntimeError"
  | "Ignored"
  | "Pending";

export type MutationReport = {
  files: Record<string, { mutants: Array<{ status: MutantStatus }> }>;
};

export type FileTally = {
  file: string;
  killed: number;
  timeout: number;
  survived: number;
  noCoverage: number;
};

export type Aggregate = {
  files: FileTally[];
  missing: string[];
  score: number | undefined;
  verdict: "pass" | "below-floor" | "incomplete";
};

function scoreOf(t: Omit<FileTally, "file">): number | undefined {
  const detected = t.killed + t.timeout;
  const valid = detected + t.survived + t.noCoverage;
  return valid === 0 ? undefined : (detected / valid) * 100;
}

/** Normalize a report's file key to the repo-relative POSIX path `mutate` uses. */
function normalize(path: string): string {
  const posix = path.replace(/\\/g, "/");
  const at = posix.lastIndexOf("src/");
  return at === -1 ? posix : posix.slice(at);
}

export function aggregate(reports: MutationReport[], mutate: string[], breakAt: number): Aggregate {
  const byFile = new Map<string, FileTally>();
  for (const report of reports) {
    for (const [path, { mutants }] of Object.entries(report.files)) {
      const file = normalize(path);
      const tally = byFile.get(file) ?? { file, killed: 0, timeout: 0, survived: 0, noCoverage: 0 };
      for (const { status } of mutants) {
        if (status === "Killed") tally.killed++;
        else if (status === "Timeout") tally.timeout++;
        else if (status === "Survived") tally.survived++;
        else if (status === "NoCoverage") tally.noCoverage++;
      }
      byFile.set(file, tally);
    }
  }
  const files = [...byFile.values()].sort((a, b) => a.file.localeCompare(b.file));
  const missing = mutate.filter((m) => !byFile.has(m));
  const total = files.reduce(
    (acc, t) => ({
      killed: acc.killed + t.killed,
      timeout: acc.timeout + t.timeout,
      survived: acc.survived + t.survived,
      noCoverage: acc.noCoverage + t.noCoverage,
    }),
    { killed: 0, timeout: 0, survived: 0, noCoverage: 0 },
  );
  const score = scoreOf(total);
  const verdict =
    missing.length > 0 || score === undefined
      ? "incomplete"
      : score < breakAt
        ? "below-floor"
        : "pass";
  return { files, missing, score, verdict };
}

function findReports(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...findReports(path));
    else if (name === "mutation.json") out.push(path);
  }
  return out;
}

function main(): void {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write("usage: tsx tools/mutation/aggregate.ts <reports-dir>\n");
    process.exit(2);
  }
  const config = JSON.parse(readFileSync("stryker.config.json", "utf8")) as {
    mutate: string[];
    thresholds: { break: number };
  };
  const reports = findReports(dir).map(
    (p) => JSON.parse(readFileSync(p, "utf8")) as MutationReport,
  );
  const result = aggregate(reports, config.mutate, config.thresholds.break);
  for (const t of result.files) {
    const s = scoreOf(t);
    process.stdout.write(
      `${(s === undefined ? "n/a" : s.toFixed(2)).padStart(6)}  ${t.file}  ` +
        `(killed ${t.killed}, timeout ${t.timeout}, survived ${t.survived}, no coverage ${t.noCoverage})\n`,
    );
  }
  const shown = result.score === undefined ? "n/a" : result.score.toFixed(2);
  process.stdout.write(`aggregate ${shown} over ${reports.length} shard report(s)\n`);
  if (result.verdict === "incomplete") {
    process.stdout.write(
      `::warning title=Mutation run incomplete::No report for ${result.missing.join(", ") || "any module"}. ` +
        `A shard did not finish, which is the runner, not the score. Re-run the workflow for a reading.\n`,
    );
    return;
  }
  if (result.verdict === "below-floor") {
    process.stdout.write(
      `::error title=Mutation score below the floor::Aggregate ${shown} is under break ${config.thresholds.break} ` +
        `in stryker.config.json. Kill the surviving mutants or move the floor deliberately.\n`,
    );
    process.exit(1);
  }
}

if (process.argv[1] && /aggregate\.ts$/.test(process.argv[1])) main();

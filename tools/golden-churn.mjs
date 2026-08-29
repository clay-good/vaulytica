#!/usr/bin/env node
/**
 * Report SUBSTANTIVE golden churn: which fixtures' finding sets changed.
 *
 * After `VAULYTICA_REGEN_GOLDEN=1` every golden is rewritten, so `git diff`
 * shows hundreds of files whose only change is `result_hash` and the rule
 * versions. Reviewers filtered that by grepping the diff for lines that were
 * not a hash — which works for the pretty-printed v3 goldens and is BLIND to
 * the v4 ones, which are a single line of JSON. A rule that stopped firing on
 * a v4 fixture looked identical to a version bump.
 *
 * This parses each changed golden and diffs the finding-id multiset instead.
 *
 *   node tools/golden-churn.mjs            # against HEAD
 *   node tools/golden-churn.mjs <ref>      # against another ref
 *
 * Exit code is 0 either way: churn is often intended, and the reviewer decides.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const ref = process.argv[2] ?? "HEAD";
const PATHS = ["tests/golden", "tests/fixtures/expected", "corpus"];

const changed = execFileSync("git", ["diff", "--name-only", ref, "--", ...PATHS], {
  encoding: "utf8",
})
  .split("\n")
  .filter((f) => f.endsWith(".json"));

/** finding-id -> count, or null when the file is not a run result. */
function findingCounts(blob) {
  let parsed;
  try {
    parsed = JSON.parse(blob);
  } catch {
    return null;
  }
  const findings = parsed?.findings ?? parsed?.run?.findings;
  if (!Array.isArray(findings)) return null;
  const counts = new Map();
  for (const f of findings) counts.set(f.rule_id, (counts.get(f.rule_id) ?? 0) + 1);
  return counts;
}

let churned = 0;
for (const file of changed) {
  let before;
  try {
    before = execFileSync("git", ["show", `${ref}:${file}`], {
      encoding: "utf8",
      // A file that is NEW at `ref` makes git print "fatal: …" to
      // stderr; that is the expected path here, not an error to show.
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    continue; // new file
  }
  const a = findingCounts(before);
  let b;
  try {
    b = findingCounts(readFileSync(file, "utf8"));
  } catch {
    // DELETED, or renamed away. `git diff --name-only` lists it, and reading
    // it threw — which crashed the whole report and hid every other fixture's
    // churn behind a stack trace. A deleted golden has no finding set to diff.
    console.log(`### ${file}\n   (deleted)`);
    churned += 1;
    continue;
  }
  if (!a || !b) continue;
  const keys = [...new Set([...a.keys(), ...b.keys()])].sort();
  const removed = keys.filter((k) => (a.get(k) ?? 0) > (b.get(k) ?? 0));
  const added = keys.filter((k) => (b.get(k) ?? 0) > (a.get(k) ?? 0));
  if (removed.length === 0 && added.length === 0) continue;
  churned += 1;
  console.log(`### ${file}`);
  if (removed.length > 0) console.log(`   - ${removed.join(", ")}`);
  if (added.length > 0) console.log(`   + ${added.join(", ")}`);
}

console.log(
  `${churned} fixture${churned === 1 ? "" : "s"} with a changed finding set, of ${changed.length} rewritten.`,
);

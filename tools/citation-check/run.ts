/**
 * Citation integrity tool — CLI entry (spec-v8 §19, Step 139).
 *
 *   tsx tools/citation-check/run.ts              # well-formedness (per-commit, pure)
 *   tsx tools/citation-check/run.ts --reachability  # + network sweep (scheduled)
 *
 * Exits non-zero when any citation URL is malformed (always) or
 * unreachable (only with --reachability). Build/CI-only; never imported
 * by `src/`.
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { collectCitationUrls, findMalformed } from "./check.js";
import { checkAllReachable } from "./reachability.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");

async function main(): Promise<void> {
  const reachability = process.argv.includes("--reachability");
  const urls = collectCitationUrls(REPO_ROOT);
  process.stdout.write(`citation-check: ${urls.length} citation URLs collected\n`);

  const malformed = findMalformed(urls);
  if (malformed.length > 0) {
    process.stderr.write(`\n✗ ${malformed.length} malformed citation URL(s):\n`);
    for (const m of malformed) process.stderr.write(`  ${m.file}: ${m.url} — ${m.reason}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write("✓ all citation URLs are well-formed\n");

  if (!reachability) return;

  process.stdout.write("\nreachability sweep (network)…\n");
  const unique = [...new Set(urls.map((u) => u.url))];
  const verdicts = await checkAllReachable(unique);
  const unreachable = verdicts.filter((v) => !v.ok);
  if (unreachable.length > 0) {
    process.stderr.write(`\n✗ ${unreachable.length} unreachable citation URL(s):\n`);
    for (const v of unreachable) process.stderr.write(`  ${v.url} — ${v.reason}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`✓ all ${unique.length} citation URLs are reachable\n`);
}

void main();

/**
 * Citation integrity tool — CLI entry (spec-v8 §19, Step 139).
 *
 *   tsx tools/citation-check/run.ts              # well-formedness (per-commit, pure)
 *   tsx tools/citation-check/run.ts --reachability  # + network sweep (scheduled)
 *   tsx tools/citation-check/run.ts --reachability --attest <path>
 *       # + write the REAL validation attestation the site footer reads
 *       # (fix-build-attestation-honesty): the timestamp of THIS check and
 *       # the count of citations left pending review. The site build never
 *       # invents these values — this tool, run by the DKB rebuild
 *       # workflow, is the only writer.
 *
 * Exits non-zero when any citation URL is malformed (always) or
 * unreachable (only with --reachability). Build/CI-only; never imported
 * by `src/`.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { collectCitationUrls, findMalformed } from "./check.js";
import { checkAllReachable } from "./reachability.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");

function writeAttestation(path: string, pending: number): void {
  // Wall clock is CORRECT here: this stamps when this check actually ran
  // — a genuine attestation, unlike the build-time fabrication it replaces.
  const attestation = {
    dkb_last_validated_at: new Date().toISOString(),
    stale_citations_pending_review: pending,
    attested: true,
  };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(attestation, null, 2) + "\n", "utf8");
  process.stdout.write(`attestation written: ${path} (${pending} pending review)\n`);
}

async function main(): Promise<void> {
  const reachability = process.argv.includes("--reachability");
  const attestIdx = process.argv.indexOf("--attest");
  const attestPath =
    attestIdx >= 0 && process.argv[attestIdx + 1] ? resolve(process.argv[attestIdx + 1]!) : null;
  const urls = collectCitationUrls(REPO_ROOT);
  process.stdout.write(`citation-check: ${urls.length} citation URLs collected\n`);

  const malformed = findMalformed(urls);
  if (malformed.length > 0) {
    process.stderr.write(`\n✗ ${malformed.length} malformed citation URL(s):\n`);
    for (const m of malformed) process.stderr.write(`  ${m.file}: ${m.url} — ${m.reason}\n`);
    if (attestPath) writeAttestation(attestPath, malformed.length);
    process.exitCode = 1;
    return;
  }
  process.stdout.write("✓ all citation URLs are well-formed\n");

  if (!reachability) {
    if (attestPath) writeAttestation(attestPath, 0);
    return;
  }

  process.stdout.write("\nreachability sweep (network)…\n");
  const unique = [...new Set(urls.map((u) => u.url))];
  const verdicts = await checkAllReachable(unique);
  const unreachable = verdicts.filter((v) => !v.ok);
  if (attestPath) writeAttestation(attestPath, unreachable.length);
  if (unreachable.length > 0) {
    process.stderr.write(`\n✗ ${unreachable.length} unreachable citation URL(s):\n`);
    for (const v of unreachable) process.stderr.write(`  ${v.url} — ${v.reason}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`✓ all ${unique.length} citation URLs are reachable\n`);
}

void main();

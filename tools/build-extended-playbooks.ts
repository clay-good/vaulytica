/**
 * Build the served extended-playbook manifest (spec-v6 — full-catalog
 * wiring).
 *
 * The live pipeline ships only the 12 launch playbooks under `playbooks/`.
 * The v3 (regulated-agreement) and v4 (all-document-family) playbooks live
 * under `src/playbooks/{v3,v4}/` and were previously loaded only by the
 * golden-test harnesses — so their ~950 rules never fired in the deployed
 * product. This script bundles every v3 + v4 playbook into a single served
 * artifact `playbooks/extended.json` (one fetch, SW-cached like the launch
 * playbooks) so the live matcher can route to them and their rules can fire.
 *
 * The manifest is a flat array of the raw playbook JSON objects, sorted by
 * id for a stable diff. `tests/integration/extended-playbooks.test.ts`
 * regenerates it in-memory and fails on drift, so the committed file can
 * never fall out of sync with the source dirs.
 *
 * Run: `npm run playbooks:bundle`.
 */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");

export const EXTENDED_SOURCE_DIRS = [
  join(REPO_ROOT, "src", "playbooks", "v3"),
  join(REPO_ROOT, "src", "playbooks", "v4"),
];
export const EXTENDED_MANIFEST_PATH = join(REPO_ROOT, "playbooks", "extended.json");

/** Read every v3 + v4 playbook JSON and return them as a flat array sorted by id. */
export function collectExtendedPlaybooks(): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  for (const dir of EXTENDED_SOURCE_DIRS) {
    const names = readdirSync(dir)
      .filter((n) => n.endsWith(".json"))
      .sort();
    for (const name of names) {
      const obj = JSON.parse(readFileSync(join(dir, name), "utf8")) as Record<string, unknown>;
      const id = String(obj.id);
      if (seen.has(id)) {
        throw new Error(`duplicate playbook id "${id}" while bundling ${dir}/${name}`);
      }
      seen.add(id);
      out.push(obj);
    }
  }
  out.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return out;
}

/** Canonical JSON text for the manifest (2-space indent, trailing newline). */
export function renderManifest(playbooks: Array<Record<string, unknown>>): string {
  return JSON.stringify(playbooks, null, 2) + "\n";
}

function main(): void {
  const playbooks = collectExtendedPlaybooks();
  writeFileSync(EXTENDED_MANIFEST_PATH, renderManifest(playbooks), "utf8");
  console.log(`wrote ${playbooks.length} playbooks → ${EXTENDED_MANIFEST_PATH}`);
}

// Only run when invoked directly (not when imported by the drift test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}

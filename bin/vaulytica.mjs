#!/usr/bin/env node
/**
 * `vaulytica` CLI launcher (spec-v8 §22 — distribution surface).
 *
 * The headless engine is TypeScript run through tsx; this thin shim lets the
 * package expose a plain `vaulytica` binary (`npx vaulytica …`, a global
 * install, or the GitHub Action) without a fragile pre-bundle of the WASM/
 * worker ingest deps (pdf.js / tesseract.js / mammoth). It resolves the CLI
 * entry relative to itself, so every runtime data read (the shipped DKB and
 * the playbook JSON, resolved by `import.meta.url`) lands in the package's own
 * tree. No socket is opened — "nothing leaves your machine" holds here too.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "tools", "cli", "run.ts");

const result = spawnSync(process.execPath, ["--import", "tsx", entry, ...process.argv.slice(2)], {
  stdio: "inherit",
});

if (result.error) {
  process.stderr.write(`vaulytica: failed to launch (${result.error.message})\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);

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
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "tools", "cli", "run.ts");

/**
 * `--import tsx` is resolved by the child against ITS working directory, which
 * is the user's own — a consumer repository under the GitHub Action, or
 * wherever `npx vaulytica` was typed. `tsx` lives beside this package, so the
 * bare specifier only resolved when the two happened to coincide, and every
 * other invocation died with "Cannot find package 'tsx'". Resolve it from this
 * file instead and hand the child an absolute URL, which no working directory
 * can affect. The bare specifier stays as the fallback for an exotic install
 * layout where resolution from here fails but the child's own would not.
 */
const require = createRequire(import.meta.url);
let loader = "tsx";
try {
  loader = pathToFileURL(require.resolve("tsx")).href;
} catch {
  // Keep the bare specifier.
}

const result = spawnSync(process.execPath, ["--import", loader, entry, ...process.argv.slice(2)], {
  stdio: "inherit",
});

if (result.error) {
  process.stderr.write(`vaulytica: failed to launch (${result.error.message})\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);

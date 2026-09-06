/**
 * The caveats the terminal was the only surface not to print.
 *
 * The CLI already treats silence as a trap where a reviewer asserted a pack
 * that did not run — `--regime` on a document that classified as something
 * else warns loudly on stderr, and so do the ingest's own warnings about what
 * it could and could not read. Two caveats of exactly that kind were missing.
 *
 * **The classification notice** qualifies every finding printed above it. When
 * no family matched, the engine says so in `run.classification_notice`: "the
 * findings below may be irrelevant or misleading for a document that is not a
 * contract." The DOCX, HTML, SARIF and JSON surfaces all carry it. The
 * terminal did not — so a bread recipe analyzed at a prompt printed
 * `[generic-fallback]  1C 2W 1I` and nothing else, and the reader had no way
 * to learn the engine did not recognize what it was reading. The terminal is
 * the surface most likely to be read in a script, where nobody opens the JSON.
 *
 * **The deprecated playbook** is annotated on the DOCX cover AND in its audit
 * trail, and the JSON carries `playbook_deprecated` / `playbook_superseded_by`.
 * The terminal printed the playbook id bare — so the surface that shows the id
 * most prominently was the one that never said it was superseded.
 *
 * Both go to stderr, like every other caveat here, so stdout stays parseable.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runAnalyze } from "../../tools/cli/run.js";

const tmp = mkdtempSync(join(tmpdir(), "vaul-caveats-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/** Run the CLI, capturing stdout and stderr separately. */
async function capture(argv: string[]): Promise<{ stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => {
    err.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  try {
    await runAnalyze(argv);
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
    process.exitCode = realExit;
  }
  return { stdout: out.join(""), stderr: err.join("") };
}

/** A document that is plainly not a contract, so no family can match it. */
const RECIPE = join(tmp, "recipe.txt");
writeFileSync(
  RECIPE,
  [
    "RECIPE FOR BREAD",
    "",
    "Mix flour, water, salt and yeast. Knead for ten minutes. Prove for one hour.",
    "",
    "Bake at 220C for thirty minutes. Cool on a wire rack before slicing.",
  ].join("\n"),
);

const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "unilateral-nda.txt");

describe("the CLI prints the classification caveat", () => {
  it("warns that an unrecognized document's findings may be misleading", async () => {
    const c = await capture([RECIPE]);
    // It still reports findings — the caveat qualifies them, it does not
    // suppress them.
    expect(c.stdout).toContain("generic-fallback");
    expect(c.stderr).toContain("No known document family matched");
    expect(c.stderr).toContain("may be irrelevant or misleading");
  }, 120_000);

  it("says nothing extra when a family DID match", async () => {
    // The caveat must not become noise on the ordinary path.
    const c = await capture([NDA]);
    expect(c.stdout).not.toContain("generic-fallback");
    expect(c.stderr).not.toContain("No known document family matched");
  }, 120_000);

  it("keeps stdout parseable — every caveat goes to stderr", async () => {
    const c = await capture([RECIPE]);
    expect(c.stdout).not.toContain("vaulytica: warning:");
  }, 120_000);
});

describe("the CLI says when the playbook is deprecated", () => {
  it("names the successor", async () => {
    // `mutual-nda` is marked deprecated with `superseded_by: mutual-nda-deep`.
    const c = await capture([NDA, "--playbook", "mutual-nda"]);
    expect(c.stdout).toContain("mutual-nda");
    expect(c.stderr).toContain('playbook "mutual-nda" is deprecated');
    expect(c.stderr).toContain("superseded by mutual-nda-deep");
  }, 120_000);

  it("says nothing when the playbook is current", async () => {
    const c = await capture([NDA, "--playbook", "mutual-nda-deep"]);
    expect(c.stderr).not.toContain("is deprecated");
  }, 120_000);
});

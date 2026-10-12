/**
 * A REPEATED LIST-VALUED FLAG ADDS; it does not replace.
 *
 * 🚨 Both of the CLI's comma-separated options were ASSIGNED on each
 * occurrence, so a second flag discarded whatever the first had set — and
 * neither said a word about it:
 *
 *   --format triage-md --format triage-json   wrote only TRIAGE.json
 *   --format triage-json --format triage-md   wrote only TRIAGE.md
 *   --regime ccpa --regime gdpr               asserted only the GDPR regimes
 *
 * The documented form is comma-separated, but repeating the flag is what a
 * caller reaches for, and dropping an artifact or a whole pack of checks they
 * asked for is worse than either accepting it or refusing it. `--format`'s own
 * parser already promises, in a comment, that empty, unknown and duplicate
 * values are "never a silent no-op".
 *
 * ⚠️ The two options keep their existing tolerance for a repeat: `--format
 * md,md` was always a usage error, so `--format md --format md` is one too,
 * while `--regime gdpr,gdpr` was always accepted, so the regime union stays
 * silent. The point is that nothing is LOST, not that both behave alike.
 *
 * Each case below was verified to fail against the assignment it replaced.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const BIN = join(process.cwd(), "bin", "vaulytica.mjs");
const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const tmp = mkdtempSync(join(tmpdir(), "vaul-repeated-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/** A folder holding one named specimen, so each case reads its own input. */
function folderWith(name: string, file: string): string {
  const dir = join(tmp, name);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(SPECIMENS, file), join(dir, file));
  return dir;
}

const run = (args: string[]): { out: string; status: number | null } => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", timeout: 240_000 });
  return { out: r.stderr + r.stdout, status: r.status };
};

describe("a repeated list-valued CLI flag", { timeout: 300_000 }, () => {
  it("writes BOTH whole-run artifacts when --format is given twice", () => {
    const room = folderWith("fmt", "privacy-notice.txt");
    const out = join(tmp, "fmt-out");
    const { out: log } = run([
      "analyze",
      room,
      "--format",
      "triage-md",
      "--format",
      "triage-json",
      "--out",
      out,
    ]);
    expect(log).not.toMatch(/unknown --format/);
    // Both triage formats are whole-run artifacts with FIXED names, so a
    // dropped one leaves nothing behind for the caller to notice.
    expect(readdirSync(out).sort()).toEqual(["TRIAGE.json", "TRIAGE.md"]);
  });

  it("refuses the same --format twice across two flags, as it does within one value", () => {
    const room = folderWith("dup", "privacy-notice.txt");
    const { out, status } = run([
      "analyze",
      room,
      "--format",
      "md",
      "--format",
      "md",
      "--out",
      join(tmp, "dup-out"),
    ]);
    expect(status).not.toBe(0);
    expect(out).toMatch(/--format md given twice/);
  });

  it("asserts EVERY regime when --regime is given twice", () => {
    const room = folderWith("reg", "privacy-notice.txt");
    const out = join(tmp, "reg-out");
    run([
      "analyze",
      join(room, "privacy-notice.txt"),
      "--regime",
      "ccpa",
      "--regime",
      "gdpr",
      "--format",
      "json",
      "--out",
      out,
    ]);
    const run_ = (
      JSON.parse(readFileSync(join(out, "privacy-notice.json"), "utf8")) as {
        run: { asserted_regimes?: string[] };
      }
    ).run;
    // "gdpr" expands to the two notice-content articles; "ccpa" must survive
    // alongside them rather than being replaced by them.
    expect(run_.asserted_regimes).toEqual(["ccpa", "gdpr-13", "gdpr-14"]);
  });
});

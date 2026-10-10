/**
 * What a first-time CLI user hits (spec-v50 §6–§9), each through the real
 * launcher so the process boundary — exit code, both streams, the files on
 * disk — is what is asserted.
 *
 *  - two inputs sharing a stem wrote ONE output and reported two;
 *  - `analyze --help` was "missing argument", `verify --help` "unknown flag";
 *  - a `.zip` was refused with advice to decode it as UTF-8;
 *  - current Node printed an `ExperimentalWarning` on every run.
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync } from "fflate";
import { afterAll, describe, expect, it } from "vitest";

const REPO_ROOT = process.cwd();
const BIN = join(REPO_ROOT, "bin", "vaulytica.mjs");
const NDA = readFileSync(
  join(REPO_ROOT, "tests", "fixtures", "contracts", "pasted-mutual-nda.txt"),
);

const tmp = mkdtempSync(join(tmpdir(), "vaul-first-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function cli(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", timeout: 120_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const hashOf = (file: string): string =>
  (JSON.parse(readFileSync(file, "utf8")) as { run: { result_hash: string } }).run.result_hash;

describe("first five minutes on the command line", { timeout: 300_000 }, () => {
  it("two inputs with one stem write two files, and the count says two", () => {
    const dir = join(tmp, "same-stem");
    const out = join(tmp, "same-stem-out");
    mkdirSync(dir);
    writeFileSync(join(dir, "deal.txt"), NDA);
    writeFileSync(join(dir, "deal.md"), NDA);
    writeFileSync(join(dir, "other.txt"), NDA);
    const r = cli("analyze", dir, "--format", "json", "--out", out);
    expect(r.status).toBe(0);
    // A unique stem is named as it always was; only the shared one changes.
    expect(readdirSync(out).sort()).toEqual(["deal.md.json", "deal.txt.json", "other.json"]);
    expect(r.stderr).toContain("wrote json for 3 file(s)");
  });

  it.each(["analyze", "verify", "compare", "coherence-trend"])(
    "`%s --help` prints that command's usage and exits 0",
    (command) => {
      const r = cli(command, "--help");
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(new RegExp(`^usage:\\n {2}${command} `));
      expect(r.stderr).not.toMatch(/missing|unknown flag/);
    },
  );

  it("a .zip is read as the folder it holds, under the archive's own name", () => {
    const dir = join(tmp, "room");
    mkdirSync(join(dir, "sub"), { recursive: true });
    writeFileSync(join(dir, "nda.txt"), NDA);
    writeFileSync(join(dir, "sub", "copy.md"), NDA);
    const zip = join(tmp, "room.zip");
    writeFileSync(
      zip,
      zipSync({
        "nda.txt": NDA,
        "sub/copy.md": NDA,
        "logo.png": new Uint8Array([1, 2, 3]),
        // An entry name is untrusted: a `..` segment is never written anywhere.
        "../../escaped.txt": NDA,
      }),
    );
    const fromDir = join(tmp, "room-out");
    const fromZip = join(tmp, "zip-out");
    expect(cli("analyze", dir, "--format", "json", "--out", fromDir).status).toBe(0);
    const before = readdirSync(tmpdir()).filter((n) => n.startsWith("vaulytica-zip-")).length;
    const r = cli("analyze", zip, "--format", "json", "--out", fromZip);
    expect(r.status).toBe(0);
    // The reports mirror the archive's layout (spec-v52 §1).
    expect(readdirSync(fromZip).sort()).toEqual(["nda.json", "sub"]);
    expect(readdirSync(join(fromZip, "sub"))).toEqual(["copy.json"]);
    for (const name of [join("sub", "copy.json"), "nda.json"]) {
      expect(hashOf(join(fromZip, name))).toBe(hashOf(join(fromDir, name)));
    }
    // Paths are shown under the archive, never under the temporary folder.
    expect(r.stderr).toContain(`${zip}/sub/copy.md`);
    expect(r.stderr).not.toContain("vaulytica-zip-");
    expect(r.stderr).toMatch(/1 file\(s\) in .*room\.zip were skipped/);
    expect(readdirSync(tmp)).not.toContain("escaped.txt");
    const after = readdirSync(tmpdir()).filter((n) => n.startsWith("vaulytica-zip-")).length;
    expect(after).toBe(before);
  });

  it("refuses an archive entry that inflates past the ratio limit", () => {
    const bomb = join(tmp, "bomb.zip");
    writeFileSync(bomb, zipSync({ "big.txt": new Uint8Array(4 * 1024 * 1024) }, { level: 9 }));
    const r = cli("analyze", bomb, "--format", "json", "--out", join(tmp, "bomb-out"));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("inflates past the archive limits");
  });

  it("stderr for a clean text analysis carries only this tool's own lines", () => {
    // The warning this guards appears from Node 25 on; on Node 22 it passes
    // without the fix, so the matrix runs one leg on current Node.
    const file = join(tmp, "plain.txt");
    writeFileSync(file, NDA);
    const r = cli("analyze", file, "--format", "json");
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/ExperimentalWarning|trace-warnings/);
    expect(r.stderr).toContain("Read as plain text.");
    expect(r.stderr).not.toContain("Pasted text");
  });
});

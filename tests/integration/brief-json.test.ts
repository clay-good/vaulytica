/**
 * `--format brief-json` and the stream rules that make it usable from a pipe
 * (spec-v50 §2–§5, spec-v48 §6).
 *
 * Asserted through the launcher, over every specimen: mapping the same array
 * twice in-process would prove the projection agrees with itself, not that the
 * file a script receives agrees with the full report.
 */

import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const REPO_ROOT = process.cwd();
const BIN = join(REPO_ROOT, "bin", "vaulytica.mjs");
const SPECIMENS = join(REPO_ROOT, "tests", "fixtures", "specimens");
const NDA = join(SPECIMENS, "mutual-nda-complete.txt");

const tmp = mkdtempSync(join(tmpdir(), "vaul-brief-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function cli(
  args: string[],
  input?: Buffer,
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    input,
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

type Full = {
  run: {
    findings: Array<{ id: string }>;
    result_hash: string;
    classification_notice?: { message: string };
  };
  ingest: { warnings: string[] };
  secondary_families?: Array<{ playbook_id: string }>;
};
type BriefFile = {
  schema: string;
  findings: Array<{ id: string; excerpt?: string; start_offset: number }>;
  secondary_families?: Array<{ id: string; findings?: unknown }>;
  caveats: Record<string, unknown>;
  rules_run: number;
  result_hash: string;
};

describe("--format brief-json", { timeout: 400_000 }, () => {
  const out = join(tmp, "corpus");
  let stems: string[] = [];

  beforeAll(() => {
    const r = cli(["analyze", SPECIMENS, "--format", "json,brief-json", "--out", out]);
    expect(r.status).toBe(0);
    stems = readdirSync(out)
      .filter((n) => n.endsWith(".brief.json"))
      .map((n) => n.slice(0, -".brief.json".length));
  }, 400_000);

  const full = (stem: string): Full => JSON.parse(readFileSync(join(out, `${stem}.json`), "utf8"));
  const briefText = (stem: string): string => readFileSync(join(out, `${stem}.brief.json`), "utf8");

  it("writes a brief beside the full report for every specimen", () => {
    expect(stems.length).toBe(readdirSync(SPECIMENS).length);
    expect(stems.length).toBeGreaterThan(300);
  });

  it("carries the same findings, by id and in order, and the same result_hash", () => {
    const wrong: string[] = [];
    for (const stem of stems) {
      const f = full(stem);
      const b = JSON.parse(briefText(stem)) as BriefFile;
      const same =
        b.schema === "vaulytica.brief.v1" &&
        b.result_hash === f.run.result_hash &&
        JSON.stringify(b.findings.map((x) => x.id)) ===
          JSON.stringify(f.run.findings.map((x) => x.id));
      if (!same) wrong.push(stem);
    }
    expect(wrong).toEqual([]);
  });

  it("holds the budgets: the NDA in 8 KB, every specimen in 40,000 characters", () => {
    expect(briefText("mutual-nda-complete").length).toBeLessThanOrEqual(8 * 1024);
    const over = stems.filter((s) => briefText(s).length > 40_000);
    expect(over).toEqual([]);
    // Minified: one line, no execution log.
    expect(briefText("mutual-nda-complete")).not.toMatch(/\n.|execution_log/);
  });

  it("carries every caveat the full report carries", () => {
    const missing: string[] = [];
    let withSecondary = 0;
    for (const stem of stems) {
      const f = full(stem);
      const b = JSON.parse(briefText(stem)) as BriefFile;
      if (f.ingest.warnings.length > 0 && !Array.isArray(b.caveats.ingest_warnings)) {
        missing.push(`${stem}: ingest warnings`);
      }
      if (f.run.classification_notice && !b.caveats.classification_notice) {
        missing.push(`${stem}: classification notice`);
      }
      if (f.secondary_families?.length) {
        withSecondary++;
        // Ids and counts only, and said to be unconfirmed.
        if (!b.caveats.secondary_families) missing.push(`${stem}: secondary caveat`);
        if (b.secondary_families?.some((s) => s.findings))
          missing.push(`${stem}: secondary findings`);
        if (b.secondary_families?.length !== f.secondary_families.length) {
          missing.push(`${stem}: secondary count`);
        }
      }
      if (typeof b.caveats.not_legal_advice !== "string") missing.push(`${stem}: not legal advice`);
    }
    expect(missing).toEqual([]);
    // Anti-vacuity: the corpus exercises the conditional caveats.
    expect(withSecondary).toBeGreaterThan(100);
  });

  it("verify names a brief for what it is", () => {
    const r = cli(["verify", join(out, "mutual-nda-complete.brief.json"), NDA]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("that is a brief");
    expect(r.stderr).toContain("--format json");
  });
});

describe("pipes and renamed files", { timeout: 300_000 }, () => {
  it("stdin equals the path form, byte for byte", () => {
    const named = join(tmp, "stdin.txt");
    copyFileSync(NDA, named);
    const fromPath = cli(["analyze", named, "--format", "json"]);
    const fromStdin = cli(["analyze", "-", "--format", "json"], readFileSync(NDA));
    expect(fromStdin.status).toBe(0);
    expect(fromStdin.stdout).toBe(fromPath.stdout);
    expect(fromStdin.stderr).toMatch(/^stdin\.txt {2}\[/);
  });

  it("stdin under --out writes stdin.<format>", () => {
    const dir = join(tmp, "stdin-out");
    const r = cli(["analyze", "-", "--format", "json,md", "--out", dir], readFileSync(NDA));
    expect(r.status).toBe(0);
    expect(readdirSync(dir).sort()).toEqual(["stdin.fixlist.md", "stdin.json"]);
  });

  it.each([
    ["--delivery", ["--delivery"]],
    ["docx-comments", ["--format", "docx-comments", "--out", join(tmp, "x")]],
  ])("stdin with %s is refused with the reason", (_what, flags) => {
    const r = cli(["analyze", "-", ...flags], readFileSync(NDA));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("no container");
  });

  it("verify reproduces a renamed copy, and says it was renamed", () => {
    const original = join(tmp, "nda.txt");
    const renamed = join(tmp, "renamed-copy.txt");
    const report = join(tmp, "nda.json");
    copyFileSync(NDA, original);
    copyFileSync(NDA, renamed);
    writeFileSync(report, cli(["analyze", original, "--format", "json"]).stdout);

    const same = cli(["verify", report, original]);
    expect(same.status).toBe(0);
    expect(same.stdout).toMatch(/^✓ Reproduced\. /);

    const moved = cli(["verify", report, renamed]);
    expect(moved.status).toBe(0);
    expect(moved.stdout).toContain("✓ Reproduced (file was renamed from `nda.txt`)");

    // A genuinely different file still fails, and names the input.
    writeFileSync(renamed, readFileSync(NDA, "utf8") + "\nOne more clause.\n");
    const changed = cli(["verify", report, renamed]);
    expect(changed.status).toBe(3);
    expect(changed.stdout).toContain("the input document differs");
    expect(changed.stdout).not.toContain("determinism defect");
  });

  it.each([
    ["html", /^<!doctype html>/i],
    ["md", /^# /],
  ])("a redirected %s artifact starts with the artifact", (format, opens) => {
    const r = cli(["analyze", NDA, "--format", format]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(opens);
    expect(r.stderr).toMatch(/mutual-nda-complete\.txt {2}\[/);
  });
});

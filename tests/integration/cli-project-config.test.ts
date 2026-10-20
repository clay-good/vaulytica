/**
 * `vaulytica.config.json` through the real launcher (add-project-config-file):
 * the process boundary — exit code, both streams, the files on disk — is what
 * is asserted. The precedence of each key is `tools/cli/config.test.ts`.
 *
 * The property that matters most: a configuration file changes WHICH settings
 * a run uses and nothing else. A report produced under a file is the report the
 * equivalent flags produce, plus one `config` block naming the file.
 */
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const BIN = join(process.cwd(), "bin", "vaulytica.mjs");
const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-complete.txt");
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "vaul-project-config-")));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function cli(cwd: string, ...args: string[]) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 240_000,
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** A repository folder with a configuration, a vendor DPA, and a draft. */
function project(name: string, config: unknown): string {
  const dir = join(tmp, name);
  mkdirSync(join(dir, ".git"), { recursive: true });
  mkdirSync(join(dir, "vendors", "acme"), { recursive: true });
  mkdirSync(join(dir, "drafts"), { recursive: true });
  copyFileSync(NDA, join(dir, "vendors", "acme", "dpa-acme.txt"));
  copyFileSync(NDA, join(dir, "drafts", "v1.txt"));
  if (config !== undefined) {
    writeFileSync(join(dir, "vaulytica.config.json"), JSON.stringify(config, null, 2));
  }
  return dir;
}

const CONFIG = {
  document_types: { "vendors/**/dpa-*.txt": "dpa-controller-processor" },
  exclude: ["drafts/**"],
  fail_on: "critical",
};

describe("a project configuration file, end to end", { timeout: 300_000 }, () => {
  it("applies document_types, exclude and fail_on, and says so", () => {
    const dir = project("applies", CONFIG);
    const out = join(tmp, "applies-out");
    const r = cli(dir, "analyze", ".", "--format", "brief-json", "--out", out);
    // fail_on: critical, and the DPA checklist finds criticals in an NDA.
    expect(r.status).toBe(2);
    expect(r.stderr).toContain(
      "vaulytica: config vaulytica.config.json applied: document_types, exclude, fail_on\n",
    );
    expect(r.stderr).toContain("1 file(s) not analyzed: excluded by vaulytica.config.json");
    // The tool's own file is not a document it skipped.
    expect(r.stderr).not.toMatch(/vaulytica\.config\.json \(unsupported file type\)/);
    expect(existsSync(join(out, "drafts"))).toBe(false);
    const brief = JSON.parse(
      readFileSync(join(out, "vendors", "acme", "dpa-acme.brief.json"), "utf8"),
    ) as { document: { type: string }; config: { path: string; applied: string[] } };
    expect(brief.document.type).toBe("dpa-controller-processor");
    // Relative to the input as given (here the folder), never absolute.
    expect(brief.config.path).toBe("vaulytica.config.json");
    expect(brief.config.applied).toEqual(["document_types", "exclude", "fail_on"]);
  });

  it("applies the same when the folder is named by a path that is not its real path", () => {
    // Windows names the runner's temp folder C:\\Users\\RUNNER~1, and realpath
    // expands it to the long name. The file was located by its REAL path and
    // the inputs by the path as given, so no glob matched and the file's path
    // printed as a climb out of the folder (the cross-OS matrix, 9.954.0). A
    // symlink is the same condition on any OS: the folder is named here
    // through a link, from another working directory.
    const real = project("linked-real", CONFIG);
    const link = join(tmp, "linked-alias");
    symlinkSync(real, link, "junction");
    const out = join(tmp, "linked-out");
    const r = cli(tmp, "analyze", link, "--format", "brief-json", "--out", out);
    expect(r.stderr).toContain("applied: document_types, exclude, fail_on");
    const brief = JSON.parse(
      readFileSync(join(out, "vendors", "acme", "dpa-acme.brief.json"), "utf8"),
    ) as { document: { type: string }; config: { path: string } };
    expect(brief.document.type).toBe("dpa-controller-processor");
    expect(brief.config.path).toBe("vaulytica.config.json");
  });

  it("produces the report the equivalent flags produce, plus a config block", () => {
    const withFile = project("same-report", CONFIG);
    const without = project("same-report-flags", undefined);
    const doc = join("vendors", "acme", "dpa-acme.txt");
    const a = cli(withFile, "analyze", doc, "--format", "json");
    const b = cli(
      without,
      "analyze",
      doc,
      "--format",
      "json",
      "--playbook",
      "dpa-controller-processor",
    );
    const ja = JSON.parse(a.stdout) as Record<string, unknown> & { run: { result_hash: string } };
    const jb = JSON.parse(b.stdout) as Record<string, unknown> & { run: { result_hash: string } };
    expect(ja.run.result_hash).toBe(jb.run.result_hash);
    expect(ja.config).toMatchObject({ path: "../../vaulytica.config.json" });
    const { config: _c, ...rest } = ja;
    expect(JSON.stringify(rest, null, 2)).toBe(b.stdout.trimEnd());
    // And the report still verifies.
    const saved = join(tmp, "same-report.json");
    writeFileSync(saved, a.stdout);
    const v = cli(withFile, "verify", saved, doc, "--playbook", "dpa-controller-processor");
    expect(v.status, v.stderr + v.stdout).toBe(0);
    expect(v.stdout + v.stderr).toContain("Reproduced");
  });

  it("an explicit flag wins and is reported as an override", () => {
    const dir = project("flag-wins", CONFIG);
    const r = cli(
      dir,
      "analyze",
      join("vendors", "acme", "dpa-acme.txt"),
      "--format",
      "brief-json",
      "--fail-on",
      "warning",
      "--playbook",
      "mutual-nda-deep",
    );
    expect(r.stderr).toContain("overridden by flags: document_types, fail_on");
    const brief = JSON.parse(r.stdout) as { document: { type: string } };
    expect(brief.document.type).toBe("mutual-nda-deep");
  });

  it("a typo fails the run, naming the key, and writes nothing", () => {
    const dir = project("typo", { "fail-on": "critical" });
    const r = cli(dir, "analyze", join("vendors", "acme", "dpa-acme.txt"), "--format", "json");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('unknown key "fail-on"');
    expect(r.stdout).toBe("");
  });

  it("refuses a playbook_file outside the folder", () => {
    const dir = project("escape", { playbook_file: "../../secrets/team.json" });
    const r = cli(dir, "analyze", join("vendors", "acme", "dpa-acme.txt"));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/playbook_file "\.\.\/\.\.\/secrets\/team\.json" resolves outside/);
  });

  it("init writes an example the next run applies, and never replaces one without --force", () => {
    const dir = project("init", undefined);
    const first = cli(dir, "init");
    expect(first.status).toBe(0);
    expect(existsSync(join(dir, "vaulytica.config.json"))).toBe(true);
    const again = cli(dir, "init");
    expect(again.status).toBe(1);
    expect(again.stderr).toContain("already exists");
    expect(cli(dir, "init", "--force").status).toBe(0);
    const run = cli(dir, "analyze", join("vendors", "acme", "dpa-acme.txt"), "--format", "json");
    expect(run.stderr).toMatch(/^vaulytica: config \.\.\/\.\.\/vaulytica\.config\.json applied: /m);
  });
});

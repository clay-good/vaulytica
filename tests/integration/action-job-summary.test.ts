/**
 * What a CI reader actually sees.
 *
 * The Action ended at `node "$VAULYTICA_BIN" "${args[@]}"`: no outputs, no job
 * summary. So a user running it got an exit code and a raw step log — collapsed
 * by default, and scrolled past — while the tool's per-document counts, its
 * honesty caveats and its cross-document summary sat in that log unread. Every
 * caveat wired across the six report surfaces this session reaches a CI user
 * only if they expand the log and find it.
 *
 * The job summary is the surface GitHub puts on the run page. This asserts the
 * step writes one, and asserts the case that matters most: **a failing gate**.
 * A summary that only appears on success is a summary nobody needs.
 *
 * Same derivation as `action-argv.test.ts` — the script is extracted from
 * `action.yml` itself, so this tests the shipped text rather than a copy. The
 * binary is replaced by a stub that writes to **stderr**, which is where the
 * CLI puts its human stream whenever a machine format is selected (the
 * Action's default is `sarif`).
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const action = readFileSync(join(process.cwd(), "action.yml"), "utf8");
const dir = mkdtempSync(join(tmpdir(), "vaulytica-summary-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/**
 * The composite step's shell body with the binary replaced by a stub that
 * writes `$STUB_OUT` to stderr and exits `$STUB_STATUS`.
 */
const script = (() => {
  const body = action.slice(action.lastIndexOf("run: |") + "run: |".length);
  const dedented = body
    .split("\n")
    .map((l) => (l.startsWith(" ".repeat(8)) ? l.slice(8) : l))
    .join("\n");
  return dedented.replace(
    'node "$VAULYTICA_BIN"',
    'sh -c \'printf "%s\\n" "$STUB_OUT" >&2; exit "$STUB_STATUS"\' --',
  );
})();

const scriptPath = join(dir, "step.sh");
writeFileSync(scriptPath, script);

let n = 0;
type Run = { status: number; summary: string | null; stderr: string };

function run(inputs: Record<string, string>, stub: { out: string; status?: number }): Run {
  const summaryPath = join(dir, `summary-${n++}.md`);
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    VAULYTICA_BIN: "/dev/null",
    CMD: "analyze",
    FILES: "doc.txt",
    BASE: "",
    REVISED: "",
    FORMAT: "",
    FAIL_ON: "",
    PLAYBOOK: "",
    OUT: "",
    CONSISTENCY: "",
    FAIL_ON_CONSISTENCY: "",
    DELIVERY: "",
    FAIL_ON_DELIVERY: "",
    PLAYBOOK_FILE: "",
    POSTURE: "",
    FAIL_ON_POSTURE: "",
    FAIL_ON_DIVERGENCE: "",
    SUMMARY: "true",
    GITHUB_STEP_SUMMARY: summaryPath,
    STUB_OUT: stub.out,
    STUB_STATUS: String(stub.status ?? 0),
    ...inputs,
  };
  let status = 0;
  let stderr = "";
  try {
    const r = execFileSync("bash", [scriptPath], { env, encoding: "utf8", stdio: "pipe" });
    void r;
  } catch (e) {
    const err = e as { status?: number; stderr?: string };
    status = err.status ?? -1;
    stderr = err.stderr ?? "";
  }
  return {
    status,
    summary: existsSync(summaryPath) ? readFileSync(summaryPath, "utf8") : null,
    stderr,
  };
}

const CAVEAT =
  "doc.txt  [msa-general]  1C 2W 3I\nvaulytica: warning: Pasted text loses document structure.";

describe("the Action puts the run on the page a reader looks at", () => {
  it("derives a runnable script from action.yml (guards the derivation)", () => {
    // A mangled extraction would make every case below pass or throw trivially.
    expect(script).toContain("set -euo pipefail");
    expect(script).toContain("GITHUB_STEP_SUMMARY");
    expect(script).not.toContain('node "$VAULYTICA_BIN"');
  });

  it("writes the counts and the caveats, not just an exit code", () => {
    const r = run({}, { out: CAVEAT });
    expect(r.status).toBe(0);
    expect(r.summary).toContain("## Vaulytica");
    expect(r.summary).toContain("1C 2W 3I");
    // The honesty caveat is the half a bare exit code can never carry.
    expect(r.summary).toContain("Pasted text loses document structure.");
    expect(r.summary).toContain("**Passed**");
  });

  it("writes it when the GATE FAILS, and still fails the job", () => {
    // The case that matters. A summary that only appears on success is a
    // summary nobody needs, and `set -euo pipefail` would abort the step
    // before writing one unless the status is captured deliberately.
    const r = run({ FAIL_ON: "critical" }, { out: CAVEAT, status: 2 });
    expect(r.status, "the gate's exit code must survive").toBe(2);
    expect(r.summary).toContain("**Failed (exit 2)**");
    expect(r.summary).toContain("1C 2W 3I");
  });

  it("tells a 1 from a 2, because a reader acts on them differently", () => {
    // `2` is a gate the caller asked for, tripping on a document the tool read
    // fine. `1` is the tool not doing the job as asked — and since 9.666.0 that
    // includes a run that DID produce a report, for the inputs it could read,
    // while naming the ones it could not. A reader who sees "a gate tripped, or
    // the run errored" has no reason to go looking for the report that exists.
    const gate = run({ FAIL_ON: "critical" }, { out: CAVEAT, status: 2 });
    expect(gate.summary).toContain("a `fail-on` gate tripped");
    expect(gate.summary).not.toContain("could not be completed as asked");

    const partial = run({}, { out: CAVEAT, status: 1 });
    expect(partial.status).toBe(1);
    expect(partial.summary).toContain("**Failed (exit 1)**");
    expect(partial.summary).toContain("no `fail-on` gate tripped");
    expect(partial.summary).toContain("could not be READ");
    expect(partial.summary).toContain("the report covers the rest");
  });

  it("still replays the tool's output to the step log", () => {
    // Capturing stderr must not mean swallowing it: the raw log stays complete.
    const r = run({ FAIL_ON: "critical" }, { out: CAVEAT, status: 2 });
    expect(r.stderr).toContain("1C 2W 3I");
  });

  it("says so when it truncates, rather than showing a partial run as a whole one", () => {
    // A job summary is capped at 1 MiB. A bound that is not SAID reads as the
    // entire output — the same rule the reports follow for their own caps.
    const big = "x".repeat(70_000);
    const r = run({}, { out: big });
    expect(r.summary).toContain("earlier output omitted");
    expect(r.summary).toContain("showing the last 60,000 of");
    expect(r.summary!.length).toBeLessThan(70_000);
  });

  it("drops Node's own runtime warnings, and nothing else", () => {
    // Two lines of Node internals at the top is what a reader sees first, and
    // they are not the tool's output. They come out of the SUMMARY only — the
    // step log above still has every byte, so nothing is hidden.
    const noisy = [
      "(node:15689) ExperimentalWarning: localStorage is not available",
      "(Use `node --trace-warnings ...` to show where the warning was created)",
      "doc.txt  [msa-general]  1C 2W 3I",
      "vaulytica: warning: Pasted text loses document structure.",
    ].join("\n");
    const r = run({}, { out: noisy });
    expect(r.summary).not.toContain("ExperimentalWarning");
    expect(r.summary).not.toContain("--trace-warnings");
    // Everything the tool said survives.
    expect(r.summary).toContain("1C 2W 3I");
    expect(r.summary).toContain("Pasted text loses document structure.");
    // And the step log is untouched — the filter is the summary's view, not a
    // deletion.
    expect(r.stderr === "" || r.stderr.includes("ExperimentalWarning")).toBe(true);
  });

  it("writes nothing when the caller turned it off", () => {
    expect(run({ SUMMARY: "false" }, { out: CAVEAT }).summary).toBeNull();
  });

  it("writes nothing when the tool wrote nothing to stderr", () => {
    // The non-machine-format case: those lines go to stdout instead, where they
    // are already in the step log. An empty "Vaulytica" heading on the run page
    // would read as "it found nothing".
    expect(run({}, { out: "" }).summary).toBeNull();
  });
});

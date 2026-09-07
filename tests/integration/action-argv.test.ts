/**
 * What the Action actually runs.
 *
 * `action-input-reach.test.ts` asserts the two halves of `action.yml` are
 * WIRED — every declared input is exported and every exported name is read.
 * This one asserts they are wired CORRECTLY: given a set of inputs, what argv
 * does the composite step hand the binary?
 *
 * The distinction matters because the wiring test passes for a script that
 * reads `$CONSISTENCY` and appends the wrong flag, appends it to `compare`
 * (which has no bundle and would reject it), or drops it when a sibling input
 * is also set. Those are the mistakes a shell script written in YAML actually
 * makes, and none of them is visible to a reader.
 *
 * The script is extracted from `action.yml` itself and run with the binary
 * replaced by `echo`, so this tests the shipped text rather than a copy of it.
 * No network, no npm install, no engine — just argv.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const action = readFileSync(join(process.cwd(), "action.yml"), "utf8");
const dir = mkdtempSync(join(tmpdir(), "vaulytica-action-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** The composite step's shell body, with the binary call replaced by an echo. */
const script = (() => {
  const body = action.slice(action.lastIndexOf("run: |") + "run: |".length);
  const dedented = body
    .split("\n")
    .map((l) => (l.startsWith(" ".repeat(8)) ? l.slice(8) : l))
    .join("\n");
  return dedented.replace('node "$VAULYTICA_BIN"', "echo ARGV:");
})();

const scriptPath = join(dir, "step.sh");
writeFileSync(scriptPath, script);

/** Run the step with these inputs and return the argv line it would execute. */
function argv(inputs: Record<string, string>): string {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    VAULYTICA_BIN: "/dev/null",
    CMD: "analyze",
    FILES: "",
    BASE: "",
    REVISED: "",
    FORMAT: "",
    FAIL_ON: "",
    PLAYBOOK: "",
    OUT: "",
    CONSISTENCY: "",
    FAIL_ON_CONSISTENCY: "",
    ...inputs,
  };
  const out = execFileSync("bash", [scriptPath], { env, encoding: "utf8" });
  const line = out.split("\n").find((l) => l.startsWith("ARGV:"));
  if (!line) throw new Error(`no argv line in step output:\n${out}`);
  return line.slice("ARGV:".length).trim();
}

describe("the Action composes the argv it advertises", () => {
  it("derives a runnable script from action.yml (guards the derivation)", () => {
    // A mangled extraction would make every case below throw or pass trivially.
    expect(script).toContain("set -euo pipefail");
    expect(script).toContain("echo ARGV:");
    expect(argv({ FILES: "contracts/" })).toContain("analyze contracts/");
  });

  it("defaults analyze to sarif and passes the ordinary inputs through", () => {
    expect(argv({ FILES: "contracts/", OUT: "out", FAIL_ON: "critical" })).toBe(
      "analyze contracts/ --format sarif --fail-on critical --out out",
    );
  });

  it("adds --consistency when asked to report, without gating", () => {
    expect(argv({ FILES: "deal/", CONSISTENCY: "true" })).toContain("--consistency");
    expect(argv({ FILES: "deal/", CONSISTENCY: "true" })).not.toContain("--fail-on-consistency");
  });

  it("passes --fail-on-consistency alone, since the flag implies the pass", () => {
    // Both set must not produce both flags: the CLI infers the pass from the
    // gate, and a duplicate would be noise in the echoed command a user reads.
    const both = argv({ FILES: "deal/", CONSISTENCY: "true", FAIL_ON_CONSISTENCY: "critical" });
    expect(both).toContain("--fail-on-consistency critical");
    expect(both).not.toMatch(/--consistency(?!\S)/);
  });

  it("maps consistency: only to the bundle-only flag", () => {
    const line = argv({ FILES: "deal/", CONSISTENCY: "only" });
    expect(line).toContain("--consistency-only");
    expect(line).not.toMatch(/--consistency(?!-only)/);
  });

  it("treats anything but the literal 'true' as not asserted", () => {
    // A YAML input is a string. "false", "no", "" must all mean off, or a
    // workflow that writes `consistency: false` gets the opposite.
    for (const v of ["false", "no", "0", ""]) {
      expect(argv({ FILES: "deal/", CONSISTENCY: v }), `consistency: ${v}`).not.toContain(
        "--consistency",
      );
    }
  });

  it("never sends the bundle flags to compare, which has no bundle", () => {
    const line = argv({
      CMD: "compare",
      BASE: "a.docx",
      REVISED: "b.docx",
      CONSISTENCY: "true",
      FAIL_ON_CONSISTENCY: "critical",
      OUT: "out",
    });
    expect(line).toBe("compare a.docx b.docx");
  });

  it("leaves compare's format alone so each command applies its own default", () => {
    // sarif is the analyze default and compare rejects it outright; passing it
    // through used to fail every compare run.
    expect(argv({ CMD: "compare", BASE: "a.docx", REVISED: "b.docx" })).not.toContain("--format");
  });

  it("fails loudly when a required input is missing", () => {
    expect(() => argv({ FILES: "" })).toThrow();
    expect(() => argv({ CMD: "compare", BASE: "a.docx", REVISED: "" })).toThrow();
  });
});

/**
 * The docs name every gate `analyze` has.
 *
 * A CI consumer branches on the exit code, so `docs/ci-integration.md`'s
 * exit-code paragraph is a contract: `2` means "a gate you asked for was
 * breached", `1` means "you used the tool wrong", `3` and `4` belong to
 * `verify`. `analyze` has grown from one gate to seven — `--fail-on`,
 * `--fail-on-divergence`, `--fail-on-coherence-regression`,
 * `--fail-on-production-gap`, `--fail-on-consistency`, `--fail-on-delivery`,
 * `--fail-on-posture` — each arriving in its own change, and the paragraph did
 * not keep up: it described `--fail-on` alone, and `--fail-on-production-gap`
 * was named nowhere in that file at all.
 *
 * That each gate exits **2** is asserted where it can be asserted honestly —
 * by running it, in `tools/cli/run.test.ts`, one test per flag. An earlier
 * version of this file tried to prove it by reading `run.ts` for
 * `process.exitCode` near a message, and twice accused the tool of breaching
 * with code 1 when what it had actually matched was the *usage* error for the
 * same flag, which correctly exits 1. Reading source for a runtime property is
 * how a guard invents a defect; this file sticks to the claim it can check.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (...p: string[]): string => readFileSync(join(root, ...p), "utf8");
const runSource = read("tools", "cli", "run.ts");
const ciDoc = read("docs", "ci-integration.md");
const actionYml = read("action.yml");
const readme = read("README.md");

/** The `--fail-on*` flags `analyze` actually parses. */
function gateFlags(): string[] {
  const body = runSource.slice(runSource.indexOf("function parseArgs("));
  return [
    ...new Set([...body.matchAll(/case "(--fail-on[a-z0-9-]*)":/g)].map((m) => m[1]!)),
  ].sort();
}

describe("the analyze gate surface", () => {
  it("derives a plausible surface (guards the derivation itself)", () => {
    // An empty list would make both assertions below vacuously true.
    const flags = gateFlags();
    expect(flags).toContain("--fail-on");
    expect(flags).toContain("--fail-on-posture");
    expect(flags.length).toBeGreaterThanOrEqual(7);
  });

  it("names every gate in the CI guide's exit-code guidance", () => {
    // Scoped to the PARAGRAPH, not the file. Checking the whole document made
    // the test pass when the `--fail-on-posture` row was deleted, because the
    // flag is also mentioned in a recipe further up — a guard whose name
    // promises more than it checks. Verified by deleting that row: it fails.
    const start = ciDoc.indexOf("Exit codes are CI-meaningful");
    const end = ciDoc.indexOf("Each gate is a **separate flag on purpose**", start);
    expect(start, "the exit-code paragraph moved or was retitled").toBeGreaterThan(0);
    expect(end, "the exit-code section's closing paragraph moved").toBeGreaterThan(start);
    const guidance = ciDoc.slice(start, end);
    const missing = gateFlags().filter((f) => !guidance.includes(f));
    expect(
      missing,
      `docs/ci-integration.md's exit-code guidance omits these gates, so a reader branching on exit codes cannot learn they exist:\n  ${missing.join(
        "\n  ",
      )}`,
    ).toEqual([]);
  });

  it("makes every gate reachable from the Action, which is the CI surface", () => {
    // The Action is how most CI consumers call this tool, and its input surface
    // is deliberately small — but a GATE that CI cannot switch on is a gate CI
    // does not have. Three were unreachable until 9.550.0: the pre-disclosure
    // scan's, and both halves of the team-ladder one.
    //
    // The mapping is the flag name without its `--`, which is how every input
    // here is named; a gate that needs a differently-named input can be listed
    // as an exception with the reason, and the assertion will say so.
    // Declared, with the reason, and asserted USED below so a stale entry
    // fails here rather than quietly covering a gate that has since arrived.
    const NEEDS_A_MODE_THE_ACTION_DOES_NOT_EXPOSE = new Map([
      [
        "fail-on-coherence-regression",
        "needs a BASELINE round — a second set of documents, or a saved coherence artifact — which the Action's single `files` input does not model",
      ],
      [
        "fail-on-production-gap",
        "belongs to `--production-qa`, a different mode: a Bates/privilege-log sweep over a production set rather than per-document analysis",
      ],
    ]);
    const exposes = (name: string): boolean => new RegExp(`^\\s{2}${name}:`, "m").test(actionYml);
    const missing = gateFlags()
      .map((f) => f.replace(/^--/, ""))
      .filter((name) => !exposes(name) && !NEEDS_A_MODE_THE_ACTION_DOES_NOT_EXPOSE.has(name));
    for (const [name, why] of NEEDS_A_MODE_THE_ACTION_DOES_NOT_EXPOSE) {
      expect(
        exposes(name),
        `declared exception "${name}" (${why}) is exposed now — delete the entry`,
      ).toBe(false);
    }
    expect(
      missing,
      `action.yml exposes no input for these gates, so a workflow cannot switch them on:\n  ${missing.join(
        "\n  ",
      )}`,
    ).toEqual([]);
  });

  it("documents every gate in the README's flag table too", () => {
    const missing = gateFlags().filter((f) => !readme.includes(f));
    expect(missing, `README omits: ${missing.join(", ")}`).toEqual([]);
  });
});

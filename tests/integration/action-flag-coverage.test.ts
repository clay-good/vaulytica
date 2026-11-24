/**
 * The OTHER direction: can the Action reach what the CLI can do?
 *
 * `action-input-reach.test.ts` asks whether every input `action.yml` DECLARES
 * is wired to a flag — a gap that silently drops a setting the caller asked
 * for. It is one-sided. It passes just as happily on an `action.yml` that
 * declares three inputs and leaves the other thirty-five analyze options with
 * no CI path at all, which is the shape this repository has shipped before:
 * `--fail-on-production-gap` existed, was documented, and had its own comment
 * saying it was "for a CI check before a production goes out" — and the
 * Action, which IS that CI check, could not switch it on for five months.
 *
 * The GitHub Action is the only surface a CI consumer has. A flag it cannot
 * reach is a capability that does not exist for them, however well it works
 * on a laptop. So this guard asserts the inverse: every flag the `analyze`
 * and `compare` parsers accept is either reachable through a declared input,
 * or named below with a written reason it is not. A new flag fails here until
 * it is wired or classified — the choice is recorded either way, never left
 * to whoever reads the parser next.
 *
 * ⚠️ `cli-exit-code-contract.test.ts` already asks this question for the GATE
 * flags, and keeps its own declared-exception list with a different rule (the
 * input must be named after the flag). Keep it: it also checks that each gate
 * is named in the CI guide's exit-code paragraph and in the README's table,
 * which this guard does not. What this one adds is the other 42 flags — the
 * assertions, the registers, the emit paths and the comparison modes, none of
 * which is a gate and none of which was covered.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (...p: string[]): string => readFileSync(join(root, ...p), "utf8");

const action = read("action.yml");
const runSource = read("tools", "cli", "run.ts");
const compareSource = read("tools", "cli", "compare.ts");

/**
 * Flags the Action deliberately does not expose, each with the reason.
 *
 * A short list by design. "Nobody asked for it" is not a reason — the entry
 * has to say why a CI consumer should not have it.
 */
const OUT_OF_SCOPE: Record<string, string> = {
  "--help":
    "prints usage and exits; a workflow input that makes the step do nothing is not a setting.",
  "--dkb":
    "points the engine at a different knowledge base. The Action installs and ships its own DKB, and its no-network guarantee rests on that being the one it reads; letting a workflow swap it would make the run's authority unverifiable from the outside.",
};

/** The flags a parser's `switch` accepts. */
function parsedFlags(source: string, from: string): string[] {
  const body = source.slice(source.indexOf(from));
  const flags = [...new Set([...body.matchAll(/case "(--[a-z0-9-]+)":/g)].map((m) => m[1]!))];
  if (flags.length === 0) throw new Error(`no flags parsed out of ${from}`);
  return flags.sort();
}

const analyzeFlags = (): string[] => parsedFlags(runSource, "function parseArgs(");
const compareFlags = (): string[] => parsedFlags(compareSource, "export");

/** Everything after `run: |` — the script that assembles the argument list. */
const script = (): string => action.slice(action.lastIndexOf("run: |"));

/**
 * Does the step's script ever append this flag?
 *
 * The flag has to appear as a whole word: a bare `includes("--consistency")`
 * is satisfied by `--consistency-only`, which would report a flag as reachable
 * because a LONGER one is.
 */
function reachable(flag: string): boolean {
  return new RegExp(`${flag.replace(/-/g, "\\-")}(?![a-z0-9-])`).test(script());
}

describe("action.yml flag coverage", () => {
  it("derives a plausible surface (guards the derivations themselves)", () => {
    // Empty derivations would make every assertion below vacuously true.
    expect(analyzeFlags().length).toBeGreaterThan(30);
    expect(compareFlags().length).toBeGreaterThan(10);
    expect(analyzeFlags()).toContain("--fail-on");
    expect(reachable("--fail-on")).toBe(true);
    // The whole-word rule is the point of the matcher, so pin it.
    expect(reachable("--consistency")).toBe(true);
    expect(reachable("--definitely-not-a-flag")).toBe(false);
  });

  it("gives every analyze flag a CI path, or a written reason it has none", () => {
    const orphans = analyzeFlags().filter((f) => !reachable(f) && !(f in OUT_OF_SCOPE));
    expect(
      orphans,
      `analyze accepts these and no Action input reaches them — wire them in action.yml, or add each to OUT_OF_SCOPE with the reason:\n  ${orphans.join("\n  ")}`,
    ).toEqual([]);
  });

  it("gives every compare flag a CI path, or a written reason it has none", () => {
    const orphans = compareFlags().filter((f) => !reachable(f) && !(f in OUT_OF_SCOPE));
    expect(
      orphans,
      `compare accepts these and no Action input reaches them — wire them in action.yml, or add each to OUT_OF_SCOPE with the reason:\n  ${orphans.join("\n  ")}`,
    ).toEqual([]);
  });

  it("keeps the exception list honest: every entry is a real flag, still unreachable", () => {
    const parsed = new Set([...analyzeFlags(), ...compareFlags()]);
    for (const [flag, reason] of Object.entries(OUT_OF_SCOPE)) {
      expect(parsed.has(flag), `OUT_OF_SCOPE names ${flag}, which no parser accepts`).toBe(true);
      expect(
        reachable(flag),
        `${flag} is listed as out of scope but action.yml now passes it — delete the entry`,
      ).toBe(false);
      // A reason has to be an argument, not a shrug.
      expect(reason.length, `the reason for ${flag} is too short to be one`).toBeGreaterThan(40);
    }
  });
});

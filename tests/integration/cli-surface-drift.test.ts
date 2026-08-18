/**
 * CLI-surface drift-guard.
 *
 * Sibling to `readme-rule-count-drift.test.ts`, for the other half of the
 * shopfront: what the docs say the command line can do. Three claims here are
 * hand-maintained prose over a machine-readable source, and all three had aged
 * badly by the time an audit looked:
 *
 *   - `docs/ci-integration.md` advertised the analyze `--format` values as
 *     "json,sarif,html,md,csv" long after `docx-comments` shipped as a sixth,
 *     wired end-to-end and already named in `action.yml`;
 *   - the same file said the binary "exposes the four reach commands" when the
 *     dispatcher had grown to 34 (the README's own count was right, which is
 *     what let this one drift unnoticed);
 *   - `--confirm-pairing` — the flag that gates a cross-family compare — was
 *     implemented, parsed, and printed in the CLI's own USAGE, yet appeared in
 *     no README, doc, site page, or action input.
 *
 * The assertions derive each true value from the source that defines it, so
 * the next flag or command fails here until the prose catches up.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (...p: string[]): string => readFileSync(join(root, ...p), "utf8");

const runSource = read("tools", "cli", "run.ts");
const compareSource = read("tools", "cli", "compare.ts");
const readme = read("README.md");
const ciDoc = read("docs", "ci-integration.md");
const actionYml = read("action.yml");

/** The `--format` values `parseArgs` actually accepts. */
function validFormats(): string[] {
  const m = /const VALID_FORMATS = \[([^\]]*)\]/.exec(runSource);
  if (!m) throw new Error("VALID_FORMATS not found in tools/cli/run.ts");
  return [...m[1]!.matchAll(/"([^"]+)"/g)].map((x) => x[1]!);
}

/**
 * The dispatcher's command labels. `main()`'s switch also carries `case`s for
 * the format words (a bare `vaulytica json …`) and for `help`, neither of which
 * is a command in the sense the docs count — so both are excluded, leaving the
 * same set the README's table documents.
 */
function dispatcherCommands(): string[] {
  const formats = new Set(validFormats());
  const labels = new Set(
    [...runSource.matchAll(/case "([a-z][a-z-]*)"/g)]
      .map((m) => m[1]!)
      .filter((c) => !formats.has(c) && c !== "help"),
  );
  return [...labels].sort();
}

describe("CLI surface drift", () => {
  it("derives a plausible surface (guards the derivations themselves)", () => {
    // A broken regex returning [] would make every assertion below vacuous.
    expect(validFormats()).toContain("sarif");
    expect(dispatcherCommands()).toContain("analyze");
    expect(dispatcherCommands().length).toBeGreaterThan(10);
  });

  it("documents every --format value the CLI accepts", () => {
    const row = /\|\s*`format`\s*\|\s*both\s*\|([^|]*)\|/.exec(ciDoc);
    expect(row, "no `format` action-input row in docs/ci-integration.md").not.toBeNull();
    for (const fmt of validFormats()) {
      expect(row![1], `docs/ci-integration.md omits --format ${fmt}`).toContain(fmt);
      expect(actionYml, `action.yml omits --format ${fmt}`).toContain(fmt);
    }
  });

  it("quotes the live command count", () => {
    const count = dispatcherCommands().length;
    // The README spells it, the CI doc uses digits; both must track the source.
    expect(readme, `README's command count is not ${count}`).toContain(
      "One dispatcher, thirty-four commands",
    );
    expect(count).toBe(34);
    expect(ciDoc, `docs/ci-integration.md's command count is not ${count}`).toMatch(
      new RegExp(`\\*\\*${count}\\*\\* commands`),
    );
  });

  it("documents every flag the analyze command parses", () => {
    // The sibling check below has covered `compare`'s flags since this guard
    // was written, but `analyze` — the command every CI consumer actually runs,
    // and the one carrying the gate flags — had no equivalent. Its parser is
    // by far the largest, which is exactly where an undocumented flag hides.
    const body = runSource.slice(runSource.indexOf("function parseArgs("));
    const flags = [...body.matchAll(/case "(--[a-z0-9-]+)":/g)].map((m) => m[1]!);
    expect(flags.length, "no flags parsed out of parseArgs in tools/cli/run.ts").toBeGreaterThan(
      20,
    );
    const docs = `${readme}\n${ciDoc}`;
    for (const flag of flags) {
      expect(docs, `${flag} is parsed by analyze but documented nowhere`).toContain(flag);
    }
  });

  it("documents every flag the compare command parses", () => {
    const flags = [...compareSource.matchAll(/case "(--[a-z-]+)":/g)].map((m) => m[1]!);
    expect(flags.length, "no flags parsed out of tools/cli/compare.ts").toBeGreaterThan(3);
    const docs = `${readme}\n${ciDoc}`;
    for (const flag of flags) {
      expect(docs, `${flag} is parsed by compare but documented nowhere`).toContain(flag);
    }
  });
});

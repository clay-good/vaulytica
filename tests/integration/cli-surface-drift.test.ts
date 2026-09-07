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

import { readFileSync, readdirSync } from "node:fs";
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
  // Strip line comments first. The array carries explanatory comments, and a
  // quoted phrase inside one used to be read as a format value — so adding a
  // comment to the array made this guard demand that the docs advertise a
  // sentence. The failure names a plausible-looking format and points at the
  // docs, which is the wrong place to look.
  const body = m[1]!.replace(/\/\/[^\n]*/g, "");
  return [...body.matchAll(/"([^"]+)"/g)].map((x) => x[1]!);
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

  /**
   * The badge's export-format count, derived rather than remembered.
   *
   * It read "10 export formats" for a long time and nothing checked it. The
   * number is now the CLI's own `VALID_FORMATS.length`, which is a defensible
   * definition of "what this tool can emit" precisely because
   * `export-reach.test.ts` holds every report builder the browser can reach to
   * being reachable here too.
   */
  it("quotes the live export-format count in the badge line", () => {
    const n = validFormats().length;
    expect(readme, `the badge's export-format count is not ${n}`).toContain(
      `\`${n} export formats\``,
    );
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

  /**
   * The other direction, which is the one that hurts a reader.
   *
   * The check above asks "is every flag the CLI parses documented?" — a
   * documentation gap. This one asks "is every flag the documentation shows
   * actually parsed?" — a reader copying a command out of the README and
   * getting `unknown flag`. Nothing covered it, and a rename that updated the
   * parser and not the prose would have looked green from both sides.
   *
   * ⚠️ The parsers are written two ways and both must be read: `analyze` and
   * `compare` use `switch (flag) { case "--x": }`, and the 28 `coherence-*`
   * commands use `else if (flag === "--x")`. Reading only the first misses
   * every coherence gate flag and reports two dozen phantom failures.
   */
  it("parses every flag the documentation shows", () => {
    const cliSources = readdirSync(join(root, "tools", "cli"))
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
      .map((f) => read("tools", "cli", f))
      .join("\n");
    const parsed = new Set([
      ...[...cliSources.matchAll(/case "(--[a-z0-9-]+)":/g)].map((m) => m[1]!),
      ...[...cliSources.matchAll(/flag === "(--[a-z0-9-]+)"/g)].map((m) => m[1]!),
    ]);

    // Flags shown in a fenced example that actually invokes the tool, plus the
    // README's own CLI flag table. Prose elsewhere is not a promise: the docs
    // also name CSS custom properties (`--link`, `--muted`) and another
    // script's flags, and neither is a claim about this CLI.
    const documented = new Set<string>();
    for (const doc of [readme, ciDoc]) {
      for (const block of doc.matchAll(/```[a-z]*\n([\s\S]*?)```/g)) {
        const body = block[1]!;
        if (!/\bvaulytica\b/.test(body)) continue;
        for (const t of body.matchAll(/(?:^|\s)(--[a-z][a-z0-9-]{2,})/g)) documented.add(t[1]!);
      }
      for (const row of doc.matchAll(/^\|\s*`(--[a-z][a-z0-9-]{2,})[^`]*`/gm))
        documented.add(row[1]!);
    }

    // The derivation must not be empty, or the assertion below is free.
    expect(documented.size, "no CLI flags found in any example or table").toBeGreaterThan(15);
    expect(parsed.size, "no flags parsed out of tools/cli").toBeGreaterThan(40);
    expect(documented.has("--fail-on"), "the sanity anchor is missing").toBe(true);

    const phantom = [...documented].filter((f) => !parsed.has(f)).sort();
    expect(
      phantom,
      `these appear in a documented vaulytica command and no parser accepts them:\n  ${phantom.join("\n  ")}`,
    ).toEqual([]);
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

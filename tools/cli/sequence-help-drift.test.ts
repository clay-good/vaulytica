/**
 * Every flag a round-archive command parses is in `--help`.
 *
 * `coherence-trend --fail-on-net-regression` shipped (9.849.0) parsed, tested
 * and documented in the reference — and missing from the usage text `--help`
 * prints, because nothing compared the two. The usage is the one surface a CI
 * author reads at the terminal. This reads each sequence command's parser for
 * the flags it accepts and requires each in that command's usage entry.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isSequenceCommand } from "./round-archive.js";

const dir = join(process.cwd(), "tools", "cli");
const run = readFileSync(join(dir, "run.ts"), "utf8");
const usage = run.slice(run.indexOf("const USAGE"));

/** The usage entry for `command`: its line and the indented lines under it. */
function usageEntry(command: string): string {
  const lines = usage.split("\n");
  const i = lines.findIndex((l) => l.startsWith(`  ${command} `));
  if (i < 0) return "";
  const out = [lines[i]!];
  for (const l of lines.slice(i + 1)) {
    if (!/^\s{3,}/.test(l)) break;
    out.push(l);
  }
  return out.join("\n");
}

const commands = readdirSync(dir)
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
  .map((f) => f.replace(/\.ts$/, ""))
  .filter((c) => isSequenceCommand(c) && c !== "coherence-sequence");

describe("a round-archive command's flags are all in --help", () => {
  it("finds the commands (guards the derivation)", () => {
    expect(commands.length).toBeGreaterThanOrEqual(25);
  });

  it.each(commands)("%s", (command) => {
    const source = readFileSync(join(dir, `${command}.ts`), "utf8");
    const flags = [...new Set([...source.matchAll(/flag === "(--[a-z-]+)"/g)].map((m) => m[1]!))];
    expect(flags.length, `${command} parses no flags`).toBeGreaterThan(0);
    const entry = usageEntry(command);
    expect(entry, `${command} has no usage entry`).not.toBe("");
    expect(flags.filter((f) => !entry.includes(f))).toEqual([]);
  });
});

/**
 * A line number is a property of the file, not of the recognizer.
 *
 * The static ratchets in this directory each carry a short list of declared
 * exceptions — recognizers that look like the defect being hunted and are not
 * one. Those lists used to be keyed by `path:line`, and a line number moves
 * whenever anything above it does. Adding a single import to a rules file
 * broke `parenthetical-numeral` and `commonwealth-spelling` in one session, on
 * edits that had nothing to do with either guard, and each time the "fix" was
 * to retype a number — which is not a fix, it is a payment.
 *
 * The loud failure is the good case. The bad one is already written down in
 * `parenthetical-numeral`: a key that stops matching stops EXEMPTING, and on
 * Windows it did that silently for a whole session while passing everywhere
 * its author could see. Both failures come from keying on position.
 *
 * `declaredExceptions` keys on a substring of the recognizer's own source
 * instead, and this file guards the migration two ways: the helper does what
 * it says, and no ratchet goes back to line numbers.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { declaredExceptions } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "integration");

describe("a declared exception", () => {
  it("exempts the recognizer it names, in that file only", () => {
    const ex = declaredExceptions([
      { file: "src/engine/rules/a.ts", pattern: String.raw`2\.5\s+months?`, why: "fractional" },
    ]);
    expect(ex.exempts("src/engine/rules/a.ts", String.raw`/2\.5\s+months?/i`)).toBe(true);
    expect(ex.exempts("src/engine/rules/b.ts", String.raw`/2\.5\s+months?/i`)).toBe(false);
    expect(ex.exempts("src/engine/rules/a.ts", String.raw`/\d{1,3}\s+months?/i`)).toBe(false);
  });

  it("accepts the absolute path the walk returns, not only the relative one", () => {
    const ex = declaredExceptions([{ file: "src/x.ts", pattern: "abc", why: "" }]);
    expect(ex.exempts(`${process.cwd()}/src/x.ts`, "abc")).toBe(true);
  });

  it("reports an entry that matched nothing", () => {
    const ex = declaredExceptions([
      { file: "src/x.ts", pattern: "abc", why: "" },
      { file: "src/x.ts", pattern: "gone", why: "" },
    ]);
    expect(ex.unused()).toHaveLength(2);
    ex.exempts("src/x.ts", "abc");
    expect(ex.unused()).toEqual(["src/x.ts  gone"]);
  });
});

describe("no ratchet", () => {
  it("keys an exception by line number", () => {
    // A source path with a trailing `:<digits>` inside a test is a positional
    // key, whatever the surrounding collection is called.
    const POSITIONAL = /["'`]src\/[\w./-]+\.ts:\d+["'`]/;
    const offenders: string[] = [];
    for (const name of readdirSync(DIR).filter((f) => f.endsWith(".test.ts"))) {
      const text = readFileSync(join(DIR, name), "utf8");
      text.split("\n").forEach((line, i) => {
        if (POSITIONAL.test(line)) offenders.push(`${name}:${i + 1}  ${line.trim().slice(0, 80)}`);
      });
    }
    expect(
      offenders,
      `key these on a substring of the recognizer instead — see declaredExceptions:\n  ${offenders.join("\n  ")}`,
    ).toEqual([]);
  });
});

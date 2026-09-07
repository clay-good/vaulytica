/**
 * In the pre-disclosure pack, a negative assertion alone is not a test.
 *
 * `HANDOFF-005`'s job is to find the SSN, the card number, the direct line left
 * in a draft about to be sent. Its failure direction is the worst one the tree
 * has: a false NEGATIVE that reports a document clean. So the tests that defend
 * it are written as *"the report must not echo the raw value"* — and a report
 * containing NOTHING satisfies every such assertion.
 *
 * That is not hypothetical. Until 9.544.0 the file's headline invariant —
 * *"never echoes an unmasked value (the §Part XIV invariant)"* — was three
 * `not.toContain` calls and nothing else. Stub `scanSensitive` to return an
 * empty array and seventeen tests in that file go red while that one stays
 * green, with the leak check no longer testing anything.
 *
 * So, for THIS pack only: a test that asserts what the output must not contain
 * must also assert something it must. The rule is deliberately not applied
 * suite-wide — 155 tests across the tree are all-negative and most are
 * legitimately "omits section X when Y is absent", where absence is the point.
 * Here the value under test is a SCAN RESULT that can vanish for reasons
 * unrelated to what the test is checking, and the cost of that is a leak.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const DIR = dirname(fileURLToPath(import.meta.url));

type Block = { file: string; name: string; body: string };

/** Every `it(...)` body in the pack's test files, by brace matching. */
function testBlocks(): Block[] {
  const out: Block[] = [];
  for (const file of readdirSync(DIR)
    .filter((f) => f.endsWith(".test.ts"))
    .sort()) {
    const src = readFileSync(join(DIR, file), "utf8");
    const re = /\b(it|test)(?:\.\w+)?\(\s*(["'`])([\s\S]*?)\2/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const open = src.indexOf("{", m.index + m[0].length);
      if (open === -1) continue;
      let depth = 0;
      let k = open;
      while (k < src.length) {
        if (src[k] === "{") depth++;
        else if (src[k] === "}") {
          depth--;
          if (depth === 0) break;
        }
        k++;
      }
      out.push({ file, name: m[3]!.replace(/\s+/g, " "), body: src.slice(open, k + 1) });
    }
  }
  return out;
}

/** The matcher chain of every `expect(...)` in a block, e.g. `.not.toContain`. */
function matchers(body: string): string[] {
  return [...body.matchAll(/expect\([\s\S]{0,400}?\)\s*((?:\.\w+)+)\(/g)].map((m) => m[1]!);
}

describe("the pre-disclosure pack's tests cannot pass on an empty result", () => {
  const blocks = testBlocks();

  it("derives a plausible surface (guards the derivation itself)", () => {
    // An empty block list, or one with no negative assertions in it, would make
    // the assertion below vacuous — which is the very defect it exists to stop.
    expect(blocks.length).toBeGreaterThan(30);
    const negatives = blocks.filter((b) =>
      matchers(b.body).some((m) => /\.not\.(toContain|toMatch)/.test(m)),
    );
    expect(negatives.length, "no negative assertions found to check").toBeGreaterThan(2);
    expect(blocks.some((b) => /never echoes an unmasked value/.test(b.name))).toBe(true);
  });

  it("every test that says what the output must NOT contain also says what it must", () => {
    const offenders = blocks
      .filter((b) => {
        const ms = matchers(b.body);
        const negative = ms.some((m) => /\.not\.(toContain|toMatch)/.test(m));
        const positive = ms.some((m) => !/\.not\./.test(m));
        return negative && !positive;
      })
      .map((b) => `${b.file} :: "${b.name}"`);
    expect(
      offenders,
      `these pass on an empty result — assert what must be FOUND before what must not be echoed:\n  ${offenders.join(
        "\n  ",
      )}`,
    ).toEqual([]);
  });
});

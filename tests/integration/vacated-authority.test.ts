/**
 * Vacated-authority drift guard.
 *
 * A deterministic linter's whole claim is that every finding cites a real
 * authority. The failure mode that claim is most exposed to is not a
 * missing citation — it is a citation that *was* good law when it was
 * written and is not any more. That is invisible in a diff, invisible in
 * the goldens, and reads to an attorney as confident, sourced advice.
 *
 * It had already happened twice:
 *
 *  - The FTC's 2024 amendments to the Negative Option Rule (the
 *    "click-to-cancel" rule) were vacated in their entirety by the Eighth
 *    Circuit on July 8, 2025 and never took effect; 16 C.F.R. Part 425 has
 *    since been recodified to its pre-2024 text, which reaches
 *    prenotification plans only. Four launch rules, one v3 rule, one v3
 *    playbook, and the report frame label all presented it as governing.
 *  - The FTC Non-Compete Clause Rule was set aside nationwide in *Ryan LLC
 *    v. FTC* and removed from the CFR. The employment and personnel packs
 *    said so correctly, but the M&A restrictive-covenant playbook still
 *    named § 910.2(a)(2) as its operative frame.
 *
 * This test pins the repair and generalizes it: any file that mentions a
 * vacated authority must also carry a disclaimer word near it. It cannot
 * know what gets vacated next — that is a research task, not a test — so
 * the value is in making an existing entry impossible to un-fix silently,
 * and in giving the next such discovery an obvious place to land.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES, V3_RULES, V4_RULES, V5_RULES, V6_RULES } from "../../src/engine/index.js";
import type { Rule } from "../../src/engine/finding.js";

/**
 * Authorities that have been vacated, set aside, or withdrawn. `mentions`
 * is how the repo names the authority; `disclaimer` is the vocabulary that
 * makes the mention honest.
 */
const VACATED: Array<{ what: string; mentions: RegExp; disclaimer: RegExp }> = [
  {
    what: 'FTC "click-to-cancel" (2024 amendments to 16 C.F.R. Part 425)',
    mentions:
      /click[- ]to[- ]cancel|negative\s+option\s+rule|16\s*c\.?f\.?r\.?\s*(part\s*|§\s*)?425/i,
    disclaimer: /vacat|set\s+aside|never\s+took\s+effect|withdraw|prenotification|recodif/i,
  },
  {
    what: "FTC Non-Compete Clause Rule (16 C.F.R. Part 910)",
    mentions: /part\s*910|§\s*910\.\d|non-?compete\s+clause\s+rule/i,
    disclaimer: /vacat|set\s+aside|never\s+took\s+effect|withdraw|would\s+(likewise\s+)?have/i,
  },
];

/** Every string a reader could see on a report, per rule. */
function readerFacingText(r: Rule): string {
  return [r.name, r.description, ...r.dkb_citations].join("\n");
}

const ALL_RULES: readonly Rule[] = [
  ...LAUNCH_RULES,
  ...V3_RULES,
  ...V4_RULES,
  ...V5_RULES,
  ...V6_RULES,
];

/** Source files whose prose reaches a report as explanation or recommendation. */
const PROSE_FILES = [
  "src/engine/rules/temporal/TEMP-004.ts",
  "src/engine/rules/temporal/TEMP-005.ts",
  "src/engine/rules/temporal/TEMP-011.ts",
  "src/engine/rules/dark-patterns/DARK-002.ts",
  "src/engine/rules/dark-patterns/DARK-009.ts",
  "src/engine/rules/v3/addenda/rules.ts",
  "src/playbooks/v3/saas-tos.json",
  "src/playbooks/v4/ma-restrictive-covenant.json",
];

describe("vacated authorities are never presented as governing", () => {
  it.each(VACATED)("$what — no rule name or description asserts it", ({ mentions, disclaimer }) => {
    const offenders = ALL_RULES.filter((r) => {
      const text = readerFacingText(r);
      return mentions.test(text) && !disclaimer.test(text);
    }).map((r) => r.id);
    expect(
      offenders,
      `rules naming a vacated authority with no disclaimer: ${offenders.join(", ")}`,
    ).toEqual([]);
  });

  /**
   * Lines around `i`, inclusive. The disclaimer for a mention rarely sits on
   * the same line: it is the next sentence of the same comment, or the next
   * clause of the same string literal wrapped by the formatter. Matching
   * line-by-line reports a multi-line comment whose second line carries the
   * caveat, which is a false positive on correct prose.
   */
  const WINDOW = 6;
  const near = (lines: string[], i: number): string =>
    lines.slice(Math.max(0, i - WINDOW), i + WINDOW + 1).join("\n");

  it.each(VACATED)(
    "$what — no repaired file mentions it undisclaimed",
    ({ mentions, disclaimer }) => {
      const offenders: string[] = [];
      for (const rel of PROSE_FILES) {
        const lines = readFileSync(join(process.cwd(), rel), "utf8").split("\n");
        lines.forEach((line, i) => {
          if (mentions.test(line) && !disclaimer.test(near(lines, i))) {
            offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
          }
        });
      }
      expect(offenders, `undisclaimed mentions:\n${offenders.join("\n")}`).toEqual([]);
    },
  );
});

describe("the substance survives the repaired citations", () => {
  it("ADDENDA-019 still checks cancellation parity, now under ROSCA", () => {
    const rule = V3_RULES.find((r) => r.id === "ADDENDA-019");
    expect(rule, "ADDENDA-019 must still ship").toBeDefined();
    expect(rule!.name).toMatch(/cancellation\s+parity/i);
    expect(rule!.version, "the citation change must bump the rule version").not.toBe("1.0.0");
  });
});

/**
 * README / landing-page rule-count drift-guard.
 *
 * Sibling to `readme-version-drift.test.ts`. Every rule-count the shopfront
 * quotes — the launch-set total, each category row of the cheat-sheet table,
 * the v3/v4 addends, and the catalog total — is hand-maintained prose, so a
 * rule added to a pack silently ages the documentation. That is exactly what
 * happened: the launch set grew to 120 while the README still said 115, the
 * dark-patterns row still said 9 against 14 shipped rules, and v4 still
 * advertised +747 against 771. The aggregate ("1,111") stayed correct the
 * whole time, which is what let the addends drift unnoticed.
 *
 * These assertions read the counts off the live rule arrays, so a new rule
 * fails here until the prose is updated. Files are read from disk so the
 * guard depends on what ships, not on a bundler-resolved copy.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES, V3_RULES, V4_RULES } from "../../src/engine/index.js";

const root = process.cwd();
const readme = readFileSync(join(root, "README.md"), "utf8");
const landing = readFileSync(join(root, "site", "index.html"), "utf8");

/** Cheat-sheet table row label -> the rule-id prefix that row counts. */
const CATEGORY_PREFIX: Record<string, string> = {
  Structural: "STRUCT",
  "Risk allocation": "RISK",
  "Choice & venue": "CHOICE",
  Temporal: "TEMP",
  Financial: "FIN",
  Termination: "TERM",
  "IP & data": "IPDATA",
  Obligations: "OBLI",
  "Dark patterns": "DARK",
  Personnel: "PERS",
};

function countByPrefix(prefix: string): number {
  return LAUNCH_RULES.filter((r) => r.id.startsWith(`${prefix}-`)).length;
}

describe("README rule counts", () => {
  it("quotes the live launch-set size", () => {
    expect(readme).toContain(`is ${LAUNCH_RULES.length} rules across ten categories`);
  });

  it.each(Object.entries(CATEGORY_PREFIX))(
    "cheat-sheet row %s quotes its live rule count",
    (label, prefix) => {
      const expected = countByPrefix(prefix);
      // Match the table row by its leading cell so the digit is read from
      // that row only: "| Dark patterns | 14 | …".
      const row = new RegExp(
        `^\\|\\s*${label.replace(/[&]/g, "\\&")}\\s*\\|\\s*(\\d+)\\s*\\|`,
        "m",
      );
      const m = row.exec(readme);
      expect(m, `no cheat-sheet row found for "${label}"`).not.toBeNull();
      expect(Number(m?.[1])).toBe(expected);
    },
  );

  it("the cheat-sheet rows account for every launch rule", () => {
    // Guards the reverse direction: a rule in a category the table omits
    // would leave the rows summing short of the launch set.
    const summed = Object.values(CATEGORY_PREFIX).reduce((n, p) => n + countByPrefix(p), 0);
    expect(summed).toBe(LAUNCH_RULES.length);
  });

  it("quotes the live v3 and v4 addends", () => {
    expect(readme).toContain(`**v3 (+${V3_RULES.length} rules)**`);
    expect(readme).toContain(`**v4 (+${V4_RULES.length} rules)**`);
    expect(readme).toContain(`| v4 | Every operative document | +${V4_RULES.length} rules,`);
  });

  it("quotes the live catalog total", () => {
    const total = LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length;
    expect(readme).toContain(`**${total.toLocaleString("en-US")}-rule**`);
  });
});

describe("landing-page rule counts", () => {
  it("quotes the live launch set, v4 addend, and total", () => {
    const total = LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length;
    expect(landing).toContain(
      `${LAUNCH_RULES.length} rules at launch across ten categories — ${V3_RULES.length} more in v3, ` +
        `${V4_RULES.length} more in v4 (${total.toLocaleString("en-US")} in`,
    );
  });
});

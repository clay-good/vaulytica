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

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES, V3_RULES, V4_RULES, V5_RULES, V6_RULES } from "../../src/engine/index.js";
import { ALL_CONSISTENCY_RULES } from "../../src/engine/consistency/rules/index.js";
import { STATE_OVERLAYS } from "../../src/dkb/state-overlays.js";
import { ESTATE_FORMALITIES } from "../../src/dkb/estate-formalities.js";

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

  it("quotes the live v3, v4, v5, and v6 addends", () => {
    expect(readme).toContain(`**v3 (+${V3_RULES.length} rules)**`);
    expect(readme).toContain(`**v4 (+${V4_RULES.length} rules)**`);
    expect(readme).toContain(`**v5 (+${V5_RULES.length} rules)**`);
    expect(readme).toContain(`**v6 (+${V6_RULES.length} rules)**`);
    // Prettier owns the column padding in a markdown table and re-aligns it
    // whenever a cell's width changes, so the row is matched on its CONTENT.
    // Asserting the single-spaced form made these two tests fail the moment
    // `format:check` was satisfied — the gate contradicting itself.
    const squeezed = readme.replace(/[ \t]+/g, " ");
    expect(squeezed).toContain(`| v4 | Every operative document | +${V4_RULES.length} rules,`);
    expect(squeezed).toContain(`| v5 | The US catalog | +${V5_RULES.length} rules,`);
    expect(squeezed).toContain(`| v6 | The lawyer's own documents | +${V6_RULES.length} rules,`);
  });

  it("quotes the live catalog total", () => {
    const total =
      LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length + V5_RULES.length + V6_RULES.length;
    expect(readme).toContain(`**${total.toLocaleString("en-US")}-rule**`);
  });

  /**
   * The README's coverage table quotes both the measured figures and the
   * enforced floors. The floors are machine-checkable against the config that
   * actually enforces them, and they had drifted ~8 points apart: the table
   * said 85/85/70/83 while real coverage had climbed to the low 90s, so the
   * "regression gate" would not have fired until coverage fell off a cliff.
   * The measured column stays trust-on-write (only a coverage run produces
   * it), but it must at least sit above its own floor.
   */
  it("quotes the coverage floors vitest.config.ts actually enforces", () => {
    const config = readFileSync(join(root, "vitest.config.ts"), "utf8");
    const enforced = Object.fromEntries(
      [...config.matchAll(/^\s*(lines|functions|branches|statements):\s*(\d+),/gm)].map((m) => [
        m[1]!,
        Number(m[2]!),
      ]),
    );
    expect(Object.keys(enforced).sort()).toEqual(["branches", "functions", "lines", "statements"]);
    // The table packs two metrics per row, so the cells are matched wherever
    // they sit rather than anchored to the start of a line.
    const rows = [
      ...readme.matchAll(
        /\|\s*(Lines|Functions|Statements|Branches)\s*\|\s*([\d.]+)%\s*\|\s*(\d+)%/g,
      ),
    ];
    const quoted = new Map(
      rows.map((m) => [m[1]!.toLowerCase(), { measured: Number(m[2]!), floor: Number(m[3]!) }]),
    );
    for (const metric of ["lines", "functions", "branches", "statements"]) {
      const row = quoted.get(metric);
      expect(row, `README coverage table has no ${metric} row`).toBeDefined();
      expect(row!.floor, `${metric} floor disagrees with vitest.config.ts`).toBe(enforced[metric]);
      expect(row!.measured, `${metric} measured sits below its own floor`).toBeGreaterThan(
        row!.floor,
      );
    }
  });

  /**
   * The suite size is quoted twice — the badge line and the verify block — and
   * both had aged to "6,014" against a suite of 6,450. Unlike a rule count it
   * cannot be read off a live array here: deriving it means collecting every
   * spec (`npx vitest list`), which is far too slow to run from inside the
   * suite it is counting. So the claim is stated as a FLOOR, which degrades
   * honestly — it stays true as tests are added and only becomes false if the
   * suite shrinks past it — and what IS machine-checkable is pinned: both
   * mentions quote the same floor, and it is a floor rather than a bare exact
   * number that will be wrong by the next commit.
   *
   * Re-derive with: `npx vitest list --reporter=tree | grep -c ' > '`
   */
  it("quotes the suite size as a single consistent floor", () => {
    const quoted = [...readme.matchAll(/`([\d,]+)\+ passing tests`/g)].map((m) => m[1]!);
    const inBlock = [...readme.matchAll(/# vitest — ([\d,]+)\+ tests/g)].map((m) => m[1]!);
    expect(quoted, "badge line must state the suite size as a floor (N+)").toHaveLength(1);
    expect(inBlock, "verify block must state the suite size as a floor (N+)").toHaveLength(1);
    expect(inBlock[0], "the two suite-size claims disagree").toBe(quoted[0]);
  });
});

describe("landing-page rule counts", () => {
  it("quotes the live catalog total in the hero facts strip", () => {
    // The hero states the headline number before anything else on the page.
    // It is the first thing a reader checks and the first thing to age.
    const total =
      LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length + V5_RULES.length + V6_RULES.length;
    const quoted = [...landing.matchAll(/data-rule-total>([\d,]+)</g)].map((m) =>
      Number(m[1]!.replace(/,/g, "")),
    );
    expect(quoted.length, "no data-rule-total count on the page").toBeGreaterThan(0);
    for (const n of quoted) expect(n).toBe(total);
  });

  it("quotes the live launch set, the v4-v6 addends, and total", () => {
    const total =
      LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length + V5_RULES.length + V6_RULES.length;
    expect(landing).toContain(
      `${LAUNCH_RULES.length} rules at launch across ten categories — ${V3_RULES.length} more in v3, ` +
        `${V4_RULES.length} more in v4, ${V5_RULES.length} more in v5, ${V6_RULES.length} more in v6 ` +
        `(${total.toLocaleString("en-US")} in`,
    );
  });
});

describe("architecture-diagram rule counts", () => {
  const architecture = readFileSync(join(root, "docs", "architecture.md"), "utf8");

  it("quotes the live launch set and catalog total", () => {
    const total =
      LAUNCH_RULES.length + V3_RULES.length + V4_RULES.length + V5_RULES.length + V6_RULES.length;
    expect(architecture).toContain(
      `${LAUNCH_RULES.length} launch · ${total.toLocaleString("en-US")} total rules`,
    );
  });

  it("quotes the live cross-document check count", () => {
    expect(architecture).toContain(`+ ${ALL_CONSISTENCY_RULES.length} cross-document checks`);
  });
});

/**
 * The badge line — the first thing anyone reads, and the least guarded.
 *
 * The counts above are checked where they appear in prose and in the
 * architecture doc. The README's own badge line carries its OWN copies of
 * several of them, and those copies were unguarded: `22 cross-document checks`
 * was correct only because nobody had added a CC- rule since it was written.
 * This is the shape `shared-vocabulary.test.ts` exists for — a number in two
 * places will eventually disagree with itself — and this session already found
 * a stale one (`22 of the 312 specimens`, really 7, wrong in eight places).
 *
 * Each assertion derives the number from what ships. Two are read out of source
 * text rather than an exported constant, and 🚨 comments are stripped first:
 * a guard that scans source without doing that has been fooled by a quoted
 * phrase in a comment three times in this repo.
 *
 * Still hand-maintained, deliberately: `3 execution-readiness
 * reconciliations`. `ChecklistCategory` has five members and the badge counts
 * three of something else, so any derivation here would be a guess dressed as
 * a check. Better an honest gap than a green test asserting the wrong thing.
 */
describe("README badge line", () => {
  const badge = readme.split("\n").find((l) => l.includes("deterministic rules"))!;
  const strip = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  it("derives a plausible badge line (guards the derivation itself)", () => {
    // An empty or mis-found line would make every assertion below vacuous.
    expect(badge).toBeDefined();
    expect(badge).toContain("`0 servers`");
    expect(badge.length).toBeGreaterThan(200);
  });

  it("quotes the live cross-document check count", () => {
    expect(badge).toContain(`\`${ALL_CONSISTENCY_RULES.length} cross-document checks\``);
  });

  it("quotes the live pre-disclosure check count", () => {
    const src = strip(
      readdirSync(join(root, "src", "delivery"))
        .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
        .map((f) => readFileSync(join(root, "src", "delivery", f), "utf8"))
        .join("\n"),
    );
    const ids = new Set([...src.matchAll(/HANDOFF-(\d+)/g)].map((m) => m[0]));
    expect(ids.size, "no HANDOFF ids found — the scan is broken").toBeGreaterThan(0);
    expect(badge).toContain(`\`${ids.size} pre-disclosure checks\``);
  });

  it("quotes the live derived-deadline family count", () => {
    const src = strip(readFileSync(join(root, "src", "report", "critical-dates.ts"), "utf8"));
    const union = /export type CriticalDateKind =([\s\S]*?);/.exec(src);
    expect(union, "CriticalDateKind is no longer a string union — update this guard").toBeTruthy();
    const kinds = [...union![1]!.matchAll(/"([a-z-]+)"/g)].map((m) => m[1]!);
    expect(kinds.length, "no kinds parsed").toBeGreaterThan(0);
    expect(badge).toContain(`\`${kinds.length} derived-deadline families\``);
  });

  it("quotes the live document sub-domain count", () => {
    const dirs = readdirSync(join(root, "src", "engine", "rules", "v4"), {
      withFileTypes: true,
    }).filter((e) => e.isDirectory());
    expect(dirs.length).toBeGreaterThan(5);
    expect(badge).toContain(`\`${dirs.length} document sub-domains\``);
  });

  it("quotes the live state-law overlay total, across BOTH catalogs", () => {
    // The number is a sum, and that is the interesting part: 37 non-compete /
    // security-deposit / usury overlays plus 51 will-formality nodes (50 states
    // + DC). A guard against either catalog alone would pass while the badge
    // was wrong about the other.
    const total = STATE_OVERLAYS.length + ESTATE_FORMALITIES.length;
    expect(STATE_OVERLAYS.length).toBeGreaterThan(0);
    expect(ESTATE_FORMALITIES.length).toBeGreaterThan(0);
    expect(badge).toContain(`\`${total} state-law overlays`);
  });
});

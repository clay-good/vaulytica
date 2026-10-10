/**
 * The drafting loop's compact comparison (spec-v51 §3, §7), on a real pair
 * and on that pair with its delta edited — a document with nothing actionable
 * left is not in the corpus, and the clean statement has to be shown to
 * appear exactly then.
 */
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";
import { isActionable } from "../../src/engine/finding.js";
import { LOOP_CLEAN_STATEMENT } from "../../src/report/disclaimers.js";
import { compareFiles, type FileComparison } from "./api.js";
import { buildComparisonBrief, comparisonBriefMarkdown } from "./comparison-brief.js";
import { formatCompareMarkdown } from "./compare.js";

const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-complete.txt");

let pair: FileComparison;
beforeAll(async () => {
  const base = await readFile(NDA, "utf8");
  pair = await compareFiles(
    { text: base, filename: "nda.txt" },
    { text: base.slice(0, Math.floor(base.length / 2)), filename: "nda.txt" },
  );
});

/** The pair with its delta replaced: what the brief says is a function of the delta. */
function withDelta(patch: Partial<FileComparison["comparison"]["delta"]>): FileComparison {
  return {
    ...pair,
    comparison: { ...pair.comparison, delta: { ...pair.comparison.delta, ...patch } },
  };
}

describe("the loop's comparison", () => {
  it("splits the delta by what there is to do, and loses nothing", () => {
    const b = buildComparisonBrief(pair);
    const { resolved, introduced, unchanged } = pair.comparison.delta;
    expect(b.fixed.length + b.no_longer_present.length).toBe(resolved.length);
    expect(b.fixed.map((f) => f.rule_id)).toEqual(
      resolved.filter(isActionable).map((f) => f.rule_id),
    );
    expect(b.introduced.map((f) => f.rule_id)).toEqual(introduced.map((f) => f.rule_id));
    expect(b.remaining.length + b.observations_unchanged).toBe(unchanged.length);
    // What is left to do says where it is in the REVISED draft, and what to do.
    for (const f of b.remaining) {
      expect(typeof f.start_offset).toBe("number");
      expect(f.recommendation).toBeTruthy();
    }
    expect(b.comparison_hash).toBe(pair.comparison.result_hash);
  });

  it("says a round is clean only when nothing actionable is left or was caused", () => {
    expect(buildComparisonBrief(pair).clean).toBeUndefined();
    const observationsOnly = pair.comparison.delta.unchanged.filter(
      (u) => !isActionable(u.finding),
    );
    const clean = buildComparisonBrief(withDelta({ unchanged: observationsOnly, introduced: [] }));
    expect(clean.remaining).toEqual([]);
    expect(clean.clean).toBe(LOOP_CLEAN_STATEMENT);
    expect(clean.clean).toMatch(/does not mean the document is complete, balanced, or enforceable/);
    // An introduced observation ("clause present") does not un-clean a round…
    const observation = pair.comparison.delta.unchanged.find(
      (u) => !isActionable(u.finding),
    )!.finding;
    expect(
      buildComparisonBrief(withDelta({ unchanged: observationsOnly, introduced: [observation] }))
        .clean,
    ).toBe(LOOP_CLEAN_STATEMENT);
    // …an introduced task does.
    const task = pair.comparison.delta.unchanged.find((u) => isActionable(u.finding))!.finding;
    expect(
      buildComparisonBrief(withDelta({ unchanged: observationsOnly, introduced: [task] })).clean,
    ).toBeUndefined();
  });

  it("says when checks cleared while clauses went missing", () => {
    const b = buildComparisonBrief(pair);
    expect(b.removed.clauses).toBeGreaterThan(0);
    expect(b.removed.words_net).toBeLessThan(0);
    // Nothing cleared in this round (the cut only breaks things), so no note…
    if (b.fixed.length + b.no_longer_present.length === 0) expect(b.removed.note).toBeUndefined();
    // …and when something did, the note says a deletion is not a fix.
    const cleared = buildComparisonBrief(
      withDelta({ resolved: [pair.comparison.delta.unchanged[0]!.finding] }),
    );
    expect(cleared.removed.note).toMatch(/removed \d+ clauses? \(−\d+ words net\).*not a fix/);
  });

  it("renders the same round as Markdown sections inside the comparison report", () => {
    const b = buildComparisonBrief(pair);
    const round = comparisonBriefMarkdown(b);
    for (const heading of ["Fixed", "Introduced", "Remaining", "No longer present"]) {
      expect(round).toMatch(new RegExp(`^### ${heading} \\(\\d+\\)$`, "m"));
    }
    const md = formatCompareMarkdown(pair.comparison, pair.clause_diff, undefined, round);
    // Named, where the table above it only counts — and before the redline.
    expect(md.indexOf("## This round")).toBeGreaterThan(md.indexOf("## Finding delta"));
    expect(md.indexOf("## This round")).toBeLessThan(md.indexOf("## Document redline"));
    expect(md).toContain(
      `**[${b.remaining[0]!.severity.toUpperCase()}] ${b.remaining[0]!.rule_id}**`,
    );
    // Without the round, the report is exactly what it was.
    expect(formatCompareMarkdown(pair.comparison, pair.clause_diff)).not.toContain("## This round");
  });
});

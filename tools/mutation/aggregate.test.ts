import { describe, expect, it } from "vitest";
import { aggregate, type MutationReport } from "./aggregate.js";

function report(files: Record<string, string[]>): MutationReport {
  return {
    files: Object.fromEntries(
      Object.entries(files).map(([path, statuses]) => [
        path,
        { mutants: statuses.map((status) => ({ status: status as never })) },
      ]),
    ),
  };
}

describe("mutation shard aggregate", () => {
  it("scores all shards together with Stryker's formula", () => {
    // 3 detected (2 killed + 1 timeout) of 5 valid (+1 survived, +1 no coverage);
    // compile errors and ignored mutants count on neither side.
    const result = aggregate(
      [
        report({ "src/a.ts": ["Killed", "Survived", "CompileError"] }),
        report({ "src/b.ts": ["Killed", "Timeout", "NoCoverage", "Ignored"] }),
      ],
      ["src/a.ts", "src/b.ts"],
      57,
    );
    expect(result.score).toBe(60);
    expect(result.verdict).toBe("pass");
  });

  it("is NOT the mean of the shard scores", () => {
    // 1/1 and 1/9: the mean is 55.6, the pooled score is 20.
    const result = aggregate(
      [
        report({ "src/a.ts": ["Killed"] }),
        report({ "src/b.ts": ["Killed", ...Array<string>(8).fill("Survived")] }),
      ],
      ["src/a.ts", "src/b.ts"],
      57,
    );
    expect(result.score).toBe(20);
    expect(result.verdict).toBe("below-floor");
  });

  it("reports a missing module as incomplete, never as a score", () => {
    // A shard the runner killed leaves no report. Scoring the rest against a
    // floor measured over every module would compare different things.
    const result = aggregate([report({ "src/a.ts": ["Survived"] })], ["src/a.ts", "src/b.ts"], 57);
    expect(result.verdict).toBe("incomplete");
    expect(result.missing).toEqual(["src/b.ts"]);
  });

  it("matches report keys written as absolute or Windows paths", () => {
    const result = aggregate(
      [report({ "C:\\runner\\work\\repo\\src\\a.ts": ["Killed"] })],
      ["src/a.ts"],
      57,
    );
    expect(result.missing).toEqual([]);
    expect(result.files[0]?.file).toBe("src/a.ts");
  });
});

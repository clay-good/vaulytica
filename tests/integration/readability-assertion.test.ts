/**
 * An asserted readability statute (add-readability-measure, task 4):
 * `--readability fl` holds a document to Fla. Stat. § 627.4145, read at its
 * official source. Without the assertion nothing changes, hash included.
 */
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { verifyReproducibility, type SavedReport } from "../../tools/cli/verify.js";
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import { resolveAnalyzeArgs } from "../../tools/cli/run.js";

const DENSE = `HOMEOWNERS INSURANCE POLICY

The insurer's obligation to indemnify the insured for consequential, incidental, or derivative losses occasioned by the occurrence of any peril enumerated in the declarations, notwithstanding any contrary provision of any endorsement, rider, or supplementary documentation incorporated by reference, shall be determined exclusively in accordance with the provisions of the applicable valuation methodology and the limitations, conditions, and exclusions specified in this policy.
`;
const PLAIN = `HOMEOWNERS INSURANCE POLICY

We pay for loss to your home. We do not pay for wear and tear. You must tell us of a loss soon. We will pay you within thirty days.
`;

describe("--readability fl", () => {
  it("reports a dense form below the statute's 45, with its counts", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    expect(r.run.asserted_readability).toBe("fl");
    const f = r.run.findings.find((x) => x.rule_id === "READ-001");
    expect(f?.title).toMatch(/below the 45 Fla\. Stat\. § 627\.4145 requires/);
    expect(f?.explanation).toMatch(/does not apply the sampling/);
  });

  it("says nothing about a plain one", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(PLAIN, "policy.txt", { deps, readability: "fl" });
    expect(r.run.findings.some((x) => x.rule_id.startsWith("READ-"))).toBe(false);
  });

  it("reports a form over 3,000 words with no table of contents, and accepts one with", async () => {
    const deps = await loadAccuracyDeps({});
    const body = Array.from(
      { length: 400 },
      (_v, i) => `We pay for loss number ${i} to your home.`,
    ).join(" ");
    const long = await analyzeText(`HOMEOWNERS POLICY\n\n${body}\n`, "policy.txt", {
      deps,
      readability: "fl",
    });
    expect(long.run.findings.map((x) => x.rule_id)).toContain("READ-002");
    const withContents = await analyzeText(
      `HOMEOWNERS POLICY\n\nTABLE OF CONTENTS\n\nCoverage ........ 2\n\n${body}\n`,
      "policy.txt",
      { deps, readability: "fl" },
    );
    expect(withContents.run.findings.map((x) => x.rule_id)).not.toContain("READ-002");
  });

  it("changes nothing without the assertion", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps });
    expect(r.run.asserted_readability).toBeUndefined();
    expect(r.run.execution_log.some((e) => e.rule_id.startsWith("READ-"))).toBe(false);
  });

  it("is re-derived by verify, so the saved report reproduces", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE, "policy.txt", { deps, readability: "fl" });
    const saved = JSON.parse(JSON.stringify({ run: r.run })) as SavedReport;
    const result = await verifyReproducibility(saved, DENSE, { deps });
    expect(result.reproduced, JSON.stringify(result.divergences)).toBe(true);
  });

  it("refuses an unknown standard, and every standard names an official source", async () => {
    await expect(resolveAnalyzeArgs(["policy.txt", "--readability", "zz"])).rejects.toThrow(
      /unknown --readability/,
    );
    expect((await resolveAnalyzeArgs(["policy.txt", "--readability", "FL"])).readability).toBe(
      "fl",
    );
    for (const s of READABILITY_STANDARDS) {
      expect(new URL(s.source_url).hostname).toMatch(/^www\.leg\.state\.fl\.us$/);
      expect(s.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});

describe("the readability block", () => {
  it("never changes the run or its hash, for any specimen", async () => {
    const { readdirSync, readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { buildJsonReport } = await import("../../src/report/json.js");
    const deps = await loadAccuracyDeps({});
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const sample = readdirSync(dir)
      .filter((f) => f.endsWith(".txt"))
      .sort()
      .filter((_f, i) => i % 9 === 0);
    for (const name of sample) {
      const r = await analyzeText(readFileSync(join(dir, name), "utf8"), name, { deps });
      const before = JSON.stringify(r.run);
      const json = JSON.parse(await buildJsonReport(r.run, r.ingest).text()) as {
        run: { result_hash: string };
        readability: { score: number };
      };
      expect(typeof json.readability.score, name).toBe("number");
      expect(json.run.result_hash, name).toBe(r.run.result_hash);
      expect(JSON.stringify(r.run), name).toBe(before);
    }
  }, 300_000);
});

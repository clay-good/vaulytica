/**
 * `compare --executed <final> <signed>` (add-executed-copy-conformity, slice A).
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compareExecuted } from "../../tools/cli/api.js";
import { formatConformityMarkdown, parseCompareArgs } from "../../tools/cli/compare.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";

const dir = mkdtempSync(join(tmpdir(), "vaulytica-executed-"));
const write = (name: string, text: string): string => {
  const path = join(dir, name);
  writeFileSync(path, text);
  return path;
};

describe("compare --executed", () => {
  it("reports a signed copy identical to its final, with the comparison", async () => {
    const r = await compareExecuted(write("final.txt", FINAL), write("signed.txt", EXECUTED));
    expect(r.conformity.verdict).toBe("identical");
    expect(r.revised.playbook_id).toBe(r.base.playbook_id);
    const md = formatConformityMarkdown(r.conformity);
    expect(md).toContain("**Identical to the final outside the execution allowance.**");
    expect(md).toMatch(/Signed · blank filled in: .*June 3, 2026/);
  });

  it("names the figure the signed copy changed", async () => {
    const r = await compareExecuted(
      write("final2.txt", FINAL),
      write("signed2.txt", EXECUTED.replace("$12,500", "$21,500")),
    );
    expect(r.conformity.verdict).toBe("differences");
    expect(formatConformityMarkdown(r.conformity)).toMatch(/\*\*Changed:\*\*.*\$12,500.*\$21,500/);
  });

  it("is the same verdict and hash on every run", async () => {
    const [f, s] = [write("final3.txt", FINAL), write("signed3.txt", EXECUTED)];
    const [a, b] = [await compareExecuted(f, s), await compareExecuted(f, s)];
    expect(b.conformity.conformity_hash).toBe(a.conformity.conformity_hash);
  });
});

describe("parseCompareArgs --executed", () => {
  it("takes the final and the signed copy, and the gate", () => {
    const a = parseCompareArgs([
      "--executed",
      "final.docx",
      "signed.pdf",
      "--fail-on-nonconformity",
    ]);
    expect(a).toMatchObject({
      executed: true,
      failOnNonconformity: true,
      base: "final.docx",
      revised: "signed.pdf",
    });
  });

  it("refuses the gate without --executed, and --executed with --redline", () => {
    expect(() => parseCompareArgs(["a.docx", "b.docx", "--fail-on-nonconformity"])).toThrow(
      /requires --executed/,
    );
    expect(() => parseCompareArgs(["--executed", "--redline", "m.docx"])).toThrow(/does not take/);
  });
});

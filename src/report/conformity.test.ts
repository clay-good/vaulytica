/**
 * The executed copy against the final (add-executed-copy-conformity, slice A).
 */
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../ingest/paste.js";
import { checkConformity, conformityLine, fillsBlanks } from "./conformity.js";
import { EXECUTED, FINAL } from "./_conformity-fixtures.js";

async function check(final: string, executed: string) {
  const [a, b] = await Promise.all([ingestPaste(final), ingestPaste(executed)]);
  return checkConformity(a.tree, b.tree);
}

describe("an executed copy against its final", () => {
  it("is identical outside what execution fills in, and lists what it set aside", async () => {
    const c = await check(FINAL, EXECUTED);
    expect(c.verdict).toBe("identical");
    expect(conformityLine(c)).toBe("Identical to the final outside the execution allowance.");
    const reasons = c.set_aside.map((s) => s.reason);
    expect(reasons).toContain("blank filled in");
    expect(reasons).toContain("signature-block line");
    expect(reasons).toContain("legend or watermark");
    expect(c.set_aside.find((s) => s.reason === "blank filled in")?.text).toMatch(/June 3, 2026/);
    expect(c.conformity_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("reports a changed figure, and only it", async () => {
    const c = await check(FINAL, EXECUTED.replace("$12,500", "$21,500"));
    expect(c.verdict).toBe("differences");
    expect(c.difference_count).toBe(1);
    expect(c.differences.changed[0]?.revised.text).toMatch(/\$21,500/);
    expect(conformityLine(c)).toBe("1 difference from the final outside the execution allowance.");
  });

  it("reports a signatory the final did not have", async () => {
    const added = EXECUTED.replace(
      "CONSULTANT\n\n/s/ Jordan Lee",
      "ACME HOLDINGS LLC, as guarantor\n\nBy: /s/ Sam Patel\nName: Sam Patel\n\nCONSULTANT\n\n/s/ Jordan Lee",
    );
    const c = await check(FINAL, added);
    expect(c.verdict).toBe("differences");
    expect(c.signature_blocks).toEqual({ final: 1, executed: 2 });
  });

  it("reports a sentence the signed copy dropped, and one it added", async () => {
    const dropped = await check(FINAL, EXECUTED.replace(/3\. Term\.[^\n]*\n/, ""));
    expect(dropped.differences.removed.map((c) => c.text)).toEqual([
      expect.stringMatching(/^3\. Term\./),
    ]);
    const added = await check(
      FINAL,
      EXECUTED.replace(
        "IN WITNESS",
        "4. Exclusivity. Consultant shall not work for a competitor.\n\nIN WITNESS",
      ),
    );
    expect(added.differences.added.map((c) => c.text)).toEqual([
      expect.stringMatching(/^4\. Exclusivity\./),
    ]);
  });

  it("is the same verdict and hash whatever the executed copy's layout", async () => {
    const base = await check(FINAL, EXECUTED);
    const doubled = await check(FINAL, EXECUTED.split("\n").join("\n\n"));
    expect(doubled.verdict).toBe("identical");
    expect((await check(FINAL, EXECUTED)).conformity_hash).toBe(base.conformity_hash);
  });
});

describe("fillsBlanks", () => {
  it("accepts a blank filled and nothing else changed", () => {
    expect(fillsBlanks("dated as of ____, 2026", "dated as of June 3, 2026")).toBe(true);
    expect(fillsBlanks("a fee of [●] per month", "a fee of $4,000 per month")).toBe(true);
  });

  it("refuses a fill that also changed the words around it, or no blank at all", () => {
    expect(fillsBlanks("dated as of ____, 2026", "dated as of June 3, 2027")).toBe(false);
    expect(fillsBlanks("a fee of [●] per month", "a fee of $4,000 per year")).toBe(false);
    expect(fillsBlanks("a fee of $4,000", "a fee of $5,000")).toBe(false);
    // New terms typed into a blank are not a fill.
    expect(
      fillsBlanks("a fee of [●] per month", "a fee of $4,000, which Client waives, per month"),
    ).toBe(false);
  });

  it("stays fast on a form with many blanks", () => {
    const form = Array.from({ length: 40 }, (_, i) => `item ${i} ____`).join(" ");
    const t = performance.now();
    fillsBlanks(form, form.replace(/____/g, "x".repeat(70)) + " tail");
    expect(performance.now() - t).toBeLessThan(500);
  });
});

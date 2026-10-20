/**
 * `compare --redline`: the two readings of one Word redline
 * (add-redline-two-sided-analysis, slice A).
 *
 * The fixture strikes a liability cap, adds an uncapped indemnity, lengthens a
 * payment term and moves a sentence. Its finding delta must be the delta of
 * the two documents it contains, and nothing the tool decides about whether
 * the markup is acceptable.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compareRedline, RedlineRefusedError } from "../../tools/cli/api.js";
import { parseCompareArgs } from "../../tools/cli/compare.js";
import { buildDocx, documentXml, redlineDocx } from "../../src/delivery/_fixtures.js";

const dir = mkdtempSync(join(tmpdir(), "vaulytica-redline-"));
const write = (name: string, bytes: ArrayBuffer | string): string => {
  const path = join(dir, name);
  writeFileSync(path, typeof bytes === "string" ? bytes : Buffer.from(bytes));
  return path;
};

describe("compare --redline", () => {
  it("compares the draft as it stood against the draft the reviser wants", async () => {
    const r = await compareRedline(write("supply-redline.docx", redlineDocx()));
    expect(r.comparison.base.name).toBe("supply-redline.docx#rejected");
    expect(r.comparison.revised.name).toBe("supply-redline.docx#accepted");
    // One document by construction: the revision is held to the base's type.
    expect(r.revised.playbook_id).toBe(r.base.playbook_id);
    expect(r.base.run.result_hash).not.toBe(r.revised.run.result_hash);
    // Striking the cap is what the markup broke: no limitation of liability,
    // and an indemnity with no cap.
    const introduced = r.comparison.delta.introduced.map((f) => f.rule_id);
    expect(introduced).toEqual(expect.arrayContaining(["RISK-005", "RISK-015"]));
    // The uncapped indemnity quotes the inserted sentence, so it names the
    // author who inserted it. "No limitation-of-liability clause" is about an
    // absence, quotes nothing a revision wrote, and names no one.
    const byRule = (rule: string): string[] | undefined => {
      const f = r.comparison.delta.introduced.find((x) => x.rule_id === rule);
      return f ? r.revision_authors?.[f.id] : undefined;
    };
    expect(byRule("RISK-015")).toEqual(["Opposing Counsel"]);
    expect(byRule("RISK-005")).toBeUndefined();
    // The clause redline is the markup. A sentence rewritten this heavily is
    // a clause removed and a clause added, not a "changed" pair; either way
    // the cap is on the rejected side only and the indemnity on the accepted.
    const d = r.clause_diff;
    const before = [...d.removed, ...d.changed.map((c) => c.base)].map((c) => c.text).join("\n");
    const after = [...d.added, ...d.changed.map((c) => c.revised)].map((c) => c.text).join("\n");
    expect(before).toMatch(/capped at the fees paid in the prior twelve months/);
    expect(after).not.toMatch(/capped at the fees/);
    expect(after).toMatch(/indemnify Buyer against all losses without limit/);
    expect(before).toMatch(/within thirty days/);
    expect(after).toMatch(/within sixty days/);
  });

  it("is the same comparison every time", async () => {
    const path = write("again.docx", redlineDocx());
    const [a, b] = [await compareRedline(path), await compareRedline(path)];
    expect(b.comparison.result_hash).toBe(a.comparison.result_hash);
  });

  it("refuses a document with no tracked changes, and a file that is not a DOCX", async () => {
    const clean = write(
      "clean.docx",
      buildDocx({
        document: documentXml("<w:p><w:r><w:t>Vendor shall perform.</w:t></w:r></w:p>"),
      }),
    );
    await expect(compareRedline(clean)).rejects.toThrow(RedlineRefusedError);
    await expect(compareRedline(clean)).rejects.toThrow(/no tracked changes/);
    await expect(compareRedline(write("notes.txt", "Vendor shall perform."))).rejects.toThrow(
      /not one/,
    );
  });
});

describe("parseCompareArgs --redline", () => {
  it("takes one file in place of two", () => {
    const a = parseCompareArgs(["--redline", "markup.docx", "--fail-on", "critical"]);
    expect(a.redline).toBe("markup.docx");
    expect(a.failOn).toBe("critical");
  });

  it("refuses a redline and two files together, and a missing value", () => {
    expect(() => parseCompareArgs(["--redline", "m.docx", "a.docx"])).toThrow(/one file/);
    expect(() => parseCompareArgs(["--redline", "--fail-on", "info"])).toThrow(/requires a value/);
  });
});

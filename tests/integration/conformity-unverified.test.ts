/**
 * The could-not-determine verdict (add-executed-copy-conformity, task 4).
 *
 * The task's note read "Blocked: no surface runs OCR", and the verdict half
 * was left with it. That conflated two things. OCR gives WORD-level confidence
 * and is indeed unavailable. But the question the verdict turns on is coarser
 * and already answered by the ingest: **was the signed copy's text extracted
 * in full?** A scan whose text layer covers four pages of twelve yields the
 * words of four and nothing from the rest, and `assessTextLayer` already says
 * so.
 *
 * 🚨 Run against such a copy, this check used to return `differences` —
 * asserting differences it cannot substantiate — or, on a document whose
 * readable part happened to match, `identical`, which is a clean bill of health
 * for pages nobody read. The second is the more dangerous of the two, and it is
 * why an incomplete read disqualifies BOTH ordinary verdicts rather than only
 * the negative one.
 */
import { describe, expect, it } from "vitest";
import { checkConformity } from "../../src/report/conformity.js";
import { incompleteTextReason } from "../../src/report/_incomplete-text.js";
import { conformityLine } from "../../src/report/conformity.js";
import { ingestPaste, ingestPdfBuffer } from "../../src/ingest/index.js";
import { mixedLayerPdf } from "./_mcp/pdf.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";

const tree = async (text: string) => (await ingestPaste(text)).tree;

describe("an incomplete signed copy gets no verdict", () => {
  it("returns could-not-determine even when nothing differed", async () => {
    // The sharp case. The two texts are conformant, so the old code would have
    // said "identical" — a clean bill of health on a partially-read document.
    const c = await checkConformity(await tree(FINAL), await tree(EXECUTED), {
      executedTextIncomplete: "it is a scan whose text layer covers only some of its pages",
    });
    expect(c.verdict).toBe("could-not-determine");
    expect(c.unverified_reason).toContain("text layer");
    expect(conformityLine(c)).toContain("Could not determine conformity");
    // It still says what WAS seen, so the line is useful, but never as a
    // verdict either way.
    expect(conformityLine(c)).toContain("not a verdict either way");
  });

  it("returns could-not-determine when differences were found too", async () => {
    const c = await checkConformity(
      await tree(FINAL),
      await tree(EXECUTED.replace("$12,500", "$19,500")),
      { executedTextIncomplete: "its words came from OCR, which may have misread them" },
    );
    expect(c.verdict).toBe("could-not-determine");
    expect(c.difference_count).toBeGreaterThan(0);
    // The count is reported as APPARENT, not as a finding.
    expect(conformityLine(c)).toContain("apparent difference");
  });

  it("is unchanged, hash included, when the text is complete", async () => {
    // The guard on the change itself: adding a third state must not move an
    // existing conformity_hash. The new field is spread conditionally for
    // exactly this reason.
    const plain = await checkConformity(await tree(FINAL), await tree(EXECUTED));
    const empty = await checkConformity(await tree(FINAL), await tree(EXECUTED), {});
    expect(plain.verdict).toBe("identical");
    expect(plain.unverified_reason).toBeUndefined();
    expect(empty.conformity_hash).toBe(plain.conformity_hash);
  });

  it("gives a different hash once the verdict changes", async () => {
    const plain = await checkConformity(await tree(FINAL), await tree(EXECUTED));
    const unverified = await checkConformity(await tree(FINAL), await tree(EXECUTED), {
      executedTextIncomplete: "no text could be extracted from it at all",
    });
    expect(unverified.conformity_hash).not.toBe(plain.conformity_hash);
  });
});

describe("the reason comes from the ingest, not from prose matching", () => {
  it("reads a thin text layer off a real multi-page PDF", async () => {
    const bytes = mixedLayerPdf("CONSULTING AGREEMENT between Acme Components and Jordan Lee");
    const ingest = await ingestPdfBuffer(
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
      { allowOcr: false },
    );
    const reason = incompleteTextReason(ingest);
    expect(reason, "a mixed-layer scan must be reported as incomplete").toBeDefined();
    expect(reason).toContain("only some of its pages");
    // And it feeds the verdict end to end.
    const c = await checkConformity(await tree(FINAL), ingest.tree, {
      ...(reason ? { executedTextIncomplete: reason } : {}),
    });
    expect(c.verdict).toBe("could-not-determine");
  }, 30_000);

  it("says nothing about an ordinary pasted document", async () => {
    // The other direction: a complete read must NOT be called incomplete, or
    // every conformity check would return no verdict.
    const ingest = await ingestPaste(EXECUTED);
    expect(incompleteTextReason(ingest)).toBeUndefined();
  });
});

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

/**
 * The WORD-level join (add-executed-copy-conformity task 4's remaining half).
 *
 * ⚠️ I recorded this half as needing "OCR actually running". That was wrong in
 * the same way the verdict half was: OCR is needed to PRODUCE the markers in
 * the wild, but `markLowConfidence` writes them into the text as
 * `word [uncertain]`, so by the time a comparison sees them they are ordinary
 * words. The join acts on text, and text is something a test can write.
 *
 * Why it is worth having on top of the document-level verdict: in an OCR'd
 * signed copy, a difference whose text carries a marker may be the scanner
 * misreading a word, while a difference with no marker near it is a real
 * difference even so. Sweeping both into one "could not determine" tells an
 * attorney to re-read the whole document, when what they need is which few
 * lines to check by eye.
 */
describe("which differences sit on words OCR was unsure of", () => {
  const OCR_REASON = "its words came from OCR, which may have misread them";

  it("names the uncertain words, and leaves a clean difference out", async () => {
    // Two changed figures. One carries an `[uncertain]` marker, one does not.
    const executed = EXECUTED.replace("$12,500 per month", "$12,500 [uncertain] per month").replace(
      "twelve months",
      "eighteen months",
    );
    const c = await checkConformity(await tree(FINAL), await tree(executed), {
      executedTextIncomplete: OCR_REASON,
    });
    expect(c.verdict).toBe("could-not-determine");
    const flagged = c.unverified_differences ?? [];
    expect(flagged.length, JSON.stringify(flagged)).toBeGreaterThan(0);
    // The marker's own word is named, so a reader knows what to look at.
    expect(flagged.flatMap((d) => d.uncertain_words).join(" ")).toContain("$12,500");
    // And the clean difference is NOT flagged: "eighteen months" carries no
    // marker, so it is a real difference even in an OCR'd copy.
    const flaggedText = flagged.map((d) => d.text).join(" ");
    expect(flaggedText).not.toContain("eighteen months");
  });

  it("says nothing when no word is uncertain", async () => {
    const c = await checkConformity(
      await tree(FINAL),
      await tree(EXECUTED.replace("twelve months", "eighteen months")),
      { executedTextIncomplete: OCR_REASON },
    );
    expect(c.verdict).toBe("could-not-determine");
    expect(c.unverified_differences).toBeUndefined();
  });

  it("tells a reader which lines to check, rather than to re-read everything", async () => {
    const executed = EXECUTED.replace("$12,500 per month", "$12,500 [uncertain] per month");
    const c = await checkConformity(await tree(FINAL), await tree(executed), {
      executedTextIncomplete: OCR_REASON,
    });
    const line = conformityLine(c);
    expect(line).toContain("OCR was unsure of");
    expect(line).toContain("check those by eye first");
  });

  it("is derived from the differences, so it moves no conformity_hash", async () => {
    // The list is computed from text the canonical object already covers, so
    // hashing it would add nothing and would move every existing hash for an
    // OCR'd pair. Same reason the DDL notes sit outside their register's hash.
    const executed = EXECUTED.replace("$12,500 per month", "$12,500 [uncertain] per month");
    const withJoin = await checkConformity(await tree(FINAL), await tree(executed), {
      executedTextIncomplete: OCR_REASON,
    });
    const sameTextNoFlag = await checkConformity(await tree(FINAL), await tree(executed), {
      executedTextIncomplete: "no text could be extracted from it at all",
    });
    expect(withJoin.unverified_differences?.length).toBeGreaterThan(0);
    // Different reason strings DO change the hash (the reason is hashed); the
    // derived list does not add to it. Assert the list's own fields are absent
    // from the canonical input by checking the hash depends only on the reason.
    expect(withJoin.conformity_hash).not.toBe(sameTextNoFlag.conformity_hash);
    const repeat = await checkConformity(await tree(FINAL), await tree(executed), {
      executedTextIncomplete: OCR_REASON,
    });
    expect(repeat.conformity_hash).toBe(withJoin.conformity_hash);
  });
});

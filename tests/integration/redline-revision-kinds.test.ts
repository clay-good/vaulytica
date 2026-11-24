/**
 * The rewrite on every revision kind (add-redline-two-sided-analysis task 1,
 * the half that needs no copy of Word).
 *
 * Task 1 asks for a redline carrying "insertions, deletions, a move, a
 * formatting-only change, and a table-cell change", AND for Word's own
 * Accept-All and Reject-All exports of it. The second half genuinely needs
 * Word — the round-trip exists to compare this product's rewrite with what
 * Word produces, and a fixture built here would compare the rewrite with
 * itself. The FIRST half needs nothing of the sort, and was missing: the only
 * fixture builder, `markEveryRun`, wraps every run in `w:ins` or `w:del`, so
 * the three kinds where the rewrite must do something other than keep or drop
 * a run — a move, a formatting-only change, a change inside a table cell —
 * were never exercised.
 *
 * A move is the interesting one. `w:moveFrom` wraps the words at their origin
 * and `w:moveTo` wraps the same words at their destination, so the two
 * readings must each contain the moved text EXACTLY ONCE, in different places:
 * rejected keeps the origin, accepted keeps the destination. Getting that
 * wrong duplicates a clause or loses one, and neither shows up in a test that
 * only counts revision elements.
 */
import { describe, expect, it } from "vitest";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { flattenText } from "../../src/ingest/types.js";
import { fiveKindRedlineDocx, fiveKindRedlineXml } from "./_redline-docx.js";

const MOVED = "Interest accrues at 1% monthly.";

/** A Node Buffer as the ArrayBuffer the ingest takes. */
const asArrayBuffer = (b: Buffer): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

const read = async (revisions: "accepted" | "rejected"): Promise<string> => {
  const r = await ingestDocxBuffer(asArrayBuffer(await fiveKindRedlineDocx()), { revisions });
  return flattenText(r.tree).replace(/\s+/g, " ");
};

describe("the fixture carries all five revision kinds", () => {
  it("has an insertion, a deletion, a move, a formatting-only change and a table cell", () => {
    // Guard the fixture itself: a derivation that silently stopped emitting a
    // kind would make every assertion below vacuous.
    const xml = fiveKindRedlineXml();
    expect(xml).toContain("<w:ins ");
    expect(xml).toContain("<w:del ");
    expect(xml).toContain("<w:moveFrom ");
    expect(xml).toContain("<w:moveTo ");
    expect(xml).toContain("<w:rPrChange ");
    expect(xml).toContain("<w:tbl>");
    // The move's two halves must carry the SAME words, or it is not a move.
    const from = /<w:moveFrom [^>]*>.*?<w:delText[^>]*>(.*?)<\/w:delText>/.exec(xml)?.[1];
    const to = /<w:moveTo [^>]*>.*?<w:t[^>]*>(.*?)<\/w:t>/.exec(xml)?.[1];
    expect(from).toBe(MOVED);
    expect(to).toBe(MOVED);
  });
});

describe("both readings of a five-kind redline", () => {
  it("leave no revision element in either reading", async () => {
    for (const side of ["accepted", "rejected"] as const) {
      const r = await ingestDocxBuffer(asArrayBuffer(await fiveKindRedlineDocx()), {
        revisions: side,
      });
      const text = flattenText(r.tree);
      for (const marker of ["w:ins", "w:del", "w:moveFrom", "w:moveTo", "w:rPrChange"]) {
        expect(text, `${side} leaked ${marker}`).not.toContain(marker);
      }
    }
  }, 60_000);

  it("takes the insertion only when accepted, and the deletion only when rejected", async () => {
    const accepted = await read("accepted");
    const rejected = await read("rejected");
    expect(accepted).toContain("fifteen (15) days");
    expect(accepted).not.toContain("thirty (30) days");
    expect(rejected).toContain("thirty (30) days");
    expect(rejected).not.toContain("fifteen (15) days");
  }, 60_000);

  it("keeps a moved clause EXACTLY ONCE in each reading, in different places", async () => {
    // 🚨 The failure this guards: a rewrite that drops neither half duplicates
    // the clause, and one that drops both loses it. Counting revision elements
    // sees neither.
    const accepted = await read("accepted");
    const rejected = await read("rejected");
    const count = (s: string): number => s.split(MOVED).length - 1;
    expect(count(accepted), "accepted must keep the destination, once").toBe(1);
    expect(count(rejected), "rejected must keep the origin, once").toBe(1);
    // And at different positions: the origin sits in the payment clause, the
    // destination in the remedies clause.
    expect(rejected).toContain(`Payment is due on invoice. ${MOVED}`);
    expect(accepted).toContain(`Remedies are cumulative. ${MOVED}`);
    expect(accepted).not.toContain(`Payment is due on invoice. ${MOVED}`);
    expect(rejected).not.toContain(`Remedies are cumulative. ${MOVED}`);
  }, 60_000);

  it("leaves a formatting-only change's text identical on both sides", async () => {
    // `w:rPrChange` carries no text, so it can move no words. If it did, the
    // two readings would disagree about a sentence nobody edited.
    const disclaimer = "THE SUPPLIER DISCLAIMS THE WARRANTY OF MERCHANTABILITY.";
    expect(await read("accepted")).toContain(disclaimer);
    expect(await read("rejected")).toContain(disclaimer);
  }, 60_000);

  it("applies a change inside a table cell like any other", async () => {
    // A revision nested in `w:tc` is the case a run-level rewrite is most
    // likely to miss, because the element sits inside table markup.
    const accepted = await read("accepted");
    const rejected = await read("rejected");
    expect(accepted).toContain("$14,500");
    expect(accepted).not.toContain("$10,000");
    expect(rejected).toContain("$10,000");
    expect(rejected).not.toContain("$14,500");
    // The cell's untouched neighbour survives both readings.
    expect(accepted).toContain("Tier 1");
    expect(rejected).toContain("Tier 1");
  }, 60_000);
});

import { describe, expect, it } from "vitest";
import { extractDates } from "./dates.js";
import { buildTree } from "./_fixtures.js";

// Guard: an ANCHORED deadline stated as a notice period — with a possessive
// apostrophe ("30 days'") or an intervening "notice" phrase — must still resolve
// to its offset and named anchor, so the deadline is computable. A bare notice
// period with no anchor must stay unextracted (nothing to compute against).
const ANCHORED: Array<[text: string, days: number, anchor: RegExp]> = [
  ["Terminable on 60 days' written notice before the Expiration Date.", -60, /Expiration Date/i],
  ["The deposit is due 30 days' before the Closing Date.", -30, /Closing Date/i],
  ["Either party may terminate on 30 days' notice prior to the Renewal Date.", -30, /Renewal Date/i],
  ["The report is due 30 days notice after the Effective Date.", 30, /Effective Date/i],
  ["Payment is due within 30 days after the Effective Date.", 30, /Effective Date/i],
];

describe("relative-deadline possessive/notice guard", () => {
  for (const [text, days, anchor] of ANCHORED) {
    it(`parses ${days}d anchored for: ${text.slice(0, 42)}`, () => {
      const rel = extractDates(buildTree(["Body", text])).find(
        (d) => d.type === "relative" && d.offset_days === days,
      );
      expect(rel, `NO REL ${days} for: ${text}`).toBeTruthy();
      expect(rel!.anchor ?? "").toMatch(anchor);
    });
  }

  it("yields nothing for an unanchored notice period", () => {
    const rel = extractDates(
      buildTree(["Body", "Termination requires 90 days' prior written notice."]),
    ).filter((d) => d.type === "relative");
    expect(rel).toHaveLength(0);
  });
});

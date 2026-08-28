/**
 * The excerpt is what a reader actually sees.
 *
 * A raw `slice(index - 30, index + 280)` cuts whatever happens to be at the
 * edge, and across the twenty-eight banked specimens that produced "n (11)
 * paid holidays per contract year", "perty in the ordinary course", "ter
 * requires, and we will use reasonable efforts", and "al Statements. The
 * Financial Statements attached as Schedule". A finding that quotes half a
 * word reads as a broken tool, whatever it says next. On the committed
 * fixtures the same defect had shipped as "ay terminate this Agreement" and
 * "ll disputes shall be resolved on an individual basis".
 *
 * The window is widened, never narrowed: each edge moves outward to the
 * nearest boundary, so no matched text is lost.
 */
import { describe, expect, it } from "vitest";
import { excerptWindow } from "./_helpers.js";

const TEXT =
  "The Company may terminate this Agreement at any time in its sole discretion, and all disputes shall be resolved on an individual basis only.";

describe("excerptWindow", () => {
  it("moves the start off a partial word", () => {
    const at = TEXT.indexOf("terminate");
    // A 6-character lookback lands inside "Company" ("y may "); the edge moves
    // OUTWARD to the word start rather than quoting "y may terminate".
    expect(excerptWindow(TEXT, at, 6, 40).startsWith("Company may terminate")).toBe(true);
  });

  it("moves the end off a partial word", () => {
    const at = TEXT.indexOf("may");
    // A window of 8 lands inside "terminate" ("may term").
    expect(excerptWindow(TEXT, at, 0, 8)).toBe("may terminate");
  });

  it("leaves a window that already lands on boundaries unchanged", () => {
    const at = TEXT.indexOf("all disputes");
    expect(excerptWindow(TEXT, at, 0, 12)).toBe("all disputes");
  });

  it("never loses the matched text", () => {
    const at = TEXT.indexOf("individual");
    const out = excerptWindow(TEXT, at, 20, 30);
    expect(out).toContain("individual basis");
  });

  it("clamps at the ends of the text", () => {
    expect(excerptWindow(TEXT, 0, 50, 11)).toBe("The Company");
    const tail = excerptWindow(TEXT, TEXT.length - 6, 6, 50);
    expect(TEXT.endsWith(tail)).toBe(true);
  });

  it("does not run away on a long unbroken token", () => {
    // The snap is bounded, so a pathological run of word characters cannot
    // drag the window arbitrarily far.
    const long = `x${"a".repeat(400)}y`;
    expect(excerptWindow(long, 200, 10, 10).length).toBeLessThanOrEqual(20 + 24 * 2);
  });
});

import { describe, expect, it } from "vitest";
import { rule as CHOICE_007 } from "./CHOICE-007.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (t: string) =>
  CHOICE_007.check(buildContext(["Consumer Terms of Service", t])) !== null;

describe("CHOICE-007 — class-action waiver recognizes passive & long-parenthetical forms (v1.2.0)", () => {
  it.each([
    "You agree to a class action waiver.",
    "You waive any right to a class action.",
    "The right to bring a class action is hereby waived by you.",
    "You waive, to the fullest extent permitted by law, any right to bring or participate in a class action.",
    "Any right to participate in a class action is expressly waived.",
  ])("fires on a class-action waiver in a consumer contract: %s", (t) => {
    expect(fires(t)).toBe(true);
  });

  it.each([
    "You do not waive your right to a class action.",
    "Nothing herein waives your right to a class action.",
    "This agreement does not contain a class action waiver.",
    "The right to a class action is not waived.",
  ])("stays silent on a preserved / negated class-action right: %s", (t) => {
    expect(fires(t)).toBe(false);
  });

  it("does not fire outside a consumer-facing document", () => {
    expect(
      CHOICE_007.check(
        buildContext([
          "Master Services Agreement",
          "The parties waive any right to a class action.",
        ]),
      ),
    ).toBeNull();
  });
});

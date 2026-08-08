import { describe, expect, it } from "vitest";
import { rule as CHOICE_008 } from "./CHOICE-008.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (t: string) => CHOICE_008.check(buildContext(["Disputes", t])) !== null;

describe("CHOICE-008 — jury-trial waiver recognizes passive & long-parenthetical forms (v1.2.0)", () => {
  it.each([
    "Each party waives any right to trial by jury.",
    "The parties waive all rights to a jury trial.",
    "The right to a jury trial is hereby waived by each party.",
    "Any and all rights to a trial by jury are hereby waived.",
    "Each party knowingly and voluntarily waives, to the fullest extent permitted by law, any right it may have to a trial by jury.",
  ])("fires on a jury-trial waiver: %s", (t) => {
    expect(fires(t)).toBe(true);
  });

  it.each([
    "The parties do not waive any right to a jury trial.",
    "Nothing herein waives the right to a jury trial.",
    "Each party retains its right to a jury trial.",
    "The right to a jury trial is not waived by either party.",
  ])("stays silent on a preserved / negated jury-trial right: %s", (t) => {
    expect(fires(t)).toBe(false);
  });
});

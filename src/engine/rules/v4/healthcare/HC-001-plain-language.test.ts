import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const HC001 = V4_RULES.find((r) => r.id === "HC-001") as Rule;

/**
 * 21 CFR 50.25 asks for a PLAIN-LANGUAGE explanation, and a well-drafted
 * consent form gives one. Demanding the regulation's own vocabulary —
 * "purpose", "duration" — reported the form the regulation asks for as missing
 * its first element, at `critical`.
 */
describe("HC-001 — the consent form 21 CFR 50.25 asks for", () => {
  it("reads the plain-language purpose and duration", () => {
    expect(
      HC001.check(
        buildContext([
          "Consent to Participate in a Research Study",
          "You are being asked to take part in a research study. WHY THIS STUDY IS BEING DONE. Early retinal disease is often missed by current screening.",
          "WHAT WILL HAPPEN. You will have four visits over eighteen months. Each visit takes about ninety minutes.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a form that says nothing about why or how long", () => {
    expect(
      HC001.check(
        buildContext([
          "Consent",
          "You are being asked to take part in a study. Please sign below if you agree.",
        ]),
      ),
    ).not.toBeNull();
  });
});

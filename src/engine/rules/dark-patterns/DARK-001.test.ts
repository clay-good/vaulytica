import { describe, expect, it } from "vitest";
import { rule as DARK_001 } from "./DARK-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Modifications", ...paras]);

describe("DARK-001 — unilateral modification right", () => {
  it("fires on the enumerated party + modify form", () => {
    expect(DARK_001.check(doc("The Company may modify these Terms at any time."))).not.toBeNull();
  });

  it("reads the consumer 'we may update / revise' forms (v1.1.0)", () => {
    for (const clause of [
      "We may update these Terms at any time without notice.",
      "We reserve the right to modify the Terms in our sole discretion.",
      "The Company may revise these Terms from time to time.",
      "The Company reserves the right to update these Terms at any time.",
    ]) {
      expect(DARK_001.check(doc(clause)), clause).not.toBeNull();
    }
  });

  it("does not fire on a mutual amendment clause", () => {
    expect(
      DARK_001.check(
        doc("This Agreement may be amended only by a written instrument signed by both parties."),
      ),
    ).toBeNull();
    expect(
      DARK_001.check(doc("The parties may amend this Agreement by mutual written agreement.")),
    ).toBeNull();
  });

  it("is suppressed when the customer has a corresponding termination right", () => {
    expect(
      DARK_001.check(
        doc(
          "The Company may modify these Terms at any time; the Customer may terminate upon notice if it objects.",
        ),
      ),
    ).toBeNull();
  });
});

describe("DARK-001 — a party by its own name, an instrument by its own (1.3.0)", () => {
  it("reads a named party and a memorandum", () => {
    for (const clause of [
      "Harbor Arts Collective may amend this Memorandum at any time without notice.",
      "The University may revise this Memorandum from time to time.",
      "Sponsor reserves the right to change this Order Form.",
      "Host may modify this Lease in its sole discretion.",
    ]) {
      expect(DARK_001.check(doc(clause)), clause).not.toBeNull();
    }
  });

  it("does not take a mutual subject for a party", () => {
    for (const clause of [
      "Either Party may amend this Agreement at any time by written notice signed by both parties.",
      "The Parties may amend this Memorandum at any time.",
      "Neither Party may modify this Agreement without notice to the other.",
      "Harbor Arts Collective may amend this Memorandum at any time with the written consent of Dana Whitfield.",
    ]) {
      expect(DARK_001.check(doc(clause)), clause).toBeNull();
    }
  });
});

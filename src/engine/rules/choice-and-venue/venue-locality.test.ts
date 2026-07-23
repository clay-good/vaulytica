/**
 * A venue clause names a courthouse, and a courthouse sits in a city. The
 * jurisdiction extractor stopped its capture at the comma, so "the state or
 * federal courts located in Wilmington, Delaware" was recorded as venue
 * "Wilmington" — a name no governing-law clause ever uses.
 *
 * Every rule that reconciles law against venue then reported a mismatch the
 * document does not contain. On the corpus's own minimal-PASS MSA (Delaware
 * law, Wilmington courts) that was four simultaneous false findings, one of
 * them calling Wilmington a "foreign venue without standard enforceability
 * treaty". Regenerating the corpus after the fix removed those four findings
 * from 62 fixtures and added none.
 *
 * CHOICE-005 carried the same defect in its own list: it recognized eleven
 * commercial states, so a venue in any of the other thirty-nine — Boise,
 * Idaho — was reported as a foreign venue needing a treaty path.
 */
import { describe, expect, it } from "vitest";
import { rule as CHOICE_004 } from "./CHOICE-004.js";
import { rule as CHOICE_005 } from "./CHOICE-005.js";
import { rule as CHOICE_009 } from "./CHOICE-009.js";
import { rule as CHOICE_012 } from "./CHOICE-012.js";
import { buildContext } from "../../_test-fixtures.js";

const aligned = () =>
  buildContext([
    "Governing Law; Venue",
    "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware, without regard to its conflict-of-laws principles.",
    "Any dispute arising under this Agreement shall be resolved exclusively in the state or federal courts located in Wilmington, Delaware, and the parties hereby consent to the personal jurisdiction of such courts.",
  ]);

describe("a venue named by city and state is that state", () => {
  it("no law-vs-venue rule fires on Delaware law with Delaware courts", () => {
    const ctx = aligned();
    expect(CHOICE_004.check(ctx)).toBeNull();
    expect(CHOICE_009.check(ctx)).toBeNull();
    expect(CHOICE_012.check(ctx)).toBeNull();
  });

  it("a Delaware city is not a foreign venue", () => {
    expect(CHOICE_005.check(aligned())).toBeNull();
  });

  it("still reports a genuine mismatch, naming the venue's state", () => {
    const ctx = buildContext([
      "Governing Law; Venue",
      "This Agreement shall be governed by the laws of the State of Delaware.",
      "Any dispute shall be resolved exclusively in the state and federal courts located in San Francisco, California.",
    ]);
    expect(CHOICE_004.check(ctx)?.title).toMatch(/California/);
    expect(CHOICE_009.check(ctx)).not.toBeNull();
    expect(CHOICE_012.check(ctx)).not.toBeNull();
  });
});

describe("CHOICE-005 — foreign venue", () => {
  it("does not call a venue in a less commercial state foreign", () => {
    const ctx = buildContext([
      "Venue",
      "Exclusive venue shall be in the state courts located in Boise, Idaho.",
    ]);
    expect(CHOICE_005.check(ctx)).toBeNull();
  });

  it("still flags a venue outside the United States", () => {
    const ctx = buildContext(["Venue", "Exclusive venue shall be in the courts of Ulaanbaatar."]);
    expect(CHOICE_005.check(ctx)).not.toBeNull();
  });
});

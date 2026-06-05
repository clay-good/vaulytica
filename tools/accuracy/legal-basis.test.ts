/**
 * Unit tests for the legal-basis ledger logic (spec-v5 §12–§14, Step 75).
 * Exercises the schema, the verdict→tier derivation, and dedup on synthetic
 * entries — independent of the real (honestly empty) committed ledger.
 */

import { describe, expect, it } from "vitest";

import {
  LegalBasisEntrySchema,
  indexLedger,
  tierForRule,
  ledgerCoverage,
  type LegalBasisEntry,
} from "./legal-basis.js";

function entry(over: Partial<LegalBasisEntry> = {}): LegalBasisEntry {
  return {
    rule_id: "BAA-019",
    claim: "A BAA must require the BA to report breaches of unsecured PHI to the CE.",
    legal_basis: [{ authority: "45 C.F.R. § 164.410", pinpoint: "(a)(1)", dkb_node: "hipaa-baa-breach-notification" }],
    review: { reviewer: "att-007", credential: "JD, NY bar (on file)", date: "2026-06-15", verdict: "sound", tier: "established" },
    ...over,
  };
}

describe("LegalBasisEntrySchema", () => {
  it("accepts a well-formed entry", () => {
    expect(() => LegalBasisEntrySchema.parse(entry())).not.toThrow();
  });

  it("rejects an empty legal_basis (spec-v5 §12: must be non-empty, DKB-linked)", () => {
    expect(() => LegalBasisEntrySchema.parse(entry({ legal_basis: [] }))).toThrow();
  });

  it("rejects a stray key (strict)", () => {
    expect(() => LegalBasisEntrySchema.parse({ ...entry(), bogus: 1 })).toThrow();
  });

  it("rejects a malformed date", () => {
    const bad = entry();
    bad.review = { ...bad.review, date: "June 15 2026" };
    expect(() => LegalBasisEntrySchema.parse(bad)).toThrow();
  });

  it("rejects an unknown verdict / tier", () => {
    expect(() => LegalBasisEntrySchema.parse({ ...entry(), review: { ...entry().review, verdict: "ok" } })).toThrow();
    expect(() => LegalBasisEntrySchema.parse({ ...entry(), review: { ...entry().review, tier: "gut-feel" } })).toThrow();
  });
});

describe("indexLedger", () => {
  it("throws on a duplicate rule_id", () => {
    expect(() => indexLedger([entry(), entry()])).toThrow(/duplicate/);
  });
});

describe("tierForRule (spec-v5 §14 verdict→tier derivation)", () => {
  it("returns the signed tier for a sound rule", () => {
    expect(tierForRule([entry()], "BAA-019")).toBe("established");
  });

  it("returns undefined for an unmentioned rule", () => {
    expect(tierForRule([entry()], "MSA-001")).toBeUndefined();
  });

  it("caps a disputed rule at opinion regardless of recorded tier", () => {
    const e = entry({ review: { ...entry().review, verdict: "disputed", tier: "established" } });
    expect(tierForRule([e], "BAA-019")).toBe("opinion");
  });

  it("returns undefined for an unsound rule (must be retired, not surfaced)", () => {
    const e = entry({ review: { ...entry().review, verdict: "unsound" } });
    expect(tierForRule([e], "BAA-019")).toBeUndefined();
  });
});

describe("ledgerCoverage", () => {
  it("reports honest signed/total and per-verdict/tier rollups", () => {
    const cov = ledgerCoverage([entry(), entry({ rule_id: "MSA-006", review: { ...entry().review, verdict: "disputed", tier: "opinion" } })], 1062);
    expect(cov).toMatchObject({
      total_rules: 1062,
      signed: 2,
      by_verdict: { sound: 1, "sound-but-narrow": 0, disputed: 1, unsound: 0 },
      by_tier: { established: 1, "prevailing-practice": 0, opinion: 1 },
    });
  });

  it("is empty for the empty ledger", () => {
    expect(ledgerCoverage([], 1062)).toMatchObject({ total_rules: 1062, signed: 0 });
  });
});

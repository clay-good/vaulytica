import { describe, expect, it } from "vitest";
import { framesForRule, filterRulesByFrames } from "./frame-filter.js";
import type { Rule } from "../engine/index.js";

function fakeRule(id: string): Rule {
  return {
    id,
    version: "1.0.0",
    name: id,
    description: id,
    citation: "test",
    severity: "info",
    category: "structural",
    check: () => null,
  } as unknown as Rule;
}

describe("framesForRule", () => {
  it("BAA-* rules are gated by HIPAA", () => {
    expect(framesForRule("BAA-001")).toEqual(["HIPAA"]);
    expect(framesForRule("BAA-042")).toEqual(["HIPAA"]);
  });

  it("DPA-* (EU controller↔processor) rules are gated by GDPR", () => {
    expect(framesForRule("DPA-001")).toEqual(["GDPR"]);
    expect(framesForRule("DPA-024")).toEqual(["GDPR"]);
  });

  it("USDPA-* rules are gated by every US state privacy statute (CCPA + 7 siblings)", () => {
    const out = framesForRule("USDPA-001");
    expect(out).toEqual(
      expect.arrayContaining(["CCPA", "VCDPA", "CPA", "CTDPA", "UCPA", "TDPSA", "OCPA", "DPDPA"]),
    );
    expect(out).toHaveLength(8);
  });

  it("USDPA- prefix wins over DPA- prefix (longer match)", () => {
    // Regression guard: a naive prefix-table that didn't sort by length
    // would map USDPA-001 to ["GDPR"].
    expect(framesForRule("USDPA-001")).not.toContain("GDPR");
  });

  it("TRANSFER-* rules are gated by GDPR + UK-GDPR", () => {
    expect(framesForRule("TRANSFER-001")).toEqual(["GDPR", "UK-GDPR"]);
  });

  it("ADDENDA-001..009 (vendor security) have no frame — playbook-bound", () => {
    expect(framesForRule("ADDENDA-001")).toEqual([]);
    expect(framesForRule("ADDENDA-009")).toEqual([]);
  });

  it("ADDENDA-010..016 (AI Addendum) are gated by NIST-AI-RMF + EU-AI-Act", () => {
    expect(framesForRule("ADDENDA-010")).toEqual(["NIST-AI-RMF", "EU-AI-Act"]);
    expect(framesForRule("ADDENDA-016")).toEqual(["NIST-AI-RMF", "EU-AI-Act"]);
  });

  it("ADDENDA-017..018 (EULA) have no frame — playbook-bound", () => {
    expect(framesForRule("ADDENDA-017")).toEqual([]);
    expect(framesForRule("ADDENDA-018")).toEqual([]);
  });

  it("ADDENDA-019 (FTC Click-to-Cancel) is gated by FTC-ROSCA", () => {
    expect(framesForRule("ADDENDA-019")).toEqual(["FTC-ROSCA"]);
  });

  it("ADDENDA-020 (privacy policy) is gated by GDPR + CCPA", () => {
    expect(framesForRule("ADDENDA-020")).toEqual(["GDPR", "CCPA"]);
  });

  it("V1 launch rule prefixes (STRUCT, FIN, TEMP, etc.) are unframed", () => {
    for (const id of [
      "STRUCT-001",
      "FIN-007",
      "TEMP-004",
      "OBLIG-001",
      "RISK-007",
      "CHOICE-009",
      "TERM-009",
      "IPDATA-008",
      "PERS-009",
      "DARK-001",
    ]) {
      expect(framesForRule(id), `${id} should be unframed`).toEqual([]);
    }
  });

  it("V3 deep-rule prefixes (NDA-D, MSA) are unframed", () => {
    expect(framesForRule("NDA-D-001")).toEqual([]);
    expect(framesForRule("MSA-006")).toEqual([]);
  });

  it("V4 rule prefixes are unframed (no frame mapping for governance, employment, etc.)", () => {
    for (const id of ["GOV-005", "EMP-006", "PRV-001", "EQT-003", "RE-003", "BNK-012", "HC-014"]) {
      expect(framesForRule(id), `${id} should be unframed`).toEqual([]);
    }
  });

  it("returns [] for an unknown prefix", () => {
    expect(framesForRule("UNKNOWN-001")).toEqual([]);
  });
});

describe("filterRulesByFrames", () => {
  const rules = [
    fakeRule("STRUCT-001"),
    fakeRule("BAA-001"),
    fakeRule("DPA-007"),
    fakeRule("USDPA-001"),
    fakeRule("TRANSFER-003"),
    fakeRule("ADDENDA-010"), // AI
    fakeRule("ADDENDA-019"), // FTC ROSCA
    fakeRule("ADDENDA-020"), // privacy policy → GDPR + CCPA
    fakeRule("NDA-D-001"),
  ];

  it("undefined activeFrames keeps every rule (preserves default behavior)", () => {
    expect(filterRulesByFrames(rules, undefined).map((r) => r.id)).toEqual(rules.map((r) => r.id));
  });

  it("empty activeFrames drops every frame-gated rule, keeps the unframed ones", () => {
    const out = filterRulesByFrames(rules, []).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "NDA-D-001"]);
  });

  it("HIPAA-only keeps BAA-* + unframed rules", () => {
    const out = filterRulesByFrames(rules, ["HIPAA"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "BAA-001", "NDA-D-001"]);
  });

  it("GDPR-only keeps DPA-* + TRANSFER-* + ADDENDA-020 + unframed rules", () => {
    const out = filterRulesByFrames(rules, ["GDPR"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "DPA-007", "TRANSFER-003", "ADDENDA-020", "NDA-D-001"]);
  });

  it("CCPA-only keeps USDPA-* + ADDENDA-020 + unframed rules", () => {
    const out = filterRulesByFrames(rules, ["CCPA"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "USDPA-001", "ADDENDA-020", "NDA-D-001"]);
  });

  it("VCDPA-only keeps USDPA-* + unframed rules (other US state laws also trigger USDPA-*)", () => {
    const out = filterRulesByFrames(rules, ["VCDPA"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "USDPA-001", "NDA-D-001"]);
  });

  it("NIST-AI-RMF-only keeps AI ADDENDA + unframed rules", () => {
    const out = filterRulesByFrames(rules, ["NIST-AI-RMF"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "ADDENDA-010", "NDA-D-001"]);
  });

  it("FTC-ROSCA-only keeps ADDENDA-019 + unframed rules", () => {
    const out = filterRulesByFrames(rules, ["FTC-ROSCA"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "ADDENDA-019", "NDA-D-001"]);
  });

  it("multi-frame activation is a union (HIPAA + FTC-ROSCA keeps both)", () => {
    const out = filterRulesByFrames(rules, ["HIPAA", "FTC-ROSCA"]).map((r) => r.id);
    expect(out).toEqual(["STRUCT-001", "BAA-001", "ADDENDA-019", "NDA-D-001"]);
  });

  it("filtering is pure — does not mutate the input array", () => {
    const before = rules.map((r) => r.id);
    filterRulesByFrames(rules, ["HIPAA"]);
    expect(rules.map((r) => r.id)).toEqual(before);
  });
});

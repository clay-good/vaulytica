import { describe, expect, it } from "vitest";
import { rule as IPDATA_008 } from "./IPDATA-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-008 — cross-border data transfer without safeguard", () => {
  it("fires when transfer outside EU is authorized without SCCs", () => {
    const ctx = buildContext([
      "Data Processing",
      "Vendor may transfer Customer Data outside the EEA to its US-based data centers.",
    ]);
    const f = IPDATA_008.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/without\s+safeguard/i);
  });

  it("fires on cross-border processing without mechanism", () => {
    const ctx = buildContext([
      "Processing",
      "Personal data may be processed outside the United Kingdom for support purposes.",
    ]);
    expect(IPDATA_008.check(ctx)).not.toBeNull();
  });

  it("is silent when SCCs are referenced", () => {
    const ctx = buildContext([
      "Data Processing",
      "Vendor may transfer Customer Data outside the EEA, subject to the Standard Contractual Clauses.",
    ]);
    expect(IPDATA_008.check(ctx)).toBeNull();
  });

  it("is silent when Data Privacy Framework is referenced", () => {
    const ctx = buildContext([
      "Data Processing",
      "Cross-border transfers to the United States are made under the EU-US Data Privacy Framework.",
    ]);
    expect(IPDATA_008.check(ctx)).toBeNull();
  });

  it("is silent when BCRs are referenced", () => {
    const ctx = buildContext([
      "Processing",
      "Vendor's Binding Corporate Rules govern any international transfer of personal data.",
    ]);
    expect(IPDATA_008.check(ctx)).toBeNull();
  });

  it("is silent when no cross-border transfer language exists", () => {
    const ctx = buildContext([
      "Confidentiality",
      "Recipient shall protect Confidential Information.",
    ]);
    expect(IPDATA_008.check(ctx)).toBeNull();
  });
});

describe("a disclaimed transfer needs no safeguard (v1.1.0)", () => {
  it("stays silent on 'No transfers outside the EEA occur'", () => {
    const ctx = buildContext([
      "Recipients",
      "Recipients are the customer fleet operator and our sub-processors listed in Annex 1. No transfers outside the EEA occur.",
    ]);
    expect(IPDATA_008.check(ctx)).toBeNull();
  });

  it("still fires on a real transfer with no safeguard named", () => {
    const ctx = buildContext([
      "Transfers",
      "Vendor may transfer Customer Data to the United States for support purposes.",
    ]);
    expect(IPDATA_008.check(ctx)).not.toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { rule as IPDATA_007 } from "./IPDATA-007.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-007 — data retention period unspecified", () => {
  it("fires when Customer Data is referenced and no retention clause exists", () => {
    const ctx = buildContext([
      "Data",
      "Vendor will store Customer Data on its infrastructure as needed to provide the Service.",
    ]);
    const f = IPDATA_007.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/retention/i);
  });

  it("fires when a DPA is incorporated by reference but no retention text appears in-document", () => {
    const ctx = buildContext([
      "Data Processing",
      "The parties' obligations regarding personal data are governed by the DPA attached as Exhibit B.",
    ]);
    expect(IPDATA_007.check(ctx)).not.toBeNull();
  });

  it("is silent when a retention period is specified", () => {
    const ctx = buildContext([
      "Data",
      "Vendor will store Customer Data only as long as needed to provide the Service.",
      "Upon termination, Vendor shall delete or return all Customer Data within 30 days.",
    ]);
    expect(IPDATA_007.check(ctx)).toBeNull();
  });

  it("is silent when the contract doesn't handle data", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement is effective for two (2) years from the Effective Date.",
    ]);
    expect(IPDATA_007.check(ctx)).toBeNull();
  });

  it("is silent on `return or destroy` survival language", () => {
    const ctx = buildContext([
      "Confidentiality",
      "Recipient shall hold Customer Data in confidence.",
      "Upon termination, Recipient shall return or destroy all Customer Data.",
    ]);
    expect(IPDATA_007.check(ctx)).toBeNull();
  });

  it("is silent when retention is stated as 'stored/kept/held for <N> …' or a 'storage period' (v1.1.0)", () => {
    for (const clause of [
      "Customer Data will be stored for 90 days and no longer.",
      "Customer Data is kept for 12 months following termination.",
      "Customer Data will be held for no longer than 24 months.",
      "The storage period for Customer Data is defined in Exhibit B.",
    ]) {
      const ctx = buildContext([
        "Data",
        "The Vendor processes Customer Data on the Company's behalf.",
        "Terms",
        clause,
      ]);
      expect(IPDATA_007.check(ctx), clause).toBeNull();
    }
  });

  it("still fires when a data contract only says data is 'kept for internal use' (v1.1.0)", () => {
    const ctx = buildContext([
      "Data",
      "The Vendor processes Customer Data on the Company's behalf.",
      "Records",
      "Records are kept for internal use by the finance team.",
    ]);
    expect(IPDATA_007.check(ctx)).not.toBeNull();
  });
});

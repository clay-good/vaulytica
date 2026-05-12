import { describe, expect, it } from "vitest";
import { rule as TEMP_012 } from "./TEMP-012.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TEMP-012 — survival clause silent on sticky obligations", () => {
  it("fires when confidentiality + IP exist but survival names neither", () => {
    const ctx = buildContext(
      ["Confidentiality", "Recipient shall protect Confidential Information using reasonable care."],
      ["IP Assignment", "All work for hire produced by Consultant shall be owned by Company."],
      ["Survival", "Sections 4 and 5 of this Agreement shall survive termination."],
    );
    const f = TEMP_012.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(/confidentiality.*IP/i);
  });

  it("fires when indemnity exists but survival doesn't name it", () => {
    const ctx = buildContext(
      ["Indemnification", "Vendor shall indemnify Customer against any third-party claim."],
      ["Survival", "The confidentiality obligations shall survive termination."],
    );
    const f = TEMP_012.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.description).toMatch(/indemnif/i);
  });

  it("is silent when survival expressly names every present sticky obligation", () => {
    const ctx = buildContext(
      ["Confidentiality", "Recipient shall protect Confidential Information."],
      ["Indemnification", "Vendor shall indemnify Customer."],
      ["Survival", "The provisions regarding confidentiality and indemnification obligations shall survive termination of this Agreement."],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });

  it("is silent when no survival clause exists (different rule's territory)", () => {
    const ctx = buildContext(
      ["Confidentiality", "Recipient shall protect Confidential Information."],
      ["Indemnification", "Vendor shall indemnify Customer."],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });

  it("is silent when no sticky obligations are present", () => {
    const ctx = buildContext(
      ["Term", "This Agreement is effective for two years."],
      ["Survival", "The notice provisions shall survive termination."],
    );
    expect(TEMP_012.check(ctx)).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { rule as PERS_006 } from "./PERS-006.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-006 — non-disparagement clause present", () => {
  it("fires on `non-disparagement`", () => {
    const ctx = buildContext([
      "Separation",
      "Employee enters into a non-disparagement obligation that continues indefinitely.",
    ]);
    expect(PERS_006.check(ctx)?.severity).toBe("warning");
  });

  it("fires on `shall not disparage`", () => {
    const ctx = buildContext([
      "Severance Agreement",
      "Employee shall not disparage the Company, its officers, or its products.",
    ]);
    expect(PERS_006.check(ctx)).not.toBeNull();
  });

  it("fires on `agrees not to disparage`", () => {
    const ctx = buildContext([
      "Mutual Release",
      "Each party agrees not to disparage the other in any public or private communication.",
    ]);
    expect(PERS_006.check(ctx)).not.toBeNull();
  });

  it("is silent on confidentiality language alone", () => {
    const ctx = buildContext([
      "Confidentiality",
      "Recipient shall protect Confidential Information using reasonable care.",
    ]);
    expect(PERS_006.check(ctx)).toBeNull();
  });

  it("reads the verb forms the enumerated list missed (v1.1.0)", () => {
    for (const clause of [
      "Employee will not disparage the Company or its officers.",
      "Employee shall refrain from disparaging the Company.",
      "Employee shall make no disparaging statements about the Company.",
      "Employee is prohibited from disparaging the Employer.",
    ]) {
      expect(PERS_006.check(buildContext(["Non-Disparagement", clause])), clause).not.toBeNull();
    }
  });
});

/**
 * The explanation says a clause WITHOUT carve-outs is indefensible, and the
 * recommendation says to add them — and the rule never looked for them. A
 * clean severance agreement whose clause carves out "any statement protected
 * by … Section 7 of the National Labor Relations Act", beside a Protected
 * Rights section preserving EEOC, NLRB and SEC charges, was told at `warning`
 * to add both. A rule that states a precondition must test it.
 */
describe("PERS-006 — reads the carve-outs it recommends", () => {
  const NONDISP =
    "Employee shall not make any false and disparaging statement about the Company's products or services.";
  const NLRA =
    "This Section does not restrict any statement protected by Section 7 of the National Labor Relations Act.";
  const AGENCY =
    "Nothing in this Agreement prevents Employee from filing a charge with, or participating in an investigation by, the Equal Employment Opportunity Commission, the National Labor Relations Board, or the Securities and Exchange Commission.";

  it("is info, naming what is present, when the NLRA and agency carve-outs are both there", () => {
    const f = PERS_006.check(buildContext(["Separation Agreement", `${NONDISP} ${NLRA}`, AGENCY]));
    expect(f?.severity).toBe("info");
    expect(f?.title).toBe("Non-disparagement clause present, with protected-activity carve-outs");
    expect(f?.recommendation).not.toMatch(/NLRA-protected/);
  });

  it("stays a warning and names the missing carve-out when only one is there", () => {
    const f = PERS_006.check(buildContext(["Separation Agreement", `${NONDISP} ${NLRA}`]));
    expect(f?.severity).toBe("warning");
    expect(f?.recommendation).toMatch(/agency/i);
    expect(f?.recommendation).not.toMatch(/NLRA-protected/);
  });
});

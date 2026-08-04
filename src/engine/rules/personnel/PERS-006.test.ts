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

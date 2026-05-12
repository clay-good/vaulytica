import { describe, expect, it } from "vitest";
import { rule as PERS_008 } from "./PERS-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-008 — training-repayment / stay-or-pay", () => {
  it("fires on `repayment of training cost`", () => {
    const ctx = buildContext([
      "Training",
      "If Employee terminates within twenty-four (24) months, Employee shall be liable for repayment of the full training cost of $15,000.",
    ]);
    const f = PERS_008.check(ctx);
    expect(f?.severity).toBe("critical");
    expect(f?.title).toMatch(/training-repayment|stay-or-pay/i);
  });

  it("fires on `reimburse Company for the cost of training`", () => {
    const ctx = buildContext([
      "Vesting",
      "Employee agrees to reimburse Company for the cost of training if employment ends prior to the 18-month vesting date.",
    ]);
    expect(PERS_008.check(ctx)).not.toBeNull();
  });

  it("fires on `repay the signing bonus`", () => {
    const ctx = buildContext([
      "Signing Bonus",
      "Employee shall repay the signing bonus in full if Employee resigns within twelve (12) months of the start date.",
    ]);
    expect(PERS_008.check(ctx)).not.toBeNull();
  });

  it("fires on `claw-back of relocation`", () => {
    const ctx = buildContext([
      "Relocation",
      "Company reserves a claw-back of relocation expenses paid on Employee's behalf upon voluntary separation.",
    ]);
    expect(PERS_008.check(ctx)).not.toBeNull();
  });

  it("is silent on a plain offer letter", () => {
    const ctx = buildContext([
      "Compensation",
      "Employee's annual base salary shall be $120,000 paid bi-weekly.",
    ]);
    expect(PERS_008.check(ctx)).toBeNull();
  });
});

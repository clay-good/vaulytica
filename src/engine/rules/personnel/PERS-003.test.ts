import { describe, expect, it } from "vitest";
import { rule as PERS_003 } from "./PERS-003.js";
import { buildContext } from "../../_test-fixtures.js";

const inIC = (body: string) =>
  PERS_003.check(buildContext(["Independent Contractor Agreement", body])) !== null;

describe("PERS-003 — IC classification risk", () => {
  it("fires on the existing control indicators", () => {
    expect(inIC("Contractor shall report to the VP of Engineering.")).toBe(true);
    expect(inIC("Contractor shall work on a full-time basis.")).toBe(true);
  });

  // v1.1.0 — the core IRS-factor signals (supervision, employee benefits, a
  // salary, Company-provided equipment/training/office) were missed.
  it("fires on supervision / benefits / salary / company-provided-equipment", () => {
    expect(
      inIC("The Contractor shall perform the Services subject to the supervision of the Manager."),
    ).toBe(true);
    expect(
      inIC("Contractor is eligible for company employee benefits including health insurance."),
    ).toBe(true);
    expect(inIC("Contractor shall be paid an annual salary of $120,000.")).toBe(true);
    expect(inIC("The Company shall provide equipment and a workspace to Contractor.")).toBe(true);
  });

  it("stays silent on a genuine IC agreement and result-only direction", () => {
    expect(
      inIC(
        "Contractor is an independent contractor, receives no benefits, provides its own tools, and controls its own schedule.",
      ),
    ).toBe(false);
    expect(
      inIC(
        "Contractor shall achieve the results specified, subject to the general direction of the Company as to deliverables.",
      ),
    ).toBe(false);
  });

  it("does not fire outside an IC agreement", () => {
    expect(
      PERS_003.check(
        buildContext(["Employment Agreement", "Employee is entitled to employee benefits."]),
      ),
    ).toBeNull();
  });

  it("flags paid-leave / at-will-employment / employer-withholding signals (v1.2.0)", () => {
    expect(inIC("Contractor shall be entitled to paid time off of fifteen days per year.")).toBe(
      true,
    );
    expect(inIC("Contractor shall accrue PTO at the standard company rate.")).toBe(true);
    expect(inIC("This is an at-will employment relationship terminable by either party.")).toBe(
      true,
    );
    expect(
      inIC("The Company shall withhold federal and state income taxes from all payments."),
    ).toBe(true);
  });

  it("does not flag genuine IC language — own taxes, discretionary vacation, terminate-at-will (v1.2.0)", () => {
    expect(
      inIC("Contractor is solely responsible for its own taxes and receives no benefits."),
    ).toBe(false);
    expect(
      inIC("Contractor may take vacation at its own discretion without Company approval."),
    ).toBe(false);
    expect(inIC("Either party may terminate this Agreement at will upon notice.")).toBe(false);
  });
});

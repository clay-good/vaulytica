import { describe, expect, it } from "vitest";
import { rule as PERS_007 } from "./PERS-007.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-007 — IC misclassification signals", () => {
  it("fires when IC label + 2 signals (fixed hours, company equipment) present", () => {
    const ctx = buildContext(
      ["Engagement", "Contractor is engaged as an independent contractor."],
      [
        "Services",
        "Contractor shall work Monday through Friday and shall use Company-supplied equipment.",
      ],
    );
    const f = PERS_007.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/2 employee-indicator signals/);
  });

  it("fires when IC label + 3 signals", () => {
    const ctx = buildContext(
      ["Engagement", "Contractor is engaged as an independent contractor."],
      [
        "Schedule",
        "Contractor shall work from 9:00 a.m. to 5:00 p.m. at Company's offices located in San Francisco.",
      ],
      ["Equipment", "Contractor shall use Company-supplied equipment."],
      ["Reporting", "Contractor shall report daily to the designated supervisor."],
    );
    const f = PERS_007.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.title).toMatch(/\b[3-9]\s+employee-indicator signals/);
  });

  it("is silent when only 1 signal present (single coincidence)", () => {
    const ctx = buildContext(
      ["Engagement", "Contractor is engaged as an independent contractor."],
      ["Equipment", "Contractor shall use Company-supplied equipment."],
    );
    expect(PERS_007.check(ctx)).toBeNull();
  });

  it("is silent when 2+ signals present but no IC label", () => {
    const ctx = buildContext([
      "Schedule",
      "Employee shall work Monday through Friday and shall use Company-supplied equipment.",
    ]);
    expect(PERS_007.check(ctx)).toBeNull();
  });

  it("fires on flat monthly retainer + exclusivity (classic salary-shaped IC)", () => {
    const ctx = buildContext(
      ["Engagement", "Contractor is engaged as an independent contractor."],
      ["Compensation", "Contractor shall receive a flat monthly retainer of $10,000."],
      [
        "Exclusivity",
        "Contractor shall not directly or indirectly perform services for any other party during the Term.",
      ],
    );
    expect(PERS_007.check(ctx)).not.toBeNull();
  });

  it("is silent on a clean IC engagement (project-based, no controls)", () => {
    const ctx = buildContext(
      [
        "Engagement",
        "Contractor is engaged as an independent contractor to deliver the project described in the SOW.",
      ],
      [
        "Compensation",
        "Customer shall pay a fixed fee of $50,000 upon delivery of the Deliverables.",
      ],
    );
    expect(PERS_007.check(ctx)).toBeNull();
  });
});

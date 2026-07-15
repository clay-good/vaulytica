import { describe, expect, it } from "vitest";
import {
  DeadlineProfileSchema,
  DEADLINE_PROFILES,
  DEADLINE_PROFILE_IDS,
  getDeadlineProfile,
} from "./profile.js";

describe("DeadlineProfileSchema", () => {
  it("parses a minimal valid profile", () => {
    const profile = {
      id: "test",
      name: "Test Profile",
      version: "2026-01-01",
      exclude_trigger_day: true,
      count_basis: "calendar-days",
      roll_forward: true,
      calendar_id: "us-federal",
      service_adjustment_days: 3,
      service_methods_adjusted: ["mail"],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => DeadlineProfileSchema.parse(profile)).not.toThrow();
  });

  it("rejects an invalid service method", () => {
    const profile = {
      id: "test",
      name: "Test Profile",
      version: "2026-01-01",
      exclude_trigger_day: true,
      count_basis: "calendar-days",
      roll_forward: true,
      calendar_id: "us-federal",
      service_adjustment_days: 3,
      service_methods_adjusted: ["carrier-pigeon"],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => DeadlineProfileSchema.parse(profile)).toThrow();
  });

  it("rejects an unknown count_basis", () => {
    const profile = {
      id: "test",
      name: "Test Profile",
      version: "2026-01-01",
      exclude_trigger_day: true,
      count_basis: "business-days",
      roll_forward: true,
      calendar_id: "us-federal",
      service_adjustment_days: 3,
      service_methods_adjusted: [],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => DeadlineProfileSchema.parse(profile)).toThrow();
  });

  it("rejects extra fields (strict)", () => {
    const profile = {
      id: "test",
      name: "Test Profile",
      version: "2026-01-01",
      exclude_trigger_day: true,
      count_basis: "calendar-days",
      roll_forward: true,
      calendar_id: "us-federal",
      service_adjustment_days: 3,
      service_methods_adjusted: [],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
      extra_field: "nope",
    };
    expect(() => DeadlineProfileSchema.parse(profile)).toThrow();
  });
});

describe("shipped profiles", () => {
  it("both frcp-6 and cal-ccp-12 validate and load", () => {
    expect(getDeadlineProfile("frcp-6")).toBeDefined();
    expect(getDeadlineProfile("cal-ccp-12")).toBeDefined();
    expect(DEADLINE_PROFILE_IDS).toEqual(["cal-ccp-12", "frcp-6"]);
    expect(Object.keys(DEADLINE_PROFILES).sort()).toEqual(DEADLINE_PROFILE_IDS);
  });

  it("frcp-6 excludes the trigger day and adjusts 3 days for mail/clerk/other-consented", () => {
    const p = getDeadlineProfile("frcp-6")!;
    expect(p.exclude_trigger_day).toBe(true);
    expect(p.roll_forward).toBe(true);
    expect(p.calendar_id).toBe("us-federal");
    expect(p.service_adjustment_days).toBe(3);
    expect(p.service_methods_adjusted).toEqual(["mail", "clerk", "other-consented"]);
    expect(p.service_methods_adjusted).not.toContain("electronic");
    expect(p.service_methods_adjusted).not.toContain("personal");
  });

  it("cal-ccp-12 points at the california calendar", () => {
    const p = getDeadlineProfile("cal-ccp-12")!;
    expect(p.calendar_id).toBe("california");
  });

  it("returns undefined for an unknown profile id", () => {
    expect(getDeadlineProfile("nonexistent")).toBeUndefined();
  });
});

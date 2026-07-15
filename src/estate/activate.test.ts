import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../engine/rules/index.js";
import { ESTATE_CHECK_RULES } from "../engine/rules/v4/trust-estate/estate-checks.js";
import { activateEstateChecks, ESTATE_CHECK_PLAYBOOK_IDS } from "./activate.js";

describe("activateEstateChecks", () => {
  it("is a no-op when the assertion is not made", () => {
    const w = activateEstateChecks(false, "last-will-and-testament", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
    expect(w.estate_checks_asserted).toBeUndefined();
  });

  it("is a no-op for a non-will playbook even when asserted", () => {
    const w = activateEstateChecks(true, "mutual-nda", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
  });

  it("adds the EST rules and stamps the assertion for each will/trust/codicil playbook", () => {
    for (const id of ESTATE_CHECK_PLAYBOOK_IDS) {
      const w = activateEstateChecks(true, id, LAUNCH_RULES);
      expect(w.rules.length, id).toBe(LAUNCH_RULES.length + ESTATE_CHECK_RULES.length);
      expect(w.estate_checks_asserted, id).toBe(true);
    }
  });

  it("every estate-check rule declares the assertion gate and the playbook gate", () => {
    for (const r of ESTATE_CHECK_RULES) {
      expect(r.assertion_gate, r.id).toBe("estate-checks");
      expect(r.applies_to_playbooks, r.id).toContain("last-will-and-testament");
    }
  });
});

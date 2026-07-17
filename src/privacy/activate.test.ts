import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../engine/rules/index.js";
import { PNOT_RULES, pnotRulesForRegimes } from "../engine/rules/privacy-notice/rules.js";
import { activatePrivacyNotice } from "./activate.js";
import { buildRegimeCoverage } from "./coverage.js";
import { REGIME_IDS } from "./regime-data.js";

describe("activatePrivacyNotice", () => {
  it("is a no-op when no regime is asserted", () => {
    const w = activatePrivacyNotice([], "privacy-notice-us", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
    expect(w.asserted_regimes).toBeUndefined();
  });

  it("is a no-op for a non-notice playbook even with regimes asserted", () => {
    const w = activatePrivacyNotice(["ccpa"], "mutual-nda", LAUNCH_RULES);
    expect(w.rules).toBe(LAUNCH_RULES);
  });

  it("adds the PNOT rules for the asserted regimes and stamps them sorted", () => {
    const w = activatePrivacyNotice(["gdpr-14", "ccpa"], "privacy-notice-us", LAUNCH_RULES);
    const expected = pnotRulesForRegimes(["ccpa", "gdpr-14"]).length;
    expect(w.rules.length).toBe(LAUNCH_RULES.length + expected);
    expect(w.asserted_regimes).toEqual(["ccpa", "gdpr-14"]); // sorted
  });
});

describe("buildRegimeCoverage", () => {
  it("marks items found unless their rule fired", () => {
    const ccpaRules = pnotRulesForRegimes(["ccpa"]);
    const fired = new Set([ccpaRules[0]!.id, ccpaRules[1]!.id]); // 2 not detected
    const [cov] = buildRegimeCoverage(["ccpa"], fired);
    expect(cov!.regime).toBe("ccpa");
    expect(cov!.total).toBe(ccpaRules.length);
    expect(cov!.found_count).toBe(ccpaRules.length - 2);
    expect(
      cov!.items
        .filter((i) => !i.found)
        .map((i) => i.rule_id)
        .sort(),
    ).toEqual([ccpaRules[0]!.id, ccpaRules[1]!.id].sort());
  });

  it("every PNOT rule maps to exactly one regime's coverage", () => {
    const cov = buildRegimeCoverage(REGIME_IDS, new Set());
    const totalItems = cov.reduce((n, c) => n + c.total, 0);
    expect(totalItems).toBe(PNOT_RULES.length);
  });
});

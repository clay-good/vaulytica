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

  it("every unconditional PNOT rule maps to exactly one regime's coverage", () => {
    // Conditional rules (TX exact-wording, VA/TX opt-out) are excluded
    // when they produced no finding — no row, no claim.
    const cov = buildRegimeCoverage(REGIME_IDS, new Set());
    const totalItems = cov.reduce((n, c) => n + c.total, 0);
    const conditional = PNOT_RULES.filter((r) => r.conditional);
    expect(conditional.map((r) => r.id).sort()).toEqual([
      "PNOT-TX-007",
      "PNOT-TX-008",
      "PNOT-TX-009",
      "PNOT-VA-007",
    ]);
    expect(totalItems).toBe(PNOT_RULES.length - conditional.length);
  });

  it("a conditional rule appears in the table ONLY when it fired (audit: lying found=True rows)", () => {
    // No-sale notice: TX conditional rules produced no finding — a
    // found=True row claimed the § 541.102 mandated sentences were
    // present though they appear nowhere. They must have NO row.
    const [quiet] = buildRegimeCoverage(["tx"], new Set());
    expect(quiet!.items.map((i) => i.rule_id)).not.toContain("PNOT-TX-007");
    expect(quiet!.items.map((i) => i.rule_id)).not.toContain("PNOT-TX-009");

    // When the trigger IS evidenced and the item missing, the row appears
    // as not-detected.
    const [fired] = buildRegimeCoverage(["tx"], new Set(["PNOT-TX-007"]));
    const row = fired!.items.find((i) => i.rule_id === "PNOT-TX-007");
    expect(row).toBeDefined();
    expect(row!.found).toBe(false);
    expect(fired!.total).toBe(quiet!.total + 1);
  });
});

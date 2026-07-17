import { describe, expect, it } from "vitest";

import { getRegime, REGIME_IDS, REGIMES } from "./regime-data.js";

describe("regime-data — registry contract", () => {
  it("REGIME_IDS covers every REGIMES key", () => {
    expect(new Set(REGIME_IDS)).toEqual(new Set(Object.keys(REGIMES)));
  });

  it("getRegime returns the matching regime, or undefined for an unknown id", () => {
    for (const id of REGIME_IDS) {
      expect(getRegime(id)?.id).toBe(id);
    }
    // @ts-expect-error — deliberately probing an invalid id at runtime.
    expect(getRegime("hipaa")).toBeUndefined();
  });

  it("every content item across every regime has non-empty citation, url, and patterns", () => {
    for (const id of REGIME_IDS) {
      const regime = REGIMES[id];
      expect(regime.items.length).toBeGreaterThan(0);
      for (const item of regime.items) {
        expect(item.key.length).toBeGreaterThan(0);
        expect(item.label.length).toBeGreaterThan(0);
        expect(item.citation.length).toBeGreaterThan(0);
        expect(item.url.length).toBeGreaterThan(0);
        expect(item.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(item.present_patterns.length).toBeGreaterThan(0);
        for (const pattern of item.present_patterns) {
          expect(() => new RegExp(pattern, "i")).not.toThrow();
        }
      }
    }
  });

  it("every regime's item keys are unique", () => {
    for (const id of REGIME_IDS) {
      const keys = REGIMES[id].items.map((i) => i.key);
      expect(new Set(keys).size).toBe(keys.length);
    }
  });
});

describe("regime-data — gdpr-14 composition", () => {
  it("includes the Art. 14-specific data-categories and data-source items", () => {
    const keys = REGIMES["gdpr-14"].items.map((i) => i.key);
    expect(keys).toContain("data-categories");
    expect(keys).toContain("data-source");
  });

  it("omits withdraw-consent and statutory-requirement (Art. 14 has no equivalent)", () => {
    const keys = REGIMES["gdpr-14"].items.map((i) => i.key);
    expect(keys).not.toContain("withdraw-consent");
    expect(keys).not.toContain("statutory-requirement");
  });

  it("otherwise carries the same shared items as gdpr-13", () => {
    const gdpr13Keys = new Set(REGIMES["gdpr-13"].items.map((i) => i.key));
    gdpr13Keys.delete("withdraw-consent");
    gdpr13Keys.delete("statutory-requirement");
    const gdpr14Keys = new Set(REGIMES["gdpr-14"].items.map((i) => i.key));
    for (const key of gdpr13Keys) {
      expect(gdpr14Keys.has(key)).toBe(true);
    }
  });
});

describe("regime-data — colorado", () => {
  it("carries the statutory items plus the four unconditional Rule 6.03 items", () => {
    const keys = REGIMES.co.items.map((i) => i.key);
    for (const statutory of [
      "categories-processed",
      "purposes",
      "rights-and-appeal",
      "shared-categories",
      "third-party-categories",
    ]) {
      expect(keys).toContain(statutory);
    }
    for (const rule603 of [
      "sale-targeted-ads-profiling",
      "request-methods",
      "contact-info",
      "last-updated",
    ]) {
      expect(keys).toContain(rule603);
    }
    // The conditional Rule 6.03 items (profiling per Rule 9.03, sensitive-data
    // inferences per Rule 6.10) are intentionally NOT presence-linted.
    expect(keys).not.toContain("profiling-disclosures");
    expect(keys).not.toContain("sensitive-data-inferences");
    const rule603Items = REGIMES.co.items.filter((i) => i.citation.includes("904-3"));
    expect(rule603Items).toHaveLength(4);
    for (const item of rule603Items) {
      expect(item.citation).toMatch(/^4 CCR 904-3, Rule 6\.03/);
    }
  });
});

describe("regime-data — ccpa", () => {
  it("includes the § 1798.106 correction right and the sold/shared 'none' alternative", () => {
    const item = REGIMES.ccpa.items.find((i) => i.key === "correction-right");
    expect(item?.citation).toBe("Cal. Civ. Code § 1798.106");
    const soldShared = REGIMES.ccpa.items.find((i) => i.key === "sold-shared-or-none");
    expect(
      soldShared?.present_patterns.some((p) => /do not sell/i.test(new RegExp(p, "i").source)),
    ).toBe(true);
  });
});

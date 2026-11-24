import { describe, expect, it } from "vitest";

import {
  getRegime,
  REGIME_IDS,
  REGIMES,
  TX_BIOMETRIC_SALE_NOTICE,
  TX_SALE_NOTICES,
  TX_SENSITIVE_SALE_NOTICE,
} from "./regime-data.js";

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

/**
 * Provenance on an exact-wording passage.
 *
 * `MANDATED_TEXTS` in `src/engine/rules/text/` is held to carrying where and
 * when each passage was read, and refuses a row with none. The two Texas
 * notices here are the same kind of authority — words a statute fixes — and
 * were bare string constants until 9.1004.0, with the URL in a comment and no
 * date at all. This holds them to the same standard, so the next exact-wording
 * literal added to this file cannot arrive bare.
 */
describe("mandated literals carry their provenance", () => {
  it("records text, citation, an official source, a read date and the enacting act", () => {
    const rows = Object.values(TX_SALE_NOTICES);
    expect(rows.length, "no mandated literals found — the assertions below would be vacuous").toBe(
      2,
    );
    for (const row of rows) {
      expect(row.text.length, row.citation).toBeGreaterThan(20);
      expect(row.citation).toMatch(/^Tex\. Bus\. & Com\. Code § 541\.102\([bc]\)$/);
      // The Texas Legislature's own statute site, not a secondary source.
      expect(new URL(row.source_url).hostname).toBe("statutes.capitol.texas.gov");
      expect(row.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(row.enacted).toMatch(/Acts \d{4}/);
    }
  });

  it("keeps the exported constants and the rows in step", () => {
    // The rules import the bare constants; if those ever drift from the rows
    // the provenance above would describe text nothing matches against.
    expect(TX_SENSITIVE_SALE_NOTICE).toBe(TX_SALE_NOTICES.sensitive.text);
    expect(TX_BIOMETRIC_SALE_NOTICE).toBe(TX_SALE_NOTICES.biometric.text);
  });

  it("quotes the statute's words exactly, including 'personal'", () => {
    // 🚨 The defect this guards: dropping one word. A controller who writes
    // "NOTICE: We may sell your sensitive data." satisfies any presence check
    // built on "sensitive" and does NOT satisfy § 541.102(b), which prescribes
    // the sentence. Read at the official source on 2026-11-23.
    expect(TX_SENSITIVE_SALE_NOTICE).toBe("NOTICE: We may sell your sensitive personal data.");
    expect(TX_BIOMETRIC_SALE_NOTICE).toBe("NOTICE: We may sell your biometric personal data.");
  });
});

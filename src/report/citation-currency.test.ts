/**
 * Citation-currency labels (fix-legal-authority-currency).
 *
 * A finding citing a DKB node retrieved further back than the configured
 * horizon must carry a visible "verify currency (retrieved <date>)" label.
 * The comparison anchors to the DKB's own `built_at` — never the wall
 * clock — so identical inputs render identical labels on any machine,
 * forever (the no-wall-clock posture of every hashed and exported
 * artifact).
 */

import { describe, expect, it } from "vitest";
import {
  currencyLabel,
  dkbCurrency,
  formatBibliographyEntry,
  DEFAULT_CURRENCY_HORIZON_MONTHS,
} from "./citations.js";
import type { SourceCitation } from "../dkb/types.js";

const cite = (retrieved_at: string): SourceCitation => ({
  id: "stat-test",
  source: "16 C.F.R. § 999",
  source_url: "https://example.gov/999",
  retrieved_at,
  license: "Public domain",
  license_url: "https://example.gov/license",
});

describe("currencyLabel", () => {
  const currency = { as_of: "2026-07-04T00:00:00Z", horizon_months: 12 };

  it("labels a node retrieved 18 months before the DKB build", () => {
    expect(currencyLabel(cite("2025-01-07T00:00:00Z"), currency)).toBe(
      "verify currency (retrieved 2025-01-07)",
    );
  });

  it("stays silent inside the horizon", () => {
    expect(currencyLabel(cite("2026-05-11T00:00:00Z"), currency)).toBeUndefined();
    expect(currencyLabel(cite("2025-07-04T00:00:00Z"), currency)).toBeUndefined(); // exactly 12mo
  });

  it("fires just past the horizon boundary", () => {
    expect(currencyLabel(cite("2025-07-03T00:00:00Z"), currency)).toContain("verify currency");
  });

  it("is undefined without a currency reference or retrieval date", () => {
    expect(currencyLabel(cite("2025-01-07"), undefined)).toBeUndefined();
    expect(currencyLabel({ ...cite("2025-01-07"), retrieved_at: "" }, currency)).toBeUndefined();
  });

  it("dkbCurrency anchors to built_at with a 12-month default", () => {
    const c = dkbCurrency({ built_at: "2026-07-04T02:00:00Z" });
    expect(c).toEqual({ as_of: "2026-07-04T02:00:00Z", horizon_months: 12 });
    expect(DEFAULT_CURRENCY_HORIZON_MONTHS).toBe(12);
    expect(dkbCurrency({ built_at: "2026-07-04", currency_horizon_months: 6 }).horizon_months).toBe(
      6,
    );
  });
});

describe("verify-currency label in rendered formats", () => {
  const currency = { as_of: "2026-07-04T00:00:00Z", horizon_months: 12 };
  const stale = cite("2025-01-07T00:00:00Z");

  it("bibliography entries (HTML/DOCX/bundle) carry the label", () => {
    const entry = formatBibliographyEntry(1, stale, currency);
    expect(entry).toContain("verify currency (retrieved 2025-01-07)");
    // Fresh citation → unchanged entry.
    expect(formatBibliographyEntry(1, cite("2026-06-01"), currency)).not.toContain(
      "verify currency",
    );
    // No currency reference → byte-identical to the pre-feature output.
    expect(formatBibliographyEntry(1, stale)).not.toContain("verify currency");
  });
});

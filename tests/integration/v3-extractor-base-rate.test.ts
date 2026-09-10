/**
 * How much of the corpus does each v3 extractor claim?
 *
 * Wiring the v3 report layer up (9.674.0) made these extractors readable for
 * the first time, and reading them produced **four defects in four releases** —
 * every one the same shape: **a common English word standing in for a
 * concept.**
 *
 *   - `hipaa-names` was `/\bnames?\b/i`, so "shall **name** Licensor as an
 *     additional insured" and every signature block's "**Name:**" counted.
 *     **235 of 327 specimens** were recorded as containing a HIPAA identifier.
 *   - `audit_rights` was `/\b(?:audit|inspect|inspection)…/i`, so a board's
 *     "**Audit** Committee." and an architect *disclaiming* site duty counted.
 *     **107 specimens**, 80% of the records carrying no detail at all.
 *   - `breach_timings` matched the NAME of the Breach Notification Rule in a
 *     BAA's glossary.
 *   - `classifyRoles` took the Title-Case run before the role marker, which in
 *     a preamble is the city in the registered-office address.
 *
 * Each was invisible for the same reason: **nothing measured how much of the
 * corpus an extractor claimed.** A detector for a specialised concept that
 * fires on three quarters of a corpus spanning leases, wills, pleadings and
 * NDAs is not detecting the concept.
 *
 * This is the extractor-side counterpart of
 * `distinguishing-base-rate.test.ts`, which holds a playbook's distinguishing
 * phrases below a 0.15 share for exactly the same reason. The numbers are
 * committed by EQUALITY, so widening a detector means raising one on purpose
 * and narrowing one means lowering it on purpose — and the ceiling is the
 * tripwire that would have caught two of the four above on the day they
 * shipped.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAllV3 } from "../../src/extract/v3/index.js";
import type { V3ExtractedData } from "../../src/extract/v3/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Documents each extractor finds something in. Measured 2026-09-10 over the
 * 327-specimen corpus. Adding a specimen moves these; say so in the CHANGELOG.
 */
const REACH: Record<keyof V3ExtractedData, number> = {
  data_categories: 117,
  insurance: 53,
  audit_rights: 50,
  subprocessor: 37,
  breach_timings: 34,
  security_measures: 26,
  roles: 15,
  dtsa_notice: 15,
  transfer_mechanisms: 10,
};

/**
 * The ceiling, and why it is where it is.
 *
 * The corpus deliberately spans families that should NOT carry these concepts:
 * residential leases, wills, pleadings, promissory notes, bylaws. A GDPR
 * transfer mechanism, a HIPAA identifier or a vendor audit right belongs to a
 * minority of them. Half is generous — the highest legitimate rate here is
 * `data_categories` at 36%, and it is the broadest concept of the nine — and
 * it is still low enough that a detector which has quietly become a
 * common-word match trips it. `audit_rights` at 33% did not trip it; the
 * committed equality above is what caught that one.
 */
const MAX_SHARE = 0.5;

/** Whether an extractor actually found something, per its own shape. */
function found(key: keyof V3ExtractedData, value: V3ExtractedData[keyof V3ExtractedData]): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (value === null || value === undefined) return false;
  if (key === "insurance") {
    const i = value as V3ExtractedData["insurance"];
    return (
      i.amounts.length > 0 ||
      i.endorsements.length > 0 ||
      i.required_am_best_rating !== null ||
      i.notice_of_cancellation_days !== null
    );
  }
  if (key === "dtsa_notice") return (value as V3ExtractedData["dtsa_notice"]).present === true;
  return true;
}

describe("v3 extractor base rates over the specimen corpus", () => {
  it("claims the share of the corpus each extractor is committed to", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    const hits: Record<string, number> = Object.fromEntries(Object.keys(REACH).map((k) => [k, 0]));

    for (const file of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      const v3 = extractAllV3(ingest.tree);
      for (const key of Object.keys(REACH) as Array<keyof V3ExtractedData>) {
        if (found(key, v3[key])) hits[key] = (hits[key] ?? 0) + 1;
      }
    }

    // Anti-vacuity: a harness that ingested nothing reports every extractor at
    // zero, which is indistinguishable from nine dead extractors.
    expect(files.length).toBeGreaterThan(300);
    expect(Object.values(hits).reduce((a, b) => a + b, 0)).toBeGreaterThan(200);

    // Dead at one end.
    for (const [key, n] of Object.entries(hits)) {
      expect(n, `${key} finds nothing in the whole corpus`).toBeGreaterThan(0);
    }

    // A common word at the other. The corpus spans leases, wills and pleadings;
    // none of these concepts belongs to most of it.
    for (const [key, n] of Object.entries(hits)) {
      expect(
        n / files.length,
        `${key} claims ${((n / files.length) * 100).toFixed(0)}% of a corpus that is ` +
          `mostly not about it — check whether its trigger has become a common word`,
      ).toBeLessThanOrEqual(MAX_SHARE);
    }

    expect(hits).toEqual(REACH);
  }, 300_000);
});

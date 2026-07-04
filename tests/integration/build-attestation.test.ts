/**
 * Build-attestation honesty (fix-build-attestation-honesty).
 *
 * Every production build used to fabricate the DKB validation
 * attestation: with no real validation-status.json anywhere in the repo,
 * vite synthesized `{ dkb_last_validated_at: new Date(),
 * stale_citations_pending_review: 0 }` — a freshness-and-review claim
 * nothing ever performed, restamped nondeterministically on every build.
 * Now the fallback is an explicit, byte-deterministic UNKNOWN, and only
 * the DKB rebuild workflow's citation-check run writes a real one.
 */

import { describe, expect, it } from "vitest";
import { buildUnknownValidationStatus } from "../../vite.config.js";

describe("the unknown validation status", () => {
  it("is byte-deterministic: two builds from the same tree ship the same file", () => {
    expect(buildUnknownValidationStatus()).toBe(buildUnknownValidationStatus());
  });

  it("claims nothing: null values, attested: false — no date, no zero count", () => {
    const parsed = JSON.parse(buildUnknownValidationStatus()) as Record<string, unknown>;
    expect(parsed).toEqual({
      dkb_last_validated_at: null,
      stale_citations_pending_review: null,
      attested: false,
    });
    // The one thing the old fallback did that this must never do:
    expect(buildUnknownValidationStatus()).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });
});

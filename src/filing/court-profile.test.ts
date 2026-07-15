import { describe, expect, it } from "vitest";
import {
  COURT_PROFILES,
  COURT_PROFILE_IDS,
  CourtProfileSchema,
  getCourtProfile,
  parseCourtProfile,
} from "./court-profile.js";

describe("court profiles", () => {
  it("ships the three launch profiles, all schema-valid", () => {
    expect(COURT_PROFILE_IDS).toEqual(["ca9-appellate", "cal-rules-8.204", "frap-default"]);
    for (const id of COURT_PROFILE_IDS) {
      expect(() => CourtProfileSchema.parse(COURT_PROFILES[id])).not.toThrow();
    }
  });

  it("FRAP default carries the 13,000-word principal limit with cited authority", () => {
    const p = getCourtProfile("frap-default")!;
    expect(p.limits.principal_words?.value).toBe(13000);
    expect(p.limits.principal_words?.cite).toMatch(/32\(a\)\(7\)\(B\)\(i\)/);
    expect(p.limits.reply_words?.value).toBe(6500);
  });

  it("every limit and required block carries a citation, URL, and retrieved_at", () => {
    for (const p of Object.values(COURT_PROFILES)) {
      for (const l of Object.values(p.limits)) {
        expect(l.cite.length).toBeGreaterThan(0);
        expect(l.url).toMatch(/^https:\/\//);
        expect(l.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
      for (const b of p.required_blocks) {
        expect(b.cite.length).toBeGreaterThan(0);
        expect(b.url).toMatch(/^https:\/\//);
        expect(b.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
    }
  });

  it("rejects a limit with no citation (CI schema gate)", () => {
    const bad = {
      ...structuredClone(getCourtProfile("frap-default")!),
    };
    // Drop the citation from the principal-words limit.
    (bad.limits.principal_words as unknown as Record<string, unknown>).cite = undefined;
    expect(() => parseCourtProfile(bad)).toThrow();
  });

  it("rejects an unknown required-block kind", () => {
    const bad = structuredClone(getCourtProfile("frap-default")!) as unknown as {
      required_blocks: Array<{ block: string; cite: string; url: string; retrieved_at: string }>;
    };
    bad.required_blocks.push({
      block: "bibliography",
      cite: "x",
      url: "https://example.com",
      retrieved_at: "2026-07-15",
    });
    expect(() => parseCourtProfile(bad)).toThrow();
  });

  it("getCourtProfile returns undefined for an unknown id", () => {
    expect(getCourtProfile("nope")).toBeUndefined();
  });
});

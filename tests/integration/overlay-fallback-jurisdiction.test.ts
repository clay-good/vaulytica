/**
 * The state-law overlays must not widen to a clause's FALLBACK jurisdiction.
 *
 * `JurisdictionReference.fallback_jurisdiction` is filled by the extractor and
 * read by nothing, which makes it look like an obvious gap: an employment
 * agreement governed by Delaware "except that the restrictive covenants shall
 * be governed by the laws of California" ought to draw California's
 * non-compete overlay, the single most consequential node in the catalog.
 * Feeding the fallback into `selectStateOverlays` is the one-line change that
 * appears to fix it.
 *
 * It is the wrong change, and this file is why.
 *
 * `detectFallback` deliberately matches a FORUM fallback alongside a law one —
 * `jurisdictions.test.ts` pins "courts of X" as a fallback connector on
 * purpose — so one field holds two different things. "Governed by the laws of
 * New York; provided that if such courts decline jurisdiction, then the courts
 * of Texas" yields `fallback_jurisdiction: "Texas"`, and Texas governs nothing
 * there. `state-overlays.ts` states the rule the widening would break:
 * "venue / arbitration-seat do not determine which state's substantive law
 * governs the covenant." A Texas usury or non-compete overlay drawn off a
 * forum-selection fallback is exactly the confidently-wrong answer the
 * module's honest-N/A posture forbids.
 *
 * And the case that motivates the change mostly does not need it: for the
 * common carve-out shapes the extractor already emits a SECOND governing-law
 * record for the carved-out state, so the overlay is selected on its own
 * merits. Measured over the 312-specimen corpus, `fallback_jurisdiction` is
 * populated ZERO times, so there is no corpus evidence to separate the two
 * readings on either.
 *
 * Wiring it up needs the field to distinguish law from forum FIRST. Until
 * then this test holds the line and carries the counterexample.
 */
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { selectStateOverlays } from "../../src/dkb/state-overlays.js";

async function governingLaw(clause: string) {
  const ingest = await ingestPaste(`EMPLOYMENT AGREEMENT\n\n1. Governing Law.\n\n${clause}\n`);
  return extractAll(ingest.tree).jurisdictions.filter((j) => j.clause_kind === "governing-law");
}

describe("state overlays and the fallback jurisdiction", () => {
  it("does not draw an overlay from a FORUM fallback", async () => {
    const refs = await governingLaw(
      "This Agreement shall be governed by the laws of the State of New York; provided that if such courts decline jurisdiction, then the courts of Texas shall hear the dispute.",
    );
    // The trap: the field is populated, and it holds a forum, not a law.
    expect(refs.map((r) => r.fallback_jurisdiction)).toContain("Texas");
    const result = selectStateOverlays("employment-at-will-us", refs)!;
    // Texas must appear in NEITHER list — not matched, and not reported as an
    // uncovered governing-law state either, because it is not one.
    expect(result.detected_states).not.toContain("us-tx");
    expect(result.uncovered_states).not.toContain("us-tx");
    expect(result.matched.map((o) => o.jurisdiction)).not.toContain("us-tx");
  });

  it("still selects a carved-out state that is stated as its own governing law", async () => {
    // Why the widening is not needed for the shape that motivates it: the
    // extractor emits a second governing-law record for California, so the
    // overlay is selected without reading the fallback at all.
    const refs = await governingLaw(
      "This Agreement shall be governed by the laws of the State of Delaware, except that the restrictive covenants set forth in Section 8 shall be governed by the laws of the State of California.",
    );
    const result = selectStateOverlays("employment-at-will-us", refs)!;
    expect(result.detected_states).toContain("us-ca");
    expect(result.matched.map((o) => o.posture)).toContain("prohibited");
  });
});

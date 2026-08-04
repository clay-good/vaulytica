/**
 * OBLI-002 reciprocity accounting.
 *
 * Two defects cancelled each other out, so the rule looked like it worked:
 *
 *  - It matched obligors against party NAMES only. Contracts overwhelmingly
 *    write the role ("Vendor shall indemnify …"), so role-phrased obligors were
 *    invisible and genuinely one-sided clauses went unreported.
 *  - It counted a DISCLAIMED obligation as the party bearing it. "Vendor shall
 *    not have any reciprocal indemnification obligation" was recorded as Vendor
 *    bearing an indemnity — the exact opposite of what it says.
 *
 * Fixing only the first would have SILENCED the true finding on the
 * bad-saas fixture, because the disclaimer would have started counting as a
 * second obligor. Both are pinned here.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { rule as obli002 } from "./OBLI-002.js";
import type { RuleContext } from "../../finding.js";
import type { Party, Obligation } from "../../../extract/types.js";

function ctxWith(parties: Partial<Party>[], obligations: Partial<Obligation>[]): RuleContext {
  const base = buildContext(["Agreement", "Body text."]);
  return {
    ...base,
    extracted: {
      ...base.extracted,
      parties: parties as Party[],
      obligations: obligations as Obligation[],
    },
  };
}

const PARTIES = [
  { name: "MegaSoft, Inc", role: "Vendor" },
  { name: "Customer" },
] as Partial<Party>[];

describe("OBLI-002 — reciprocity accounting", () => {
  it("sees a role-phrased obligor that the legal name never matched", () => {
    // Only Vendor indemnifies. Before roles were matched, "Vendor" was invisible
    // and the asymmetry went unreported.
    const finding = obli002.check(
      ctxWith(PARTIES, [{ obligor: "Vendor", action: "indemnify Customer for all claims" }]),
    );
    expect(finding).not.toBeNull();
    expect(finding?.description).toContain("vendor");
  });

  it("does not count a disclaimed obligation as the party bearing it", () => {
    // Customer indemnifies; Vendor expressly does NOT. That is one-sided, and
    // the disclaimer must not register Vendor as a second obligor.
    expect(
      obli002.check(
        ctxWith(PARTIES, [
          { obligor: "Customer", action: "indemnify, defend, and hold Vendor harmless" },
          { obligor: "Vendor", action: "not have any reciprocal indemnification obligation" },
        ]),
      ),
    ).not.toBeNull();
  });

  it("stays silent when both parties genuinely bear the obligation", () => {
    expect(
      obli002.check(
        ctxWith(PARTIES, [
          { obligor: "Vendor", action: "indemnify the other party" },
          { obligor: "Customer", action: "indemnify the other party" },
        ]),
      ),
    ).toBeNull();
  });

  it("does not read a generic reciprocal role as a one-sided obligor", () => {
    // A mutual NDA writes confidentiality to "the Receiving Party" — a position
    // BOTH parties occupy. The single role label is not a specific party bearing
    // a one-sided burden, so this must not read as an asymmetry.
    const mutual = [
      { name: "Acme Corp", role: "Receiving Party" },
      { name: "Globex LLC", role: "Receiving Party" },
    ] as Partial<Party>[];
    expect(
      obli002.check(
        ctxWith(mutual, [
          { obligor: "Receiving Party", action: "hold all Confidential Information in confidence" },
        ]),
      ),
    ).toBeNull();
    // Recipient / Discloser are treated the same way.
    expect(
      obli002.check(
        ctxWith(
          [
            { name: "A", role: "Recipient" },
            { name: "B", role: "Recipient" },
          ] as Partial<Party>[],
          [{ obligor: "Recipient", action: "indemnify the other for a confidentiality breach" }],
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely party-specific one-sided obligation", () => {
    // The guard is scoped to reciprocal ROLE labels only — a one-sided indemnity
    // from a specific party (Vendor) is a real asymmetry and still reported.
    const finding = obli002.check(
      ctxWith(PARTIES, [{ obligor: "Vendor", action: "indemnify Customer for all claims" }]),
    );
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("indemnification");
  });
});

describe("OBLI-002 — negated noun lists", () => {
  it("does not read a later item of a negated noun list as a borne obligation", () => {
    // "make NO representations, warranties, or guarantees" — a single leading
    // "no" disclaims all three. A 12-char look-back caught only the first noun;
    // "warranties" and "guarantees" were misread as obligations Partner bears.
    const parties = [
      { name: "Acme Corp", role: "Company" },
      { name: "Beta LLC", role: "Partner" },
    ] as Partial<Party>[];
    expect(
      obli002.check(
        ctxWith(parties, [
          {
            obligor: "Partner",
            action:
              "make no representations, warranties, or guarantees about the Company or its products",
          },
        ]),
      ),
    ).toBeNull();
  });

  it("does not over-suppress: a warranty across a verb from a 'no' still counts", () => {
    // "…deliver the goods with no delay, AND warrant that they conform" — the
    // "no" governs "delay", not the later verb "warrant". The negated-list guard
    // spans nouns and separators, never a verb, so the genuine one-sided
    // warranty must still surface.
    const finding = obli002.check(
      ctxWith(PARTIES, [
        {
          obligor: "Vendor",
          action: "deliver the goods with no delay, and warrant that they conform to spec",
        },
      ]),
    );
    expect(finding?.title).toBe("Asymmetric warranties obligation");
  });
});

describe("OBLI-002 — how the finding reads", () => {
  it("names the obligation, not the pattern that found it", () => {
    const ctx = buildContext([
      "Agreement",
      'This Agreement is between Acme Corp, a Delaware corporation ("Vendor"), and Globex LLC, a New York limited liability company ("Customer").',
      "Vendor shall hold all Confidential Information of Customer in strict confidence.",
    ]);
    const f = obli002.check(ctx);
    expect(f?.title).toBe("Asymmetric confidentiality obligation");
    // Engine internals must never reach an attorney.
    expect(JSON.stringify(f)).not.toMatch(/\\b|\(\?:/);
  });
});

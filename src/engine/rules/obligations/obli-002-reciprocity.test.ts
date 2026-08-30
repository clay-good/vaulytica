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

  it("treats a 'the parties' / 'each party' obligation as mutual even beside a stray party mention", () => {
    // Confidentiality written mutually ("the parties shall keep it confidential")
    // is mutual by construction — but "the parties" is not a party name/role, so
    // it never lands in partySet. A co-located, mis-segmented party-specific
    // mention ("Buyer shall pay … and each party shall return Confidential
    // Information") must not then read as a one-sided Buyer confidentiality duty.
    expect(
      obli002.check(
        ctxWith(PARTIES, [
          {
            obligor: "Customer",
            action:
              "pay for all goods and each party shall return the other's Confidential Information",
          },
          {
            obligor: "the parties",
            action: "keep the other's Confidential Information confidential",
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

describe("OBLI-002 v1.5.0 — the warranty SENSE, and a class of counterparties", () => {
  const twoParties = [
    { name: "Lumenarc Materials, Inc", role: "Company" },
    { name: "Westford Venture Lending II, LLC", role: "Holder" },
  ];

  /**
   * A bare `\bwarrant` also matches the SECURITY. On a warrant agreement every
   * operative sentence names it, and the instrument was reported as a
   * one-sided set of warranties.
   */
  it("does not read the warrant INSTRUMENT as a warranty", () => {
    expect(
      obli002.check(
        ctxWith(twoParties, [
          { obligor: "Company", action: "issue a replacement warrant to the transferee" },
          { obligor: "Company", action: "reserve a number of shares for the Warrant Shares" },
        ]),
      ),
    ).toBeNull();
  });

  it("still reads a genuine one-sided warranty", () => {
    const f = obli002.check(
      ctxWith(twoParties, [
        { obligor: "Company", action: "warrants that the Shares are duly authorized" },
      ]),
    );
    expect(f?.description).toContain("company");
  });

  /**
   * The counterparties are a CLASS the party extractor cannot register — the
   * Investors sign a schedule. An investor rights agreement that binds the
   * Company and every Investor alike was reported as binding only the Company.
   */
  it.each(["Each Investor", "Each selling Investor", "Every Member"])(
    "counts %s as a second side",
    (obligor) => {
      expect(
        obli002.check(
          ctxWith(twoParties, [
            { obligor: "Company", action: "indemnify the Investors against any loss" },
            { obligor, action: "indemnify the Company against any loss" },
          ]),
        ),
      ).toBeNull();
    },
  );

  /** A noun phrase that merely starts a sentence is not a party class. */
  it("does not count a lower-case noun phrase as a side", () => {
    expect(
      obli002.check(
        ctxWith(twoParties, [
          { obligor: "Company", action: "indemnify the Holder against any loss" },
          { obligor: "each of the foregoing amounts", action: "be indemnified in full" },
        ]),
      ),
    ).not.toBeNull();
  });
});

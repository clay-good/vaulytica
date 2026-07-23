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
});

/**
 * The NVCA drafting a stockholders' agreement actually uses.
 *
 * GOV-040 wanted "vote in favor" adjacently, and every real voting agreement
 * puts the OBJECT between them — "each Stockholder shall vote its shares in
 * favor of the transaction". A section headed VOTING AGREEMENT was reported
 * at `critical` as containing no voting agreement.
 *
 * GOV-041 wanted "terminat*" near the public offering, and the NVCA term
 * clause ends the agreement without ever using the word: "continues until the
 * earliest of (a) the closing of a Sale of the Company, (b) the closing of a
 * firm-commitment underwritten public offering".
 */
import { describe, expect, it } from "vitest";
import { GOVERNANCE_RULES as GOVERNANCE } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";

const byId = (id: string) => {
  const rule = GOVERNANCE.find((r) => r.id === id);
  if (!rule) throw new Error(`${id} not in the governance ruleset`);
  return rule;
};

describe("GOV-040 — a voting agreement with its object in place", () => {
  it.each([
    "Each Stockholder shall vote all shares of capital stock over which it has voting control so that the Board of Directors consists of seven (7) directors.",
    "Each Stockholder shall vote its shares in favor of the transaction and shall not exercise appraisal rights.",
    "Each Investor agrees to vote its shares to approve the Sale of the Company.",
  ])("is silent on %s", (clause) => {
    expect(byId("GOV-040").check(buildContext(["Voting Agreement", clause]))).toBeNull();
  });

  it("still reports an agreement with no voting commitment", () => {
    expect(
      byId("GOV-040").check(
        buildContext([
          "Transfer Restrictions",
          "No Key Holder shall transfer any shares except in compliance with this Section 3.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-041 — a term clause that ends the agreement without the word", () => {
  it.each([
    "This Agreement continues until the earliest of (a) the closing of a Sale of the Company and (b) the closing of a firm-commitment underwritten public offering of the Company's Common Stock.",
    "This Agreement remains in effect until the closing of a qualified public offering.",
    "This Agreement terminates upon the closing of an initial public offering.",
  ])("is silent on %s", (clause) => {
    expect(byId("GOV-041").check(buildContext(["Term", clause]))).toBeNull();
  });

  it("still reports an agreement with no IPO termination", () => {
    expect(
      byId("GOV-041").check(
        buildContext(["Term", "This Agreement continues until the parties agree in writing."]),
      ),
    ).not.toBeNull();
  });
});

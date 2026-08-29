/**
 * Three defects a hand-written membership interest purchase agreement found.
 *
 * RISK-009 read the most standard sentence in M&A indemnification — "the
 * Sellers' aggregate liability shall not exceed the Escrow Amount, except that
 * liability for Fraud is unlimited" — as uncapped liability, at `critical`.
 * Every professional purchase agreement, buyer-favorable and seller-favorable
 * alike, carves fraud, wilful misconduct, and the indemnity out of the cap, so
 * the rule reported the presence of a cap as its absence.
 *
 * MNA-106 asked for a seller non-compete and non-solicit and could not read
 * one drafted the way its own `fix` text says to draft it, because a
 * sale-of-business covenant states its scope between the modal and the verb.
 *
 * STRUCT-016 named a "Schedule 2" the agreement never mentions, because its
 * number bound stopped at the first digit of "Schedule 2.3" — the numbering
 * every purchase agreement uses to tie a schedule to the representation it
 * qualifies. STRUCT-018 named it correctly two findings below.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as RISK_009 } from "./risk-allocation/RISK-009.js";
import { rule as STRUCT_016 } from "./structural/STRUCT-016.js";
import { V5_RULES } from "./v5/index.js";

const mna106 = V5_RULES.find((r) => r.id === "MNA-106")!;

describe("RISK-009 on a carve-out from the cap", () => {
  it("stays silent when the unlimited language names a carve-out subject", () => {
    expect(
      RISK_009.check(
        buildContext([
          "Indemnification",
          "The Sellers' aggregate liability under Section 4.2 shall not exceed the Escrow Amount, except that liability for Fraud is unlimited.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when a party's liability is genuinely uncapped", () => {
    // A clause that really does leave liability uncapped names no exception.
    expect(
      RISK_009.check(
        buildContext(["Liability", "The Supplier's liability under this Agreement is unlimited."]),
      ),
    ).not.toBeNull();
  });

  it("reads the present tense as well as the modal", () => {
    // "Guarantor's liability IS NOT LIMITED in amount" is the operative
    // sentence of every unlimited guaranty, and of any agreement that
    // declines to cap. The branch read only "shall not be limited".
    expect(
      RISK_009.check(
        buildContext([
          "Guaranty",
          "Guarantor's liability under this Guaranty is not limited in amount.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still fires when the cap is removed rather than excepted", () => {
    expect(
      RISK_009.check(
        buildContext([
          "Liability",
          "There is no cap on the Supplier's liability for any claim arising under this Agreement.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("MNA-106 on a covenant that states its scope", () => {
  const doc = (...paras: string[]) =>
    buildContext(["Membership Interest Purchase Agreement", ...paras]);

  it("reads a covenant with a geography between the modal and the verb", () => {
    expect(
      mna106.check(
        doc(
          "For three years after the Closing, each Seller shall not, within the states in which the Company conducted business as of the Closing, engage in a business competitive with the Business, or solicit for employment any employee of the Company.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on an agreement with no restrictive covenant at all", () => {
    expect(
      mna106.check(doc("Each Seller shall deliver the Interests free and clear of all Liens.")),
    ).not.toBeNull();
  });
});

describe("STRUCT-016 on a decimal schedule number", () => {
  // The old bound stopped at the first digit of "Schedule 2.3" — the numbering
  // every purchase agreement uses to tie a schedule to the representation it
  // qualifies — so the finding named a "Schedule 2" the document never
  // mentions. Read through the EMPTY-exhibit branch since v1.3.0, which is the
  // fact this rule kept when STRUCT-018 took over attachment presence.
  it("names the schedule the document actually references", () => {
    const finding = STRUCT_016.check(
      buildContext(
        [
          "Representations",
          "The Financial Statements attached as Schedule 2.3 were prepared in accordance with GAAP.",
        ],
        ["Schedule 2.3", "[TBD]"],
      ),
    );
    expect(finding).not.toBeNull();
    expect(finding!.title).toContain("Schedule 2.3");
    expect(finding!.title).not.toBe("Schedule 2 referenced but empty");
  });
});

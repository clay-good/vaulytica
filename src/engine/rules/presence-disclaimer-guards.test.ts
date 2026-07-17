import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import type { Rule } from "../finding.js";
import { rule as FIN_006 } from "./financial/FIN-006.js";
import { rule as FIN_007 } from "./financial/FIN-007.js";
import { rule as FIN_008 } from "./financial/FIN-008.js";
import { rule as RISK_013 } from "./risk-allocation/RISK-013.js";
import { rule as TEMP_006 } from "./temporal/TEMP-006.js";
import { rule as OBLI_007 } from "./obligations/OBLI-007.js";
import { rule as OBLI_008 } from "./obligations/OBLI-008.js";
import { rule as OBLI_009 } from "./obligations/OBLI-009.js";
import { rule as TERM_001 } from "./termination/TERM-001.js";
import { rule as TERM_004 } from "./termination/TERM-004.js";
import { rule as TERM_006 } from "./termination/TERM-006.js";
import { rule as TERM_007 } from "./termination/TERM-007.js";
import { rule as IPDATA_006 } from "./ip-and-data/IPDATA-006.js";
import { rule as IPDATA_009 } from "./ip-and-data/IPDATA-009.js";
import { rule as PERS_004 } from "./personnel/PERS-004.js";
import { rule as PERS_006 } from "./personnel/PERS-006.js";
import { rule as PERS_008 } from "./personnel/PERS-008.js";

/**
 * Presence-detector negation guards. Each of these always-on rules asserts a
 * clause is PRESENT; each was firing on the document's explicit statement that
 * the clause is NOT present ("does not include a X clause", "shall not [do X]"),
 * a confident false accusation. Every row pins the disclaimed form → null and a
 * genuine form → fires, so the guard can never regress into either a false
 * accusation or an over-suppression.
 */
describe("presence-detector disclaimer guards", () => {
  const ctx = (text: string) => buildContext(["Clause", text]);
  const fires = (rule: Rule, text: string) => rule.check(ctx(text)) !== null;

  const cases: Array<{ id: string; rule: Rule; disclaimed: string; genuine: string }> = [
    {
      id: "FIN-006",
      rule: FIN_006,
      disclaimed:
        "This Agreement does not include a liquidated damages clause; actual damages shall be proven.",
      genuine:
        "If Vendor fails to meet the SLA, Vendor shall pay liquidated damages of $10,000 per incident.",
    },
    {
      id: "FIN-007",
      rule: FIN_007,
      disclaimed:
        "This Agreement does not contain a most-favored-nation clause; pricing may differ across customers.",
      genuine:
        "Vendor shall ensure Customer receives most-favored-nation pricing no less favorable than any other customer.",
    },
    {
      id: "FIN-008",
      rule: FIN_008,
      disclaimed:
        "This Agreement contains no minimum commitment or take-or-pay obligations; Customer may purchase any quantity.",
      genuine:
        "Customer shall pay a minimum commitment of $50,000 per quarter regardless of usage.",
    },
    {
      id: "RISK-013",
      rule: RISK_013,
      disclaimed:
        "This Agreement does not contain a force majeure clause; each party remains liable regardless of intervening events.",
      genuine:
        "Neither party shall be liable for delay caused by force majeure, including acts of God, war, or natural disaster.",
    },
    {
      id: "TEMP-006",
      rule: TEMP_006,
      disclaimed: "No provisions of this Agreement shall survive termination.",
      genuine:
        "Sections 5 (Confidentiality) and 8 (Indemnity) shall survive termination of this Agreement.",
    },
    {
      id: "OBLI-007",
      rule: OBLI_007,
      disclaimed: "This Agreement does not include a Material Adverse Change clause.",
      genuine:
        "Buyer may terminate this Agreement if a Material Adverse Change occurs prior to Closing.",
    },
    {
      id: "OBLI-008",
      rule: OBLI_008,
      disclaimed:
        "The parties shall not be held to any efforts standard, including best efforts, but rather to a fixed schedule.",
      genuine: "Contractor shall use best efforts to deliver the software by the milestone date.",
    },
    {
      id: "OBLI-009",
      rule: OBLI_009,
      disclaimed:
        "This Section shall not permit Recipient to retain or use information in unaided memory.",
      genuine:
        "Recipient may use Residuals, meaning information retained in the unaided memory of persons with access.",
    },
    {
      id: "TERM-001",
      rule: TERM_001,
      disclaimed:
        "Vendor shall not have the right to terminate this Agreement for convenience upon 30 days notice.",
      genuine:
        "Either party may terminate this Agreement for convenience upon 30 days written notice.",
    },
    {
      id: "TERM-004",
      rule: TERM_004,
      disclaimed: "Notice of termination need not be in writing and may be given orally.",
      genuine:
        "Notice of termination shall be given in writing to the other party's designated address.",
    },
    {
      id: "TERM-006",
      rule: TERM_006,
      disclaimed:
        "This Agreement does not include any wind-down or transition services obligations.",
      genuine:
        "Upon termination, Provider shall furnish transition services for up to 90 days to assist migration.",
    },
    {
      id: "TERM-007",
      rule: TERM_007,
      disclaimed:
        "Upon termination, Customer shall have no obligation to return, destroy, certify, or delete any data.",
      genuine:
        "Upon termination, Customer shall return or destroy all Confidential Information and certify destruction.",
    },
    {
      id: "IPDATA-006",
      rule: IPDATA_006,
      disclaimed: "This Agreement does not provide for source code escrow.",
      genuine:
        "The parties shall establish a source code escrow with a neutral third-party agent, releasable on Vendor bankruptcy.",
    },
    {
      id: "IPDATA-009",
      rule: IPDATA_009,
      disclaimed: "Vendor shall not use Customer Data to train any AI or machine-learning models.",
      genuine:
        "Vendor may use Customer Data to train and improve Vendor's AI and machine-learning models.",
    },
    {
      id: "PERS-004",
      rule: PERS_004,
      disclaimed:
        "This Agreement does not include a no-hire restriction on the other party's employees.",
      genuine:
        "Each party agrees to a no-hire covenant covering the other party's employees for 12 months.",
    },
    {
      id: "PERS-006",
      rule: PERS_006,
      disclaimed: "This Agreement does not include a non-disparagement obligation.",
      genuine:
        "Employee agrees not to disparage the Company, its officers, or its products in any communication.",
    },
    {
      id: "PERS-008",
      rule: PERS_008,
      disclaimed: "Employee shall not be required to repay training costs upon termination.",
      genuine:
        "If Employee resigns within 12 months of completing the training, Employee shall repay the full training cost.",
    },
  ];

  for (const c of cases) {
    it(`${c.id} suppresses the disclaimed form and fires on the genuine one`, () => {
      expect(fires(c.rule, c.disclaimed)).toBe(false);
      expect(fires(c.rule, c.genuine)).toBe(true);
    });
  }

  it("PERS-004 still fires on the operative 'will not hire' covenant (negator is the restriction)", () => {
    // The disclaimer guard must not suppress a genuine no-hire whose own trigger
    // is the negated verb — the "not" is at the match, not before it.
    expect(
      fires(PERS_004, "During the term, Employer will not hire the other party's employees."),
    ).toBe(true);
  });

  it("OBLI-009 suppresses a 'no <trigger>' disclaimer (bare determiner negates the trigger)", () => {
    // "no residuals clause is granted" negates the trigger noun directly — the
    // clause-absence markers reached "does not include" / "contains no" but not a
    // bare "no" sitting immediately before the trigger. A missed flag is safer
    // than a confident false accusation on a document that declined the clause.
    expect(
      fires(
        OBLI_009,
        "The receiving party shall not use residual knowledge; no residuals clause is granted.",
      ),
    ).toBe(false);
  });

  it("OBLI-007 still fires on an operative MAC materiality qualifier", () => {
    // "would not result in a material adverse effect" is an operative qualifier,
    // not a disclaimer of a MAC clause — the concept is present and must fire.
    expect(
      fires(
        OBLI_007,
        "Each representation must remain true except where the breach would not result in a material adverse effect.",
      ),
    ).toBe(true);
  });
});

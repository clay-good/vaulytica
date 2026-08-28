/**
 * Pack checks that assert a conjunction and implemented it as an OR.
 *
 * The joint-venture pack was 6 for 6; HC-120 and MNA-116 came out of a
 * corpus-wide experiment described at the bottom of this file.
 *
 * Every one of these six checks is named for two things — "Scope AND
 * exclusivity", "Governance, reserved matters, AND deadlock", "IP ownership
 * AND background IP" — and COMM-149's rationale spells out why both halves
 * matter: "Allocation and distribution are different decisions; a member
 * allocated taxable income with no distribution to pay the tax on it has a
 * real grievance from year one." `pat` defaults to an OR, so either half
 * alone scored the document clean, and a JV agreement that distributed cash
 * without ever allocating profit and loss passed COMM-149 in silence.
 *
 * Each case supplies BOTH halves as a real clause (must stay silent) and
 * then ONE half alone (must fire) — the direction an OR cannot test.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V5_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v5 rule ${id}`);
  return r;
};

const doc = (...rest: string[]) => buildContext(["Joint Venture Agreement", ...rest]);
const named = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

type Case = { id: string; both: string[]; halfOnly: string[]; missing: string };

const CASES: Case[] = [
  {
    id: "COMM-146",
    both: [
      "The Venture is formed for the sole purpose of developing and commercializing a combined immunoassay platform in North America.",
      "Neither Member shall compete with the Business during the term.",
    ],
    halfOnly: ["Neither Member shall compete with the Business during the term."],
    missing: "the purpose of the venture",
  },
  {
    id: "COMM-147",
    both: [
      "Each Member shall make an initial capital contribution of $6,000,000 in cash on the Effective Date.",
      "No Member shall be required to make any additional capital contribution without its written consent.",
    ],
    halfOnly: [
      "Each Member shall make an initial capital contribution of $6,000,000 in cash on the Effective Date.",
    ],
    missing: "what happens when more money is needed",
  },
  {
    id: "COMM-148",
    both: [
      "The Venture is managed by a board of four managers, two appointed by each Member.",
      "Any borrowing in excess of $500,000 requires the unanimous approval of the Board.",
    ],
    halfOnly: ["The Venture is managed by a board of four managers, two appointed by each Member."],
    missing: "the reserved matters and the deadlock ladder",
  },
  {
    id: "COMM-149",
    both: [
      "Profits and losses of the Venture shall be allocated to the Members pro rata in accordance with their membership interests.",
      "Distributable Cash shall be distributed to the Members pro rata, no less frequently than quarterly.",
    ],
    halfOnly: [
      "Distributable Cash shall be distributed to the Members pro rata, no less frequently than quarterly.",
    ],
    missing: "the allocation the distribution is measured against",
  },
  {
    id: "COMM-150",
    both: [
      "No Member shall transfer its membership interest without the prior written consent of the other Member.",
      "Either Member may then initiate the buy-sell procedure in this Section.",
    ],
    halfOnly: ["Either Member may then initiate the buy-sell procedure in this Section."],
    missing: "the transfer restriction the exit mechanism operates against",
  },
  {
    id: "COMM-151",
    both: [
      "Each Member retains sole ownership of all intellectual property it owned before the Effective Date.",
      "All intellectual property conceived or reduced to practice in the course of the Business is owned by the Venture.",
    ],
    halfOnly: [
      "All intellectual property conceived or reduced to practice in the course of the Business is owned by the Venture.",
    ],
    missing: "what each Member brought with it",
  },
];

describe.each(CASES)("$id — both halves required", ({ id, both, halfOnly, missing }) => {
  it("stays silent when the clause carries both halves", () => {
    const finding = rule(id).check(doc(...both));
    expect(finding, `${id} flagged a complete clause: ${finding?.title ?? ""}`).toBeNull();
  });

  it(`fires when the clause omits ${missing}`, () => {
    const finding = rule(id).check(doc(...halfOnly));
    expect(finding, `${id} accepted half a clause`).not.toBeNull();
    expect(finding!.rule_id).toBe(id);
  });
});

/**
 * Two more conjunctions, each found by conjoining all sixty candidates in a
 * throwaway build and running the specimen corpus through it. Only these two
 * moved anything, and only one of the two moves was a real defect — which is
 * why the other fifty-eight are still ORs.
 */
describe("HC-120 — two certifications, two statutes", () => {
  // "Part 54 requires the sponsor to collect investigator financial
  // disclosures, and § 335a bars using a debarred person in any capacity."
  const DEBARMENT =
    "Institution certifies that no person engaged in the Study is debarred under 21 U.S.C. § 335a or excluded from any federal health care program.";
  const DISCLOSURE =
    "Principal Investigator shall complete and deliver a financial disclosure on Form FDA 3455 before enrollment of the first subject, as required by 21 C.F.R. Part 54.";

  it("stays silent when the agreement carries both certifications", () => {
    const f = rule("HC-120").check(named("Clinical Trial Agreement", DEBARMENT, DISCLOSURE));
    expect(f, `HC-120 flagged a complete clause: ${f?.title ?? ""}`).toBeNull();
  });

  it("fires on a debarment certification with no Part 54 financial disclosure", () => {
    const f = rule("HC-120").check(named("Clinical Trial Agreement", DEBARMENT));
    expect(f, "HC-120 accepted a debarment certification alone").not.toBeNull();
  });
});

describe("MNA-116 — an effective time and further assurances", () => {
  const FURTHER =
    "Seller shall execute and deliver such further instruments as Buyer may reasonably request to vest title in the Assets.";

  it("reads the effective time out of the execution clause", () => {
    // "executed this Bill of Sale AS OF October 20, 2026" is where a bill of
    // sale states its effective time; conjoining the pillars without reading
    // it would have reported a dated instrument as undated.
    const f = rule("MNA-116").check(
      named(
        "Bill of Sale",
        FURTHER,
        "IN WITNESS WHEREOF, Seller has executed this Bill of Sale as of October 20, 2026.",
      ),
    );
    expect(f, `MNA-116 flagged a dated instrument: ${f?.title ?? ""}`).toBeNull();
  });

  it("fires on further assurances with no effective time at all", () => {
    const f = rule("MNA-116").check(named("Bill of Sale", FURTHER));
    expect(f, "MNA-116 accepted an instrument with no effective time").not.toBeNull();
  });
});

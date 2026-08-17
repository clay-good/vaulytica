import { describe, expect, it } from "vitest";

import { BAA_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";

const CLEAN_BAA =
  "Permitted Uses and Disclosures. Business Associate may use and disclose PHI only as permitted by this Agreement or as required by law. " +
  "Business Associate shall not use or further disclose PHI other than as permitted by this Agreement. " +
  "Safeguards. Business Associate shall implement appropriate safeguards, including administrative, physical, and technical safeguards, to protect PHI. " +
  "Reporting. Business Associate shall report to the Covered Entity any use or disclosure of PHI not provided for by this Agreement, including any security incident or breach. " +
  "Subcontractors. Business Associate shall ensure that any subcontractor or sub-processor that handles PHI agrees in writing to the same restrictions and conditions. " +
  "Individual Rights. Business Associate shall provide access to PHI in accordance with 164.524, shall make amendment of PHI in accordance with 164.526, and shall maintain an accounting of disclosures in accordance with 164.528. " +
  "HHS Access. Business Associate shall make its internal practices, books and records available to the Secretary for determining compliance. " +
  "Security Rule. Business Associate shall comply with the HIPAA Security Rule. " +
  "Termination. Covered Entity may terminate for material breach. On termination Business Associate shall return or destroy all PHI.";

const DENIALS: [string, string][] = [
  ["BAA-003", "Business Associate does not implement appropriate safeguards for PHI."],
  [
    "BAA-004",
    "Business Associate shall not report to the Covered Entity any use or disclosure of PHI not provided for by this Agreement.",
  ],
  [
    "BAA-005",
    "Business Associate is not required to ensure that any subcontractor agrees in writing to the same restrictions.",
  ],
  ["BAA-006", "Business Associate does not provide access to PHI to any individual."],
  ["BAA-007", "Business Associate shall not make any amendment of PHI upon request."],
  ["BAA-008", "Business Associate maintains no accounting of disclosures."],
  ["BAA-009", "Business Associate does not make its books and records available to the Secretary."],
];

const DECOYS: string[] = [
  "",
  "Business Associate shall not report to any third party other than the Covered Entity.",
  "Nothing in this Agreement limits the Covered Entity's right of access to PHI.",
  "This Section does not apply to subcontractors that never receive PHI.",
  "Business Associate may not disclose PHI without appropriate safeguards in place.",
  "Failure to provide an accounting of disclosures in any single instance is not permitted.",
  "The books and records provision does not affect any separate audit right.",
];

const fired = (text: string): string[] =>
  BAA_RULES.filter((r) => {
    const f = r.check(buildContext(["Business Associate Agreement", text]));
    return f !== null && /disclaim|denied/i.test(f.title);
  }).map((r) => r.id);

/**
 * A BAA clause-presence rule fires when NONE of its `present_patterns` match,
 * so a BAA that AFFIRMATIVELY DISCLAIMS an obligation matches every topic word
 * and the rule stays silent — while one that merely omits the topic is flagged
 * critical. Under HIPAA the disclaimer is the worse document. `denied_if`
 * inverts that.
 *
 * The assertion reads the finding TITLE: a partial fixture also trips the
 * ordinary missing-clause branch on unrelated rules, so only the denial title
 * proves `denied_if` is what matched.
 */
describe("v3 BAA presence rules — express denial", () => {
  it.each(DENIALS)("%s fires on an express disclaimer: %s", (id, tail) => {
    expect(fired(`${CLEAN_BAA} ${tail}`)).toContain(id);
  });

  // BAA-002's compliant drafting IS a negation ("shall not use or disclose PHI
  // other than as permitted"), so it deliberately carries no denial guard.
  it("leaves the rule whose required clause is itself a negation unguarded", () => {
    const baa002 = BAA_RULES.find((r) => r.id === "BAA-002");
    expect(baa002).toBeDefined();
    const f = baa002!.check(buildContext(["Business Associate Agreement", CLEAN_BAA]));
    expect(f, "BAA-002 must read the negated compliant clause as PRESENT").toBeNull();
  });

  it.each(DECOYS)("does not read compliant drafting as a denial: %s", (tail) => {
    expect(fired(`${CLEAN_BAA} ${tail}`)).toEqual([]);
  });
});

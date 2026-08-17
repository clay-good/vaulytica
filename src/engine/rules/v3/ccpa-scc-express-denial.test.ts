import { describe, expect, it } from "vitest";

import { DPA_US_STATE_RULES } from "./dpa-us-state/rules.js";
import { TRANSFER_RULES } from "./transfer/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";

const CLEAN_US =
  "Service Provider Addendum. Personal information is processed only for the limited and specified business purposes set out in the Agreement. " +
  "Service Provider shall not sell or share personal information, shall not use it for cross-context behavioral advertising, and shall not combine it with personal information from other sources. " +
  "Service Provider shall provide the same level of privacy protection as required by the CCPA. Service Provider certifies that it understands and will comply with these restrictions. " +
  "Business may monitor Service Provider's compliance through reasonable oversight, including audits. " +
  "Service Provider shall assist the Business with consumer requests to know, delete, and correct. " +
  "Service Provider shall notify the Business promptly of any inability to comply with its obligations. " +
  "Service Provider shall bind each subcontractor and subprocessor to the same restrictions by written contract.";

const CLEAN_SCC =
  "Standard Contractual Clauses. Clause 1 Purpose and Scope applies. Clause 2 Effect and Invariability of the Clauses applies and the Clauses are not modified. " +
  "Clause 8 Data Protection Safeguards applies in full. Clause 9 Use of Sub-processors applies, with general written authorisation. " +
  "Clause 11 Redress applies and data subjects may lodge a complaint. Clause 14 Local Laws requires a transfer impact assessment, which the parties warrant they have made. " +
  "Clause 15 Public Authority Access requires the importer to notify the exporter of any request from a public authority and to challenge it. " +
  "Clause 16 Non-Compliance applies. Clause 18 Governing Law and Forum applies.";

const CASES: [Rule[], string, string, boolean, string][] = [
  // dpa-us-state denials
  [
    DPA_US_STATE_RULES,
    "USDPA-005",
    CLEAN_US,
    true,
    "Service Provider does not provide the same level of privacy protection.",
  ],
  [
    DPA_US_STATE_RULES,
    "USDPA-007",
    CLEAN_US,
    true,
    "The Business may not monitor Service Provider's compliance.",
  ],
  [
    DPA_US_STATE_RULES,
    "USDPA-008",
    CLEAN_US,
    true,
    "Service Provider does not assist the Business with consumer requests.",
  ],
  [
    DPA_US_STATE_RULES,
    "USDPA-009",
    CLEAN_US,
    true,
    "Service Provider is not required to notify the Business of any inability to comply.",
  ],
  [
    DPA_US_STATE_RULES,
    "USDPA-010",
    CLEAN_US,
    true,
    "Subcontractors are not bound by the same restrictions.",
  ],
  // dpa-us-state decoys
  [DPA_US_STATE_RULES, "", CLEAN_US, false, ""],
  [
    DPA_US_STATE_RULES,
    "",
    CLEAN_US,
    false,
    "Nothing herein limits the Business's oversight rights.",
  ],
  [
    DPA_US_STATE_RULES,
    "",
    CLEAN_US,
    false,
    "This Section does not apply to subcontractors that never receive personal information.",
  ],
  [
    DPA_US_STATE_RULES,
    "",
    CLEAN_US,
    false,
    "Service Provider may not engage a subcontractor without a written contract.",
  ],
  // transfer denials
  [
    TRANSFER_RULES,
    "TRANSFER-004",
    CLEAN_SCC,
    true,
    "Clause 8 Data Protection Safeguards shall not apply to this transfer.",
  ],
  [
    TRANSFER_RULES,
    "TRANSFER-005",
    CLEAN_SCC,
    true,
    "The parties do not adopt Clause 9 Use of Sub-processors.",
  ],
  [
    TRANSFER_RULES,
    "TRANSFER-006",
    CLEAN_SCC,
    true,
    "Data subjects have no right of redress under these Clauses.",
  ],
  [
    TRANSFER_RULES,
    "TRANSFER-007",
    CLEAN_SCC,
    true,
    "The parties have performed no transfer impact assessment.",
  ],
  [
    TRANSFER_RULES,
    "TRANSFER-008",
    CLEAN_SCC,
    true,
    "The importer is not required to notify the exporter of any public authority request.",
  ],
  // transfer decoys
  [TRANSFER_RULES, "", CLEAN_SCC, false, ""],
  [
    TRANSFER_RULES,
    "",
    CLEAN_SCC,
    false,
    "Nothing in this Addendum limits the redress available under Clause 11.",
  ],
  [
    TRANSFER_RULES,
    "",
    CLEAN_SCC,
    false,
    "Clause 9 does not apply to sub-processors engaged before the effective date.",
  ],
  [
    TRANSFER_RULES,
    "",
    CLEAN_SCC,
    false,
    "The importer may not disclose data to a public authority without notifying the exporter.",
  ],
];

const denied = (rules: Rule[], text: string): string[] =>
  rules
    .filter((r) => {
      const f = r.check(buildContext(["Agreement", text]));
      return f !== null && /disclaim|denied/i.test(f.title);
    })
    .map((r) => r.id);

/**
 * Express-denial guards for the CCPA service-provider and SCC transfer packs.
 *
 * A clause-presence rule fires when NONE of its `present_patterns` match, so a
 * document that AFFIRMATIVELY DISCLAIMS the obligation matches every topic word
 * and the rule stays silent — while one that merely omits the topic is flagged.
 * `denied_if` inverts that. The assertion reads the finding TITLE, because a
 * fixture also trips the ordinary missing-clause branch on unrelated rules.
 *
 * USDPA-002/003/004 carry no guard by design: their required clauses ARE
 * prohibitions ("shall not sell", "shall not use for cross-context advertising",
 * "shall not combine"), so a denial frame would flag the compliant drafting.
 */
describe("v3 CCPA + SCC presence rules — express denial", () => {
  it.each(CASES.filter(([, , , want]) => want).map(([r, id, base, , tail]) => [id, r, base, tail]))(
    "%s fires on an express disclaimer: %s",
    (id, rules, base, tail) => {
      expect(denied(rules as Rule[], `${base} ${tail}`)).toContain(id);
    },
  );

  it.each(CASES.filter(([, , , want]) => !want).map(([r, , base, , tail]) => [tail, r, base]))(
    "does not read compliant drafting as a denial: %s",
    (_tail, rules, base) => {
      expect(denied(rules as Rule[], `${base} ${_tail}`)).toEqual([]);
    },
  );

  it("leaves the CCPA rules whose required clause is itself a prohibition unguarded", () => {
    for (const id of ["USDPA-002", "USDPA-003", "USDPA-004"]) {
      const r = DPA_US_STATE_RULES.find((x) => x.id === id);
      expect(r, id).toBeDefined();
      expect(r!.check(buildContext(["Agreement", CLEAN_US])), id).toBeNull();
    }
  });
});

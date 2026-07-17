import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";
import { IP_LICENSING_RULES } from "./ip-licensing/rules.js";
import { SETTLEMENT_RULES } from "./settlement/rules.js";
import { EQUITY_RULES } from "./equity/rules.js";
import { INSURANCE_RULES } from "./insurance/rules.js";
import { EMPLOYMENT_RULES } from "./employment/rules.js";
import { GOVERNANCE_RULES } from "./governance/rules.js";
import { COMPLIANCE_POLICY_RULES } from "./compliance-policy/rules.js";

/**
 * v4 language-quality rules built by buildV4LanguageRule fire when a
 * `bad_pattern` matches a paragraph. Without a carve-out guard, the pattern
 * also matches the DISCLAIMED / COMPLIANT form of the very thing it flags —
 * "royalties shall NOT extend beyond expiration" (Brulotte-compliant), "this
 * release does NOT apply to gross negligence" — a confident false accusation on
 * good drafting. Each row pins the compliant form → no finding and the genuine
 * violation → fires, locking in the `exclude_if` guards.
 */
describe("v4 language-rule carve-out guards", () => {
  const all: Rule[] = [
    ...IP_LICENSING_RULES,
    ...SETTLEMENT_RULES,
    ...EQUITY_RULES,
    ...INSURANCE_RULES,
    ...EMPLOYMENT_RULES,
    ...GOVERNANCE_RULES,
    ...COMPLIANCE_POLICY_RULES,
  ];
  const byId = (id: string): Rule => {
    const r = all.find((x) => x.id === id);
    if (!r) throw new Error(`rule ${id} not found`);
    return r;
  };
  const fires = (id: string, text: string) =>
    byId(id).check(buildContext(["Clause", text])) !== null;

  const cases: Array<{ id: string; compliant: string; violation: string }> = [
    {
      id: "IPL-009",
      compliant: "Royalties shall not extend beyond the expiration of the licensed patent.",
      violation:
        "Licensee shall pay royalties continuing after the expiration of the patent, in perpetuity.",
    },
    {
      id: "SET-005",
      compliant: "This release does not extend to future claims arising after the Effective Date.",
      violation:
        "This release covers any and all future claims of any kind whatsoever that may arise.",
    },
    {
      id: "SET-013",
      compliant:
        "This letter does not threaten arrest, criminal prosecution, or imprisonment if you fail to respond.",
      violation: "You will face arrest and criminal prosecution if you fail to pay within 10 days.",
    },
    {
      id: "SET-020",
      compliant: "Nothing in this letter constitutes extortion or blackmail.",
      violation: "We will expose your conduct to your employer unless you settle.",
    },
    {
      id: "EQT-012",
      compliant:
        "In no event shall interest exceed the maximum rate permitted by law, not to exceed 25% per annum.",
      violation: "Interest shall accrue at 30% per annum on the outstanding balance.",
    },
    {
      id: "EQT-028",
      compliant: "The Company shall not reprice any option without stockholder approval.",
      violation:
        "The Board may reprice outstanding options without stockholder approval at its discretion.",
    },
    {
      id: "INS-015",
      compliant:
        "Indemnitor shall not be obligated to indemnify Indemnitee, regardless of the theory of liability, for claims arising from Indemnitee's sole negligence.",
      violation:
        "Indemnitor shall indemnify Indemnitee regardless of Indemnitee's sole negligence.",
    },
    {
      id: "INS-022",
      compliant:
        "This Release does not apply to claims arising from gross negligence, willful misconduct, or intentional acts of Releasee.",
      violation:
        "Releasor agrees to release and hold harmless Releasee from gross negligence and willful misconduct.",
    },
    {
      id: "INS-010",
      compliant: "This endorsement does not exclude all coverage for pollution-related claims.",
      violation: "This endorsement excludes all coverage for pollution-related claims.",
    },
    {
      id: "EMP-020",
      compliant:
        "This confidentiality provision does not restrict Employee's right to discuss the terms of this agreement with an attorney or government agency.",
      violation:
        "Employee shall not disparage any person and shall keep confidential the terms of this agreement and any aspect thereof.",
    },
    {
      id: "GOV-011",
      compliant:
        "The exclusive forum shall be the Delaware Court of Chancery; provided that this provision shall not apply to any claim arising under the Securities Exchange Act of 1934.",
      violation:
        "The exclusive forum for all claims shall be the Delaware Court of Chancery, including any claim arising under the Securities Exchange Act of 1934.",
    },
    {
      id: "GOV-022",
      compliant:
        "Nothing in this Agreement shall waive or be deemed to waive the implied covenant of good faith and fair dealing.",
      violation:
        "Each Member waives the implied covenant of good faith and fair dealing to the fullest extent permitted.",
    },
    {
      id: "GOV-070",
      compliant:
        "This Agreement does not waive, eliminate, or disclaim the implied covenant of good faith and fair dealing.",
      violation:
        "The Manager may eliminate the implied covenant of good faith to the maximum extent permitted by law.",
    },
    {
      id: "POL-042",
      compliant:
        "This social media policy does not prohibit employees from discussing the company, their wages, or working conditions.",
      violation:
        "On social media, employees may not criticize the company or the employer in any public forum.",
    },
  ];

  for (const c of cases) {
    it(`${c.id} suppresses the compliant/disclaimed form and fires on the violation`, () => {
      expect(fires(c.id, c.compliant)).toBe(false);
      expect(fires(c.id, c.violation)).toBe(true);
    });
  }
});

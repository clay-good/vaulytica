import { describe, expect, it } from "vitest";

import { HEALTHCARE_RULES } from "./healthcare/rules.js";
import { PRIVACY_EXTENDED_RULES } from "./privacy-extended/rules.js";
import { EMPLOYMENT_RULES } from "./employment/rules.js";
import { SETTLEMENT_RULES } from "./settlement/rules.js";
import { BANKING_RULES } from "./banking/rules.js";
import { GOVERNANCE_RULES } from "./governance/rules.js";
import { REAL_ESTATE_RULES } from "./real-estate/rules.js";
import { M_AND_A_RULES } from "./m-and-a/rules.js";
import { EQUITY_RULES } from "./equity/rules.js";
import { TRUST_ESTATE_RULES } from "./trust-estate/rules.js";
import { IP_LICENSING_RULES } from "./ip-licensing/rules.js";
import { CONSTRUCTION_RULES } from "./construction/rules.js";
import { REGULATORY_PROSE_RULES } from "./regulatory-prose/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";

const ALL: Rule[] = [
  ...HEALTHCARE_RULES,
  ...PRIVACY_EXTENDED_RULES,
  ...EMPLOYMENT_RULES,
  ...SETTLEMENT_RULES,
  ...BANKING_RULES,
  ...GOVERNANCE_RULES,
  ...REAL_ESTATE_RULES,
  ...M_AND_A_RULES,
  ...EQUITY_RULES,
  ...TRUST_ESTATE_RULES,
  ...IP_LICENSING_RULES,
  ...CONSTRUCTION_RULES,
  ...REGULATORY_PROSE_RULES,
];
const byId = (id: string): Rule => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

// [rule, expect-fire?, sentence]
const CASES: [string, boolean, string][] = [
  // HC-015 — right to revoke
  ["HC-015", true, "The individual may not revoke this authorization once it has been signed."],
  ["HC-015", true, "This authorization cannot be revoked."],
  ["HC-015", true, "This authorization is irrevocable."],
  [
    "HC-015",
    false,
    "Right to Revoke. The individual may revoke this authorization in writing at any time, except to the extent the Company has already taken action in reliance on it. Send revocation to the Privacy Officer.",
  ],
  [
    "HC-015",
    false,
    "Right to Revoke. You may revoke this authorization at any time in writing. This authorization does not limit your right to revoke consent for future disclosures.",
  ],
  // PRV-004 — withdraw consent
  [
    "PRV-004",
    true,
    "Once given, consent to non-essential cookies may not be withdrawn for the remainder of the session.",
  ],
  ["PRV-004", true, "You cannot withdraw consent after accepting."],
  [
    "PRV-004",
    false,
    "You may withdraw your consent at any time via the cookie preference center. Withdrawing consent does not affect the lawfulness of processing carried out before the withdrawal.",
  ],
  [
    "PRV-004",
    false,
    "Withdraw Consent. Use the preference center to withdraw consent. Strictly necessary cookies do not require consent.",
  ],
  // PRV-029 — encryption
  [
    "PRV-029",
    true,
    "Customer data is not encrypted at rest; database backups are stored in plaintext.",
  ],
  [
    "PRV-029",
    false,
    "Data is encrypted at rest with AES-256 and encrypted in transit with TLS 1.3. Encryption at rest does not apply to non-production test fixtures containing only synthetic data.",
  ],
  // PRV-032 — incident response
  [
    "PRV-032",
    true,
    "The vendor does not maintain a documented incident response plan and provides no breach notification SLA.",
  ],
  [
    "PRV-032",
    false,
    "Incident Response. We maintain a documented incident response plan and provide breach notification within 72 hours. This section does not limit the incident response plan's application to systems outside production.",
  ],
  // EMP-016 — OWBPA revocation
  [
    "EMP-016",
    true,
    "Once signed, the Employee may not revoke this Agreement or the release of ADEA claims contained herein.",
  ],
  [
    "EMP-016",
    false,
    "Employee may revoke this Agreement within seven (7) days after signing, and this Agreement shall not become effective until the revocation period expires.",
  ],
  [
    "EMP-016",
    false,
    "Employee has twenty-one (21) days to consider. Nothing in this Section limits Employee's right to revoke this Agreement within the statutory revocation period.",
  ],
  // EMP-021 — protected rights
  [
    "EMP-021",
    true,
    "Employee shall not communicate with the SEC, EEOC, or NLRB regarding any matter addressed in this Agreement.",
  ],
  [
    "EMP-021",
    false,
    "Nothing in this Agreement prevents Employee from communicating with the SEC, EEOC, or NLRB or from filing a charge with any government agency.",
  ],
  [
    "EMP-021",
    false,
    "Protected Rights. This confidentiality provision does not restrict Employee's right to communicate with the SEC or to receive a whistleblower award.",
  ],
  // SET-008 — whistleblower carve-out
  [
    "SET-008",
    true,
    "Claimant shall not communicate with the SEC, EEOC, NLRB, or DOL regarding the facts underlying this settlement.",
  ],
  [
    "SET-008",
    false,
    "Nothing in this Agreement prohibits Claimant from communicating with the SEC, EEOC, NLRB, or DOL or from retaining any whistleblower award.",
  ],
  [
    "SET-008",
    false,
    "Protected Activity. This confidentiality clause does not apply to communications with government agencies regarding possible violations of law.",
  ],
  // BNK-015 — grant of security interest
  [
    "BNK-015",
    true,
    "Notwithstanding anything herein, Debtor does not grant Secured Party any security interest in the Collateral.",
  ],
  [
    "BNK-015",
    false,
    "Grant of Security Interest. Debtor hereby grants Secured Party a security interest in the Collateral. The security interest granted hereunder does not include any Excluded Collateral.",
  ],
  [
    "BNK-015",
    false,
    "Debtor grants a security interest in all accounts and inventory. Secured Party's failure to perfect its security interest does not affect the validity of the grant.",
  ],
  // BNK-013 — TILA / Reg Z
  [
    "BNK-013",
    true,
    "Borrower acknowledges that Lender does not provide Regulation Z disclosures in connection with this consumer loan.",
  ],
  [
    "BNK-013",
    false,
    "Truth in Lending. Lender has delivered the Regulation Z disclosures, including the APR and finance charge. This Agreement does not apply Regulation Z requirements to any advance made for business purposes.",
  ],
  // GOV-069 — partnership representative
  [
    "GOV-069",
    true,
    "The Partnership does not designate a Partnership Representative for purposes of Section 6223 of the Internal Revenue Code.",
  ],
  [
    "GOV-069",
    false,
    "Partnership Representative. The Members designate the Manager as the Partnership Representative under Section 6223. This designation does not apply to any tax year prior to the BBA regime.",
  ],
  // RE-048 — attornment
  ["RE-048", true, "Tenant shall not attorn to Lender or any purchaser at a foreclosure sale."],
  [
    "RE-048",
    false,
    "Attornment. Tenant shall attorn to and recognize any successor landlord. Tenant's attornment obligation does not apply to a successor who acquires the Property by voluntary conveyance.",
  ],
  // RE-056 — assumption of obligations
  [
    "RE-056",
    true,
    "Assignee does not assume any obligations of Assignor arising under the Lease from and after the Effective Date.",
  ],
  [
    "RE-056",
    false,
    "Assumption. Assignee assumes all obligations of Tenant under the Lease. Assignee's assumption of obligations does not apply to any obligation arising prior to the Effective Date.",
  ],
  // MNA-031 — appraisal rights
  [
    "MNA-031",
    true,
    "Appraisal rights shall not be available to any holder of Company Stock in connection with the Merger.",
  ],
  [
    "MNA-031",
    false,
    "Appraisal Rights. Stockholders who perfect their rights under DGCL § 262 are entitled to appraisal. This Section does not limit any stockholder's statutory appraisal rights.",
  ],
  // MNA-016 — restrictive covenants
  [
    "MNA-016",
    true,
    "For the avoidance of doubt, the Selling Stockholders shall not be subject to any non-compete or non-solicit restriction under this Agreement.",
  ],
  [
    "MNA-016",
    false,
    "Non-Competition. Each Selling Stockholder agrees to a three-year non-compete and non-solicit. The non-compete does not restrict passive ownership of less than 2% of a public company's stock.",
  ],
  // EQT-049 — demand registration
  ["EQT-049", true, "The Investors shall have no demand registration rights under this Agreement."],
  [
    "EQT-049",
    false,
    "Demand Registration. Investors may require two S-1 demand registrations. The demand registration rights do not apply prior to the six-month anniversary of the IPO.",
  ],
  // EQT-052 — pro rata participation
  [
    "EQT-052",
    true,
    "The Investors shall have no pro rata participation right in any future issuance of the Company's securities.",
  ],
  [
    "EQT-052",
    false,
    "Pro Rata Rights. Each Major Investor has a pro rata right to participate in future issuances. The pro rata right does not apply to Exempted Issuances.",
  ],
  // EST-032 — durable POA
  [
    "EST-032",
    true,
    "This power of attorney shall terminate upon the Principal's incapacity and is not durable.",
  ],
  [
    "EST-032",
    false,
    "Durable Power of Attorney. This power of attorney is durable and shall not be affected by the Principal's subsequent incapacity or disability.",
  ],
  [
    "EST-032",
    false,
    "This durable power of attorney survives incapacity. The durability of this power does not extend to a successor agent who has not accepted appointment.",
  ],
  // EST-039 — prenup financial disclosure
  [
    "EST-039",
    true,
    "The parties acknowledge that no financial disclosure was exchanged and each waives any right to disclosure of the other's assets.",
  ],
  [
    "EST-039",
    false,
    "Financial Disclosure. Each party has made full financial disclosure of assets and liabilities on Schedule A. The financial disclosure does not include assets held in a blind trust, disclosed separately in Schedule C.",
  ],
  // IPL-014 — trademark quality control
  ["IPL-014", true, "Licensor shall exercise no quality control over Licensee's use of the Marks."],
  [
    "IPL-014",
    false,
    "Quality Control. Licensor may inspect and approve goods bearing the Marks against its quality standards. This Section does not limit Licensor's right to exercise quality control through periodic inspection.",
  ],
  // CON-006 — indemnification
  [
    "CON-006",
    true,
    "Contractor shall not indemnify Owner for any claims, damages, or losses arising out of the Work.",
  ],
  [
    "CON-006",
    false,
    "Indemnification. Contractor shall indemnify and hold Owner harmless from all claims arising out of the Work. This indemnity does not extend to claims arising from Owner's sole negligence.",
  ],
  // REG-030 — conflicts of interest
  [
    "REG-030",
    true,
    "This Memorandum does not disclose any conflicts of interest between the General Partner and the Fund.",
  ],
  [
    "REG-030",
    false,
    "Conflicts of Interest. The General Partner discloses the related-party transactions described below. This disclosure requirement does not apply to conflicts immaterial to a reasonable investor.",
  ],
];

/**
 * A clause-presence rule fires when NONE of its `present_patterns` match, so a
 * document that AFFIRMATIVELY DISCLAIMS the required clause matches every topic
 * word and the rule stays silent — while a document that merely omits the topic
 * is flagged. `denied_if` inverts that. These cases pin both halves: the express
 * disclaimer fires with the denial title, and the compliant drafting that pairs
 * the topic with a negation does NOT.
 *
 * The assertion reads the finding TITLE rather than merely "did it fire",
 * because a one-sentence fixture also trips the ordinary missing-clause branch;
 * only the denial title proves `denied_if` is what matched.
 */
describe("v4 presence rules — express denial across packs", () => {
  it.each(CASES.filter(([, want]) => want).map(([id, , text]) => [id, text]))(
    "%s fires on an express disclaimer: %s",
    (id, text) => {
      const f = byId(id).check(buildContext(["Doc", text]));
      expect(f, `${id} did not fire`).not.toBeNull();
      expect(f?.title, `${id} fired as a plain omission, not a denial`).toMatch(
        /disclaim|denied|expressly/i,
      );
    },
  );

  it.each(CASES.filter(([, want]) => !want).map(([id, , text]) => [id, text]))(
    "%s does not read compliant drafting as a denial: %s",
    (id, text) => {
      const f = byId(id).check(buildContext(["Doc", text]));
      if (f) expect(f.title, `${id} misread a compliant clause`).not.toMatch(/disclaim|denied/i);
    },
  );
});

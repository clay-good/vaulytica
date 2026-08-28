/**
 * Both directions for the checks repaired off the KNOWN_VACUOUS list.
 *
 * Each of these had one `present_patterns` entry that was a word from its own
 * family's name, and `present_patterns` is an OR, so the check could never
 * fire on the only document it runs on. Conjoining the pillars makes it able
 * to fire — and makes it STRICTER, which is the dangerous direction. A check
 * that flags a compliant document is worse than one that never fires.
 *
 * So every repair is paired here with a clause written the way that rule's
 * own recommendation asks for it, and the clause must not be flagged.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";

const rule = (id: string) => {
  const r = V4_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

const CASES: Array<{ id: string; title: string; compliant: string }> = [
  {
    id: "CON-008",
    title: "Subcontractor Agreement",
    compliant:
      "Halloran Builders, Inc., as general contractor, and Meridian Steel LLC, as subcontractor, enter into this agreement for the Riverside Terminal project under the prime contract with the Owner.",
  },
  {
    id: "CON-014",
    title: "Construction Lien Waiver",
    compliant:
      "This is a conditional waiver and release on progress payment, effective only upon actual receipt of the payment identified below.",
  },
  {
    id: "CON-016",
    title: "Construction Lien Waiver",
    compliant:
      "The claimant waives and releases its lien rights only to the extent of the amount of $84,500 actually received, and only through the date of March 14, 2026.",
  },
  {
    id: "CON-021",
    title: "Payment / Performance Bond",
    compliant:
      "This performance bond and the accompanying payment bond are issued on AIA A312 forms for a project subject to the Miller Act.",
  },
  {
    id: "INS-005",
    title: "Insurance Policy Summary / Declarations",
    compliant:
      "Coverage is provided under form CG 00 01, edition 04 13, and form CP 00 10, edition 10 12, as scheduled below.",
  },
  {
    id: "INS-007",
    title: "Insurance Endorsement Review",
    compliant:
      "The endorsement is ISO form CG 20 10, edition 04 13, attached to and forming part of the policy.",
  },
  {
    id: "INS-011",
    title: "Insurance Endorsement Review",
    compliant:
      "Additional insured status is granted under CG 20 10 04 13 and CG 20 37 04 13, which together restore completed-operations coverage.",
  },
  {
    id: "INS-020",
    title: "Hold-Harmless Agreement",
    compliant:
      "The protecting party shall hold harmless the protected party, and the parties acknowledge that this obligation survives completion of the work.",
  },
  {
    id: "EST-011",
    title: "Revocable Living Trust",
    compliant:
      "During the Settlor's lifetime, the Settlor may revoke this Trust in whole or in part, and may amend or alter any of its terms, by a signed writing delivered to the Trustee.",
  },
  {
    id: "EST-024",
    title: "Healthcare Proxy / POA for Healthcare",
    compliant:
      "I, the undersigned principal, Dermot Halloran, appoint Priya Raghunathan as my agent and attorney-in-fact to make health care decisions for me.",
  },
  {
    id: "EST-032",
    title: "Durable Power of Attorney (Financial)",
    compliant:
      "This power of attorney is durable. It shall not be affected by my subsequent disability or incapacity, and shall not be terminated by my incapacity.",
  },
  {
    id: "HC-001",
    title: "Informed Consent (Research / Clinical)",
    compliant:
      "You are being asked to take part in a research study. The purpose of the study is to evaluate a benchtop immunoassay reader. Your participation is expected to last approximately six months.",
  },
  {
    id: "HC-010",
    title: "Patient Authorization for Release of PHI",
    compliant:
      "This authorization applies specifically to the following protected health information: laboratory results and imaging records from January 2025 to the present, which may be used and disclosed as described below.",
  },
  {
    id: "COMM-008",
    title: "Reseller / Distribution Agreement",
    compliant:
      "Supplier appoints Distributor as its non-exclusive distributor of the Products in the Territory, which comprises the United States and Canada.",
  },
  {
    id: "COMM-019",
    title: "Marketing Services Agreement",
    compliant:
      "Agency shall provide the marketing services described in each statement of work. The scope of services and the deliverables for each campaign are set out in the applicable SOW, and services to be performed outside it require a change order.",
  },
  {
    id: "GOV-071",
    title: "Nonprofit Bylaws (501(c)(3))",
    compliant:
      "The Corporation is organized exclusively for charitable purposes within the meaning of Section 501(c)(3) of the Internal Revenue Code, and its tax-exempt purpose is to advance public health research.",
  },
  {
    id: "EQT-043",
    title: "§ 83(b) Election Form",
    compliant:
      "The undersigned taxpayer hereby makes an election under Section 83(b) of the Internal Revenue Code of 1986, as amended. This 83(b) election is filed with respect to the restricted shares described below.",
  },
  {
    id: "EQT-066",
    title: "ROFR / Co-Sale Agreement (NVCA)",
    compliant:
      "Each Investor has a co-sale right: if a Key Holder proposes to transfer shares, each Investor may participate in the transfer on a tag-along basis, pro rata to its holdings.",
  },
  {
    id: "MNA-039",
    title: "Disclosure Schedules",
    compliant:
      "These disclosure schedules are delivered pursuant to the Purchase Agreement. General notes: the section headings are for convenience only, and disclosure in any section qualifies every other section to the extent reasonably apparent.",
  },
  {
    id: "MNA-055",
    title: "Transition Services Agreement (TSA)",
    compliant:
      "Seller shall provide the transition services set out in the schedule of services attached hereto. Each service description states the service level, the duration, and the monthly fee.",
  },
  {
    id: "RE-001",
    title: "Single-Tenant Net Lease (NNN)",
    compliant:
      "This is a triple-net lease. Tenant shall pay all real estate taxes and assessments levied against the Premises, together with all common area maintenance and operating expenses, in addition to Base Rent.",
  },
  {
    id: "RE-032",
    title: "CC&Rs (Declaration of Covenants, Conditions, and Restrictions)",
    compliant:
      "This Declaration of Covenants, Conditions, and Restrictions was recorded on March 14, 2026 in Book 4821 at Page 117 of the official records of the Register of Deeds of Mecklenburg County.",
  },
  {
    id: "EMP-032",
    title: "Proprietary Information and Inventions Agreement (PIIA)",
    compliant:
      "Employee shall hold all Confidential Information and proprietary information of the Company in strict confidence, and this non-disclosure obligation continues after employment ends.",
  },
  {
    id: "SET-021",
    title: "Tolling Agreement",
    compliant:
      "The parties agree that the statute of limitations and any limitations period applicable to the claims and causes of action described in Exhibit A are tolled from the Effective Date through the Termination Date.",
  },
  {
    id: "SET-025",
    title: "Litigation Hold Notice",
    compliant:
      "The Company is a party to a pending litigation matter and reasonably anticipates further claims arising from the same investigation. Preserve all documents described below.",
  },
  {
    id: "IPL-021",
    title: "Copyright License Agreement",
    compliant:
      "Licensor grants Licensee the right to reproduce, distribute, publicly display, publicly perform, and prepare derivative works of the Licensed Works, being the exclusive rights enumerated in 17 U.S.C. § 106.",
  },
  {
    id: "IPL-025",
    title: "Contributor License Agreement (CLA)",
    compliant:
      "If you are an individual, you represent that you are legally entitled to grant this license. If your employer is a corporation or other entity with rights in your Contribution, you represent that it has authorized the grant.",
  },
  {
    id: "IPL-031",
    title: "OSS Compliance Audit Document",
    compliant:
      "Each component is listed with its SPDX license identifier: openssl (Apache-2.0), zlib (Zlib), libxml2 (MIT), and readline (GPL-3.0-or-later).",
  },
  {
    id: "IPL-036",
    title: "Work-for-Hire Agreement",
    compliant:
      "The Work is a work made for hire under 17 U.S.C. § 101, specially ordered or commissioned for use as a contribution to a collective work and as a supplementary work.",
  },
  {
    id: "PRV-016",
    title: "Records of Processing Activities (GDPR Art. 30)",
    compliant:
      "This record of processing activities states, for each activity, the purposes of the processing: payroll administration, customer support, and security monitoring.",
  },
  {
    id: "PRV-023",
    title: "Data Protection Impact Assessment (GDPR Art. 35)",
    compliant:
      "The assessment evaluates the risks to the rights and freedoms of data subjects, scoring each by likelihood and by the severity of its impact.",
  },
  {
    id: "PRV-040",
    title: "Data-Incident Notification Template",
    compliant:
      "Where the incident affects 500 or more residents of a state, notice must be given to the state attorney general and to the supervisory authority, and substitute notice through statewide media may be required.",
  },
  {
    id: "HC-019",
    title: "Notice of Privacy Practices Acknowledgment",
    compliant:
      "I hereby acknowledge receipt of the Notice of Privacy Practices of Vanterra Health, and I have had an opportunity to ask questions about it.",
  },
];

describe.each(CASES)("$id", ({ id, title, compliant }) => {
  it("fires when the document carries nothing but its own title", () => {
    const f = rule(id).check(
      buildContext([title, "This document was signed on March 14, 2026 by the parties."]),
    );
    expect(f, `${id} cannot fire — its family's title alone satisfies it`).not.toBeNull();
  });

  it("stays silent on a clause written the way its recommendation asks", () => {
    const f = rule(id).check(buildContext([title, compliant]));
    expect(f, `${id} flagged a compliant clause: ${f?.title ?? ""}`).toBeNull();
  });
});

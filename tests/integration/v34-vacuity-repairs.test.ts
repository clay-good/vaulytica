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

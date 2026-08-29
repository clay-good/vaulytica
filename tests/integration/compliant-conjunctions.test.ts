/**
 * A conjunction must be satisfiable by a COMPLIANT clause.
 *
 * `require_all_present` (v4) and `all: true` (v5/v6) turn a pattern list into
 * PILLARS that must all be met. Getting that wrong is invisible from inside
 * the suite: the rule still fires on a bad document, and it also fires on a
 * good one, so the only way to see it is to write the clause the rule's own
 * recommendation asks for and check the rule goes quiet.
 *
 * These are the ones that did not. Every row below was a real defect — a
 * column that could not be satisfied by the drafting it exists to bless —
 * found by sweeping every conjunction in the catalog for one whose own
 * recommendation text does not satisfy it, then writing the clause by hand.
 *
 * The list is a floor, not a ceiling: add a row whenever a conjunction is
 * repaired, and the repair stays repaired.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import type { Rule } from "../../src/engine/finding.js";

const ALL: Rule[] = [...V4_RULES, ...V5_RULES, ...V6_RULES];
const rule = (id: string): Rule => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

/** [rule id, heading, the compliant clause, what the rule used to demand]. */
const COMPLIANT: Array<[string, string, string, string]> = [
  [
    "ENG-002",
    "Engagement Letter",
    "Our client in this matter is Halstead Brothers Aggregates, LLC only. We do not represent its members, officers, affiliates, or subsidiaries, and our representation of the Company does not create an attorney-client relationship with any of them.",
    'the adjacent "our client is", which a letter opening more than one matter never writes',
  ],
  [
    "SET-106",
    "Settlement Agreement and Release",
    "This document is a settlement agreement and general release. It is not a covenant not to sue and shall not be construed as one.",
    "the covenant-side characterization only, never its mirror",
  ],
  [
    "COMM-231",
    "Subscription Terms",
    "Your subscription renews for a further term of one year at the then-current annual price of $1,188, billed annually, unless you cancel through the account page before the renewal date. We disclose the renewal term, price, and billing frequency clearly and conspicuously before we collect your billing information.",
    'the adverb in "automatically renews"',
  ],
  [
    "COMM-146",
    "Joint Venture Agreement",
    "The Venture's business is the design, manufacture, and sale of benchtop immunoassay readers in North America and the European Union. Neither Member may pursue that business outside the Venture in those territories during the Term.",
    'the of-phrase "business of the venture", never the possessive',
  ],
  [
    "MNA-055",
    "Transition Services Agreement",
    "SCHEDULE OF SERVICES. Payroll administration, twelve months, $18,400 per month. IT helpdesk, six months, $9,200 per month. Accounts payable processing, nine months, $6,750 per month.",
    "three spellings of one fact, conjoined, the first being the family's own title",
  ],
  [
    "RE-001",
    "Office Lease",
    "In addition to Base Rent, Tenant shall pay its Proportionate Share of real estate taxes, property insurance premiums, and common area maintenance charges for the Building, as Additional Rent, within thirty days after Landlord's statement.",
    'the words "triple net", which the clause never carries and only the lease title might',
  ],
  [
    "PRV-040",
    "Incident Response Plan",
    "The Company notifies the affected state attorneys general where the number of affected residents of a state exceeds that state's threshold, notifies the Secretary of Health and Human Services where a breach affects 500 or more individuals, and files an Item 1.05 Form 8-K where the incident is material.",
    'the singular "attorney general"',
  ],
  [
    "DISC-019",
    "Responses and Objections to Requests for Production",
    "Subject to and without waiving the foregoing objections, Defendant will produce all non-privileged responsive documents in its possession, custody, or control, and is withholding documents responsive to this request solely on the basis of the attorney-client privilege, which are identified on the privilege log served herewith.",
    "a withholding statement written any way but the plainest",
  ],
  [
    "GOV-071",
    "Article I — Purposes",
    "The corporation is organized exclusively for charitable and educational purposes within the meaning of Section 501(c)(3) of the Internal Revenue Code of 1986, as amended.",
    "three spellings of one fact, conjoined",
  ],
  [
    "EMP-148",
    "Disclosure Regarding Background Investigation",
    'Halverson Grid Services, Inc. may obtain information about you from a consumer reporting agency for employment purposes. Thus, you may be the subject of a "consumer report" which may include information about your character, general reputation, and mode of living.',
    "that the disclosure describe ITSELF as stand-alone, which a lawful one never does",
  ],
  [
    "MNA-039",
    "Disclosure Schedules",
    'These Disclosure Schedules are delivered by the Company pursuant to the Stock Purchase Agreement dated as of February 20, 2026 (the "Purchase Agreement"). The section numbers below correspond to the section numbers of the Purchase Agreement, and any matter disclosed in any section is deemed disclosed for the purposes of every other section to the extent its relevance is reasonably apparent.',
    'the literal heading "General Notes"',
  ],
  [
    "MNA-042",
    "Disclosure Schedules",
    "Nothing disclosed here is an admission that the matter is material, that it is required to be disclosed, or that it constitutes a breach of any representation. The inclusion of any dollar amount is not a representation that the amount is material.",
    'the negator "not" and the noun "admission", never "Nothing" and "representation"',
  ],
  [
    "ENG-012",
    "Contingency Fee Agreement",
    "The Firm will not represent the Client on appeal, in a bankruptcy, in a related insurance coverage dispute, or in any other matter unless the parties sign a separate agreement.",
    "a label, where the exclusion is written as a promise",
  ],
  [
    "RE-128",
    "Quitclaim Deed",
    "THE GRANTOR, Rosalind Amara Ferreira, conveys and quitclaims to THE GRANTEE all right, title, and interest that the Grantor may have in the property.",
    'the word "hereby", which the statutory short form does not contain',
  ],
  [
    "DISC-004",
    "Requests for Production",
    "Produce electronically stored information in single-page TIFF images with document-level extracted text, a Concordance-delimited load file, and the metadata fields listed in Appendix A; produce spreadsheets and audio in native format.",
    "the passive voice only, never the imperative the instruction is written in",
  ],
  [
    "DISC-017",
    "Responses and Objections to Requests for Production",
    "Defendant objects to this request as overbroad because it seeks documents from 2011, six years before the parties first did business, and as unduly burdensome because collecting them would require restoring forty backup tapes at a cost of approximately $180,000.",
    'the phrase "on the ground that", never the "as X because Y" practitioners write',
  ],
  [
    "DISC-018",
    "Responses and Objections to Requests for Production",
    "Defendant is withholding documents responsive to this request on the basis of the attorney-client privilege and the work-product doctrine, and has identified them on the privilege log served with these responses.",
    "the passive withholding statement only, never the active one",
  ],
];

describe("a conjunction is satisfiable by the clause it asks for", () => {
  it.each(COMPLIANT)("%s is silent on a compliant clause", (id, heading, clause) => {
    const ctx = buildContext(
      [heading, clause],
      ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
    );
    const finding = rule(id).check(ctx);
    expect(finding, `${id} fired: ${finding?.title ?? ""}`).toBeNull();
  });

  it("every row names a rule that still exists", () => {
    for (const [id] of COMPLIANT) expect(() => rule(id), id).not.toThrow();
  });
});

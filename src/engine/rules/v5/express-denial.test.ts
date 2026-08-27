/**
 * Express-denial guards for the v5 catalog (spec-v45.md §4, `denied`).
 *
 * A clause-presence check reads the document for the words the required
 * clause would use, so a document that AFFIRMATIVELY DISCLAIMS the term —
 * "the Company performs no restricted-party screening", "IRB approval is not
 * required before enrollment" — is silent: every topic word is present, and
 * the column scores as satisfied. That is backwards. An express denial is
 * strictly worse than an omission, because an omission may be an oversight
 * and a denial is a decision.
 *
 * `expressDenial()` was built for the v4 packs and wired into 27 of their
 * rules; none of the 697 rules the v5/v6 shorthand builds used it. Fourteen
 * columns now do — the ones where a denial is realistic drafting and the
 * required clause is an affirmative undertaking rather than a prohibition. A
 * column whose required clause is ITSELF a negation, waiver, or ban is
 * disqualified: PRV-114 (consent not a condition of purchase) and HC-123
 * (balance-billing ban) are checked by their absence, and a "denial" of them
 * is unreadable.
 *
 * Both directions are pinned, and the second half is the load-bearing one:
 * every decoy below is COMPLIANT drafting that puts the topic words inside a
 * negation. That is where the frames break. EMP-103 broke on the first
 * attempt — "the employee shall not be required to bear arbitration costs
 * beyond a court filing fee" is the clause the rule exists to bless, and a
 * bare "arbitration costs" topic read it as a denial, because the frames
 * cannot see WHOSE obligation is being negated. The topic is now the
 * employer's undertaking (paying), not the cost.
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V5_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v5 rule ${id}`);
  return r;
};
const doc = (text: string) => buildContext(["Document", text]);

/** [rule, the disclaimer, compliant drafting that negates around the topic]. */
const CASES: Array<[string, string, string]> = [
  [
    "PRV-101",
    "The Company does not obtain a written release before collection of biometric identifiers.",
    "The Company shall not collect any biometric identifier without a written release signed by the subject.",
  ],
  [
    "PRV-104",
    "The Company maintains no retention and destruction schedule for biometric data.",
    "Biometric data shall not be retained after the retention and destruction schedule requires its destruction.",
  ],
  [
    "PRV-109",
    "Verifiable parental consent is not obtained before collection from children.",
    "No personal information will be collected from a child unless verifiable parental consent is first obtained.",
  ],
  [
    "PRV-113",
    "Prior express written consent is not required for messages sent under this program.",
    "No marketing message will be sent unless prior express written consent has been obtained.",
  ],
  [
    "PRV-117",
    "An opt-out mechanism is not provided; replying STOP has no effect.",
    "Message frequency varies. The opt-out mechanism may not be disabled by any vendor. Reply STOP to cancel and HELP for help.",
  ],
  [
    "HC-104",
    "The Practice does not provide tail coverage upon termination.",
    "The Physician shall not terminate without procuring tail coverage at the Physician's expense.",
  ],
  [
    "HC-115",
    "IRB approval is not required before enrollment begins at this site.",
    "No subject shall be enrolled before IRB approval is obtained for this site.",
  ],
  [
    "POL-114",
    "The Company performs no restricted-party screening of counterparties.",
    "No shipment shall be released without restricted-party screening against the SDN List.",
  ],
  [
    "COMM-233",
    "An online cancellation mechanism is not provided to subscribers.",
    "Subscribers may cancel at any time. The online cancellation mechanism shall not be more burdensome than the enrollment flow.",
  ],
  [
    "COMM-178",
    "Creator is not required to disclose the material-connection disclosure to followers.",
    "Creator shall not publish sponsored content without a clear and conspicuous material-connection disclosure.",
  ],
  [
    "EMP-103",
    "The Company does not pay arbitration fees; the employee bears them.",
    "The Company shall pay all arbitration fees. The employee shall not be required to bear arbitration costs beyond a court filing fee.",
  ],
  [
    "EMP-150",
    "A written authorization is not required before the report is obtained.",
    "No consumer report will be obtained unless a clear written authorization has been signed by the applicant.",
  ],
  [
    "EMP-153",
    "A pre-adverse action notice is not provided before the decision is made.",
    "No adverse action shall be taken until a pre-adverse action notice has been provided with the report and the summary of rights.",
  ],
  [
    "CON-106",
    "The Architect does not maintain professional liability insurance for this project.",
    "The Architect shall not commence services without professional liability insurance in the amounts stated below.",
  ],
];

describe("v5 express-denial guards", () => {
  for (const [id, denial] of CASES) {
    it(`${id} reports a disclaimer AS a disclaimer`, () => {
      // The assertion reads the TITLE, not merely "did it fire". A denial that
      // reported "— not found" would be indistinguishable from an omission in
      // the findings index, the compliance matrix, and the execution log.
      expect(rule(id).check(doc(denial))?.title).toContain("expressly disclaimed");
    });
  }

  for (const [id, , decoy] of CASES) {
    it(`${id} is not fooled by compliant drafting that negates around the topic`, () => {
      expect(rule(id).check(doc(decoy))?.title ?? "").not.toContain("expressly disclaimed");
    });
  }

  it("every wired column carries a distinct denial title", () => {
    // The title is generated once in `pack()`, from the column name, so a
    // duplicate would mean two columns share a name — and the reader could
    // not tell which one the document disclaimed.
    const titles = CASES.map(([id, denial]) => rule(id).check(doc(denial))?.title);
    expect(new Set(titles).size).toBe(CASES.length);
  });
});

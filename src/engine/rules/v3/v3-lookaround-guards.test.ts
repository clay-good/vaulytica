/**
 * Guards against DIRECTIONAL-LOOKAROUND and compliant-form false accusations in
 * the v3 packs.
 *
 * Three rules expressed "…and no carve-out follows" as a forward-only negative
 * lookahead, so a carve-out or required element drafted BEFORE the trigger — a
 * completely ordinary way to draft ("Notwithstanding the foregoing, … ;
 * therefore, neither party may assign …") — was reported as absent:
 *
 *  - NDA-D-020 reported "no general-solicitation carve-out … in the same
 *    paragraph" when the carve-out opened that very paragraph.
 *  - USDPA-020 (critical) reported a CCPA Service Provider claim as missing its
 *    § 7051 elements when both elements were recited immediately before it.
 *  - MSA-023 reported an assignment clause as silent on change-of-control when
 *    the change-of-control hook was the preceding sentence.
 *
 * Two more matched the compliant form outright:
 *  - NDA-D-011 read "for any purpose OTHER THAN the Purpose" — the narrow
 *    framing NDA-D-012 checks for — as an unbounded any-purpose grant.
 *  - TRANSFER-003 read a non-derogation savings clause ("incorporated in full
 *    and without modification, notwithstanding any other term … the SCCs shall
 *    govern") as forbidden modification of the SCCs.
 *
 * Both directions are pinned for each rule.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";
import { NDA_DEEP_RULES } from "./nda-deep/index.js";
import { DPA_US_STATE_RULES } from "./dpa-us-state/index.js";
import { MSA_DEEP_RULES } from "./msa-deep/index.js";
import { TRANSFER_RULES } from "./transfer/index.js";

const find = (rules: readonly Rule[], id: string) => rules.find((r) => r.id === id)!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("NDA-D-011 — narrow 'other than the Purpose' framing", () => {
  it("stays silent on a use clause limited to a defined Purpose", () => {
    expect(
      find(NDA_DEEP_RULES, "NDA-D-011").check(
        doc(
          "Permitted Use",
          'Receiving Party shall not use the Confidential Information for any purpose other than to evaluate the potential business relationship between the parties (the "Purpose").',
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely unbounded any-purpose grant", () => {
    expect(
      find(NDA_DEEP_RULES, "NDA-D-011").check(
        doc(
          "Permitted Use",
          "Receiving Party may use the Confidential Information for any business purpose.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("NDA-D-020 — carve-out drafted before the non-solicit trigger", () => {
  it("stays silent when the general-solicitation carve-out precedes the covenant", () => {
    expect(
      find(NDA_DEEP_RULES, "NDA-D-020").check(
        doc(
          "Non-Solicitation",
          "Notwithstanding the foregoing, this Section shall not restrict general solicitations of employment, such as public job postings not specifically directed at the other party's employees. Subject to that carve-out, each party shall not solicit for employment any employee of the other party.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a non-solicit with no carve-out at all", () => {
    expect(
      find(NDA_DEEP_RULES, "NDA-D-020").check(
        doc(
          "Non-Solicitation",
          "During the term and for one year thereafter, each party shall not solicit for employment any employee of the other party.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("USDPA-020 — § 7051 elements recited before the status claim", () => {
  it("stays silent when both required elements precede the Service Provider claim", () => {
    expect(
      find(DPA_US_STATE_RULES, "USDPA-020").check(
        doc(
          "CCPA Terms",
          "Service Provider shall not retain, use, or disclose personal information for any purpose other than the specific business purpose enumerated in this Agreement, and shall provide the same level of privacy protection as required by the CCPA. Based on the foregoing restrictions, Vendor is granted Service Provider status under the CCPA.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a bare Service Provider claim with no § 7051 elements", () => {
    expect(
      find(DPA_US_STATE_RULES, "USDPA-020").check(
        doc("CCPA Terms", "Vendor is granted Service Provider status under the CCPA."),
      ),
    ).not.toBeNull();
  });
});

describe("MSA-023 — change-of-control hook before the assignment sentence", () => {
  it("stays silent when change-of-control is addressed just before the clause", () => {
    expect(
      find(MSA_DEEP_RULES, "MSA-023").check(
        doc(
          "Assignment",
          "For purposes of this Section, a change of control, merger, or acquisition of a party shall be deemed an assignment requiring the other party's prior written consent. Except as set forth above, neither party may assign this Agreement without consent.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags an assignment clause genuinely silent on change-of-control", () => {
    expect(
      find(MSA_DEEP_RULES, "MSA-023").check(
        doc(
          "Assignment",
          "Neither party may assign this Agreement without the prior written consent of the other party.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("TRANSFER-003 — SCC non-derogation savings clause", () => {
  it("stays silent on SCCs incorporated in full and without modification", () => {
    expect(
      find(TRANSFER_RULES, "TRANSFER-003").check(
        doc(
          "Standard Contractual Clauses",
          "The parties incorporate the Standard Contractual Clauses (Module Two) in full and without modification, notwithstanding any other term of this Agreement, so that the SCCs shall govern to the extent of any conflict.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags SCCs that are actually modified", () => {
    expect(
      find(TRANSFER_RULES, "TRANSFER-003").check(
        doc(
          "Standard Contractual Clauses",
          "The Standard Contractual Clauses, as modified by Annex IV, shall apply to transfers under this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });

  it("still flags a term overriding a provision of the SCCs", () => {
    expect(
      find(TRANSFER_RULES, "TRANSFER-003").check(
        doc(
          "Liability",
          "Notwithstanding any provision of the SCCs, each party's liability shall be capped at the fees paid.",
        ),
      ),
    ).not.toBeNull();
  });
});

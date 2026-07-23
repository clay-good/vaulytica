/**
 * Guards against carve-out blindness in the *McLaren Macomb* / NLRA § 7
 * overbroad-confidentiality rules (EMP-020, SET-007).
 *
 * Post-*McLaren Macomb*, the compliant way to draft a settlement or separation
 * confidentiality clause is to state the restriction and then preserve § 7
 * rights with a "Nothing in this Agreement prohibits or restricts …" carve-out.
 * Flagging that clause as "broad enough to chill protected concerted activity"
 * — and recommending the carve-outs it already contains — is a confident false
 * accusation against the textbook-compliant draft.
 *
 * EMP-020 previously guarded only the "does/shall not restrict" phrasing and
 * SET-007 carried no guard at all, so both fired on the dominant real-world
 * drafting form. Both directions are pinned: the compliant carve-out is
 * silent, a genuinely overbroad clause still fires.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { EMPLOYMENT_V4_RULES } from "./employment/index.js";
import { SETTLEMENT_RULES } from "./settlement/index.js";

const EMP020 = EMPLOYMENT_V4_RULES.find((r) => r.id === "EMP-020")!;
const SET007 = SETTLEMENT_RULES.find((r) => r.id === "SET-007")!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("EMP-020 — McLaren Macomb carve-out blindness", () => {
  it("stays silent on a clause preserving § 7 rights via 'Nothing in this Agreement prohibits'", () => {
    expect(
      EMP020.check(
        doc(
          "Confidentiality",
          "Employee agrees to keep the terms of this Agreement confidential. Nothing in this Agreement prohibits or restricts Employee from communicating with the SEC, EEOC, NLRB, or any other government agency, or from engaging in protected concerted activity under Section 7 of the NLRA.",
        ),
      ),
    ).toBeNull();
  });

  it("still honors the pre-existing 'does not restrict' carve-out phrasing", () => {
    expect(
      EMP020.check(
        doc(
          "Confidentiality",
          "Employee shall not disclose the terms of this Agreement to any person. This Agreement does not restrict Employee from filing a charge with the EEOC.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely overbroad clause carrying no carve-out", () => {
    expect(
      EMP020.check(
        doc(
          "Confidentiality",
          "Employee shall not disclose the terms of this Agreement to any person, and shall not disparage the Company to any individual, at any time.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("SET-007 — McLaren Macomb carve-out blindness", () => {
  it("stays silent on a settlement clause that carves out agency communication", () => {
    expect(
      SET007.check(
        doc(
          "Confidentiality",
          "The Parties agree to keep the terms of this Agreement confidential, and shall not disclose the terms of this Agreement to any third party, except that either Party may disclose the terms to their attorney, accountant, or spouse, or as required by law. Nothing in this Agreement prohibits or restricts Claimant from communicating with the SEC, EEOC, or NLRB.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely overbroad settlement confidentiality clause", () => {
    expect(
      SET007.check(
        doc(
          "Confidentiality",
          "Claimant shall not disclose the terms of this Agreement to any person, and shall not disparage the Company to any individual or entity, for any reason whatsoever.",
        ),
      ),
    ).not.toBeNull();
  });
});

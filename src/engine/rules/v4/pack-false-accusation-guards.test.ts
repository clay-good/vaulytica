/**
 * Guards against three v4 language rules that accused compliant documents.
 *
 *  - RE-038 matched `no/not` within 40 characters of a protected-class term,
 *    so a Fair Housing Act compliance / repudiation clause tripped the very
 *    rule that cites the FHA and *Shelley v. Kraemer* — the tool accused the
 *    remediation clause of being the discriminatory covenant it voids. This is
 *    a `critical` finding, and the worst false accusation this rule can make.
 *  - IPL-009 recognized only the modal "shall not extend", so the equally
 *    standard "royalty obligations DO NOT extend beyond ... expiration" — a
 *    textbook *Brulotte / Kimble*-compliant clause — was reported as extending
 *    royalties past expiration.
 *  - MNA-074 took any 6-19 year figure sharing a sentence with the covenant as
 *    the covenant's own duration, so "the Company has 10 years of history
 *    supporting the restricted period" was reported as a 10-year non-compete.
 *
 * Both directions are pinned for each rule.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { REAL_ESTATE_RULES } from "./real-estate/index.js";
import { IP_LICENSING_RULES } from "./ip-licensing/index.js";
import { M_AND_A_RULES } from "./m-and-a/index.js";
import { REGULATORY_PROSE_RULES } from "./regulatory-prose/index.js";
import { EMPLOYMENT_V4_RULES } from "./employment/index.js";

const re038 = REAL_ESTATE_RULES.find((r) => r.id === "RE-038")!;
const ipl009 = IP_LICENSING_RULES.find((r) => r.id === "IPL-009")!;
const mna074 = M_AND_A_RULES.find((r) => r.id === "MNA-074")!;
const reg019 = REGULATORY_PROSE_RULES.find((r) => r.id === "REG-019")!;
const emp024 = EMPLOYMENT_V4_RULES.find((r) => r.id === "EMP-024")!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("RE-038 — fair-housing compliance clause is not a discriminatory covenant", () => {
  it("stays silent on a Fair Housing Act compliance / repudiation clause", () => {
    expect(
      re038.check(
        doc(
          "Fair Housing Compliance",
          "Consistent with the Fair Housing Act, 42 U.S.C. § 3604, occupancy shall not be denied to any person who is Black, Asian, Hispanic, or Jewish. Any prior recorded restriction purporting to exclude such persons is void and of no further force or effect.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags an actual legacy discriminatory covenant", () => {
    expect(
      re038.check(
        doc(
          "Use Restrictions",
          "No Negro or person of color shall occupy any lot within this subdivision.",
        ),
      ),
    ).not.toBeNull();
  });

  it("still flags a Caucasian-only occupancy restriction", () => {
    expect(
      re038.check(
        doc("Use Restrictions", "Occupancy is restricted to persons of the Caucasian race."),
      ),
    ).not.toBeNull();
  });
});

describe("IPL-009 — Brulotte guard recognizes non-modal negation", () => {
  it("stays silent when royalty obligations DO NOT extend beyond expiration", () => {
    expect(
      ipl009.check(
        doc(
          "Royalties",
          "Licensee's royalty obligations do not extend beyond the date of expiration of the Licensed Patents.",
        ),
      ),
    ).toBeNull();
  });

  it("still honors the pre-existing 'shall not extend' phrasing", () => {
    expect(
      ipl009.check(
        doc(
          "Royalties",
          "Royalties shall not extend beyond the expiration of the last Licensed Patent.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags royalties genuinely payable after expiration", () => {
    expect(
      ipl009.check(
        doc(
          "Royalties",
          "Licensee shall continue to pay royalties after the expiration of the Licensed Patents for so long as the Agreement remains in effect.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("MNA-074 — the year count must be the covenant's own duration", () => {
  it("does not read an unrelated year figure as the restricted period", () => {
    expect(
      mna074.check(
        doc(
          "Background",
          "The Company has 10 years of history supporting the restricted period in Section 1.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a restricted period that is stated as over five years", () => {
    expect(
      mna074.check(doc("Restrictive Covenants", "The Restricted Period shall be 7 years.")),
    ).not.toBeNull();
  });

  it("still flags a long non-compete stated as a period of years", () => {
    expect(
      mna074.check(
        doc(
          "Restrictive Covenants",
          "For a period of 7 years following the Closing, the Seller shall not compete with the Business.",
        ),
      ),
    ).not.toBeNull();
  });

  it("still flags the adjectival form", () => {
    expect(
      mna074.check(doc("Restrictive Covenants", "The Seller agrees to a 7-year non-compete.")),
    ).not.toBeNull();
  });

  it("leaves a compliant 3-year covenant alone", () => {
    expect(
      mna074.check(doc("Restrictive Covenants", "The Restricted Period shall be 3 years.")),
    ).toBeNull();
  });
});

describe("REG-019 — a disclosed actual incident is not a hypothetical risk", () => {
  it("stays silent when the paragraph discloses the incident that already occurred", () => {
    expect(
      reg019.check(
        doc(
          "Risk Factors",
          "In March 2026, we experienced and disclosed an actual data breach affecting 40,000 customers, for which we incurred 2.3 million dollars in remediation costs. We may face cyber incidents again in the future, which could adversely affect our reputation.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a purely hypothetical cyber risk factor", () => {
    expect(
      reg019.check(
        doc(
          "Risk Factors",
          "We may experience cyber incidents in the future, which could adversely affect our reputation and results of operations.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("EMP-024 — an agreement that disclaims a non-compete has no non-compete", () => {
  it("stays silent on a clause stating the employee is subject to no non-compete", () => {
    expect(
      emp024.check(
        doc(
          "No Non-Compete",
          "Employee shall not be subject to any covenant not to compete following termination of employment. The Company relies solely on confidentiality and non-solicitation protections.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a real worker non-compete", () => {
    expect(
      emp024.check(
        doc(
          "Non-Competition",
          "Employee shall not compete with the Company for two years following termination of employment.",
        ),
      ),
    ).not.toBeNull();
  });
});

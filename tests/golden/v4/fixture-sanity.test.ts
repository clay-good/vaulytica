/**
 * Per-fail-fixture sanity guards for the v4 corpus.
 *
 * Each entry pins down the rule IDs that MUST fire for a given
 * `*-fail.txt` fixture. The golden test catches byte-level drift;
 * this test catches *semantic* drift — e.g. a regex tweak that
 * silently stops a critical rule from firing on the intended failure
 * mode.
 *
 * Pass-fixtures live alongside but carry no sanity entries — the
 * golden test already locks them down structurally.
 */

import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runV4Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");

const EXPECTED_RULE_IDS: Record<string, string[]> = {
  // Bylaws with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // quorum provision, relying instead on the residual DGCL § 216
  // default rule. No "quorum" anchor appears anywhere in the
  // document. GOV-005 (critical) fires — its present_pattern
  // `/quorum/i` is no longer matched anywhere in the document.
  // DGCL § 216 supplies a majority-default if the bylaws are
  // silent, but the bylaws themselves should restate the threshold
  // explicitly; otherwise stockholders and proxy solicitors have
  // no four-corners answer to what the quorum requirement is.
  "governance-bylaws-missing-quorum-fail.txt": ["GOV-005"],

  // Executive Employment Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned severance-schedule provision, relying instead on the
  // employer's general termination-pay practices and any equity-
  // plan documents. No "severance", "salary continuation", or
  // "COBRA / continuation coverage" anchor appears anywhere in the
  // document. EMP-006 fires — its present_patterns `/severance/i`,
  // `/salary\s+continuation/i`, and `/(cobra|continuation\s+coverage)/i`
  // are no longer matched anywhere in the document. Severance terms
  // are the central economic feature of an executive agreement; a
  // generic at-will-with-no-severance contract leaves the executive
  // with no contractual hook for post-termination compensation.
  "employment-executive-missing-severance-fail.txt": ["EMP-006"],

  // Cookie Notice with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // categories-of-cookies section, relying instead on a published
  // cookie inventory and the consent-management tool. No
  // "strictly necessary / essential" / "functional / preferences" /
  // "analytics / performance / targeting / advertising" anchor
  // appears anywhere in the document. PRV-001 fires — its three
  // present_patterns
  //   `/(strictly\s+necessary|essential)/i`
  //   `/(functional|preferences?)/i`
  //   `/(analytics|performance|targeting|advertising)/i`
  // are no longer matched anywhere in the document. ePrivacy
  // Directive Art. 5(3) requires informed consent for non-strictly-
  // necessary cookies; without a categorized inventory the user
  // cannot give the granular consent the directive contemplates.
  "privacy-cookie-notice-missing-categories-fail.txt": ["PRV-001"],

  // SAFE with the preamble extended by a sentence that affirmatively
  // elects not to include a separately captioned economic-conversion-
  // terms section (deliberately avoiding "valuation cap", "discount
  // rate", "most favored nation", and "MFN"). No post-money or pre-
  // money valuation cap, discount rate, or MFN anchor appears
  // anywhere in the document. EQT-003 (critical) fires — its five
  // present_patterns `/post.money\s+valuation\s+cap/i`,
  // `/valuation\s+cap/i`, `/discount\s+rate/i`,
  // `/most\s+favored\s+nation/i`, and `/\bmfn\b/i` are no longer
  // matched anywhere in the document. The economic essence of a SAFE
  // is the conversion price; without a cap, discount, or MFN the
  // investor converts at the next-round price with no downside
  // protection, defeating the purpose of the instrument.
  "equity-safe-missing-valuation-cap-fail.txt": ["EQT-003"],

  // Triple Net Lease with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // insurance-requirements section (deliberately avoiding "commercial
  // general liability", "property insurance", and "waiver of
  // subrogation"). None of those anchors appears anywhere in the
  // document. RE-003 (critical) fires — its three present_patterns
  // `/commercial\s+general\s+liability/i`, `/property\s+insurance/i`,
  // and `/waiver\s+of\s+subrogation/i` are no longer matched. NNN
  // leases rely on tenant-carried insurance to protect both parties;
  // without minimum CGL limits, a loss-payee clause, and a waiver of
  // subrogation, landlord's coverage stack is exposed and recovery
  // after a casualty is uncertain.
  "real-estate-net-lease-missing-insurance-fail.txt": ["RE-003"],

  // Loan Agreement with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // remedial-trigger section (deliberately avoiding "events of
  // default", "cross-default", "cure period", "grace period",
  // "insolvency", and "bankruptcy"). None of those anchors appears
  // anywhere in the document. BNK-012 (critical) fires — its three
  // present_patterns `/events?\s+of\s+default/i`,
  // `/(cross.?default|cure\s+period|grace\s+period)/i`, and
  // `/(insolvenc|bankruptc)/i` are no longer matched anywhere in the
  // document. Without an enumerated default catalogue and cure
  // periods, the lender cannot accelerate until maturity and loses
  // the early-warning protection that EoD cross-default triggers
  // are designed to provide.
  "banking-loan-agreement-missing-events-of-default-fail.txt": ["BNK-012"],

  // Asset Purchase Agreement with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // retained-obligations schedule enumerating liabilities not assumed
  // by Buyer (deliberately avoiding "excluded liabilities"). No
  // "excluded liabilities" anchor appears anywhere in the document.
  // MNA-023 (critical) fires — its present_pattern
  // `/excluded\s+liabilities/i` is no longer matched anywhere in the
  // document. The structural advantage of an APA is that Buyer assumes
  // only specifically-identified liabilities; without a broad
  // Excluded Liabilities clause the catch-all protection evaporates
  // and Buyer faces unquantified successor-liability exposure.
  "m-and-a-asset-purchase-missing-excluded-liabilities-fail.txt": ["MNA-023"],

  // Copyright License Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned grant-scope clause specifying whether the license is
  // exclusive or non-exclusive (deliberately avoiding "exclusive",
  // "non-exclusive", and "sole"). Neither "exclusive / non-exclusive /
  // sole" nor "in writing / signed / executed" appears anywhere in
  // the document. IPL-020 (critical) fires — its two present_patterns
  // `/(exclusive|non.?exclusive|sole)/i` and
  // `/(in\s+writing|signed|executed)/i` are no longer matched
  // anywhere in the document. Under 17 U.S.C. § 204(a) an exclusive
  // copyright transfer must be in a signed writing; without a stated
  // exclusivity designation neither party has a four-corners answer
  // to whether the licensee holds exclusive or shared rights.
  "ip-licensing-copyright-missing-exclusivity-fail.txt": ["IPL-020"],

  // PHI Authorization with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // time-limit clause (deliberately avoiding "expir*", "on [digit]",
  // "by [digit]", "years from", "end of", and "conclusion of"). No
  // expiration date or expiration event appears anywhere in the
  // document. HC-014 (critical) fires — its two present_patterns
  // `/(expir(es?|ation|ing)|expir\b)/i` and
  // `/((on|by)\s+\d|years?\s+from|end\s+of|conclusion\s+of)/i`
  // are no longer matched anywhere in the document. 45 C.F.R.
  // § 164.508(c)(1)(v) requires an expiration date or event; an
  // authorization without one creates an open-ended consent that
  // HIPAA Privacy Rule compliance depends on the patient revoking
  // rather than the authorization naturally lapsing.
  "healthcare-phi-authorization-missing-expiration-fail.txt": ["HC-014"],

  // Confidential Settlement Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned compensation clause (deliberately avoiding "settlement
  // payment", "settlement amount", "settlement sum", "consideration",
  // "in consideration", and any "$NNN" dollar figure). None of those
  // anchors appears anywhere in the document. SET-006 (critical)
  // fires — its three present_patterns
  // `/(settlement\s+payment|settlement\s+amount|settlement\s+sum)/i`,
  // `/(consideration|in\s+consideration)/i`, and `/\$\s*[\d,]+/`
  // are no longer matched anywhere in the document. Without recited
  // consideration the agreement is vulnerable to a failure-of-
  // consideration defense; the parties cannot verify the bargained-for
  // exchange without a stated settlement payment amount.
  "settlement-confidential-missing-consideration-fail.txt": ["SET-006"],

  // Anti-Bribery and Anti-Corruption Policy with the preamble
  // extended by a sentence that affirmatively elects not to include a
  // separately captioned counterparty-vetting section (deliberately
  // avoiding "third party / parties", "agent(s)", "intermediary /
  // intermediaries", "distributor", "due diligence", "screening",
  // and "background"). Neither present_pattern for third-party
  // identification nor due-diligence review appears anywhere in the
  // document. POL-007 (critical) fires — its two present_patterns
  // `/(third.?part(y|ies)|agents?|intermediar(y|ies)|distributor)/i`
  // and `/(due\s+diligence|screening|background)/i` are no longer
  // matched anywhere in the document. DOJ-SEC FCPA Resource Guide
  // identifies third-party intermediaries as the most common FCPA
  // channel; without a vetting obligation the policy has no textual
  // hook to trigger risk-based review before a high-risk engagement.
  "compliance-anti-bribery-missing-third-party-diligence-fail.txt": ["POL-007"],

  // Construction Contract with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // pricing clause (deliberately avoiding "contract sum", "stipulated
  // sum", "guaranteed maximum price", "GMP", and "cost-plus") and a
  // separately captioned payment-cadence clause (deliberately avoiding
  // "progress payments" and "payment schedule / terms"). Neither
  // present_pattern for pricing nor payment cadence appears anywhere
  // in the document. CON-003 (critical) fires — its two present_patterns
  // `/(contract\s+sum|stipulated\s+sum|guaranteed\s+maximum\s+price|gmp|cost.plus)/i`
  // and `/(progress\s+payments?|payment\s+(schedule|terms))/i` are no
  // longer matched anywhere in the document. AIA A101 §§ 4-5 require
  // the contract sum and progress-payment schedule; without a stated
  // pricing model and draw cadence the pricing basis for any change-
  // order dispute is undefined.
  "construction-contract-missing-contract-sum-fail.txt": ["CON-003"],

  // Commercial General Liability Policy Summary with the preamble
  // extended by a sentence that affirmatively elects not to include a
  // separately captioned economic-terms provision (deliberately
  // avoiding "premium", "deductible", "self-insured retention", and
  // "SIR"). None of those anchors appears anywhere in the document.
  // INS-004 (critical) fires — its two present_patterns
  // `/premium/i` and
  // `/(deductible|self.?insured\s+retention|sir)/i` are no longer
  // matched anywhere in the document. Premium + deductible / SIR are
  // the economic core of an insurance policy; without a stated
  // premium and the insured's retained-risk threshold, the parties
  // cannot verify the consideration paid or the attachment point at
  // which the insurer's payment obligation begins.
  "insurance-policy-summary-missing-premium-deductible-fail.txt": ["INS-004"],

  // Form D Narrative with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // safe-harbor-identification provision (deliberately avoiding
  // "Rule 504 / 506 / 506(b) / 506(c)" and "exempt / exemption").
  // None of those anchors appears anywhere in the document. REG-002
  // fires — its two present_patterns
  // `/(rule\s+50[46]|rule\s+506\(b\)|rule\s+506\(c\))/i` and
  // `/(exempt|exemption)/i` are no longer matched anywhere in the
  // document. Form D Item 6 requires identification of the exemption
  // claimed; the difference between 506(b) (no general solicitation,
  // reasonable belief) and 506(c) (general solicitation permitted,
  // verified accredited status) is the central regulatory question
  // for a Reg D offering and must be stated.
  "regulatory-form-d-missing-exemption-fail.txt": ["REG-002"],

  // Revocable Living Trust with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // third-party-claim-protection provision (deliberately avoiding
  // "spendthrift", "creditor", "involuntary transfer", and
  // "attachment"). None of those anchors appears anywhere in the
  // document. EST-016 fires — its two present_patterns `/spendthrift/i`
  // and `/(creditor|involuntary\s+transfer|attachment)/i` are no
  // longer matched anywhere in the document. UTC § 502 enforces
  // spendthrift provisions restraining both voluntary and involuntary
  // transfers of beneficial interests; without one, a beneficiary's
  // judgment creditors can reach the beneficial interest and defeat
  // the trust's estate-planning purpose.
  "trust-revocable-living-missing-spendthrift-fail.txt": ["EST-016"],

  // Bylaws with the preamble extended by a sentence that affirmatively
  // elects not to include a separately captioned director-and-officer
  // protection article, relying instead on the residual authority
  // supplied by DGCL § 145 and separately executed advancement-of-
  // expenses contracts. No "indemnification / indemnify / indemnified"
  // anchor appears anywhere in the document. GOV-008 fires — its
  // present_pattern `/indemnif(ication|y|ied)/i` is no longer matched
  // anywhere in the document. DGCL § 145 authorizes indemnification
  // but is not self-executing; without a bylaw clause electing into the
  // statutory authority, directors and officers lose the contractual
  // hook for the protection.
  "governance-bylaws-missing-indemnification-fail.txt": ["GOV-008"],

  // Executive Employment Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned cash-compensation schedule, relying instead on a
  // separately executed compensation letter and the Employer's
  // standard payroll practices. No "base salary", "annual bonus /
  // incentive", or "target bonus" anchor appears anywhere in the
  // document. EMP-002 fires — its three present_patterns
  // `/base\s+salary/i`, `/annual\s+(bonus|incentive)/i`, and
  // `/target\s+bonus/i` are no longer matched anywhere in the document.
  // Reg S-K Item 402 requires disclosure of compensation arrangements
  // for named executive officers; without a stated base salary and
  // bonus structure the central economic terms of the engagement are
  // off the four corners.
  "employment-executive-missing-base-salary-fail.txt": ["EMP-002"],

  // Cookie Notice with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // consent-withdrawal section, relying instead on the user's ability
  // to clear stored cookies through their browser controls and lodge a
  // supervisory-authority complaint. Neither a "withdraw / change /
  // update / revoke ... consent" anchor nor a "cookie preferences /
  // cookie settings / preference center" anchor appears anywhere in
  // the document. PRV-004 fires — its two present_patterns
  // `/(withdraw|change|update|revoke).{0,40}consent/i` and
  // `/(cookie\s+(preferences?|settings)|preference\s+center)/i` are no
  // longer matched anywhere in the document. GDPR Art. 7(3) requires
  // that withdrawing consent be as easy as giving it; routing the user
  // to generic browser controls fails the equal-prominence standard
  // EDPB Guidelines 5/2020 contemplate.
  "privacy-cookie-notice-missing-withdraw-consent-fail.txt": ["PRV-004"],
};

describe("v4 fixture sanity", () => {
  for (const [fixture, expectedIds] of Object.entries(EXPECTED_RULE_IDS)) {
    it(`${fixture} fires the expected rules`, async () => {
      const { run } = await runV4Fixture(join(FIXTURES, fixture));
      const firedIds = new Set(run.findings.map((f) => f.rule_id));
      const missing = expectedIds.filter((id) => !firedIds.has(id));
      expect(missing, `expected rules did not fire: ${missing.join(", ")}`).toEqual([]);
    });
  }
});

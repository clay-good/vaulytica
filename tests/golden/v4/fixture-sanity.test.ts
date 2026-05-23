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

  // Loan Agreement with the preamble extended by a sentence that
  // affirmatively elects not to include a separately titled pricing
  // provision (deliberately avoiding "SOFR / prime rate / LIBOR",
  // "margin / spread / basis points / bps", and "floor / cap"). The
  // Interest section is removed. None of those anchors appears anywhere
  // in the document. BNK-008 fires — its three present_patterns
  // `/(sofr|prime\s+rate|libor)/i`,
  // `/(margin|spread|basis\s+points|bps)/i`, and
  // `/(floor|cap|cap\s+and\s+floor)/i` are no longer matched anywhere
  // in the document. Without a stated index, margin, and floor the
  // pricing of the credit is off the four corners; post-LIBOR
  // transition (June 2023) the index is SOFR-based and the rate-reset
  // mechanic must be in the agreement, not in a side letter.
  "banking-loan-agreement-missing-interest-rate-fail.txt": ["BNK-008"],

  // SAFE with the preamble extended by a sentence that affirmatively
  // elects not to include a separately captioned conversion-trigger
  // definition (deliberately avoiding "equity financing", "preferred
  // stock financing", and "next priced round"). None of those anchors
  // appears anywhere in the document. EQT-002 fires — its three
  // present_patterns `/equity\s+financing/i`,
  // `/preferred\s+stock\s+financing/i`, and `/next\s+priced\s+round/i`
  // are no longer matched anywhere in the document. Without a defined
  // Equity Financing the SAFE cannot convert; YC's post-money template
  // uses "Equity Financing" or "Standard Preferred Stock" as the
  // conversion trigger and the absence of an in-document definition
  // leaves the investor with no four-corners trigger for conversion.
  "equity-safe-missing-conversion-event-fail.txt": ["EQT-002"],

  // Triple Net Lease with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // ad-valorem-charge pass-through provision (deliberately avoiding
  // "real estate taxes", "impositions", and "property taxes"). None
  // of those anchors appears anywhere in the document. RE-002 fires —
  // its two present_patterns `/real\s+estate\s+taxes?/i` and
  // `/(impositions|property\s+taxes)/i` are no longer matched anywhere
  // in the document. Direct payment shifts tax-bill risk; reimbursement
  // keeps landlord on the bill and creates timing disputes — an NNN
  // lease must specify which mechanic governs to keep both parties
  // out of an avoidable post-loss allocation fight.
  "real-estate-net-lease-missing-tax-passthrough-fail.txt": ["RE-002"],

  // Anti-Bribery Policy with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // non-US-statute applicability provision (deliberately avoiding
  // "UK Bribery Act", "UKBA", "Bribery Act 2010", "failure to prevent",
  // "cross-border", and "adequate procedures"). The Compliance-with-Law
  // section drops the UKBA reference. None of those anchors appears
  // anywhere in the document. POL-010 fires — its two present_patterns
  // `/(uk\s+bribery\s+act|ukba|bribery\s+act\s+2010)/i` and
  // `/(failure\s+to\s+prevent|cross.border|adequate\s+procedures)/i`
  // are no longer matched anywhere in the document. UKBA is broader
  // than FCPA — commercial bribery, the "failure to prevent bribery"
  // corporate offense, no facilitating-payments exception, broad
  // jurisdictional reach. A policy that ignores the stricter regime
  // leaves the multinational employer exposed to the criminal-corporate
  // theory the SFO has used since 2017.
  "compliance-anti-bribery-missing-ukba-cross-border-fail.txt": ["POL-010"],

  // Construction Contract with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // schedule-and-delay-remedy provision (deliberately avoiding
  // "substantial completion", "final completion", "completion date",
  // "liquidated damages", "delay damages", and "no damages for delay").
  // The Schedule section is removed; the Payment section's retainage
  // anchor reads "until Final Acceptance" instead of "until Substantial
  // Completion". None of those anchors appears anywhere in the
  // document. CON-004 fires — its two present_patterns
  // `/(substantial\s+completion|final\s+completion|completion\s+date)/i`
  // and `/(liquidated\s+damages|delay\s+damages|no\s+damages\s+for\s+delay)/i`
  // are no longer matched anywhere in the document. AIA A101 § 3
  // requires commencement, substantial-completion, and final-completion
  // dates; without them, schedule slip — the single largest source of
  // construction disputes — has no contractually defined trigger for
  // owner-suffered delay damages.
  "construction-contract-missing-time-of-completion-fail.txt": ["CON-004"],

  // PHI Authorization with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // cancellation-mechanic provision (deliberately avoiding "revoke",
  // "revoking", "revocation", "in writing", "written notice", "except",
  // and "reliance"). The Expiration section drops the revocation
  // sentence; the Patient Rights section replaces "except as permitted
  // by" with "subject to the limits set forth in" to avoid the
  // "except" anchor. None of those anchors appears anywhere in the
  // document. HC-015 fires — its three present_patterns
  // `/(revoke|revoking|revocation)/i`, `/(in\s+writing|written\s+notice)/i`,
  // and `/(except|reliance)/i` are no longer matched anywhere in the
  // document. 45 C.F.R. § 164.508(c)(2)(i) requires a statement of
  // the right to revoke in writing and the exceptions; without one
  // the patient has no four-corners hook to withdraw consent and the
  // covered entity has no instruction for when reliance-based
  // disclosures may still proceed.
  "healthcare-phi-authorization-missing-right-to-revoke-fail.txt": ["HC-015"],

  // Copyright License Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned enumeration of the geographic-and-durational scope of
  // the license (deliberately avoiding "term", "territory", "media",
  // "channels", "format", "now known", and "hereafter developed").
  // The Term-and-Termination section is renamed to "Duration and
  // Discontinuance" and the Licensee is renamed from "Acme Media Inc."
  // to "Acme Studios Inc." so that the substring "media" does not
  // appear anywhere in the document. None of those anchors appears
  // anywhere in the document. IPL-022 fires — its three present_patterns
  // `/(term|territor)/i`, `/(media|channels?|format)/i`, and
  // `/(now\s+known|hereafter\s+developed)/i` are no longer matched
  // anywhere in the document. Term + territory + media define the
  // boundary of the license; open-ended grants in unfamiliar media
  // invite Bourne v. Walt Disney-style disputes when new exploitation
  // surfaces emerge, and the in-document scope must control over a
  // separately negotiated rate card.
  "ip-licensing-copyright-missing-term-territory-media-fail.txt": ["IPL-022"],

  // Asset Purchase Agreement with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // schedule enumerating the specific liability categories that Buyer
  // is contractually undertaking at the Closing (deliberately avoiding
  // "assumed liabilities"). No "assumed liabilities" anchor appears
  // anywhere in the document. MNA-022 fires — its present_pattern
  // `/assumed\s+liabilities/i` is no longer matched anywhere in the
  // document. The structural advantage of an APA is that Buyer assumes
  // only specifically-identified liabilities; without an Assumed
  // Liabilities clause that catalogues the closed set, the implicit
  // carve-in fails and Buyer faces ambiguity about which Seller
  // obligations transfer at Closing.
  "m-and-a-asset-purchase-missing-assumed-liabilities-fail.txt": ["MNA-022"],

  // Form D Narrative with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // screening-and-disclosure provision addressing Rule 506(d) bad-actor
  // disqualification (deliberately avoiding "bad-actor", "rule 506(d)",
  // "disqualif", "covered persons", and "disqualifying events"). The
  // Bad-Actor Disqualification section is removed. None of those
  // anchors appears anywhere in the document. REG-005 fires — its two
  // present_patterns `/(bad.actor|rule\s+506\(d\)|disqualif)/i` and
  // `/(covered\s+persons?|disqualifying\s+events?)/i` are no longer
  // matched anywhere in the document. Rule 506(d) disqualifies covered
  // persons (directors, officers, 20%+ owners) with disqualifying
  // events from relying on Rule 506; an issuer that omits the
  // screening recital cannot show it performed the reasonable-care
  // diligence the rule contemplates.
  "regulatory-form-d-missing-bad-actor-fail.txt": ["REG-005"],

  // Commercial General Liability Policy Summary derived from the
  // existing premium-deductible fail-fixture by renaming the "Named
  // Insured" line to "Insured Party" and the "Producer" line to
  // "Insurance Intermediary" (with the broker entity renamed to
  // "Insurance Wholesale Services LLC" so neither "broker" nor "agent"
  // appears anywhere in the document). The preamble extension narrates
  // the affirmative election not to include a party-and-intermediary
  // identification provision. INS-001 fires — its two present_patterns
  // `/named\s+insured/i` and `/(producer|broker|agent)/i` are no longer
  // matched anywhere in the document. Coverage rights run to the
  // Named Insured under state insurance codes; without a clearly
  // labelled "Named Insured" and a stated producer / broker, the
  // declarations are off the four corners and the carrier's
  // book-of-business record becomes the only source for who is
  // entitled to coverage.
  "insurance-policy-summary-missing-named-insured-fail.txt": ["INS-001"],

  // Revocable Living Trust with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // post-passing apportionment provision (deliberately avoiding "upon
  // settlor's death", "after death", "beneficiar", and "distribute").
  // The Distribution-Upon-Death section is removed entirely so neither
  // "distribute" nor "beneficiary" appears anywhere in the document.
  // EST-014 fires — its two present_patterns
  // `/(upon\s+(settlor.?s|grantor.?s)\s+death|after\s+death)/i` and
  // `/(beneficiar|distribute)/i` are no longer matched anywhere in
  // the document. The post-death disposition is the trust's principal
  // estate-planning function; without named beneficiaries and stated
  // shares, the trust corpus is at risk of intestate disposition
  // through the pour-over will rather than the planned distribution.
  "trust-revocable-living-missing-death-distribution-fail.txt": ["EST-014"],

  // Confidential Settlement Agreement and Mutual Release (pinned to
  // the `mutual-release` playbook since SET-005 applies only to that
  // playbook id) with the preamble extended by a sentence affirmatively
  // electing to extend the release beyond the conduct underlying the
  // Action to bind the releasing party with respect to prospective
  // claims of any kind whatsoever, and the Mutual Release section
  // amplified with "any future claims that may arise hereafter against
  // the other party, including any prospective claims of any kind
  // whatsoever". SET-005 fires — its two bad-language patterns
  // `/releases?.{0,80}(future|hereafter\s+arising|may\s+arise).{0,80}claims?/is`
  // and `/(future|prospective)\s+claims?.{0,80}(of\s+any\s+kind|whatsoever)/is`
  // both match. California Civ. Code § 1668 voids contracts that
  // exempt a party from responsibility for their own fraud, willful
  // injury, or violation of law, and many jurisdictions are skeptical
  // of releases of unaccrued claims — a release that purports to cover
  // post-execution conduct is at risk of being limited or voided.
  "settlement-confidential-overbroad-future-claims-fail.txt": ["SET-005"],

  // Bylaws with the preamble narrating a comprehensive
  // exclusive-forum election and a new Exclusive Forum section
  // designating the Court of Chancery of the State of Delaware as the
  // exclusive forum for any claim asserted against the corporation,
  // including without limitation any claim arising under the Securities
  // Exchange Act of 1934 or any other federal securities laws.
  // GOV-011 fires — its bad-language pattern
  // `/exclusive\s+forum.{0,120}(state\s+of\s+delaware|chancery).{0,200}(exchange\s+act|1934\s+act|federal\s+securities)/is`
  // matches. Salzberg v. Sciabacucchi (Del. 2020) upheld Delaware-
  // forum bylaws for Securities Act of 1933 claims but expressly
  // declined to extend that holding to Exchange Act claims, which
  // carry exclusive federal-court jurisdiction under § 27; an
  // exclusive-forum bylaw that purports to capture Exchange Act claims
  // is at risk of being struck on petition.
  "governance-bylaws-overbroad-exclusive-forum-fail.txt": ["GOV-011"],

  // Executive Employment Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned post-employment-behavior provision (avoiding the rule's
  // anchor phrases by paraphrase: "constraining the Executive's
  // ability to compete", "communicate confidential information", and
  // "recruit Employer personnel after termination"). The Restrictive
  // Covenants section is removed entirely. EMP-008 fires — its two
  // present_patterns `/restrictive\s+covenant/i` and
  // `/(non.?disclosure|non.?solicit)/i` are no longer matched anywhere
  // in the document. Executives need NDA + non-solicit (and
  // non-compete only where enforceable) coverage; without an
  // in-document restrictive-covenants clause or reference, the
  // separately executed Confidentiality and Invention Assignment
  // Agreement is the only operative restraint, and the Employer's
  // post-termination protections rest entirely off the four corners.
  "employment-executive-missing-restrictive-covenants-fail.txt": ["EMP-008"],

  // Cookie Notice with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // downstream-disclosure provision (deliberately avoiding the rule's
  // anchor phrases: "third-party", "recipients", "international
  // transfers", "outside the EU / EEA / UK", "SCC", "DPF", and "Data
  // Privacy Framework" — the preamble uses "downstream-counterparty
  // identification" so neither "recipients" nor "third-party" appears
  // anywhere in the document). The Third-Party Cookies section is
  // removed. PRV-006 fires — its three present_patterns
  // `/(third.?party|recipients?)/i`,
  // `/(international\s+transfers?|outside\s+the\s+(eu|eea|uk))/i`,
  // and `/(scc|dpf|data\s+privacy\s+framework)/i` are no longer
  // matched anywhere in the document. GDPR Art. 13(1)(e)–(f) requires
  // disclosure of recipients and international-transfer mechanisms;
  // cookie data routinely flows to third-party analytics / ad-tech
  // in the US and elsewhere and the notice must surface those flows.
  "privacy-cookie-notice-missing-third-party-recipients-fail.txt": ["PRV-006"],

  // Anti-Bribery Policy with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // financial-records-and-controls provision (deliberately avoiding
  // "books and records", "accounting records / controls", "internal
  // controls", "78m", "accurate", and "accuracy"). The Books-and-
  // Records section is removed entirely. POL-008 fires — its three
  // present_patterns
  // `/(books\s+and\s+records|accounting\s+(records|controls))/i`,
  // `/(internal\s+(accounting\s+)?controls?|78m)/i`, and
  // `/(accurate|accuracy)/i` are no longer matched anywhere in the
  // document. 15 U.S.C. § 78m(b)(2) requires issuers to maintain
  // accurate books and records and adequate internal accounting
  // controls; violations can be charged without underlying bribery, so
  // the policy must affirmatively address the accounting-provisions
  // half of FCPA enforcement.
  "compliance-anti-bribery-missing-books-and-records-fail.txt": ["POL-008"],

  // Construction Contract with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // risk-allocation provision (deliberately avoiding "indemnify",
  // "indemnification", "insurance", "CGL", "workers compensation",
  // and "waiver of subrogation"). The Insurance and Bonds section is
  // narrowed to just Bonds (removing the insurance language). CON-006
  // fires — its three present_patterns
  // `/(indemnif(y|ies|ied|ication))/i`,
  // `/(insurance|cgl|workers?\s+compensation)/i`, and
  // `/(waiver\s+of\s+subrogation)/i` are no longer matched anywhere
  // in the document. AIA A201 §§ 3.18 (indemnification) + 11
  // (insurance) provide the standard pattern; state anti-indemnity
  // statutes (CA Civ. § 2782, NY Gen. Oblig. § 5-322.1, TX Ins. § 151)
  // void indemnity for owner's own / sole negligence, so the carve-
  // outs must be in the contract — a separate Owner-Controlled Risk
  // Management Program is not a substitute.
  "construction-contract-missing-indemnification-insurance-fail.txt": ["CON-006"],

  // PHI Authorization with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // reason-for-disclosure provision (deliberately avoiding "purpose",
  // "at the request of", and "for litigation / life insurance /
  // treatment / payment / research / marketing"). The Purpose section
  // is removed, "treatment notes" in the Description is changed to
  // "clinical notes" so `for treatment` cannot match, and the
  // Recipient is renamed from "Insurance Underwriter Inc." to "Acme
  // Underwriting Inc." so the phrase "for life insurance" never
  // appears. HC-013 fires — its two present_patterns `/purpose/i` and
  // `/(at\s+the\s+request\s+of|for\s+(litigation|life\s+insurance|treatment|payment|research|marketing))/i`
  // are no longer matched anywhere in the document. 45 C.F.R.
  // § 164.508(c)(1)(iv) requires a description of each purpose; an
  // authorization without one fails the meaningful-and-specific
  // standard and is unenforceable on its face.
  "healthcare-phi-authorization-missing-purpose-fail.txt": ["HC-013"],

  // SAFE with the preamble narrating an affirmative departure from
  // the YC post-money form by adding an interest-accrual mechanic, and
  // a new Interest section stating "This SAFE shall bear interest at
  // a rate of 6% per annum, compounded annually". EQT-008 fires — its
  // two bad-language patterns
  // `/this\s+safe\s+(shall|will)\s+(bear|accrue)\s+interest/i` and
  // `/interest\s+(rate|accrues|shall\s+accrue)\s+(at|of)\s+\d/i` are
  // both matched. A SAFE is not a debt instrument; interest accrual
  // is inconsistent with the YC template, may indicate a convertible
  // note in disguise, and is state-law-sensitive under usury caps.
  "equity-safe-interest-bearing-fail.txt": ["EQT-008"],

  // Form D Narrative with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // non-federal-jurisdiction-coordination provision (deliberately
  // avoiding "blue-sky", "state notice", "NSMIA", "notice filing",
  // and "state securities"). The Blue Sky section is removed.
  // REG-007 fires — its two present_patterns
  // `/(blue.sky|state\s+notice|nsmia)/i` and
  // `/(notice\s+filing|state\s+securities)/i` are no longer matched
  // anywhere in the document. Most states require notice filings for
  // Reg D offerings (NSMIA-preempted but most states require Form D
  // copies + filing fees); failure to file blocks resale, so the
  // narrative must surface the per-state coordination obligation.
  "regulatory-form-d-missing-blue-sky-fail.txt": ["REG-007"],

  // Revocable Living Trust with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // probate-coordination provision (deliberately avoiding "pour-over",
  // "pourover", "will", and "last will"). The Pour-Over section is
  // removed entirely so no "will" or "pour-over" substring appears
  // anywhere in the document. EST-015 fires — its two present_patterns
  // `/(pour.?over|pourover)/i` and `/(will|last\s+will)/i` are no
  // longer matched anywhere in the document. Pour-over wills devise
  // residuary to the trust; coordination prevents probate of trust-
  // funded property — without a pour-over reference, unfunded probate
  // property goes through intestacy and defeats the trust's estate-
  // planning purpose.
  "trust-revocable-living-missing-pour-over-fail.txt": ["EST-015"],

  // Loan Agreement with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // remedial-mechanic provision (deliberately avoiding "default",
  // "events of default", "accelerat", "insolvency", "bankruptcy", and
  // "payment default"). The Events-of-Default section is removed so
  // no "default" or "bankruptcy/insolvency" substring appears anywhere
  // in the document. BNK-005 fires — its three present_patterns
  // `/(events?\s+of\s+default|default)/i`, `/accelerat/i`, and
  // `/(insolvenc|bankruptc|payment\s+default)/i` are no longer matched
  // anywhere in the document. Without an enumerated default and
  // acceleration mechanic the payee must wait for maturity to sue
  // and may face unjust-enrichment / cure arguments — the doc's
  // reliance on the Lender's published collection practices is not a
  // substitute for in-contract remedial-trigger machinery.
  "banking-loan-agreement-missing-default-acceleration-fail.txt": ["BNK-005"],

  // Single-Tenant Commercial Lease (derived from the NNN minimal but
  // rewritten as a "fully-burdened single-tenant arrangement") with
  // the preamble extended by a sentence that affirmatively elects not
  // to include a separately captioned tenant-cost-assumption provision
  // (deliberately avoiding "triple-net", "NNN", "CAM", "common area
  // maintenance", "operating expenses", and any "real estate taxes
  // ... tenant" co-occurrence within 80 chars). The "Real Estate
  // Taxes" section is renamed "Ad Valorem Assessments" so the rule's
  // 80-char-windowed `/real\s+estate\s+taxes?.{0,80}(tenant)/is`
  // co-occurrence cannot match through the heading-to-tenant
  // proximity that joining-newline would otherwise create. RE-001
  // fires — its four present_patterns `/triple.net/i`, `/\bnnn\b/i`,
  // `/real\s+estate\s+taxes?.{0,80}(tenant)/is`, and
  // `/(cam|common\s+area\s+maintenance|operating\s+expenses)/i` are
  // no longer matched anywhere in the document. The economic essence
  // of an NNN lease is tenant assumption of three expense categories;
  // silence converts the lease to gross by default.
  "real-estate-net-lease-missing-nnn-cost-allocation-fail.txt": ["RE-001"],

  // Mutual Release (pinned to the `mutual-release` playbook since
  // SET-001 applies only to that playbook id) with the preamble
  // extended by a sentence that affirmatively elects not to include a
  // separately captioned identification provision naming the persons
  // and entities on each side (deliberately avoiding "releasor",
  // "releasee", "releasing party / parties", "released party /
  // parties", "affiliates", "subsidiaries", "officers", "directors",
  // and "agents"). The Release body uses bare "Plaintiff / Defendant"
  // language without any extended-identification recitations. SET-001
  // fires — its two present_patterns
  // `/releas(or|ee|ing\s+part(y|ies)|ed\s+part(y|ies))/i` and
  // `/(affiliates?|subsidiaries|officers|directors|agents)/i` are no
  // longer matched anywhere in the document. An effective release
  // must bind every entity intended to benefit; failure to enumerate
  // affiliates, officers, directors, agents, and assigns leaves
  // residual claims against unnamed parties.
  "settlement-mutual-release-missing-releasing-parties-fail.txt": ["SET-001"],

  // Patent License Agreement (pinned to the `patent-license` playbook,
  // a different IPL sub-domain playbook from the copyright-license
  // minimal/fail series) with the preamble extended by a sentence
  // that affirmatively elects not to include a separately captioned
  // identification provision listing the licensed patents by their
  // issued / pending serial designations. The Exhibit reference uses
  // "Exhibit A" rather than "Schedule A" to avoid the rule's
  // `/schedule\s+a/i` anchor, and the preamble uses the paraphrase
  // "industrial-monopoly grants" so the literal anchor "licensed
  // patents" does not appear anywhere in the document. IPL-007 fires —
  // its two present_patterns `/(licensed\s+patents?|schedule\s+a)/i`
  // and `/(patent\s+no|u\.?s\.?\s+pat|application\s+no)/i` are no
  // longer matched anywhere in the document. Patent licenses must
  // identify the licensed claims with sufficient specificity for
  // both enforcement and royalty accounting; without listed patent /
  // application numbers, the licensed estate is off the four corners.
  "ip-licensing-patent-missing-licensed-patents-fail.txt": ["IPL-007"],

  // Letter of Intent (pinned to the `loi-term-sheet` playbook, a
  // different M&A sub-domain playbook from the asset-purchase
  // minimal/fail series) without any "non-binding / not binding /
  // except as / except for" demarcation. The doc affirmatively states
  // it "is binding upon the parties" and includes a Confidentiality
  // section — pattern 2 (`/(binding|legally\s+binding)/i`) and
  // pattern 3 (`/(confidentiality|exclusivity|expenses)/i`) match, but
  // pattern 1 (`/(non.?binding|not\s+binding|except\s+(as|for))/i`)
  // does not, so the compound rule's min_match=3 threshold is missed
  // (2/3) and MNA-001 fires. The *SIGA / Pennzoil* line shows that
  // LOIs can be enforced as binding contracts if the parties do not
  // clearly disclaim intent to be bound on commercial terms; the
  // standard pattern is confidentiality / exclusivity / expenses /
  // governing law / forum binding and price / structure non-binding,
  // and a doc that says only "is binding upon the parties" without
  // demarcating the non-binding commercial provisions invites
  // unintended enforcement.
  "m-and-a-loi-missing-binding-demarcation-fail.txt": ["MNA-001"],

  // Endorsement (pinned to the `insurance-endorsement` playbook, a
  // different insurance sub-domain playbook from the policy-summary
  // minimal/fail series) styled as a Commercial General Liability
  // Endorsement — Absolute Pollution Exclusion. The body affirmatively
  // states "This endorsement is an absolute exclusion of pollution and
  // applies in addition to all other terms of the Policy" — the
  // language-rule's first bad pattern
  // `/(absolute\s+exclusion|total\s+exclusion).{0,80}(pollution|cyber|communicable\s+disease|silica|asbestos|abuse|molest)/is`
  // matches and INS-010 fires. Coverage-restricting endorsements
  // (absolute pollution / cyber / communicable-disease exclusions,
  // $25K sublimits) materially shrink coverage and should be flagged
  // to underwriters and the broker — IRMI / ALI-CLE practice treats
  // them as the most common source of unintended coverage gaps.
  "insurance-endorsement-coverage-restricting-fail.txt": ["INS-010"],

  // Bylaws with the preamble extended by a sentence that affirmatively
  // elects not to include a separately captioned governance-body
  // composition and election article, relying instead on the residual
  // authority supplied by DGCL § 141 and the certificate of
  // incorporation. The document consistently uses "governing body"
  // rather than "board of directors", and the annual-meeting sentence
  // reads "annual governance-body election" rather than "election of
  // directors". No "board of directors" or "(elect|appoint) ...
  // directors?" anchor appears anywhere in the document. GOV-006
  // (critical) fires — its two present_patterns
  // `/board\s+of\s+directors/i` and
  // `/(elect|appoint).{0,30}directors?/i` are no longer matched
  // anywhere in the document. DGCL § 141(b) and MBCA § 8.03 require
  // the bylaws (or charter) to fix the number of directors and the
  // manner of election; without a board-composition clause, the
  // stockholder proxy materials and company's internal records have no
  // four-corners anchor for board size or election procedure.
  "governance-bylaws-missing-board-composition-fail.txt": ["GOV-006"],

  // Executive Employment Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned deferred-compensation-tax-compliance provision, relying
  // instead on applicable federal income tax law and company-wide
  // tax-compliance policies. No "section 409A", "409A", "specified
  // employee", or "six-month delay" anchor appears anywhere in the
  // document. EMP-003 (critical) fires — its two present_patterns
  // `/(section\s+409a|\b409a\b)/i` and
  // `/(specified\s+employee|six.month\s+delay)/i` are no longer
  // matched anywhere in the document. IRC § 409A triggers a 20%
  // additional tax plus interest on the executive if deferred-
  // compensation rules are violated; a § 409A compliance recital
  // (including the six-month delay for specified employees and
  // reformation authority) is universal in modern executive agreements
  // because severance and deferred bonuses are inherently § 409A-
  // sensitive arrangements.
  "employment-executive-missing-409a-compliance-fail.txt": ["EMP-003"],

  // Cookie Notice with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // opt-in mechanism section, relying instead on users' browser
  // settings and supervisory-authority guidance. The Consent section
  // and the Withdrawal section are both removed; "cookie management
  // tool" is not present in this fixture. No "consent", "banner",
  // "preference center", "cookie preference", "accept", "reject", or
  // "manage" anchor appears anywhere in the document. PRV-002
  // (critical) fires — its three present_patterns `/consent/i`,
  // `/(banner|preference\s+center|cookie\s+preference)/i`, and
  // `/(accept|reject|manage)/i` are no longer matched anywhere in the
  // document. ePrivacy Art. 5(3) + GDPR Art. 7 require freely given,
  // specific, informed, and unambiguous affirmative-action consent
  // (CJEU Planet49); routing users to generic browser controls
  // neither satisfies the granular opt-in requirement nor documents
  // a valid consent signal for each non-essential cookie category.
  "privacy-cookie-notice-missing-consent-mechanism-fail.txt": ["PRV-002"],

  // Loan Agreement with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // borrower-undertakings provision (deliberately avoiding "affirmative
  // covenants", "financial statements", "books and records", and
  // "maintenance"). No "affirmative covenants" or "financial
  // statements / books and records / maintenance" anchor appears
  // anywhere in the document. BNK-009 fires — its two present_patterns
  // `/affirmative\s+covenants?/i` and
  // `/(financial\s+statements?|books\s+and\s+records|maintenance)/i`
  // are no longer matched anywhere in the document. Affirmative
  // covenants (maintain corporate existence, comply with law, deliver
  // financial statements, books-and-records access, notice of defaults)
  // are the lender's information-rights backbone; without them the
  // lender has no contractual hook to monitor deteriorating credit
  // quality before it matures into a payment default.
  "banking-loan-agreement-missing-affirmative-covenants-fail.txt": ["BNK-009"],

  // SAFE with the preamble extended by a sentence that affirmatively
  // elects not to include a separately captioned exit-event treatment
  // provision (deliberately avoiding "liquidity event", "change of
  // control", and "acquisition"). The document uses "strategic
  // combination" and "purchase of the Company's outstanding shares"
  // as paraphrases so none of the rule's anchors appears anywhere.
  // EQT-004 fires — its three present_patterns `/liquidity\s+event/i`,
  // `/change\s+of\s+control/i`, and `/acquisition/i` are no longer
  // matched anywhere in the document. YC SAFE treats a strategic
  // combination as a liquidity event where the investor receives the
  // greater of (a) the purchase amount or (b) the as-converted amount;
  // without an express liquidity-event clause the investor's exit
  // treatment is undefined and the SAFE may inadvertently leave the
  // investor with no contractual right to any proceeds on a sale of
  // the Company prior to an Equity Financing.
  "equity-safe-missing-liquidity-event-fail.txt": ["EQT-004"],

  // Triple Net Lease with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // upkeep-and-remediation provision (deliberately avoiding "maintenance
  // and repair", "roof", "structural integrity", and "structural
  // repair"). No "maintenance and repair" or
  // "(roof|structural) (integrity|repair|maintenance)" anchor appears
  // anywhere in the document. RE-004 fires — its two present_patterns
  // `/maintenance\s+and\s+repair/i` and
  // `/(roof|structural)\s+(integrity|repair|maintenance)/i` are no
  // longer matched anywhere in the document. The allocation between
  // roof / structure (landlord) and all other upkeep (tenant) is the
  // heart of a single-tenant NNN lease; without an explicit maintenance-
  // and-repair clause, the parties have no four-corners answer to which
  // side bears the cost of a failing HVAC system, a leaking facade, or
  // a parking-lot resurfacing — the most common category of NNN
  // landlord-tenant disputes.
  "real-estate-net-lease-missing-maintenance-repair-fail.txt": ["RE-004"],
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

/**
 * The hand-written specimen corpus, and the findings each document is allowed
 * to produce.
 *
 * Every routing and rule defect fixed on 2026-08-27 was found the same way:
 * write a realistic document, run the CLI on it, and read what comes back.
 * None was reachable from the suite — the fixtures are shorter, cleaner, and
 * more cooperative than anything a lawyer would actually drop in. A letter
 * puts its title in a "Re:" line; a filing puts it under a caption; a
 * negotiated agreement stamps "EXECUTION VERSION" above it; an amendment
 * defines nothing and points at its parent; a discovery response carries the
 * name of the request it answers.
 *
 * These are those documents. Pinning the rule ids each produces makes the
 * method permanent: a future change that mis-routes an engagement letter, or
 * that starts reporting a lease amendment's own defined terms as undefined,
 * fails here rather than in a user's hands.
 *
 * The set is the assertion, in both directions — a new false finding fails,
 * and so does a real one that stops firing. When a change legitimately alters
 * one, update the row and say why in the commit.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

export type Expectation = { playbook: string; findings: string[] };

/**
 * Exported so `self-penalizing-features.test.ts` can read the family each
 * specimen belongs to. The routing is the thing being asserted here, so it is
 * the right source for "which playbook's vocabulary is this document written
 * in".
 */
export const EXPECTED: Record<string, Expectation> = {
  // A civil complaint filed in state court. Pleads jurisdiction under an
  // Illinois long-arm statute and venue in a county, which the PLDG checks
  // could not read until they stopped assuming a federal caption.
  "complaint.txt": { playbook: "complaint", findings: [] },
  // A broker's summary of insurance coverage. It routed to `coi` — on a
  // document that says in terms that it "is not a certificate of insurance" —
  // because the summary family listed "ENDORSEMENT" as a negative feature,
  // and every policy summary lists its key endorsements, while `coi` matched
  // four words any insurance document carries (policy number, general
  // liability, additional insured, carrier). The summary family now carries
  // its own register and its title keywords read "SUMMARY OF INSURANCE
  // COVERAGE". INS-001 and INS-005 stay and are fair: the summary identifies
  // the insured as "Prepared for" rather than as the Named Insured, and
  // enumerates coverage parts without form numbers or edition dates.
  // STRUCT-003 is fair too: nobody signs a broker's summary. It was silent
  // until STRUCT-003 v1.19.0 stopped reading the cover block's "Prepared
  // by: … Date prepared: …" as a two-token signature line.
  "insurance-policy-summary.txt": {
    playbook: "insurance-policy-summary",
    findings: ["INS-001", "STRUCT-003", "INS-005", "TEMP-002"],
  },
  // A Regulation D private placement memorandum. Clean: the whole
  // REG-025..032 pack is silent on a memorandum that covers every column —
  // the § 4(a)(2) / Rule 506(b) legend, the no-approval legend, use of
  // proceeds, risk factors, manager compensation, transfer restrictions,
  // suitability standards, and the Rule 502(b) investor-access undertaking.
  // REG-040 is the standing scope disclosure, not a defect in the document.
  "ppm-narrative.txt": { playbook: "ppm-narrative", findings: ["OBLI-005", "REG-040"] },
  // An omnibus equity incentive plan. Clean: the whole EQT-101..114 plan pack
  // is silent on a plan that covers every column — share reserve, evergreen,
  // capitalization adjustment, the no-repricing covenant, § 409A, the § 422(d)
  // $100,000 ISO limit, change-in-control treatment, clawback, and the
  // amendment triggers that need stockholder approval. STRUCT-006 is right
  // that the plan uses Incentive Stock Option, Nonstatutory Stock Option and
  // Restricted Stock without defining them in Section 2.
  "equity-incentive-plan.txt": {
    playbook: "equity-incentive-plan",
    findings: ["STRUCT-006", "OBLI-005", "STRUCT-009"],
  },
  // A public design-build agreement with a guaranteed maximum price. Clean:
  // it routes at 1.0 and its own pack — including the single-point-of-
  // responsibility check — is silent on a compliant one. IPDATA-001 stays and
  // is real: Section 7.4 grants Owner a LICENCE to the design documents but
  // never says who owns them, and in design-build that is the IP question.
  // A guaranteed-maximum-price contract caps nothing else, so RISK-005 is
  // skipped for the family as it is for `construction-contract`.
  "design-build.txt": {
    playbook: "design-build-agreement",
    findings: [
      "IPDATA-001",
      "RISK-002",
      "STRUCT-006",
      "STRUCT-018",
      "FIN-006",
      "OBLI-002",
      "OBLI-005",
      "RISK-010",
      "RISK-011",
      "TERM-001",
    ],
  },
  // A Clean Water Act consent judgment. It fell to `generic-fallback`: the
  // family's five distinguishing phrases were verbatim sentences ("judgment is
  // hereby entered", "the court retains jurisdiction") that a real one does
  // not say. Once routed, SET-103 reported no admission recital on a document
  // whose second WHEREAS is one — the pack's text source STRIPS RECITALS, and
  // a consent judgment states that recital nowhere else — and SET-105 wanted
  // a satisfaction of judgment where a decree is discharged by a MOTION TO
  // TERMINATE after a compliance period. STRUCT-006 also reported "Consent
  // Judgment", the document's own name.
  "consent-judgment.txt": {
    playbook: "consent-judgment",
    findings: ["STRUCT-018", "OBLI-008"],
  },
  // A remote work agreement. It routed correctly but only just — 0.5, right at
  // the threshold — because the family's distinguishing phrases were headings
  // rather than register ("work hours and availability", "the employee's home
  // office") and it had one title keyword. Its own pack is silent on a
  // compliant one. The family also shipped with no rule profile, so an
  // employment addendum that says in terms that it does not change Employee's
  // status was told it allocates no IP, provides no indemnity, caps no
  // liability, and states no termination path.
  "remote-work.txt": {
    playbook: "remote-work-agreement",
    findings: ["CHOICE-003", "OBLI-002", "OBLI-005"],
  },
  // A second amendment to a revocable living trust. It routed to
  // `revocable-living-trust` and was told it states no pour-over reference and
  // no spendthrift clause — a two-page amendment restates neither, because
  // both are in the trust it amends. The amendment family's own title keywords
  // could not match "SECOND AMENDMENT TO THE HARROWGATE FAMILY REVOCABLE
  // LIVING TRUST" (they read "trust amendment" and "first amendment to the
  // trust"), and its distinguishing phrases were verbatim sentences. Clean
  // once routed.
  "trust-amendment.txt": { playbook: "trust-amendment", findings: [] },
  // A mutual employment arbitration agreement, drafted around the Ending
  // Forced Arbitration Act. CHOICE-001 reported no governing-law clause on
  // "This Agreement is governed by the FEDERAL ARBITRATION ACT, 9 U.S.C.
  // §§ 1-16" — every governing-law pattern wanted "the laws of <place>", and
  // an FAA-governed agreement names a federal statute instead. DARK-005 stays
  // and is the point: the class-action waiver is the central term a reviewer
  // must see, and CHOICE-003 / CHOICE-006 are right that the seat is stated
  // only by reference ("the county where Employee last worked").
  "employment-arbitration.txt": {
    playbook: "arbitration-agreement-employment",
    findings: ["DARK-005", "CHOICE-003", "CHOICE-006"],
  },
  // A warehousing and third-party logistics agreement. Clean: it routes on its
  // own title and its pack is silent on a well-drafted one.
  "warehousing-3pl.txt": {
    playbook: "warehousing-3pl-agreement",
    findings: [
      "RISK-015",
      "RISK-016",
      "STRUCT-018",
      "OBLI-005",
      "RISK-007",
      "RISK-010",
      "TERM-001",
    ],
  },

  // A venue rental agreement for a firm reception. It routed to
  // `lease-residential-us` and drew DARK-012, a residential security-deposit
  // dark-pattern rule, on a non-refundable EVENT booking deposit — on a
  // document that says in terms that it "creates no leasehold estate,
  // tenancy, or other interest in real property". The venue family's own
  // distinguishing phrases were HOTEL vocabulary ("room block", "attrition",
  // "food and beverage minimum") that a conservatory hire does not use. Once
  // routed, COMM-243 reported no cancellation schedule on a clause that sets
  // one out in tiered day windows — it wanted the words "cancellation fee".
  "venue-rental.txt": {
    playbook: "venue-rental-agreement",
    // RISK-016 came off in v9.336.0: the caterer's insurance requirement
    // points at Section 5, which states $1,000,000 per occurrence and
    // $2,000,000 in the aggregate, so the minimum was one cross-reference
    // away and the finding asked for a figure the document already gives.
    findings: ["RISK-015", "OBLI-005", "RISK-010", "RISK-011", "RISK-013", "TEMP-002"],
  },
  // An equipment finance agreement — a loan secured by the equipment, which
  // the document says in terms ("This Agreement is a loan secured by the
  // Equipment and is NOT A LEASE"). It routed to `loan-agreement`, the
  // syndicated-credit family, because its own distinguishing phrases were
  // verbatim sentences ("grants a security interest in the equipment", with
  // the indirect object removed; "title to the equipment passes", which a
  // loan never says) and it had one title keyword to stand on. Its own
  // BNK-139..143 pack is silent on a well-drafted one. A secured loan does
  // not terminate for cause — it accelerates — and allocates no IP.
  "equipment-finance.txt": {
    playbook: "equipment-finance-agreement",
    findings: ["RISK-001", "RISK-005", "STRUCT-018", "FIN-009", "OBLI-005", "RISK-010"],
  },
  // A title-sponsorship agreement for a road race. COMM-175 reported no
  // trademark licence or approval right on a document with a section headed
  // "USE OF MARKS" and another headed "Approvals" — it wanted the noun phrase
  // in one order and "prior written approval" verbatim. FIN-005 could not
  // read "payable $425,000 on JANUARY 31 and $425,000 on JUNE 30 of each
  // year": the amount sits between the verb and the date, and the date
  // carries no year because it recurs.
  "sponsorship-agreement.txt": {
    playbook: "sponsorship-agreement",
    findings: [
      "RISK-015",
      "STRUCT-018",
      "IPDATA-005",
      "OBLI-005",
      "RISK-007",
      "RISK-010",
      "RISK-013",
    ],
  },
  // An FTC-compliant influencer endorsement agreement. It routed to
  // `independent-contractor` at 1.0 — three required clauses at 0.8 plus
  // "independent contractor", "not an employee" and "1099" — so the whole
  // endorsement pack never ran on a document written to 16 C.F.R. Part 255.
  // Fixed on both sides: "influencer" and "endorsement" as title keywords for
  // the family whose documents carry them, and the endorsement markers as
  // negatives of the contractor family, which never carries them. COMM-183
  // stays and is real: the agreement requires disclosure but does not commit
  // the brand to train and monitor.
  "influencer-agreement.txt": {
    playbook: "influencer-agreement",
    findings: ["COMM-183", "RISK-015", "STRUCT-018", "OBLI-005", "RISK-007"],
  },
  // An OEM agreement — the OEM incorporates the components, it does not
  // resell them. It routed to `distribution-agreement` at 0.6 and drew five
  // criticals from the distribution pack, three of them on clauses the
  // document carries under those very headings ("Appointment", the trademark
  // licence, the post-termination sell-off). The OEM family's own
  // distinguishing phrases were verbatim sentences nobody writes ("embedded
  // in the oem product", "under the oem's brand", "support tiers"), so it
  // matched none of them and had a single title keyword to stand on. Once
  // routed, COMM-237 wanted "under THE oem's brand" where the document says
  // "under OEM's OWN brand". COMM-239 stays and is real: the agreement states
  // a response time but no support tiering.
  "oem-agreement.txt": {
    playbook: "oem-agreement",
    findings: ["COMM-239", "STRUCT-018", "OBLI-002", "OBLI-005", "RISK-007"],
  },
  // A cross-border joint development agreement. It routed to
  // `consulting-agreement` at 1.0, then to `mutual-nda`: the JDA family's own
  // distinguishing phrases were the SPELLED-OUT forms ("background
  // intellectual property"), and every real one writes "Background IP";
  // `consulting-agreement` was leaning on "Consultant" and "expertise"; and
  // `mutual-nda` reached 1.0 on three required clauses any agreement with a
  // confidentiality section and a term satisfies. STRUCT-006 also reported
  // "Joint Foreground" — the front half of "Joint Foreground IP", cut by the
  // acronym.
  "joint-development.txt": {
    playbook: "joint-development-agreement",
    findings: [
      "RISK-001",
      "STRUCT-006",
      "STRUCT-018",
      "CHOICE-006",
      "OBLI-005",
      "RISK-007",
      "TEMP-006",
      "TERM-001",
      "TERM-007",
    ],
  },
  // A public-health limited-data-set data sharing agreement. IPDATA-008
  // reported a cross-border transfer missing its Article 46 safeguard on a
  // data-LOCALIZATION clause — "shall store and process ... only within the
  // United States and SHALL NOT TRANSFER it outside the United States without
  // Provider's prior written consent" — inverting what the document says. And
  // TERM-005 reported no effect-of-termination clause on the standard return
  // clause, because its trigger read "(up)on termination" and the clause
  // reads "within thirty (30) days AFTER expiration or termination".
  "data-sharing.txt": {
    playbook: "data-sharing-agreement",
    findings: ["STRUCT-018", "OBLI-005", "TERM-007"],
  },
  // An NVCA Series B PREFERRED STOCK PURCHASE AGREEMENT — a primary venture
  // financing, in which the company ISSUES new shares.
  //
  // The catalog carried the whole NVCA suite — the investors' rights
  // agreement, the voting agreement, the ROFR and co-sale agreement, the
  // SAFE, the convertible note — but not the document that closes the round,
  // so this routed to the ABA private-target M&A SPA and was checked for
  // sandbagging, a stockholder representative, and selling-stockholder
  // restrictive covenants, none of which a financing has. 9.201.0 added the
  // family and its EQT-131..136 pack; all six are silent on a well-drafted
  // one.
  "stock-purchase.txt": {
    playbook: "venture-stock-purchase-agreement",
    findings: [
      "OBLI-007",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-012",
      "CHOICE-003",
      "OBLI-005",
      "TEMP-002",
    ],
  },
  // An NVCA-style right of first refusal and co-sale agreement. FOUR of its
  // own checks fired on the drafting they exist to require, three at
  // `critical`: EQT-064 and EQT-065 wanted the defined phrase adjacent to the
  // party in ONE order, and the operative clauses never repeat it ("The
  // COMPANY MAY ELECT TO PURCHASE …", "Each INVESTOR MAY THEN ELECT TO
  // PURCHASE …"); EQT-066 required BOTH "co-sale" and "tag-along", which are
  // the same right under two names, so no compliant document could satisfy
  // it; and EQT-069 wanted the word "terminate" beside the offering, where
  // the term clause reads "continues until … a firm-commitment underwritten
  // public offering".
  "rofr-co-sale.txt": {
    playbook: "rofr-co-sale",
    findings: ["STRUCT-006", "STRUCT-018", "OBLI-005"],
  },
  // A staffing services agreement. Clean: routes at 0.9 and every finding is
  // real — the confidentiality obligation runs one way, and the agreement
  // defines "Assigned Personnel" but uses the undefined singular "Assigned
  // Person". RISK-002 came OFF this row in 9.249.0: the indemnities are 2:1,
  // which is inside the rule's own `max - min >= 2` tolerance, and it fired
  // only because the natural person who SIGNS sat in the tally at zero.
  "staffing-services.txt": {
    playbook: "staffing-services-agreement",
    findings: [
      "RISK-015",
      "STRUCT-006",
      "OBLI-002",
      "OBLI-005",
      "PERS-002",
      "RISK-006",
      "RISK-007",
      "RISK-010",
      "TEMP-006",
      "TERM-001",
    ],
  },

  // An NVCA-style investors' rights agreement. EQT-053 reported no
  // information-rights clause at `critical` on a section headed "INFORMATION
  // AND INSPECTION RIGHTS" that delivers four sets of statements: its pillars
  // wanted "information rights" adjacent, and a cadence-first, "financial"-
  // required statement phrase ("unaudited MONTHLY financial statements",
  // "unaudited QUARTERLY STATEMENTS" and "AUDITED ANNUAL STATEMENTS" all
  // failed it). EQT-054 wanted the NVCA's own heading, and a large share of
  // these agreements head the same right "PREEMPTIVE RIGHTS".
  "investor-rights.txt": {
    playbook: "investor-rights-agreement",
    findings: [
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "OBLI-005",
      "OBLI-008",
      "RISK-003",
      "RISK-010",
      "RISK-011",
    ],
  },
  // A pharmaceutical contract-manufacturing and supply agreement. Three
  // findings inverted what the document says: COMM-024 reported no
  // title/lien warranty at `critical` on a warranty that the Products are
  // "free of ANY LIEN" (the singular, behind a determiner); RISK-006 reported
  // ZERO limitation-of-liability carve-outs on a clause that carves out four,
  // because its window stopped at the "8.1" of a section citation and the
  // `indemnif` stem does not match the noun "indemnity"; and TERM-005
  // reported no effect-of-termination clause on a transition obligation
  // stated as a TRANSFER. COMM-025 and COMM-040 stay and are real: this
  // agreement states no exclusive remedy and does not address the UCC implied
  // warranties either way.
  "manufacturing-supply.txt": {
    playbook: "manufacturing-supply-agreement",
    findings: [
      "COMM-025",
      "COMM-040",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "TERM-003",
      "OBLI-002",
      "OBLI-005",
      "OBLI-008",
      "RISK-006",
      "RISK-007",
      "RISK-010",
      "RISK-013",
      "TERM-001",
    ],
  },
  // A Delaware limited partnership agreement. RISK-015 and RISK-011 both
  // demanded commercial indemnity machinery of the Partnership's indemnity of
  // its GENERAL PARTNER — an aggregate cap, a notice provision, defense
  // control. That indemnity is uncapped by design, and the existing statutory
  // guard wanted the "fullest extent permitted" formula, which an LP agreement
  // usually does not use: it writes the governance-role indemnitee and the
  // statutory carve-out (fraud, willful misconduct, gross negligence, knowing
  // violation of law) instead. STRUCT-006 stays: this specimen omits the
  // definition of Percentage Interest.
  // OBLI-002 came ONTO this row in 9.248.0. "To the fullest extent permitted
  // by law," was not a recognized fronted adverbial, so the obligor of the
  // clause read as part of the adverbial and matched no party; and a party
  // whose entity type is written "LLC"/"LLP" was found with no ROLE, which
  // is what an obligor is matched against. The asymmetry each of these
  // documents carries is real and was simply invisible.
  "partnership-agreement.txt": {
    playbook: "partnership-agreement",
    findings: ["STRUCT-006", "STRUCT-018", "CHOICE-006", "OBLI-002", "OBLI-005"],
  },
  // A three-party subordination agreement. Clean: routes at 1.0 and its own
  // pack is silent on a well-drafted one.
  "subordination-agreement.txt": {
    playbook: "subordination-agreement",
    findings: ["OBLI-005"],
  },

  // An AAA demand for arbitration. Three names it INVOKES rather than defines
  // were reported as undefined Title-Case terms: a VESSEL name behind its
  // prefix ("the M/V Bayou Sentinel"), a fragment of a compound instrument
  // name ("the Vessel Refit AND SERVICES AGREEMENT", where the Title-Case run
  // stops at the lowercase "and"), and the name of a rule set ("the Commercial
  // Arbitration Rules").
  "arbitration-demand.txt": {
    playbook: "arbitration-demand",
    findings: ["STRUCT-018"],
  },
  // A bankruptcy trade-claim purchase. It routed to `ip-assignment` at 0.6 and
  // drew two `critical` findings about assigned INTELLECTUAL PROPERTY scope
  // and a power of attorney — there is no IP. Its own family's distinguishing
  // phrases were verbatim sentences nobody writes ("hereby assigns all right,
  // title and interest in the claim", "no warranty of collectability"), and
  // `ip-assignment` was leaning on "assignor"/"assignee". Then: CHOICE-003
  // reported no forum on a clause naming two; SET-115 read a title warranty
  // written as a VERB SERIES as warranting nothing; and STRUCT-002 could not
  // see the execution recital that dates the instrument at its foot.
  // SET-112 stays: a claim purchase should confirm the underlying claim is
  // assignable, and this one does not.
  "assignment-of-claim.txt": {
    playbook: "assignment-of-claim",
    findings: ["SET-112", "STRUCT-018", "OBLI-002", "RISK-011"],
  },
  // A one-step cash merger of a private target approved at a stockholder
  // MEETING. Two false positives: OBLI-004 reported the agreement as using
  // "best efforts" when it deliberately chose "REASONABLE best efforts" — the
  // middle standard, which OBLI-008 already surfaces — and MNA-035 demanded
  // § 228 written consents and drag-along letters, which its own title and
  // explanation scope to PRIVATE targets and which a merger approved on a
  // proxy statement has none of. STRUCT-006 stays: the specimen omits the
  // definitions article, so Acquisition Proposal and its siblings really are
  // undefined here.
  "merger-agreement.txt": {
    playbook: "merger-agreement",
    findings: [
      "OBLI-007",
      "RISK-016",
      "STRUCT-006",
      "STRUCT-018",
      "OBLI-005",
      "OBLI-008",
      "STRUCT-005",
    ],
  },
  // A tenant work letter attached to an office lease. Clean: it routes on its
  // own title, the family's checks are silent, and the always-on absence
  // checks stand down because "This Tenant Work Letter is attached to and made
  // a part of the Office Lease" is now read as a subordination recital.
  "work-letter.txt": {
    playbook: "tenant-improvement-work-letter",
    findings: ["OBLI-005"],
  },

  // A residential property management agreement. FIN-005 could not read a
  // management fee "payable from the Operating Account on the TENTH (10TH) DAY
  // of the following month" — the payment SOURCE sits between the verb and the
  // date, and the ordinal is spelled with the numeral in a parenthetical.
  //
  // OBLI-002 came off when the second party's ROLE was finally read: its
  // parenthetical sits behind a long qualifier ("an Arizona corporation
  // holding Arizona real estate broker license number BR-558214
  // (\"Manager\")"), `PARTY_DECL` wanted it immediately after the entity type,
  // and `BETWEEN_RE`'s capture terminates at the comma before "an Arizona
  // corporation". A party with no role is invisible to every rule that
  // compares an obligor against the party set, so the mutual indemnities in
  // Sections 6.3 and 6.4 read as one-sided.
  "property-management.txt": {
    playbook: "property-management-agreement",
    findings: [
      "RISK-015",
      "RISK-016",
      "TEMP-004",
      "OBLI-005",
      "RISK-010",
      "RISK-011",
      "TEMP-006",
      "TERM-001",
    ],
  },
  // A 99-year ground lease with leasehold-mortgage protections. Four of its
  // own checks fired on the drafting they exist to require: RE-022 at
  // `critical` on a section headed "Escalation" (it knew CPI and "fair market
  // rent", not a flat periodic step or "fair market GROUND rent"); RE-023 on
  // a section headed "ASSIGNMENT AND TRANSFER" (it wanted the bigram
  // "assignment and sublet", and the two rights are granted in separate
  // sentences); RE-024 on "a memorandum of THIS Lease"; and TERM-005 on the
  // reversion, which is the whole economic point of a ground lease — "title
  // to the Improvements VESTS IN Landlord automatically".
  "ground-lease.txt": {
    playbook: "ground-lease",
    findings: [
      "RISK-001",
      "RISK-005",
      "STRUCT-018",
      "CHOICE-006",
      "OBLI-005",
      "RISK-010",
      "TEMP-008",
    ],
  },
  // A single-tenant ABSOLUTE net lease. Three lease families were leaning on
  // "Landlord", "Tenant" and "Premises" — the three words every lease
  // contains — so it routed first to `lease-commercial-multitenant` and then
  // to `lease-residential-us`, and `net-lease`'s own phrases were the
  // MULTITENANT vocabulary ("common area maintenance", "CAM"), which no
  // single-tenant net lease carries. Once routed, two of its own checks fired
  // at `critical` on the drafting they exist to require: RE-001 conjoined a
  // CAM / operating-expense pillar onto a family named "Single-Tenant Net
  // Lease", and RE-004 wanted "maintenance and repair" adjacent where the
  // lease writes the verb series "maintain, repair, and replace". RE-005
  // stays and is real: this lease gives the tenant no audit right.
  "net-lease.txt": {
    playbook: "net-lease",
    findings: [
      "RE-005",
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "OBLI-002",
      "OBLI-005",
      "OBLI-008",
      "RISK-010",
      "RISK-011",
    ],
  },
  // A book publishing copyright license. It routed to `msa-general`: the
  // family listed "patent", "trademark" and "assignment" as NEGATIVE
  // features, and a copyright license reserves patent and trademark rights in
  // terms and says in its own Ownership section that it "is a license and not
  // a transfer of copyright ownership, and nothing in it constitutes an
  // ASSIGNMENT of the copyright". Once routed, IPL-021 demanded a CITATION to
  // 17 U.S.C. § 106 at `critical` — which no real copyright license carries,
  // and which its own recommendation does not supply. It was firing on this
  // family's own minimal-PASS fixture.
  "copyright-license.txt": {
    playbook: "copyright-license",
    findings: ["OBLI-002", "OBLI-005", "RISK-011", "TEMP-006"],
  },
  // A university exclusive patent license, Bayh-Dole subject. It routed to
  // `eula` — an end-user licence for consumer software — and was told it
  // states no EU consumer-law minimums under the Digital Content Directive.
  // The family listed "trademark", "copyright" and "assignment" as NEGATIVE
  // features, and a patent license reserves trademark and copyright rights in
  // terms ("No license is granted under any copyright, trademark, or know-how
  // of Licensor") and has an assignment clause. Three penalties on its own
  // standard drafting. Everything that stays is real: no patent-marking
  // clause, no grant-back, no liability cap, and only the licensee may
  // terminate for convenience.
  "patent-license.txt": {
    playbook: "patent-license",
    findings: [
      "FIN-008",
      "IPL-011",
      "IPL-012",
      "OBLI-002",
      "OBLI-005",
      "OBLI-008",
      "RISK-005",
      "RISK-010",
      "RISK-015",
      "STRUCT-018",
      "TERM-001",
      "TERM-003",
    ],
  },
  // An ASF-style individual contributor license agreement. Four defects, and
  // three of them are shapes any signed FORM has: `"You" (or "Your") means …`
  // — the parenthesized alias — registered NEITHER term, so the definition
  // was lost and "Your Contributions" was reported as never defined; the only
  // date is on the "Date:" line the signer fills in, at the bottom of the
  // page, and STRUCT-002 looks only at the first quarter; and the family
  // shipped with no rule profile, so a one-way copyright grant was told it
  // provides no indemnity, caps no liability, and states no termination path.
  // The family also listed "royalty" as a NEGATIVE feature, and every CLA
  // grants a ROYALTY-FREE license.
  // STRUCT-005 stays: "the Meridian Grid project (the "Project")" defines the
  // term out of the generic noun that precedes it, and "Project" is genuinely
  // never used again. The case-insensitive use scan added in 9.247.0 ignores
  // what comes before a PARENTHETICAL definition for exactly this reason.
  // An export control and trade sanctions compliance policy. Routes on its
  // register alone — the family's title keywords are all of the form "export
  // control policy", and a real one is titled for both halves of the subject
  // ("Export Control and Trade Sanctions Compliance Policy"). STRUCT-006 on
  // "Trade Compliance" came off in 9.354.0: a department is not a defined
  // term, the same call made on the employee handbook's "People Operations"
  // and the commission plan's "Sales Operations". OBLI-005 tallies the two
  // prohibitions and is correct.
  "export-control-policy.txt": {
    playbook: "export-control-policy",
    findings: ["OBLI-005"],
  },

  // An FCPA/UKBA anti-bribery policy, drafted the way a multinational's
  // compliance function drafts one. POL-010 reported that it says nothing
  // about the UK Bribery Act or cross-border reach, on a policy whose first
  // section names the Act and applies the stricter of local law and the
  // policy: the rule matched "uk bribery act" with a space, which the
  // American rendering "U.K. Bribery Act" never has, and required one of
  // three phrases its own recommendation ("apply the stricter standard")
  // does not contain.
  // STRUCT-009 stays and is fair — the policy defines "Government official"
  // and then writes it lowercase everywhere it uses it.
  "anti-bribery-policy.txt": {
    playbook: "anti-bribery-policy",
    findings: ["STRUCT-009"],
  },

  // A trademark coexistence agreement settling a TTAB opposition. It routed
  // to `mutual-nda-deep` and was told, at `critical`, that it defined no
  // Confidential Information, listed no exclusions, and had no
  // return-or-destruction clause — nine criticals, none of which any
  // coexistence agreement carries.
  //
  // Both families scored 0.6. They were not equal: the NDA family's three
  // distinguishing phrases came to 0.2 × 3 = 0.6000000000000001 and the
  // coexistence family's two title keywords to 0.3 × 2 = 0.6, so the tie —
  // and every tiebreak written for it — never happened. Ranking now
  // compares at the precision the scores are reported in, and prefers the
  // family the title named.
  //
  // IPL-113 then reported the consent missing on the document whose whole
  // operative section is the consent: it looked for "consents to
  // registration" adjacently and for "shall not oppose", where the
  // agreement says "consents to Cellars' use and registration" and "will
  // not oppose". IPDATA-001/RISK-001/RISK-005 came from an empty rule
  // profile; a coexistence agreement allocates no IP, indemnifies nobody,
  // and caps no liability.
  "trademark-coexistence-agreement.txt": {
    playbook: "trademark-coexistence-agreement",
    findings: ["CHOICE-008", "OBLI-005", "STRUCT-006", "STRUCT-018", "TEMP-006", "TEMP-007"],
  },

  // A Delaware director indemnification agreement. GOV-142 reported no
  // § 145(e) undertaking on the agreement that says "Indemnitee undertakes
  // to repay the amounts advanced ... an unsecured general obligation": the
  // pattern read the noun ("undertaking to repay") and not the verb.
  // OBLI-002 and RISK-005 came from the rule profile — the indemnity runs
  // one way by design, and a liability cap would defeat the instrument.
  // GOV-139 and GOV-148 stay and are fair: this specimen states no § 145(a)
  // standard of conduct and no assumption-of-defense or settlement-consent
  // procedure.
  "indemnification-agreement.txt": {
    playbook: "director-indemnification-agreement",
    findings: ["GOV-139", "GOV-148", "RISK-016", "STRUCT-018", "STRUCT-009", "TEMP-006"],
  },

  // A motor carrier transportation agreement. FIN-005 reported no payment
  // term on "Shipper will pay undisputed amounts within thirty days" — the
  // branch led on `shall`, and half of American drafting uses `will`.
  // FIN-008 reported a minimum-commitment clause and quoted the sentence
  // denying one ("This Agreement does not commit Shipper to tender any
  // minimum volume"); the shared absence guard knew "does not obligate" but
  // not "does not commit". IPDATA-001 and RISK-005 came from an empty rule
  // profile: a carriage contract allocates no IP, and its liability regime
  // is 49 U.S.C. § 14706, not a contractual cap.
  "freight-transportation-agreement.txt": {
    playbook: "freight-transportation-agreement",
    findings: ["OBLI-005", "RISK-010", "RISK-011", "STRUCT-018", "TEMP-004", "TEMP-006"],
  },

  "cla.txt": {
    playbook: "contributor-license-agreement",
    findings: ["CHOICE-003", "STRUCT-005"],
  },
  // An AIA-style owner-contractor agreement. It routed to
  // `independent-contractor` at 0.9 and none of its seven CON-001..007 checks
  // ran, because the family listed "subcontractor", "lien waiver",
  // "performance bond" and "change order" as NEGATIVE features — the four
  // things every construction contract is made of. Once routed, two of its own
  // checks fired on the drafting they exist to require: CON-006 read the
  // ANTI-INDEMNITY carve-out ("does not require Contractor to indemnify any
  // party for that party's own negligence") as the contract denying it
  // indemnifies at all, at `critical`; and CON-005 read only the plural
  // "differing site conditions" and only "materially differ".
  "construction-contract.txt": {
    playbook: "construction-contract",
    findings: [
      "RISK-002",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "FIN-006",
      "OBLI-002",
      "OBLI-005",
      "RISK-010",
      "RISK-011",
      "TERM-001",
    ],
  },
  // A trademark license. It routed to `msa-general` at 0.7 and none of its six
  // IPL-013..018 checks ran, because the family listed "patent", "copyright"
  // and "assignment" as NEGATIVE features — and every trademark license
  // reserves patent and copyright rights in terms ("No license is granted
  // under any patent, copyright, or trade secret") and has an assignment
  // clause. Three penalties on its own standard drafting cost it 0.3.
  // RISK-015 stays and is right: the cap carves out the indemnity.
  "trademark-license.txt": {
    playbook: "trademark-license",
    findings: [
      "FIN-008",
      "OBLI-002",
      "OBLI-005",
      "RISK-010",
      "RISK-015",
      "STRUCT-005",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-008",
    ],
  },
  // A managed-care participating provider agreement. All six HC-121..126
  // checks are silent on a compliant one. Its family shipped with an empty
  // rule profile, so it was told it allocates no IP and caps no liability —
  // a provider agreement does neither, and the same was true of the equipment
  // lease, the credit agreement, and the factoring agreement, whose pins each
  // carried an IPDATA-001 that no such contract can answer.
  "payer-provider.txt": {
    playbook: "payer-provider-agreement",
    findings: [
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-004",
      "OBLI-005",
      "RISK-010",
      "TEMP-006",
      "TEMP-007",
      "TERM-001",
      "TERM-007",
    ],
  },
  // A third-party litigation funding agreement. All six SET-138..143 checks
  // are silent on a compliant one. It drew three false positives: CHOICE-011
  // told a Delaware LP and a Massachusetts corporation that their New York
  // governing law is void as to a California worker, because the funder's
  // ADDRESS is in San Francisco — § 925 is a rule about employment contracts,
  // and there is no worker here; FIN-005 could not read "shall FUND each
  // conforming draw within fifteen (15) business days"; and the family shipped
  // with an empty rule profile.
  // OBLI-002 came ONTO this row in 9.248.0. "To the fullest extent permitted
  // by law," was not a recognized fronted adverbial, so the obligor of the
  // clause read as part of the adverbial and matched no party; and a party
  // whose entity type is written "LLC"/"LLP" was found with no ROLE, which
  // is what an obligor is matched against. The asymmetry each of these
  // documents carries is real and was simply invisible.
  "litigation-funding.txt": {
    playbook: "litigation-funding-agreement",
    findings: ["STRUCT-018", "OBLI-002", "OBLI-005", "TEMP-006"],
  },
  // A North Carolina residential purchase and sale contract. It routed to the
  // COMMERCIAL `real-estate-psa` and was told at `warning` to add a § 1031
  // like-kind-exchange cooperation clause to a family home sale — and at
  // `critical` that it has no legal description, on a paragraph that sets one
  // out ("legally described as Lot 17, Block 4, Fernbank Estates, Plat Book
  // 42, Page 118"). The eight RE-138..145 residential checks are silent on a
  // compliant contract.
  "residential-purchase.txt": {
    playbook: "residential-purchase-agreement",
    findings: ["FIN-006", "OBLI-005", "TEMP-006", "TEMP-008"],
  },
  // An amended and restated NVCA-style stockholders' agreement. Four false
  // positives, all rigid drafting assumptions: a section headed VOTING
  // AGREEMENT reported at `critical` as containing none (the OBJECT sits
  // between "vote" and "in favor"); an IPO-termination clause reported
  // missing on "continues until ... the closing of a firm-commitment
  // underwritten public offering"; the drag-along's CARVE-OUT ("No
  // Stockholder shall be required ... to agree to any non-competition
  // covenant") reported as a non-compete, twice; and a covenant about the
  // CHARTER's indemnification provisions read as an indemnity of this
  // document. The three that stay are real: protective provisions are absent,
  // the Schedules travel separately, and Common/Preferred Stock are defined
  // in the certificate of incorporation rather than here.
  // An exclusive right to sell listing agreement — the 203rd specimen, and the
  // first for `listing-agreement`. RE-118..122 are all satisfied: the listing
  // type with its period, the commission with a ready-willing-and-able trigger
  // and the negotiability disclosure, the ninety-day protection period limited
  // to a written registered-prospect list, the Idaho agency disclosure with
  // informed written dual-agency consent, and the MLS and marketing
  // authorizations with an Internet opt-out. The family had an empty
  // `rule_overrides`, so a residential listing was told it does not allocate
  // IP and has no indemnity or liability cap.
  "listing-agreement.txt": {
    playbook: "listing-agreement",
    findings: ["OBLI-005"],
  },
  // An enterprise information security policy — the 201st specimen, and the
  // first for `information-security-policy`. POL-101..107 are all satisfied,
  // and the document is clean: scope with an owner and a review cadence,
  // least-privilege access control with quarterly reviews, classification with
  // AES-256 and TLS, remediation SLAs by severity, SIEM logging with an
  // eighteen-month retention, vendor risk tiers with contractual security
  // requirements, and a time-boxed exception process.
  "information-security-policy.txt": {
    playbook: "information-security-policy",
    findings: ["OBLI-005"],
  },
  // A security incident response plan — the 202nd specimen, and the first for
  // `security-incident-response-plan`. POL-126..132 are all satisfied: the
  // 800-61r3 lifecycle, a four-level severity matrix, the Incident Commander
  // and counsel roles, evidence preservation with chain of custody, the GDPR /
  // HIPAA / state / SEC notification clocks with a named owner, vendor
  // incident coordination, and the post-incident review. STRUCT-006 stays and
  // is fair: "Incident Commander" is a role the plan describes rather than
  // defines.
  "security-incident-response-plan.txt": {
    playbook: "security-incident-response-plan",
    findings: ["STRUCT-006", "STRUCT-018"],
  },
  // A petition for a writ of certiorari — the 200th specimen, and the first
  // for `petition`. It exposed a seventh thing above the title: the DOCKET
  // NUMBER. "No. 26-1147" opens an appellate caption and the court is named on
  // the next line, so the caption reader — which required the court on the
  // first line — threw the whole caption away and the petition fell to
  // `generic-fallback`.
  "petition.txt": {
    playbook: "petition",
    findings: ["STRUCT-018"],
  },
  // A § 423 employee stock purchase plan — the 199th specimen, and the first
  // for `employee-stock-purchase-plan`. EQT-108..113 are all satisfied: the
  // § 423 qualification election with its Non-423 Component, the equal-rights
  // and eligibility conditions, the $25,000 annual accrual limit, the 85%
  // lookback price, the five-percent shareholder exclusion with § 424(d)
  // attribution, and the withdrawal and termination rules.
  "employee-stock-purchase-plan.txt": {
    playbook: "employee-stock-purchase-plan",
    findings: ["OBLI-005"],
  },
  // A first codicil to a will — the 198th specimen, and the first for
  // `codicil`. It exposed STRUCT-007 reporting the WILL's articles as broken
  // references — "I revoke Article VII of my Will", and, in a sentence whose
  // subject is the will, "the tax-apportionment clause in Article VIII".
  //
  // TEMP-002 was pinned here as fair until 9.360.0, on the reasoning that the
  // will it amends is five years older. That is what a codicil IS. The date
  // belongs to the will — "the First Codicil to my Last Will and Testament
  // dated March 6, 2021" — and the referenced-instrument exclusion now reads
  // the estate and real-property instruments alongside the commercial ones.
  "codicil.txt": {
    playbook: "codicil",
    findings: [],
  },
  // A Form D narrative supplement — the 196th specimen, and the first for
  // `form-d-narrative`. REG-001..007 are all satisfied: issuer identification
  // with its jurisdiction, the Rule 506(b) exemption, accredited-investor
  // representations with the verification contrast against 506(c), the
  // general-solicitation prohibition, the Rule 506(d) bad-actor inquiry over
  // every covered person, the offering amount with a minimum investment, and
  // the NSMIA-preempted state notice filings.
  "form-d-narrative.txt": {
    playbook: "form-d-narrative",
    findings: ["OBLI-005", "REG-040"],
  },
  // A digital advertising insertion order — the 197th specimen, and the first
  // for `advertising-insertion-order`. COMM-168..172 are all satisfied. It
  // exposed the sixth half of `amendsParentAgreement()`: an order form that
  // incorporates a NAMED STANDARD FORM — here the IAB Standard Terms — drew
  // six findings for the clauses that live in the form it incorporates.
  "advertising-insertion-order.txt": {
    playbook: "advertising-insertion-order",
    findings: ["STRUCT-018"],
  },
  // An irrevocable trust — the 194th specimen, and the first for
  // `irrevocable-trust`. EST-401..407 are all satisfied: the express
  // irrevocability recital, the three-pillar spendthrift provision, the HEMS
  // ascertainable standard with its beneficiary-trustee limit, trustee powers
  // with succession and removal, Crummey rights with notice and a 5-or-5
  // hanging power, the § 675(4)(C) substitution power with an Independent
  // Trustee tax reimbursement, and situs with decanting.
  "irrevocable-trust.txt": {
    playbook: "irrevocable-trust",
    findings: ["OBLI-005", "STRUCT-018"],
  },
  // An FY2027 sales commission plan — the 195th specimen, and the first for
  // `commission-plan`. EMP-109..114 are all satisfied: earned-on-collection
  // with a stated payment date, post-termination commissions with a state
  // wage-law savings clause, chargebacks with a twelve-month limit, the
  // prospective-only modification right, recoverable versus non-recoverable
  // draw, and the statement-and-dispute procedure.
  //
  // STRUCT-006 came off in 9.354.0, REVERSING the judgment recorded here that
  // it was fair. The term was "Sales Operations", and the same shape turned up
  // in an export control policy as "Trade Compliance" and in an employee
  // handbook as "People Operations": the internal function that administers
  // the document. A plan does not define its own org chart, and no drafting
  // change answers the finding. Naming a department three times is what makes
  // it the administrator, not what makes it an undefined term.
  "commission-plan.txt": {
    playbook: "commission-plan",
    findings: ["OBLI-005", "OBLI-006"],
  },
  // A GSA Multiple Award Schedule contract — the 193rd specimen, and the first
  // for `gsa-schedule-contract`. COMM-163..167 are all satisfied: the
  // basis-of-award customer with its discount relationship and the
  // 552.238-81 Price Reductions clause, the industrial funding fee with
  // quarterly sales reporting, Trade Agreements Act country of origin, FAR 8.4
  // ordering with order-level materials, and the 52.217-9 option periods.
  // STRUCT-006 stays and is fair: the Federal Supply Schedule is named three
  // times and introduced nowhere. STRUCT-004 is fair too — a Schedule contract
  // defines nothing itself, it incorporates the FAR by reference.
  "gsa-schedule-contract.txt": {
    playbook: "gsa-schedule-contract",
    findings: ["OBLI-005", "STRUCT-004", "STRUCT-006"],
  },
  // An audit committee charter — the 191st specimen, and the first for
  // `committee-charter`. GOV-051..060 are all satisfied: purpose, composition
  // and independence under Rule 10A-3, the § 301 auditor-oversight authority,
  // the complaint procedures with confidential anonymous submission, funding
  // for advisors, at-least-quarterly meetings, the annual self-evaluation,
  // regular reporting to the Board, and the annual charter review.
  "committee-charter.txt": {
    playbook: "committee-charter",
    findings: ["OBLI-005"],
  },
  // A records retention and destruction policy — the 192nd specimen, and the
  // first for `document-retention-policy`. POL-028..032 are all satisfied.
  // STRUCT-009 stays and is fair: the retention schedule writes its category
  // labels as "Corporate records", "Tax records", "HR records", which is a
  // lowercase use of the defined "Record". It exposed STRUCT-003 reporting a
  // `critical` "no signature block" on a policy nobody signs.
  "document-retention-policy.txt": {
    playbook: "document-retention-policy",
    findings: ["OBLI-005", "STRUCT-009"],
  },
  // A code of business conduct and ethics — the 190th specimen, and the first
  // for `code-of-conduct`. POL-001..005 are all satisfied: the scope over
  // directors, officers, and employees; the SOX § 406 honest-and-ethical and
  // full-fair-accurate-disclosure elements; the waiver mechanism with its
  // four-business-day Form 8-K disclosure; reporting with a helpline and
  // non-retaliation; and compliance with laws. STRUCT-006 stays and is fair:
  // the Integrity Helpline is named three times and introduced nowhere.
  "code-of-conduct.txt": {
    playbook: "code-of-conduct",
    findings: ["OBLI-005", "STRUCT-006"],
  },
  // A motion to compel in the Circuit Court of Cook County — the 189th
  // specimen, and the first for `trial-motion`. Clean but for the exhibits,
  // which travel with the supporting declaration. It exposed CITE-001 reading
  // the signature block's phone number and attorney registration number,
  // "0192 ARDC No. 6318842", as a malformed case citation.
  "trial-motion.txt": {
    playbook: "trial-motion",
    findings: ["STRUCT-018"],
  },
  // A durable financial power of attorney — the 188th specimen, and the first
  // for `durable-poa-financial`. EST-031..037 are all satisfied: principal and
  // agent with a successor, durability that survives incapacity, the general
  // subject-matter grant, the seven "hot powers" that require an express
  // grant, the agent's fiduciary duties with an accounting, third-party
  // reliance protection, and a notarial acknowledgment with recording. It
  // exposed the possessive determiner: "My Agent" was reported as a term the
  // instrument forgot to define.
  "durable-poa-financial.txt": {
    playbook: "durable-poa-financial",
    findings: ["EST-060", "OBLI-005"],
  },
  // An assignment and assumption agreement — the 187th specimen, and the first
  // for `assignment-and-assumption-agreement`. MNA-108..112 are all satisfied:
  // the schedule of assigned contracts, assumed versus excluded liabilities,
  // the third-party consent carve-out, an effective time of 12:01 a.m. on the
  // Closing Date, and further assurances with a power of attorney.
  "assignment-and-assumption-agreement.txt": {
    playbook: "assignment-and-assumption-agreement",
    findings: ["OBLI-008", "STRUCT-018"],
  },
  // A postnuptial agreement — the 186th specimen, and the first for
  // `postnuptial-agreement`. EST-046..052 are all satisfied: the
  // during-marriage recital, consideration beyond the marriage itself,
  // heightened fiduciary disclosure with schedules, transmutation of two
  // specific assets, a support waiver with a limited carve-out, independent
  // counsel with a review period, and a notarial acknowledgment. The family
  // had an empty `rule_overrides` and drew seven generic contract findings; it
  // now carries `prenuptial-agreement`'s profile, extended with RISK-001 and
  // CHOICE-003 — a marital agreement has no indemnity and states its
  // governing law without a forum.
  "postnuptial-agreement.txt": {
    playbook: "postnuptial-agreement",
    findings: ["EST-060", "STRUCT-018", "TEMP-002"],
  },
  // A profits-interest award in an LLC — the 184th specimen, and the first for
  // `profits-interest-award`. EQT-114..119 are all satisfied: the threshold
  // amount set at grant-date liquidation value, the Rev. Proc. 93-27 and
  // 2001-43 recitals, the § 83(b) direction with its 30-day deadline, vesting
  // with forfeiture allocations, capital-account book-up, and the partner-not-
  // employee warning. The family had an empty `rule_overrides`, so an equity
  // award was told it has no payment terms.
  "profits-interest-award.txt": {
    playbook: "profits-interest-award",
    findings: ["OBLI-005", "STRUCT-018"],
  },
  // An option to purchase real property — the 185th specimen, and the first
  // for `option-to-purchase-real-estate`. RE-123..127 are all satisfied:
  // non-refundable independent option consideration, strict exercise
  // mechanics with time of the essence, a price with an appraisal formula, a
  // recordable memorandum of option, and a perpetuities savings clause. It
  // took the `easement-agreement` skip profile — an interest in land is not a
  // services bargain.
  "option-to-purchase-real-estate.txt": {
    playbook: "option-to-purchase-real-estate",
    findings: [
      "FIN-006",
      "OBLI-002",
      "OBLI-005",
      "RISK-011",
      "RISK-015",
      "RISK-016",
      "STRUCT-018",
      "TEMP-006",
      "TEMP-007",
    ],
  },
  // A foundation grant award — the 183rd specimen, and the first for
  // `grant-agreement`. GOV-133..138 are all satisfied. It exposed two
  // defects: the family had an empty `rule_overrides`, so a charitable grant
  // was told it does not allocate IP and has no indemnity or liability cap;
  // and TEMP-007 reported that its survival list omits confidentiality and
  // indemnity, two clauses the instrument does not have at all.
  "grant-agreement.txt": {
    playbook: "grant-agreement",
    findings: ["OBLI-005", "STRUCT-018", "TEMP-006", "TEMP-008"],
  },
  // A pre-suit demand letter on unpaid invoices — the 182nd specimen, and the
  // first for `demand-letter`. Clean: SET-011..014 are satisfied by the
  // statement of facts, the specific demand with a deadline, the absence of
  // abusive language, and the reservation of rights. It exposed two defects:
  // SET-015 reported missing PAGA elements on an Illinois UCC collection
  // letter, and "section 11 of the terms of sale" read as a broken reference
  // to a section of the letter.
  "demand-letter.txt": {
    playbook: "demand-letter",
    findings: [],
  },
  // An appellate brief in the Ninth Circuit — the 181st specimen, and the
  // first for `appellate-brief`. Entirely clean: the filing-format pack is
  // dormant without --court, and the 53-rule contract-lint skip profile is
  // doing its job. It exposed the case-name defect: STRUCT-006 reported
  // "Celotex Corp", "Entek Int", and "Sanderson Plumbing Prods" as terms the
  // brief forgot to define.
  "appellate-brief.txt": {
    playbook: "appellate-brief",
    findings: [],
  },
  // Amended and restated bylaws of a Delaware corporation — the 180th
  // specimen. Clean but for one info: GOV-001..012 are all satisfied, and the
  // exclusive-forum bylaw carves out the Exchange Act. It was this document
  // that exposed the run-in "Section 1.1 Registered Office." heading, which
  // the cross-reference extractor registered as no section at all and then
  // reported as 28 broken references to itself.
  "bylaws-corporation.txt": {
    playbook: "bylaws-corporation",
    findings: ["OBLI-005"],
  },
  // A revolving credit agreement on LSTA architecture — the 179th specimen.
  // The whole BNK-101..108 pack is silent: commitment and borrowing base,
  // the SOFR benchmark-replacement waterfall, the financial covenants with
  // testing dates and an equity cure, conditions to each borrowing, events of
  // default with cure and cross-default, the collateral and guarantor
  // package, agent authority with assignment and participation, and
  // prepayment with breakage, increased costs, and the tax gross-up.
  // OBLI-002 came ONTO this row in 9.248.0. "To the fullest extent permitted
  // by law," was not a recognized fronted adverbial, so the obligor of the
  // clause read as part of the adverbial and matched no party; and a party
  // whose entity type is written "LLC"/"LLP" was found with no ROLE, which
  // is what an obligor is matched against. The asymmetry each of these
  // documents carries is real and was simply invisible.
  "revolving-credit-agreement.txt": {
    playbook: "revolving-credit-agreement",
    findings: [
      "OBLI-007",
      "STRUCT-006",
      "STRUCT-018",
      "CHOICE-008",
      "OBLI-002",
      "OBLI-003",
      "OBLI-005",
      "TEMP-006",
      "TEMP-007",
    ],
  },
  // An asset purchase agreement — the 178th specimen. The whole MNA-020..028
  // pack is silent: purchased assets, excluded assets, assumed and excluded
  // liabilities, the bulk-sales waiver, the § 1060 allocation with Form 8594,
  // the required-consents mechanics, WARN allocation, and the bill of sale.
  // What remains is fair: no termination article (TERM-005), schedules and
  // exhibits delivered separately (STRUCT-018), and four terms this body uses
  // without defining (STRUCT-006).
  "asset-purchase-agreement.txt": {
    playbook: "asset-purchase-agreement",
    findings: [
      "OBLI-001",
      "OBLI-002",
      "OBLI-005",
      "OBLI-007",
      "OBLI-008",
      "RISK-002",
      "RISK-003",
      "RISK-004",
      "RISK-011",
      "STRUCT-005",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-012",
      "TERM-005",
    ],
  },
  // OBLI-002 arrived with the parties fix in v9.220.0: "Investor" is a named
  // party, and § 5.3 puts the confidentiality obligation on the Investors
  // alone. That is accurate, and `info`.
  "stockholders-agreement.txt": {
    playbook: "stockholders-agreement",
    findings: [
      "GOV-039",
      "OBLI-002",
      "STRUCT-006",
      "STRUCT-018",
      "OBLI-005",
      "RISK-010",
      "TEMP-006",
      "TEMP-007",
    ],
  },
  // A franchise disclosure document, cover page through the receipt. The six
  // FTC Franchise Rule checks are silent on a compliant one. It named its
  // officers the way an FDD does — "Renata Kowalczyk, Chief Executive Officer"
  // — and signs nothing, so the signature-line and notarial sources of person
  // names found nothing and the CEO was reported as a Title-Case term the
  // document forgot to define. The two that stay are real: an FDD's exhibits
  // travel separately, and "Gross Sales" is defined in the franchise
  // agreement, not here.
  "fdd.txt": {
    playbook: "franchise-disclosure-document",
    findings: ["STRUCT-006", "STRUCT-018", "STRUCT-009"],
  },
  // An expert witness retention letter from counsel to a forensic engineer.
  // The family shipped with an empty rule profile while its sibling
  // `engagement-letter` already had the right one, so a retention letter was
  // told at `warning` that it allocates no IP, provides no indemnity, caps no
  // liability and states no termination for cause. A retention letter carries
  // none of those and is not supposed to.
  "expert-retention.txt": {
    playbook: "expert-witness-retention",
    findings: ["CHOICE-003", "OBLI-005", "TEMP-006", "TEMP-007", "TERM-007"],
  },
  // A vendor information-security exhibit. It carries no ratification clause —
  // an exhibit changes nothing, so it has none — and relies on the recital
  // every such document opens on: "This INFORMATION SECURITY Exhibit is
  // attached to and incorporated into the Master Services Agreement dated
  // October 12, 2024". `amendsParentAgreement()` required the bare noun
  // immediately after "This", and admitted "incorporated into" only right
  // after "is", so it saw neither: the exhibit was reported as having no
  // governing law, no venue, no IP allocation, no indemnity, no liability cap
  // and no termination clause. All six live in the agreement it is attached to.
  // OBLI-002 joined this row in 9.263.0, when the party extractor learned to
  // read a legal name written the way this document writes it — "Beacon Ledger Systems, Inc. ("Vendor")" with no
  // "a Delaware corporation" appositive behind it. OBLI-002 needs TWO parties
  // before it will compare sides, so until the second one was visible the
  // check was silently inert on this document.
  // The finding is right: every confidentiality duty in the exhibit runs to
  // Vendor, which is the shape a security exhibit is normally drafted in and
  // exactly the "intentional but worth confirming" case the rule reports at
  // `info`.
  "security-addendum.txt": {
    playbook: "vendor-security-addendum",
    findings: ["IPDATA-004", "OBLI-002", "OBLI-005", "TERM-007"],
  },
  // A general assignment and assumption of a transportation services contract.
  // It routed to `lease-assignment` at 0.9 and drew a `critical` about a
  // LANDLORD'S CONSENT: that family listed "assignor" and "assignee" as
  // distinguishing phrases — words in every assignment of anything — and
  // claimed the bare title keyword "assignment and assumption", which is the
  // other family's own name. MNA-108 then demanded a SCHEDULE of assigned
  // contracts, at `critical`, from a document that names the one contract it
  // assigns: the pattern read only the plural.
  // STRUCT-017 joined this row in 9.263.0 for the same reason OBLI-002 joined
  // the rows below it: 'Vantage Grocery Distribution, Inc. ("Counterparty")'
  // became visible to the party extractor. The document declares three parties
  // with roles and gives signature lines to two of them — the Counterparty's
  // consent is a separate instrument, attached (or here, not attached) as
  // Exhibit A, which STRUCT-018 reports on the next line.
  "assignment-assumption.txt": {
    playbook: "assignment-and-assumption-agreement",
    findings: ["STRUCT-017", "STRUCT-018", "OBLI-005", "RISK-011"],
  },
  // An AI addendum to a master services agreement. Three false positives, all
  // vocabulary: "Vendor shall not PERMIT any subprocessor ... to use Customer
  // Data to train" was read as denying that subprocessors are disclosed;
  // "model provider" — the current term of art — was in neither the
  // subprocessor-disclosure nor the hosting-disclosure list; and "Customer
  // owns all right, title, and interest in and to Customer Data" could not be
  // read as allocating data ownership. Three findings stay and are real:
  // the addendum discloses neither the default-on/opt-in state nor the model
  // hosting (ADDENDA-012), states no deletion of fine-tuning data on
  // termination (ADDENDA-016), and adds an indemnity whose cap it leaves to
  // the parent Agreement (RISK-015).
  // OBLI-002 joined this row in 9.263.0, when the party extractor learned to
  // read a legal name written the way this document writes it — "Sablefield Software, Inc. ("Vendor")" with no
  // "a Delaware corporation" appositive behind it. OBLI-002 needs TWO parties
  // before it will compare sides, so until the second one was visible the
  // check was silently inert on this document.
  // Section 8 gives Customer a Vendor IP indemnity and Customer none in
  // return, so the asymmetry it reports is on the page.
  "ai-addendum.txt": {
    playbook: "ai-addendum",
    findings: ["ADDENDA-012", "ADDENDA-016", "OBLI-002", "RISK-015", "OBLI-005", "STRUCT-009"],
  },
  // A NON-BINDING lease letter of intent, countersigned. The family shipped
  // with an empty rule profile while its M&A sibling `loi-term-sheet` already
  // had the right one, so a term sheet was told at `warning` that it states no
  // IP ownership, no indemnity, no liability cap and no termination for cause
  // — four clauses an LOI is not supposed to carry. It also pins the run-in
  // heading fix: "4. Base Rent. Base Rent shall be $34.50 ..." titles its own
  // section, and every use beneath it read as an undefined Title-Case term.
  "lease-loi.txt": {
    playbook: "letter-of-intent-lease",
    findings: ["STRUCT-006", "CHOICE-003", "OBLI-005", "TEMP-006"],
  },
  // A three-party technology escrow. The escrow pack (IPL-129..133) is silent
  // on a well-drafted deposit, and the specimen pins three repairs it exposed:
  // a payment term stated as "payable in advance on each anniversary"
  // (FIN-005), a survival clause that names its sections by number where the
  // labels carry no trailing delimiter (TEMP-007 / TEMP-012), and an
  // arbitration seat hung off the administering body with a comma (CHOICE-006).
  "source-code-escrow.txt": {
    playbook: "source-code-escrow-agreement",
    findings: [
      "STRUCT-018",
      "CHOICE-006",
      "IPDATA-003",
      "IPDATA-006",
      "OBLI-005",
      "RISK-011",
      "STRUCT-005",
      "TEMP-006",
      "TEMP-007",
      "TERM-007",
    ],
  },

  // An employee handbook: a policy nobody signs, which says so in its first
  // substantive sentence. STRUCT-006 came off in 9.354.0 — the term was
  // "People Operations", the internal function that administers the handbook.
  "handbook.txt": { playbook: "employee-handbook", findings: ["OBLI-005"] },

  // A union collective bargaining agreement, with arabic-numbered articles.
  "cba.txt": {
    playbook: "union-cba",
    findings: ["RISK-015", "STRUCT-006", "STRUCT-018", "CHOICE-006", "OBLI-005", "RISK-011"],
  },

  // A clinical trial agreement: a payment term behind a hyphenated qualifier,
  // and a survival clause that names its sections by number.
  "cta.txt": {
    playbook: "clinical-trial-agreement",
    findings: [
      "OBLI-002",
      "OBLI-005",
      "RISK-002",
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-006",
    ],
  },

  // A cyber liability policy with roman-numbered sections.
  "cyber-policy.txt": {
    playbook: "cyber-insurance-policy",
    findings: ["STRUCT-006", "CHOICE-006", "OBLI-005"],
  },

  // A convertible promissory note behind a restrictive-securities legend.
  "convertible-note.txt": {
    playbook: "convertible-note",
    findings: ["EQT-018", "OBLI-005", "STRUCT-006", "CHOICE-003"],
  },

  // A law-firm engagement letter: no styled title, and the only thing above
  // its "Re:" line is the firm's letterhead.
  "engagement-letter.txt": {
    playbook: "engagement-letter",
    findings: ["STRUCT-006", "CHOICE-006", "OBLI-005", "OBLI-008", "RISK-010"],
  },

  // Responses and objections to interrogatories. The three criticals are
  // real: Rule 34(b)(2)(C) withholding statement, the "subject to and without
  // waiving" boilerplate, and no production completion date.
  "interrogatory-responses.txt": {
    playbook: "discovery-responses",
    // DISC-018 and DISC-019 came off when the privilege-log undertaking was
    // recognized as the Rule 26(b)(5)(A) withholding statement it is, and
    // STRUCT-006 when a phrase naming one of the document's own SECTION
    // HEADINGS stopped reading as an undefined term. DISC-020 stays: the
    // responses state no completion date.
    findings: ["DISC-020"],
  },

  // A third amendment to an office lease: defines nothing, ratifies the rest.
  "lease-amendment.txt": {
    playbook: "lease-commercial-multitenant",
    findings: ["RISK-015", "STRUCT-018", "OBLI-005", "RISK-011"],
  },

  // A mutual NDA stamped EXECUTION VERSION / CONFIDENTIAL above its title.
  //
  // It routes to `mutual-nda-deep` from 9.273.0. `mutual-nda` has carried
  // `"deprecated": true, "superseded_by": "mutual-nda-deep"` since the deep
  // family landed, and the matcher's whole deprecation mechanism was a
  // TIEBREAK — which never fired, because the legacy family carries
  // `required_clauses` (0.4 each) and its successor carries none. So the 23
  // NDA-D rules never ran on an auto-routed document, and the six findings
  // this row used to hold contained nothing about the NDA's own substance.
  // NDA-D-007 came off it in the same release: the standard exclusion reads
  // "rightfully known to the Receiving Party without restriction before
  // disclosure", which is 42 characters between "known" and "before" against
  // a 40-character window.
  "legend-nda.txt": {
    playbook: "mutual-nda-deep",
    findings: [
      "OBLI-005",
      "RISK-001",
      "RISK-014",
      "NDA-D-014",
      "NDA-D-016",
      "NDA-D-019",
      "NDA-D-022",
      "NDA-D-023",
    ],
  },

  // A medical director agreement drafted to the Stark and AKS personal-service
  // exceptions, with a three-year term.
  // TERM-002 came off this row in 9.251.0. The agreement states its cause
  // grounds SPECIFICALLY, the way a regulated-services agreement does —
  // "Hospital may terminate immediately upon: (a) suspension, revocation, or
  // restriction of Medical Director's license or DEA registration … (d)
  // failure to maintain the insurance required by Section 10" — and every
  // branch of the check wanted the noun "breach" or the phrase "for cause".
  "medical-director.txt": {
    playbook: "medical-director-agreement",
    findings: [
      "IPDATA-001",
      "RISK-001",
      "RISK-005",
      "STRUCT-018",
      "TERM-005",
      "OBLI-002",
      "OBLI-005",
      "RISK-010",
      "TERM-001",
    ],
  },

  // An insurer's reservation-of-rights letter, titled only in its "Re:" line.
  "ror-letter.txt": { playbook: "reservation-of-rights-letter", findings: ["OBLI-005"] },

  // A post-money SAFE behind the same securities legend. An instrument, not a
  // bilateral bargain — nobody indemnifies and nothing terminates for cause.
  "safe.txt": {
    playbook: "safe-yc",
    findings: ["EQT-006", "STRUCT-006", "OBLI-005", "STRUCT-005"],
  },

  // A syndicated credit agreement: venue laid in a borough inside a city.
  "loan-agreement.txt": {
    playbook: "loan-agreement",
    findings: [
      "RISK-001",
      "RISK-005",
      "RISK-016",
      "STRUCT-006",
      "STRUCT-018",
      "TERM-005",
      "CHOICE-008",
      "FIN-009",
      "OBLI-003",
      "OBLI-005",
      "STRUCT-005",
    ],
  },

  // A membership interest purchase agreement, stamped EXECUTION VERSION, with
  // decimal-numbered schedules and a fraud carve-out from the indemnity cap.
  "mipa.txt": {
    playbook: "membership-interest-purchase-agreement",
    findings: [
      "MNA-103",
      "FIN-005",
      "IPDATA-001",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-012",
      "OBLI-005",
      "TEMP-006",
    ],
  },

  // An EEA/UK privacy notice: names its controller with a non-US corporate
  // suffix, cites the regulation's articles by bare number, and is signed by
  // nobody.
  "gdpr-notice.txt": { playbook: "privacy-notice-gdpr", findings: [] },

  // An Ohio will with a conformed signature, an attestation clause, and a
  // self-proving affidavit. Clean under the estate checks — the one info is
  // the disclosure that execution formalities cannot be verified from text.
  // (EST-060 is the standing disclosure, not a defect in the will.)
  "will.txt": { playbook: "last-will-and-testament", findings: ["EST-060"] },

  // A confidential settlement agreement enforceable in a named federal court.
  "settlement.txt": { playbook: "confidential-settlement", findings: ["SET-009", "OBLI-005"] },

  // A desktop EULA that recites FAR 12.212's quoted phrase.
  // An Article 30 record of processing activities: a REGISTER a controller
  // keeps, not an agreement with anybody. It routed to
  // `dpa-controller-processor` and drew seventy-five findings, every one of
  // them a clause a register is not supposed to contain.
  "ropa-art-30.txt": { playbook: "ropa-art-30", findings: [] },

  // A completed vendor security questionnaire: question-and-answer pairs, not
  // clauses. The one finding is the family's own — the questionnaire never
  // asks about vulnerability management.
  "vendor-security-questionnaire.txt": {
    playbook: "vendor-security-questionnaire",
    findings: ["PRV-031"],
  },

  // An ACORD-style certificate of liability insurance, which says in its own
  // first paragraph that it is not a contract.
  "coi.txt": { playbook: "coi", findings: [] },

  // A Washington state set of interrogatories. The caption puts the docket on
  // its OWN line and writes it bare — "No. 26-2-04188-1 SEA" — and the party
  // block arrives as one paragraph ending in ", Defendant.", so the caption
  // walk stopped short of the title and the document routed to
  // `document-requests`, which reported at `critical` that it stated no form
  // of production for electronically stored information.
  // STRUCT-005 dropped in 9.247.0: the term IS used, in lowercase
  // ("Document" → "document", "Descendants" → "descendants"). The use scan
  // was case-sensitive, so a term the document uses only in the other case
  // was reported as never used at all — while STRUCT-009 was separately
  // reporting the same term as inconsistently capitalized. Both cannot be
  // true.
  "interrogatories.txt": {
    playbook: "interrogatories",
    // DISC-010 came off in 9.352.0. This set has a DEFINITIONS AND
    // INSTRUCTIONS section and bounds several interrogatories "between
    // January 1, 2025 and December 31, 2025"; the pattern wanted the words
    // "time period" or "from <Month> <year>" with no day number.
    findings: [],
  },

  // A Washington quitclaim deed, whose granting words are the statutory short
  // form: "conveys and quitclaims to". RE-128 wanted "hereby quitclaims" and
  // reported at `critical` that the deed lacked the words it is written in.
  "quitclaim-deed.txt": { playbook: "quitclaim-deed", findings: [] },

  // A performance improvement plan. Its family's distinguishing phrases were
  // "30 days", "60 days", and "90 days" — which distinguish nothing — so a
  // textbook PIP scored 0.3 and fell to `generic-fallback`, and not one of the
  // six PIP checks ran on it.
  "pip.txt": { playbook: "pip", findings: ["TEMP-002"] },

  // An AIA-style construction change order. It closes by ratifying the
  // contract it modifies, which is where Contract Sum and Contract Time are
  // defined — and it was told it had forgotten to define them.
  "change-order.txt": { playbook: "change-order", findings: ["STRUCT-004"] },

  // A California set of requests for admission. Its proof of service is not
  // called a "certificate of service" anywhere outside federal practice, and
  // "Code of Civil Procedure section 2033.010" is a citation, not a broken
  // internal reference to a "section 2033.010".
  "requests-for-admission.txt": {
    playbook: "requests-for-admission",
    findings: ["STRUCT-005", "STRUCT-018"],
  },

  // An SEC Form 10-K Item 1A. A narrative disclosure section: no parties, no
  // signature, and its "we may not" sentences are risk statements rather than
  // covenants. REG-022 wanted the word "cybersecurity" from a filer whose risk
  // factor is headed "Risks Related to Data Privacy and Security".
  "10-k-risk-factors.txt": {
    playbook: "10-k-risk-factors",
    findings: ["REG-017", "REG-021", "REG-023", "REG-024", "REG-040"],
  },

  // A HIPAA notice of privacy practices. It speaks HIPAA's regulatory
  // vocabulary throughout — "designated record set", "unsecured protected
  // health information" — and never uses the acronym, so IPDATA-005 reported
  // that it cited no data regime.
  "hipaa-npp.txt": { playbook: "hipaa-npp", findings: ["OBLI-005"] },

  // The disclosure schedules to a stock purchase agreement: a list of
  // exceptions keyed to another instrument's section numbers. MNA-039 wanted
  // the literal heading "General Notes" and reported the three paragraphs that
  // ARE the introduction as no introduction at all, at `critical`.
  "disclosure-schedules.txt": {
    playbook: "disclosure-schedules",
    findings: ["MNA-044", "MNA-045"],
  },

  // Bylaws of a North Carolina nonprofit with no members and no stock. They
  // routed to `bylaws-corporation` and were told at `critical` that they had
  // no annual stockholders meeting, no stock certificate clause, and no DGCL
  // § 220 inspection right.
  "nonprofit-bylaws.txt": {
    playbook: "nonprofit-bylaws",
    findings: ["OBLI-005", "RISK-011"],
  },

  // An FCRA stand-alone disclosure and authorization. Two of its family's
  // columns could not be satisfied by a COMPLIANT document: one required the
  // disclosure to describe itself as stand-alone, and the other required it to
  // say it carries no liability waiver. A lawful form says neither; it simply
  // carries neither.
  "background-check-disclosure.txt": { playbook: "background-check-disclosure", findings: [] },

  // A CTIA-standard SMS program disclosure. Its family's title keywords and
  // three of its six distinguishing phrases were spellings nobody uses, so it
  // scored 0.4 and fell to `generic-fallback`; PRV-113 then wanted the
  // first-person "I agree to receive" from a page that addresses the reader as
  // "you".
  "sms-consent-disclosure.txt": { playbook: "sms-consent-disclosure", findings: [] },

  // An ISO additional-insured endorsement. "declarations" sat in its family's
  // NEGATIVE features, and an endorsement references the Declarations by
  // definition, so it routed to `coi`. Its references into the policy's own
  // divisions — "Section II — Who Is An Insured is amended" — read as broken
  // internal cross-references.
  "insurance-endorsement.txt": {
    playbook: "insurance-endorsement",
    findings: ["INS-012"],
  },

  // A tenant estoppel certificate and a UK cookie notice: both already clean,
  // pinned so they stay that way.
  "estoppel-certificate.txt": {
    playbook: "estoppel-certificate",
    findings: ["STRUCT-018"],
  },

  "cookie-notice.txt": { playbook: "cookie-notice", findings: ["PRV-003"] },

  // A California Civil Code § 8132 conditional waiver on progress payment, in
  // the statutory wording the form must use verbatim. Clean, and pinned so it
  // stays clean.
  "construction-lien-waiver.txt": { playbook: "construction-lien-waiver", findings: [] },

  // A blank HIPAA acknowledgment form. Its own "Date: ______" line is the
  // date-of-receipt line HC-020 asked for; its labeled blanks are fields, not
  // unfilled template content; and "Privacy Practices" is a fragment of its
  // own all-caps caption.
  "npp-acknowledgment.txt": { playbook: "npp-acknowledgment", findings: ["HC-025"] },

  // A credit union's whistleblower policy, with the DTSA § 1833(b) notice.
  // Clean, and pinned so it stays clean.
  "whistleblower-policy.txt": { playbook: "whistleblower-policy", findings: [] },

  // A joint-representation conflict waiver. ENG-021 wanted the letter to say
  // "the clients are" when a letter identifies its clients by addressing them,
  // and ENG-023 wanted "if a conflict arises" from a section headed "What
  // happens if a conflict becomes actual". The letter was also reported as
  // containing a non-compete, on a sentence naming "the non-competition
  // covenants each of you will sign" — a covenant it describes, in an
  // instrument it is not.
  // CHOICE-001, CHOICE-003, and STRUCT-004 stay: this family shares the
  // five-skip engagement profile with the four fee agreements, and a waiver
  // letter can state its governing law as readily as they can.
  // CHOICE-001 and CHOICE-003 were pinned here as known-false until 9.359.0:
  // a consent letter under Rule 1.7 has no governing-law clause and no forum
  // clause, and is not defective for it. The family now skips both, along
  // with FIN-005 — the fees are in the engagement letter this one references.
  "joint-representation-waiver.txt": {
    playbook: "joint-representation-waiver",
    findings: ["STRUCT-004"],
  },

  // The same waiver from the other common posture: two founders forming an
  // LLC together, where the conflict is over the operating agreement's own
  // terms rather than over an existing dispute. Paragraph 3 lists what the
  // founders are opposed on — including "the scope of any non-competition
  // covenant" — and PERS-001 and PERS-005 both read the sentence WARNING the
  // clients about a covenant as a covenant the letter imposes. OBLI-005 is
  // fair: "We will not thereafter represent either of you individually
  // against the other" is a negative covenant, and it is the operative
  // promise of the paragraph.
  "joint-representation-waiver-founders.txt": {
    playbook: "joint-representation-waiver",
    findings: ["OBLI-005"],
  },

  // An Article 35 data protection impact assessment — an assessment document,
  // not an agreement. Clean, and pinned so it stays clean.
  "dpia-art-35.txt": { playbook: "dpia-art-35", findings: [] },

  // A California contingency fee agreement. It defines both its parties in its
  // first sentence — ("the Firm"), ("the Client") — with the article INSIDE the
  // quotes, which the parenthetical-definition pattern could not see, so it was
  // reported as having no defined terms at all. ENG-012 wanted a label where
  // the exclusion is written as a promise.
  "contingency-fee-agreement.txt": {
    playbook: "contingency-fee-agreement",
    findings: [
      "CHOICE-001",
      "CHOICE-003",
      "CHOICE-006",
      "FIN-005",
      "OBLI-005",
      "RISK-010",
      "TEMP-002",
    ],
  },

  // A research informed-consent form. 21 CFR 50.25 asks for a PLAIN-LANGUAGE
  // explanation, and HC-001 demanded the regulation's own vocabulary: a form
  // headed "WHY THIS STUDY IS BEING DONE" that says "four visits over eighteen
  // months" was told at `critical` that it stated neither purpose nor
  // duration.
  "informed-consent.txt": { playbook: "informed-consent", findings: ["OBLI-005"] },

  // An Illinois BIPA § 15(b) consent. Its consent paragraph recites the
  // statute's own elements, and PRV-101 wanted "written release" or "I consent
  // to" from a form that says "I give my written consent … to that collection,
  // storage, and use".
  "biometric-consent.txt": { playbook: "biometric-consent", findings: ["OBLI-005"] },

  // A blank 45 C.F.R. § 164.508 authorization. It is a FORM, and five of its
  // own fields — marked with prose rather than a colon, "for the period ______
  // through ______" — were reported at `critical` as unfilled template
  // content.
  "phi-authorization.txt": { playbook: "phi-authorization", findings: ["OBLI-005"] },

  // A COPPA direct notice to parents. It routed to `cookie-notice` — 16 CFR
  // 312.4(b)'s own name for the document, "direct notice to parents", was not
  // a title keyword — and PRV-110 wanted "parent may review" from a notice
  // that addresses the parent as "you", which is what the regulation asks for.
  "childrens-privacy-notice.txt": {
    playbook: "childrens-privacy-notice",
    findings: ["OBLI-005"],
  },

  // A North Carolina health care power of attorney. Its family's title
  // keywords carried the CLOSED spelling only — "healthcare power of attorney"
  // — so the document titled with the spaced one fell to `generic-fallback`,
  // and EST-027 wanted "takes effect upon" from "my agent's authority BEGINS
  // when my attending physician determines that I LACK THE CAPACITY".
  "healthcare-poa.txt": {
    playbook: "healthcare-poa",
    findings: ["EST-060", "OBLI-005"],
  },

  // A joint Rule 26(f) report. It routed to `complaint` — whose distinguishing
  // phrases were "plaintiff", "jurisdiction", "venue", and "jury", the words of
  // every commercial contract's own governing-law and dispute clauses — and was
  // told at `critical` that it demanded no relief and no jury trial.
  "rule-26f-report.txt": { playbook: "rule-26f-report", findings: [] },

  // A Rule 30(b)(6) deposition notice. DISC-037 wanted Rule 30(b)(1)'s own
  // vocabulary — "the name of the deponent is" — from a notice that NAMES the
  // organization three times: in its title, in its opening sentence, and in
  // its designation paragraph.
  "deposition-notice.txt": { playbook: "deposition-notice", findings: ["STRUCT-018"] },

  // An answer with affirmative defenses and a jury demand, and a Rule
  // 41(a)(1)(A)(ii) stipulation of dismissal. Both already clean; pinned so
  // they stay that way.
  "answer.txt": { playbook: "answer", findings: [] },
  "stipulation-of-dismissal.txt": { playbook: "stipulation-of-dismissal", findings: [] },

  // An open-source compliance policy, adopted by an OFFICER rather than by the
  // board — which STRUCT-003's dated-adoption recital did not recognize, so a
  // policy nobody signs was told at `critical` that it had no signature block.
  "oss-compliance.txt": { playbook: "oss-compliance", findings: ["IPL-035"] },

  // An OWBPA-compliant separation agreement and general release. EMP-019
  // demanded the § 626(f)(1)(H) decisional-unit disclosure of an INDIVIDUAL
  // separation, which the statute asks only of a group termination program;
  // EMP-022 wanted the words "over and above" from an agreement that says the
  // earned wages are paid "whether or not the Employee signs" and the
  // severance only "if the Employee signs".
  "separation-agreement.txt": {
    playbook: "separation-agreement",
    findings: ["CHOICE-003", "OBLI-005", "PERS-006", "TEMP-002"],
  },

  // A California proprietary-information and inventions agreement. EMP-032
  // conjoined "proprietary information" — this family's own TITLE, so it could
  // never fail — with "non-disclosure", which the agreement never uses; it
  // states the obligation instead. EMP-036 wanted "power of attorney" or
  // "coupled with an interest" from a clause that says "I appoint the Company
  // as my attorney-in-fact"; and IPDATA-002 read the carve-out only in the
  // assignment's own paragraph, when it is always its own section.
  "piia.txt": { playbook: "piia", findings: ["OBLI-005", "STRUCT-018"] },

  // An NVCA-style voting agreement. It routed to `stockholders-agreement` —
  // which listed "voting agreement" among its own title keywords — and was
  // told at `critical` that it had no tag-along, no right of first refusal,
  // and no voting-agreement clause, on a document whose Article 1 is one.
  "voting-agreement.txt": {
    playbook: "voting-agreement",
    findings: [
      "CHOICE-003",
      "EQT-059",
      "EQT-060",
      "EQT-063",
      "OBLI-005",
      "STRUCT-006",
      "STRUCT-018",
      "TERM-005",
    ],
  },

  // A company's insider trading policy, with the Rule 10b5-1(c) cooling-off
  // periods as amended. Already clean; pinned so it stays that way.
  "insider-trading-policy.txt": { playbook: "insider-trading-policy", findings: [] },

  // A proxy statement's Compensation Discussion and Analysis. It routed to
  // `executive-employment` — whose distinguishing phrases were "chief
  // executive officer", "chief financial officer", and "named executive
  // officer", which a CD&A names on every page — and drew five criticals,
  // including that it had no § 409A clause and no signature block. The three
  // findings left are the rest of the proxy, which this section is not.
  "proxy-statement-narrative.txt": {
    playbook: "proxy-statement-narrative",
    findings: ["GOV-117", "GOV-118", "GOV-122"],
  },

  // An amended and restated Delaware certificate of incorporation. GOV-027
  // demanded an incorporator clause of it, at `critical` — the incorporator
  // signs the ORIGINAL certificate, and a restatement is executed by an
  // officer under DGCL § 245 — and GOV-031 could not read the blank-check
  // authority in Article IV because "by resolution" sits between the words it
  // wanted.
  "charter-incorporation.txt": {
    playbook: "charter-incorporation",
    findings: ["GOV-030", "OBLI-005", "STRUCT-006"],
  },

  "eula.txt": {
    playbook: "eula",
    findings: ["ADDENDA-018", "IPDATA-010", "OBLI-005", "RISK-007", "TERM-007"],
  },

  // A Delaware LLC operating agreement: a governance instrument, not a
  // commercial bargain.
  "operating-agreement.txt": {
    playbook: "operating-agreement-llc",
    findings: ["OBLI-005", "STRUCT-006", "STRUCT-018"],
  },

  // An executive employment agreement — 409A, 280G, Good Reason, and an
  // arbitration seat behind a named rule set.
  "executive-employment.txt": {
    playbook: "executive-employment",
    // TERM-005 came off this row in 9.119.0: the agreement has a full
    // severance clause — "If the Company terminates Executive without Cause …
    // the Company shall pay Executive twelve (12) months of base salary" —
    // and was being told it does not state what happens on termination.
    findings: [
      "EMP-007",
      "CHOICE-006",
      "OBLI-002",
      "OBLI-005",
      "PERS-002",
      "RISK-011",
      "RISK-015",
      "TEMP-008",
    ],
  },

  // A commercial real estate purchase and sale agreement.
  "cre-psa.txt": {
    playbook: "real-estate-psa",
    findings: [
      "RE-013",
      "RE-016",
      "RISK-016",
      "STRUCT-018",
      "FIN-006",
      "OBLI-002",
      "OBLI-005",
      "OBLI-006",
      "RISK-011",
    ],
  },

  // A continuing guaranty: an instrument, and deliberately uncapped.
  "guaranty.txt": { playbook: "guaranty", findings: ["CHOICE-008", "RISK-009"] },

  // A SaaS order form issued under a named master subscription agreement.
  "order-form.txt": { playbook: "saas-customer", findings: ["TEMP-004", "OBLI-005"] },

  // A well-drafted consulting agreement, the 244th specimen and the first for
  // `consulting-agreement`, one of the ten families the product launched with.
  // The RULES came back clean — nine findings, every one a fact about the
  // document rather than an accusation — and the defect the specimen exposed
  // was in the EXTRACTOR.
  //
  // '(each, an "SOW", and the services under all SOWs, the "Consulting
  // Services")' defines two terms in one parenthetical without a
  // collective connective, and NEITHER was found: the plain parenthetical
  // pattern needs its quote closed by ")", the trailing-prose pattern's run
  // cannot cross the first quote, and the pair pattern requires one of
  // "collectively / together / individually / each / severally" between the
  // two names. Both were then reported by STRUCT-006 as terms the document
  // forgot to define, on the sentence that defines them.
  //
  // `msa-general` also had to name the specialisation: a consulting agreement
  // that works through statements of work carries the MSA vocabulary, and the
  // two tied at 0.9.
  "consulting-agreement.txt": {
    playbook: "consulting-agreement",
    findings: [
      "OBLI-002",
      "OBLI-005",
      "PERS-002",
      "RISK-002",
      "RISK-007",
      "TEMP-004",
      "TERM-001",
      "TERM-007",
    ],
  },

  // A sale-of-business non-competition and non-solicitation covenant, the 243rd
  // specimen and the first for `ma-restrictive-covenant`. It was written to
  // check that 9.269.0's title-keyword fix for the EMPLOYMENT covenant had not
  // taken this family's documents, and it had: "non-competition and
  // non-solicitation" and "non-solicitation agreement" both matched, the
  // employment family scored two title keywords, and the M&A covenant was
  // audited as an employment one. Both sides are corrected — the M&A family
  // gains the conjoined titles and the sale-of-business vocabulary, and the
  // employment family names the sale-of-business context as a negative
  // feature.
  //
  // Three MNA rules then failed on the document itself, all the same shape: a
  // covenant is drafted as a PROHIBITION, not as a noun. MNA-077 and MNA-078
  // wanted "non-solicit" or "not to solicit" and could not read "Seller shall
  // not solicit any customer of the Company"; MNA-079 wanted the nouns
  // "blue-pencil" or "reformation" and could not read "the court shall reform
  // it to the narrowest terms that are enforceable".
  "ma-restrictive-covenant.txt": {
    playbook: "ma-restrictive-covenant",
    findings: ["PERS-005", "PERS-001", "PERS-002", "OBLI-002", "OBLI-005"],
  },

  // A vendor DPA that DEFINES ITS OWN TERM for the regulated data — "Customer
  // Personal Data" — which is how every major vendor DPA is drafted, the 242nd
  // specimen. Written to test whether the CCPA pack's object-noun defect was
  // systemic. It was: this textbook Article 28(3) addendum drew SIX false
  // criticals from the GDPR pack for the same reason.
  //
  // DPA-004 wanted "types of personal data" and the document says "the types
  // of Customer Personal Data"; DPA-024 anchored the breach notice on the word
  // "controller" where the document names that party by its role ("shall
  // notify Customer"); DPA-002 wanted "duration of the processing" where a DPA
  // ties the duration to the agreement's term; DPA-016 wanted the right to
  // object where the standard drafting states the thirty-day notice that gives
  // effect to it; DPA-029 wanted "Article 35" where the Regulation's own
  // range is "Articles 32 to 36"; and DPA-046 could not read "Irish law
  // governs this DPA" — the fourth ruleset found carrying its own narrower copy
  // of a clause the jurisdictions extractor has read since v1.
  //
  // What is left is on the page: this DPA names no transfer mechanism, no EU
  // representative and no sub-processor annex, and it incorporates rather than
  // restates the technical measures.
  "dpa-defined-term.txt": {
    playbook: "dpa-controller-processor",
    findings: [
      "DPA-006",
      "DPA-019",
      "DPA-020",
      "DPA-021",
      "DPA-022",
      "DPA-028",
      "DPA-030",
      "DPA-032",
      "DPA-033",
      "DPA-034",
      "DPA-040",
      "DPA-044",
      "DPA-045",
      "DPA-047",
      "DPA-051",
      "DPA-052",
      "DPA-053",
      "DPA-054",
      "DPA-055",
      "OBLI-005",
      "TRANSFER-018",
      "TRANSFER-019",
      "TRANSFER-020",
    ],
  },

  // A downstream (subcontractor) BAA, the 245th specimen and the first for
  // `baa-subcontractor` — a family the general `baa` was taking until 9.276.0.
  // It drew SEVENTEEN findings including two CRITICALS, and one of the two was
  // INVERTED: BAA-005 reported that the agreement "states that subcontractors
  // handling PHI are not bound by the same restrictions", on § 6.1, which says
  // the opposite. `expressDenial`'s conditional-tail guard — the one that keeps
  // "may not engage a subcontractor WITHOUT a written contract" out — allowed
  // only 40 characters between the topic and the connective, and the drafting
  // § 164.502(e)(1)(ii) actually asks for spells the definition out inline:
  // "shall not engage a further subcontractor THAT WILL CREATE, RECEIVE,
  // MAINTAIN OR TRANSMIT PHI without a written agreement".
  //
  // The other five were one class: **the pack assumes the counterparty is the
  // COVERED ENTITY, and in a downstream BAA it is the BUSINESS ASSOCIATE.**
  // BAA-004 wanted "report to the Covered Entity" from a subcontractor that
  // has no relationship with the covered entity at all; BAA-026 wanted covered-
  // entity audit rights where the audit right runs upstream. BAA-031, BAA-034
  // and BAA-040 wanted noun phrases ("workforce training", "sanctions policy",
  // "notice shall be") where the document uses the verb.
  //
  // What is left is the generic commercial set a BAA does not carry — no IP
  // allocation, no indemnity, no liability cap, no venue — which is the same
  // shape as the SCC and NDA families, and the family's near-empty
  // `rule_overrides` is now a profile: a BAA allocates no IP, states no
  // indemnity, caps no liability and names no venue, because the underlying
  // services agreement does all four.
  "baa-subcontractor.txt": {
    playbook: "baa-subcontractor",
    findings: ["OBLI-005", "OBLI-008", "TEMP-006", "TERM-007"],
  },

  // A model CCPA service-provider addendum, the 241st specimen and the first
  // for `dpa-ccpa-service-provider` — a family that reached NO family at all
  // on its own bad document until 9.276.0. It drew THIRTEEN CRITICALS, and
  // eleven were false.
  //
  // The systemic cause is one sentence: the pack was written to the words a
  // model TEMPLATE uses, and it required the literal object "personal
  // information" — while a real addendum defines its own term for it. '"Covered
  // Data" means Personal Information the Business discloses' and then "shall
  // not Sell or Share Covered Data" matched nothing. USDPA-002 and USDPA-015
  // now read a defined-term object (case-SENSITIVELY: the capital is what makes
  // it a defined term). The rest wanted a template phrase where the STATUTE has
  // its own: "limited and specified" for USDPA-001, "another source" singular
  // for USDPA-004, "the same restrictions this Addendum imposes" for USDPA-005,
  // "reasonable and appropriate steps" — § 1798.140(ag)(1)(E)'s own words — for
  // USDPA-017, and a SOC 2 report for USDPA-019. USDPA-003 required the literal
  // "cross-context behavioral advertising" from a document that says "shall not
  // Sell or Share", which is the prohibition the Act's own verb states.
  "ccpa-service-provider.txt": {
    playbook: "dpa-ccpa-service-provider",
    findings: ["OBLI-002", "OBLI-005", "TERM-007"],
  },

  // A well-drafted SBA 7(a) loan agreement, the 240th specimen and the first
  // for `sba-loan-agreement` — a family the general `loan-agreement` was
  // taking until 9.276.0. Three rule defects on the first real one, and all
  // three were a word with two meanings.
  //
  // FIN-009 read "the Loan BEARS INTEREST at the prime rate plus 2.75%" as a
  // periodless late-payment penalty. FIN-005 told a loan repayable in 120
  // monthly installments that it states no payment term, because it wanted
  // "Net 30". RISK-016 told it that hazard insurance "for at least its full
  // replacement cost" states no coverage minimum, because it wanted a dollar
  // figure — and replacement cost is the minimum every secured lender
  // requires.
  //
  // All six BNK-109..114 columns are satisfied, which is what a document
  // drafted to SOP 50 10 should produce.
  "sba-loan-agreement.txt": {
    playbook: "sba-loan-agreement",
    findings: ["OBLI-005"],
  },

  // A well-drafted private-target stock purchase agreement, the 239th specimen
  // and the first for `stock-purchase-agreement` — a family that reached its
  // own bare document only from 9.275.0. Two rule defects on the first real
  // one.
  //
  // MNA-018's pattern was "stockholder.s?\\s+representative", where the `.`
  // was meant to be an optional apostrophe and MUST match a character — so it
  // required "Stockholders' Representative" with both the apostrophe and a
  // space, and could not read the plain "Stockholder Representative" a
  // private-target SPA defines. And STRUCT-005 reported "Closing Working
  // Capital" as a term the drafter defined and never used, on the clause that
  // uses it three times: the "definition talking about itself" suppression ran
  // to the end of the PARAGRAPH rather than the end of the definition's own
  // SENTENCE.
  //
  // What is left is on the page. RISK-002 and OBLI-002 both read the indemnity
  // as running from Seller alone, which is what a private-target indemnity
  // does; STRUCT-018 counts the seven schedules the agreement references and
  // does not attach; RISK-003 reads the $4,200,000 cap; PERS-002 the
  // sale-of-business non-solicit.
  "stock-purchase-agreement.txt": {
    playbook: "stock-purchase-agreement",
    findings: [
      "RISK-002",
      "RISK-005",
      "STRUCT-018",
      "OBLI-002",
      "OBLI-005",
      "PERS-002",
      "RISK-003",
      "TEMP-002",
      "TEMP-006",
    ],
  },

  // A well-drafted unilateral NDA, the 238th specimen and the first for
  // `unilateral-nda-deep` — a family that was unreachable by auto-routing
  // until 9.273.0 promoted a deprecated playbook's named successor. All
  // twenty-five NDA-D rules are silent on it, and three of them were fixed to
  // get there: "Nothing in this Agreement grants Recipient any LICENCE" is the
  // textbook no-licence clause with the negation on "nothing" and the noun
  // spelled with a c (NDA-D-021); "indefinitely for any Confidential
  // Information that is a trade secret" is the carve-out written as a tail on
  // the term sentence (NDA-D-004); and "Discloser"/"Recipient" is the other
  // standard role pair, the one `mutual-nda` itself lists as distinguishing
  // phrases (NDA-D-025).
  //
  // RISK-001 stays at `info`, which is the profile the legacy family already
  // carried and the deep families now inherit: an NDA has no indemnity by
  // design, and saying so at `warning` was noise on every one of them.
  "unilateral-nda.txt": {
    playbook: "unilateral-nda-deep",
    findings: ["OBLI-005", "RISK-001"],
  },

  // A work-made-for-hire agreement for commissioned illustration, animation and
  // score, the 237th specimen and the first for `work-for-hire-agreement`. Two
  // routing defects, both about a sibling.
  //
  // The family carried "royalty" as a NEGATIVE feature, which is backwards:
  // every work-for-hire agreement licenses the contractor's pre-existing
  // material "royalty-free", so the family lost 0.1 on the standard clause it
  // is written to see. And `independent-contractor` — whose three required
  // clauses (ip-ownership, term, termination-for-convenience) a work-for-hire
  // agreement necessarily has — took the document at 1.0, so the § 101
  // ruleset never ran. It now names the work-for-hire markers as negative
  // features, which is the direction the steal actually runs.
  //
  // OBLI-002 is right: only Contractor holds anything in confidence here.
  "work-for-hire.txt": {
    playbook: "work-for-hire-agreement",
    findings: ["OBLI-002", "OBLI-005"],
  },

  // A founder restricted stock purchase agreement, the 236th specimen and the
  // first for `rspa`. The third demonstrated instance of a family routed on
  // its own compliance, and the sharpest: four of the five distinguishing
  // phrases — "repurchase right", "83(b)", "stock power", "escrow" — are the
  // clauses EQT-036..042 require. A founder RSPA that takes a promissory note
  // for the purchase price and states no 83(b) advisory, no escrow, no stock
  // power, no right of first refusal, no legend and no lock-up scored 0.3 on
  // its title — an EXACT title keyword — fell to `generic-fallback`, and drew
  // ZERO findings. It now routes at 0.9 and draws five, three of them
  // critical.
  //
  // EQT-041 also came off this well-drafted one: a lock-up is written as a
  // covenant, not a heading — "Purchaser shall not sell any Share during the
  // one hundred eighty (180) days following the effective date of the
  // Company's initial public offering" — and the `180\s+days` branch could not
  // read the numeral where every American agreement puts it, inside the
  // parenthetical after the spelled number.
  "restricted-stock-purchase.txt": {
    playbook: "rspa",
    findings: ["OBLI-005"],
  },

  // A model automatic-renewal page, the 235th specimen and the first for
  // `auto-renewal-terms`. Two findings of the session's recurring shape, and
  // the sharper of the two is that the rules were written in the REGULATOR'S
  // words and a compliant consumer page is written in the SUBSCRIBER'S.
  // COMM-231 wanted "clearly and conspicuously" and "before obtaining billing
  // information"; a page that actually discloses before checkout says "before
  // you pay", and one that renews says "your subscription renews
  // automatically" — the adverb after the verb, which every branch read only
  // in the reverse order. It drew a CRITICAL for a disclosure that is its
  // entire section 1. And COMM-233's two pillars were joined by an OR, so the
  // bare word "cancel" satisfied "Simple cancellation mechanism" — the page
  // its own rationale calls the paradigm violation ("to cancel, call our
  // support line and speak to a retention specialist") passed it clean.
  //
  // The family also shipped with an empty `rule_overrides`, so a published
  // terms page forming part of a subscriber agreement was told it has no
  // signature block, no governing law, no venue, no payment terms, no IP
  // allocation, no indemnity, no liability cap and no termination clause.
  // TEMP-004 is the one finding left, and it is right: the page does contain
  // automatic-renewal language, which is a fact worth surfacing.
  "auto-renewal-terms.txt": {
    playbook: "auto-renewal-terms",
    findings: ["TEMP-004"],
  },

  // A Colorado non-compete and non-solicitation covenant, the 234th specimen
  // and the first for `employment-restrictive-covenant`. It routed to
  // `mutual-nda-deep` and drew NINE CRITICALS about an NDA it is not — no
  // definition of Confidential Information, no publicly-available exclusion,
  // no return-or-destruction clause — because the family's title keywords were
  // written as exact full titles ("non-compete agreement", "non-competition
  // agreement") and this document is headed NON-COMPETITION AND
  // NON-SOLICITATION AGREEMENT. The EMP-024..031 ruleset never ran on it.
  //
  // PERS-005 and PERS-001 both report the covenant, at warning and at info,
  // which is the intended pair: a non-compete is a fact worth surfacing and a
  // scope worth reading. PERS-002 is the non-solicit. TEMP-007 is fair — the
  // survival list omits the $25,000 retention payment.
  "employment-restrictive-covenant.txt": {
    playbook: "employment-restrictive-covenant",
    findings: ["PERS-005", "PERS-001", "PERS-002", "OBLI-005", "TEMP-006", "TEMP-007"],
  },

  // An executed UK IDTA — Part 1's four tables and Part 2's Mandatory Clauses
  // — the 233rd specimen and the first for `uk-idta-addendum`. The sibling of
  // the SCC specimen below, and it found four more ways the same relationship
  // was unread. The ICO writes its adoption NAME-FIRST ("The Mandatory Clauses
  // are incorporated in full"), which an ordered pattern could not read; the
  // vocabulary the ICO's own form defines — Appropriate Safeguards, Approved
  // Addendum, General Authorisation — was reported as six terms the addendum
  // forgot to define; its references into that form ("as Section 18 permits")
  // as three references it broke; and the ICO's version string, "the template
  // Addendum B.1.0", as a reference to a missing attachment "Addendum B".
  // CHOICE-001 and CHOICE-003 come off the family: Section 17 of the Mandatory
  // Clauses fixes the law and the forum, and an IDTA never states them itself.
  //
  // What is left is on the page: a well-drafted addendum adds a fallback for
  // the adequacy decision being invalidated, and this one does not.
  "uk-idta-addendum.txt": {
    playbook: "uk-idta-addendum",
    findings: ["TRANSFER-018", "TEMP-002"],
  },

  // An executed EU SCC Module Two set — a cover page, the option selections,
  // and three completed annexes — the 232nd specimen and the first for
  // `scc-module-2`. It drew THIRTY-NINE findings, THIRTEEN of them critical,
  // and every critical one was false: Clause 8's documented instructions,
  // Clause 8.5's deletion-or-return, Clause 8.6's breach notification and the
  // rest of Article 28(3) live in the Commission Implementing Decision the
  // document adopts in full, and Clause 2 (invariability) is why a
  // well-drafted set does not restate them. `adoptsStandardFormInFull` is the
  // `amendsParentAgreement` of that relationship, and it is applied PER RULE:
  // the checks for Annex II and Annex III still fire on a set that arrives
  // without them, which is the whole point of the family.
  //
  // What is left is on the page. The importer is a US processor and no Article
  // 27 representative is named (DPA-030); the set carries signature dates but
  // no stated effective date (DPA-044) and no notices clause outside the Annex
  // I.A contacts (DPA-051); and it adds no fallback for the adequacy decision
  // being invalidated (TRANSFER-018), which a careful exporter's counsel does.
  "scc-module-2.txt": {
    playbook: "scc-module-2",
    findings: ["DPA-030", "DPA-044", "DPA-051", "TRANSFER-018", "OBLI-005", "OBLI-008", "TEMP-002"],
  },

  // A university exclusive license, the 231st specimen and the first for
  // `technology-transfer-agreement`. Writing it exposed the family's routing:
  // six of its seven distinguishing phrases were the Bayh-Dole clauses its own
  // checks require — "bayh-dole", "march-in rights", "government license
  // rights", "substantially manufactured in the united states", "diligence
  // milestones", "sponsored research" — so a licence that omits them scored
  // 0.5 and lost to `patent-license` at 0.6, and IPL-123, the CRITICAL check
  // for the government's retained licence, could only fire on a document that
  // had already recited it. The phrases that identify a UNIVERSITY licence
  // whatever it says — "board of trustees", "office of technology",
  // "sublicense income", "principal investigator", "research foundation" —
  // now carry the routing.
  //
  // RISK-005 and RISK-015 stay: this licence caps nothing, which is the
  // university’s intent and the licensee’s risk, and both are the shape
  // the rules are written to surface. TERM-003 and OBLI-002 are the same
  // one-sidedness read from the other two directions.
  "technology-transfer.txt": {
    playbook: "technology-transfer-agreement",
    findings: [
      "RISK-005",
      "RISK-015",
      "TERM-003",
      "OBLI-002",
      "OBLI-005",
      "OBLI-008",
      "RISK-010",
      "TEMP-006",
      "TEMP-008",
      "TEMP-009",
      "TERM-001",
    ],
  },

  // A cross-border exclusive distribution agreement: an ICC seat stated in the
  // participle, and the GDPR cited by its regulation number.
  //
  // OBLI-002 came off this row in 9.264.0. Its only "representation" here is
  // inside the indemnity — "third-party claims arising from Distributor's
  // representations beyond those Supplier authorizes" — which is the
  // distributor's sales talk to a customer, not a contractual representation
  // to the supplier. The rule's noun now has to appear in its contractual
  // sense.
  "distribution.txt": {
    playbook: "distribution-agreement",
    findings: [
      "COMM-026",
      "COMM-038",
      "COMM-039",
      "IPDATA-007",
      "RISK-015",
      "STRUCT-018",
      "TEMP-005",
      "CHOICE-006",
      "FIN-008",
      "OBLI-005",
      "RISK-007",
    ],
  },

  // A bill of sale: a one-time conveyance, executed by the seller alone.
  "bill-of-sale.txt": {
    playbook: "bill-of-sale",
    findings: ["RISK-015", "STRUCT-018", "OBLI-002", "RISK-011"],
  },

  // A fixed-rate promissory note with a flat late charge.
  "promissory-note.txt": {
    playbook: "promissory-note",
    findings: ["FIN-009", "STRUCT-005"],
  },

  // An assignment is a completed conveyance: it has no term, nothing to
  // terminate, and nothing that "survives" a termination that cannot happen.
  // TERM-002 / TERM-005 / TEMP-012 are skipped for this playbook. What is
  // left is real — the Schedule A that enumerates the Assigned IP is
  // referenced and not attached, and the indemnity states no notice,
  // defense-control, or settlement-consent mechanics.
  "ip-assignment.txt": {
    playbook: "ip-assignment",
    findings: ["STRUCT-018", "OBLI-002", "OBLI-005", "RISK-011"],
  },

  // A trademark cease-and-desist letter. Its playbook used to be reachable on
  // the bare topic words "infringement" / "trademark" / "copyright" /
  // "patent", which every IP document on earth contains — an IP ASSIGNMENT
  // scored 0.6 on it. The phrases are now the letter's own register.
  "cease-and-desist.txt": {
    playbook: "cease-and-desist",
    findings: ["OBLI-005"],
  },

  // A North Carolina deed of trust with an assignment of rents, a power of
  // sale, and a notarial acknowledgment. A security instrument states no
  // payment terms (they are in the Note it secures), allocates no IP, caps
  // nobody's liability, and ends by reconveyance rather than termination.
  // Its notary block — "My commission expires: October 31, 2028" — was read
  // as the instrument's own expiration, which made the Note's 2036 maturity
  // a date after the document expired.
  "deed-of-trust.txt": {
    playbook: "deed-of-trust",
    findings: ["STRUCT-018", "OBLI-003", "OBLI-005", "RISK-010"],
  },

  // A 50/50 Delaware joint venture, drafted to be complete: purpose and
  // exclusivity, capital contributions and a no-further-calls covenant,
  // board and reserved matters and a deadlock ladder, allocation AND
  // distribution AND a tax distribution, transfer restrictions AND a
  // buy-sell, and background AND foreground IP. All six COMM-146..151
  // checks are silent on it — which is what makes it the compliant
  // direction for the conjunctions they became.
  "joint-venture.txt": {
    playbook: "joint-venture-agreement",
    findings: [
      "CHOICE-006",
      "OBLI-005",
      "PERS-001",
      "PERS-005",
      "RISK-004",
      "RISK-006",
      "RISK-007",
      "RISK-010",
      "STRUCT-005",
      "STRUCT-006",
      "STRUCT-017",
      "STRUCT-018",
      "TEMP-006",
      "TEMP-007",
      "TEMP-008",
    ],
  },

  // A US privacy notice: no parties, no definitions section, nothing to
  // terminate. Clean, which is the assertion — a compliant notice must
  // produce nothing.
  "privacy-notice.txt": { playbook: "privacy-notice-us", findings: [] },

  // A stipulated protective order under FRCP 26(c), captioned with two
  // defendants. The caption walk stopped on "CORVUS SYSTEMS CORPORATION and
  // MARISOL ANDRADE," because the lowercase "and" broke its all-uppercase
  // test, so the matcher was handed the defendants' names as the title: the
  // order routed to `mutual-nda` at 0.9 and was told it had no governing law,
  // no liability cap, no IP allocation, and no termination-for-cause clause.
  // The judge's own signature line was reported at `critical` as an unfilled
  // template placeholder. What is left is real — an Exhibit A that is
  // referenced and not attached, and three Title-Case terms used undefined.
  "protective-order.txt": {
    playbook: "protective-order-stipulated",
    findings: ["OBLI-008", "STRUCT-006", "STRUCT-009", "STRUCT-014", "STRUCT-018"],
  },

  // A DGCL § 141(f) unanimous written consent of the board. The playbook
  // listed "bylaws" as a negative feature — the recital every such consent
  // opens on ("pursuant to ... the Bylaws of the Corporation").
  "written-consent.txt": {
    playbook: "written-consent",
    findings: ["STRUCT-006"],
  },

  // A Series B financing term sheet, titled "Summary of Terms" — the standard
  // title, and one no title keyword recognized. It lost to `mutual-nda`.
  // `loi-term-sheet` also listed "definitive agreement" as BOTH a
  // distinguishing phrase and a negative feature, and shipped with an empty
  // `rule_overrides`: a non-binding term sheet was told it allocated no IP,
  // capped no liability, indemnified nobody, and could not be terminated for
  // cause. MNA-004 reported at `critical` that a document stating a
  // $28,000,000 round, a $112,000,000 pre-money valuation, and a per-share
  // price stated no price — it knew only the M&A vocabulary.
  "term-sheet.txt": {
    playbook: "loi-term-sheet",
    findings: ["CHOICE-003", "OBLI-005", "STRUCT-006", "TEMP-006"],
  },

  // A WARN Act plant-closing notice, titled only in its "Re:" line. Two
  // checks accused a compliant notice: EMP-147 recognized a state mini-WARN
  // overlay only in four states and the literal phrase "mini-WARN", so a
  // notice reciting "Nevada Revised Statutes Chapter 613" was told at
  // `critical` that it addressed no state law; EMP-146 wanted the WORD
  // "contact" or "telephone" from a notice that names its HR director and
  // gives her number.
  // STRUCT-006 came off this row in 9.249.0. The notice is issued by the
  // "Office of Economic Development" and copied to the "Director of Human
  // Resources", and the Title-Case run breaks at the lower-case "of", so both
  // tails arrived as terms the notice had supposedly forgotten to define.
  "warn-notice.txt": { playbook: "warn-notice", findings: ["TERM-006"] },

  // An Oregon revocable living trust. The family shipped with an EMPTY
  // `rule_overrides` while its two nearest siblings — the will and the
  // irrevocable trust — share an identical eleven-skip estate profile, so a
  // trust instrument was told it had no payment terms, no IP allocation, no
  // indemnity, no liability cap, and nothing to terminate for cause.
  // (Its sibling `irrevocable-trust` had the substring bug in its purest
  // form: the negative feature "revocable" is inside "irrevocable", so every
  // irrevocable trust was penalized on its own name.)
  // IPDATA-005 reported "references personal data but does not cite GDPR /
  // CCPA / HIPAA" on the paragraph that cites the Health Insurance
  // Portability and Accountability Act by name and 45 C.F.R. Parts 160 and
  // 164 by number.
  // STRUCT-005 dropped in 9.247.0: the term IS used, in lowercase
  // ("Document" → "document", "Descendants" → "descendants"). The use scan
  // was case-sensitive, so a term the document uses only in the other case
  // was reported as never used at all — while STRUCT-009 was separately
  // reporting the same term as inconsistently capitalized. Both cannot be
  // true.
  "revocable-trust.txt": {
    playbook: "revocable-living-trust",
    findings: ["EST-060", "OBLI-005"],
  },

  // A notice of stock option grant. Every equity award carries its plan's
  // name on the line above its own title — "HALCYON INSTRUMENTS, INC. 2026
  // EQUITY INCENTIVE PLAN" over "NOTICE OF STOCK OPTION GRANT" — and reading
  // only the first line routed the grant to `equity-incentive-plan`, where it
  // was checked against the Plan's compliance matrix: no share reserve
  // (critical), no evergreen, no capitalization adjustment, no
  // change-in-control treatment, no amendment triggers, no clawback hook.
  // Those are provisions of the Plan.
  "option-grant.txt": {
    playbook: "stock-option-grant",
    findings: ["OBLI-005"],
  },

  // A recreational-use hold harmless and indemnity agreement. TEMP-012
  // reported that its survival clause does not name the indemnity, on
  // "Sections 2 through 5 and Section 7 survive termination indefinitely" —
  // whose Section 2 is headed "Indemnity". Two things defeated it: the
  // enumeration expander read only the first endpoint of a RANGE, and the
  // indemnity test used the stem `indemnif`, which does not match the word a
  // section is actually headed with.
  // An AI acceptable use policy written to the NIST AI RMF and the EU AI Act.
  // It maintains an "AI Tool Register", and STRUCT-006 reported that the
  // policy uses a term "Tool Register" it never defined — the Title-Case
  // scanner cannot cross an all-caps word, so the capture began one word in
  // and named a phrase the document does not contain.
  "ai-use-policy.txt": { playbook: "ai-aup-policy", findings: ["OBLI-005"] },
  // An owner-architect agreement on AIA B101 architecture — the 215th
  // specimen, and the source of four defects at once:
  //
  //   - IPDATA-001 said it allocated no IP ownership, on a document whose §7
  //     is titled Instruments of Service and reserves copyright in them. The
  //     retention branch wanted "retains all rights IN <object>" adjacent;
  //     the standard sentence reads "rights, including copyright, in".
  //   - STRUCT-006 reported an undefined term "Following Owner", from the
  //     sentence that paces each phase on Owner's written approval.
  //   - The party extractor read the TITLE — "AGREEMENT BETWEEN OWNER AND
  //     ARCHITECT FOR DESIGN SERVICES" — as the party clause, and the title
  //     restated at the head of the preamble beat the real party clause in
  //     the same sentence.
  //   - The indemnity obligor came out as "fullest extent permitted by law,
  //     Architect", because "to the FULLEST extent" was not a recognized
  //     fronted adverbial, so OBLI-002 called a mutual indemnity one-sided.
  "architect-agreement.txt": {
    playbook: "architect-agreement",
    findings: [
      "STRUCT-018",
      "TEMP-012",
      "OBLI-005",
      "RISK-007",
      "RISK-010",
      "RISK-011",
      "TEMP-006",
      "TEMP-007",
      "TERM-001",
    ],
  },
  // A university technology transfer licence on Bayh-Dole architecture — the
  // 216th specimen. Its signing office, the "Office of Technology Transfer",
  // was reported as an undefined term "Technology Transfer": the Title-Case
  // run breaks at the lower-case "of", so the tail of an organizational
  // unit's name arrives as its own candidate. The three IPL findings are
  // real and deliberate — the licence has no patent-marking clause and no
  // grant-back, and its 2% post-expiration royalty is the Brulotte problem
  // IPL-009 exists to surface. OBLI-002 is real too: only the Licensee
  // indemnifies, which is how a university writes one.
  "technology-transfer-license.txt": {
    playbook: "patent-license",
    findings: [
      "IPL-009",
      "IPL-011",
      "IPL-012",
      "OBLI-002",
      "OBLI-005",
      "OBLI-008",
      "RISK-007",
      "RISK-010",
      "TEMP-006",
      "TEMP-008",
      "TERM-001",
    ],
  },
  // A UCC Article 2 master purchase agreement for machined goods — the 217th,
  // and the first for `master-purchase-agreement`. Two false accusations:
  //
  //   - COMM-107 reported that no clause addressed "price, price adjustment,
  //     and payment" on a document whose §2 is titled PRICE AND PAYMENT and
  //     does exactly what the rule's own `fix` recommends. Its patterns
  //     wanted the NOUNS "price list" / "price schedule" / "price
  //     adjustment"; its own sibling COMM-102 already read "unit price".
  //   - RISK-002 called a mutual indemnity asymmetric. The tally seeded
  //     itself from every extracted party, so the two natural persons who
  //     SIGN sat at zero and dragged `min` down until an ordinary 2:1 split
  //     cleared the `max - min >= 2` threshold.
  //
  // What remains is real: no aggregate liability cap, a 180-day non-renewal
  // window, and two exhibits the specimen does not carry.
  "master-purchase-agreement.txt": {
    playbook: "master-purchase-agreement",
    findings: [
      "DARK-002",
      "RISK-005",
      "RISK-015",
      "STRUCT-018",
      "TEMP-004",
      "TEMP-005",
      "OBLI-005",
      "OBLI-008",
      "RISK-007",
      "RISK-010",
      "RISK-012",
      "RISK-013",
      "TEMP-006",
      "TERM-001",
    ],
  },
  // A bank's business continuity and disaster recovery plan — the 218th
  // specimen, and the first that reports NOTHING. Getting there took three
  // fixes, all in the same undefined-Title-Case-term family: the plan's
  // alternate site is a CITY ("the co-location facility in Sioux Falls, South
  // Dakota", then twice more bare), its spokesperson HEADS a department ("the
  // head of Corporate Communications"), and its "Crisis Management Team" is a
  // body the plan itself constitutes in the sentence naming its chair and its
  // members — the same case as an office, which was already excluded.
  "business-continuity-plan.txt": { playbook: "business-continuity-plan", findings: [] },
  // A Regulation D Rule 506(b) subscription agreement for seed preferred — the
  // 219th. Its counterparty is named only by a descriptor, "and the undersigned
  // subscriber (the \"Subscriber\")", and `ROLE_PAREN` required the quote to
  // open the parenthesis, so the Subscriber never reached the party set: the
  // agreement had one side, and OBLI-002 reported that only the Company
  // indemnified, in a section where each side indemnifies the other sentence by
  // sentence. The family also carried an empty `rule_overrides`, so a one-time
  // purchase that CLOSES was told it states no path to terminate for material
  // breach, no effect of termination, no payment term, no IP allocation, and no
  // limitation of liability. It now carries the `secondary-stock-transfer`
  // profile, whose five skips are exactly those five accusations.
  "subscription-agreement.txt": {
    playbook: "subscription-agreement",
    findings: ["RISK-015", "STRUCT-018", "OBLI-005", "OBLI-006"],
  },
  // An FLSA primary-beneficiary internship agreement — the 220th specimen, and
  // the first for `internship-agreement`. Four defects at once:
  //
  //   - TERM-002 said it states no path to terminate for cause, on a §7.2 that
  //     ends the internship "immediately upon: (a) a material violation of a
  //     Company policy …" — the termination VERB list held "end the
  //     membership" and not "end the internship".
  //   - TERM-005 said it states no effect of termination, on a §7.3 titled
  //     Effect. Its window is one sentence, and the survival list "Sections 4,
  //     5, 7.3, and 8" stopped it dead at the period inside "7.3"; the
  //     consequence verb was written in the third person, which the list did
  //     not hold either.
  //   - STRUCT-007 reported a broken reference to "section 24L", which is
  //     Massachusetts General Laws chapter 149 — cited chapter-first, a style
  //     the external-citation guard could not read.
  //   - The family carried an empty `rule_overrides`, so an internship
  //     agreement was asked for an indemnity and a liability cap.
  "internship-agreement.txt": { playbook: "internship-agreement", findings: ["OBLI-005"] },
  // A data licence with an explicit machine-learning restriction — the 221st
  // specimen, and the first for `data-license-agreement`. Clean on arrival:
  // every finding is real, including RISK-015, which reads the indemnity
  // carve-out from the liability cap correctly rather than as a missing cap.
  "data-license-agreement.txt": {
    playbook: "data-license-agreement",
    findings: [
      "RISK-015",
      "STRUCT-018",
      "TEMP-004",
      "OBLI-005",
      "RISK-003",
      "RISK-007",
      "TEMP-006",
      "TERM-007",
    ],
  },
  // A relocation assistance and repayment letter — the 222nd, and the first
  // for `relocation-agreement`. It routed to `offer-letter`, which won on
  // three phrases every relocation letter carries ("start date", "base
  // salary", "at-will"), and was then asked for the pre-employment-check and
  // plan-subject clauses an offer letter carries. The family's title keywords
  // were four exact full titles — "relocation assistance agreement",
  // "relocation repayment agreement" — and this document combines two of
  // them, so none matched and it scored no title weight at all.
  //
  // Behind the mis-routing: FIN-005 read "Any amount you owe under Section 4
  // is DUE WITHIN sixty (60) days" as no payment term, because its subject
  // alternation held "amount due" and "amount owed" but not "amount you owe";
  // and the family's empty `rule_overrides` asked a relocation letter for an
  // IP clause, an indemnity, and a limitation of liability.
  "relocation-agreement.txt": {
    playbook: "relocation-agreement",
    findings: ["OBLI-005", "STRUCT-009", "TEMP-008"],
  },
  // A Minnesota marital settlement agreement — the 223rd specimen, and the
  // first for `family-msa`. It carried an empty `rule_overrides`, so a divorce
  // settlement was told it allocates no intellectual property, states no
  // limitation of liability, caps no indemnity, states no path to terminate
  // for material breach, and states no effect of termination. It now carries
  // the `cohabitation-agreement` profile — the fullest family-law profile in
  // the catalog — plus TEMP-012, because a survival clause that enumerates
  // indemnification is a commercial convention and a marital settlement
  // survives as an independent contract instead.
  //
  // RISK-016 was fixed at the rule level rather than skipped: "Wife shall
  // maintain health and dental insurance for the Children through her
  // employer" was reported as an insurance requirement with no coverage
  // minimum — a minimum no health-coverage clause has ever stated. The same
  // sentence shape appears in every employment and physician agreement.
  "marital-settlement-agreement.txt": {
    playbook: "family-msa",
    findings: ["STRUCT-018", "EST-060", "OBLI-003", "OBLI-005"],
  },
  // A first set of FRCP 34 requests for production — the 224th specimen, and
  // the first for `document-requests`. It reports NOTHING, which took two
  // fixes:
  //
  //   - DISC-003 said it stated no relevant time period, on a request set
  //     whose definitions read `"Relevant Period" means January 1, 2023
  //     through the date of production` and whose requests use that term. The
  //     check's second pillar wanted a scoping phrase ("unless otherwise
  //     stated", "these requests cover") — one way to bound a period, and not
  //     the way a definitions section does it.
  //   - STRUCT-006 reported "Purchase Orders" as undefined, from "Purchase
  //     Orders 44117, 44219, and 44320" — the sentence that identifies exactly
  //     which orders it means. A phrase followed by an identifying number
  //     names an instrument; the Title-Case run just stops at the digits.
  "document-requests.txt": { playbook: "document-requests", findings: [] },
  // A nonprofit conflict-of-interest policy adopted from the IRS's own model —
  // the one in the Form 1023 instructions — the 225th specimen, and the first
  // for `coi-policy`. POL-034 told it at CRITICAL that it has no annual
  // disclosure clause, on a policy whose Article VI is headed ANNUAL
  // STATEMENTS and reads "shall ANNUALLY SIGN A STATEMENT which affirms". The
  // check wanted the nouns "annual disclosure" or "annual certification",
  // which the model text does not use.
  "conflict-of-interest-policy.txt": {
    playbook: "coi-policy",
    findings: ["OBLI-005", "OBLI-008"],
  },
  // A Delaware plan of dissolution and winding up — the 226th, and the first
  // for `dissolution-plan`. Three defects:
  //
  //   - STRUCT-007 reported five broken references to sections 277, 278, 280,
  //     281 and 311, which are DGCL sections. The plan ties one of them to the
  //     code — "as section 275 of the General Corporation Law of the State of
  //     Delaware requires" — and cites the rest bare, which is how a plan of
  //     dissolution is written; the declaration matcher also wanted the label
  //     capitalized, and this one writes it mid-sentence.
  //   - STRUCT-006 reported "Preferred Stock" as undefined, from "Series B
  //     Preferred Stock": a single capital letter heads a phrase exactly as an
  //     acronym does, and the Title-Case run breaks at the designator.
  //   - FIN-007 reported an MFN clause, from "terminate all leases and
  //     contracts on the most favorable terms REASONABLY AVAILABLE" — an
  //     instruction about the best deal the officers can get, not a promise of
  //     the best terms to anyone.
  "dissolution-plan.txt": { playbook: "dissolution-plan", findings: ["OBLI-005"] },
  // A flat-fee engagement letter for a startup formation and seed financing —
  // the 227th specimen, and the first for `flat-fee-agreement`. ENG-002 told
  // it at CRITICAL that it does not identify its client, on a letter whose §1
  // is headed THE CLIENT and reads "Our client is Chandrasekaran Robotics, LLC
  // only. We do not represent you individually, and we do not represent any
  // other member, officer, employee, or investor of the company." The
  // disclaimer pillar wanted the constituent noun immediately after "any" and
  // in the plural.
  //
  // It also routed to `engagement-letter`, on "legal services agreement" in
  // its title, so none of the flat-fee checks ran — earned-on-receipt, the
  // refund of the unearned portion, the out-of-scope list. The flat-fee
  // family's title keywords were three exact full titles.
  "flat-fee-agreement.txt": {
    playbook: "flat-fee-agreement",
    findings: ["OBLI-003", "OBLI-005", "STRUCT-004"],
  },
  // A social media and external communications policy for a clinical-stage
  // biotech — the 228th specimen, and the first for `social-media-policy`. It
  // reports nothing. STRUCT-007 reported a broken reference to "section 50",
  // from "Tennessee Code ANNOTATED section 50-1-1003": half the states trail
  // their code's name that way, and the guard added in 9.251.0 for the
  // chapter-first citation style required the code word to be the last one
  // before the section.
  "social-media-policy.txt": { playbook: "social-media-policy", findings: [] },
  // A national trust company's BSA/AML compliance policy — the 229th specimen,
  // and the first for `aml-policy`. Two defects:
  //
  //   - POL-012 told it at CRITICAL that it has no five-pillar AML program, on
  //     a policy whose §2 is headed THE FOUR PILLARS AND THE FIFTH and
  //     enumerates all five with the citation. The officer pillar read
  //     "compliance officer" and "AML officer" but not "BSA Officer" — the
  //     industry title in every US bank's program, and the regulation itself
  //     asks only for "a designated individual".
  //   - STRUCT-006 reported "Suspicious Activity Report" as undefined. The
  //     Code of Federal Regulations names that instrument; the policy does not
  //     define it because it does not have to.
  "aml-policy.txt": { playbook: "aml-policy", findings: ["OBLI-005"] },
  "hold-harmless.txt": {
    playbook: "hold-harmless-agreement",
    findings: ["OBLI-002", "OBLI-005", "RISK-010", "TEMP-006", "TEMP-007"],
  },

  // An assignment and assumption of a commercial lease, with the landlord's
  // consent and estoppel statements. It routed to `estoppel-certificate`,
  // whose distinguishing phrases were "no default", "full force and effect",
  // and "security deposit" — what every lease amendment, SNDA, and assignment
  // consent says about the lease it touches. `lease-assignment`'s own title
  // keywords were "assignment of lease" and "lease assignment", and the title
  // a real one carries is "Assignment and Assumption of Lease", which contains
  // neither. RE-057 then reported the release / continuing-liability clause
  // missing on a section headed "Assignor's Continuing Liability" that says
  // "Assignor is not released … Assignor remains liable".
  // TEMP-002 was pinned here as known-false until 9.360.0: the earliest date
  // in the document is the First Amendment's, and the referenced-instrument
  // exclusion listed "addendum" but not "amendment", so a recital naming the
  // lease and its amendment in one breath read as 828 days of back-dating.
  "lease-assignment.txt": {
    playbook: "lease-assignment",
    findings: ["OBLI-005", "RE-060"],
  },

  // The two-party posture of the same family: the landlord consents on a
  // separate exhibit rather than signing the assignment. It reaches its
  // family for the first time in 9.358.0 — "assignment and assumption of
  // lease" had been losing on the alphabet to the family that read only
  // "assignment and assumption". STRUCT-018 is fair (the exhibits are named
  // and not attached), and so is RISK-011: the mutual indemnity states no
  // notice, defense-control or settlement-consent machinery.
  "lease-assignment-retail.txt": {
    playbook: "lease-assignment",
    findings: ["STRUCT-018", "RE-060", "RISK-011"],
  },

  // A patent covenant not to sue. Its playbook's distinguishing phrases were
  // written as verbatim sentences nobody writes — "this is a covenant not to
  // sue and not a release", "shall not institute any action" — so a document
  // titled COVENANT NOT TO SUE scored 0.3, fell below the threshold to
  // `generic-fallback`, and none of its five checks ran. Once they did, two
  // fired at `critical` on the sections that state exactly what they check
  // for: SET-106 knew only the not-a-RELEASE characterization, and the
  // commonest covenant not to sue is a patent one that says it is not a
  // LICENSE; SET-107 wanted "claims arising from" adjacent, and the drafting
  // puts the subject matter in between. SET-108 is real — a patent covenant
  // states no joint-tortfeasor effect, and this one does not either.
  "covenant-not-to-sue.txt": {
    playbook: "covenant-not-to-sue",
    findings: ["OBLI-005", "SET-108"],
  },

  // A Series B side letter. Two defects about citing a parent document.
  // STRUCT-007 reported "Section 3.5 of the IRA" as a broken reference to a
  // section this letter never had — the extractor reads "Section 3.7 of the
  // Agreement" and the three-letter forms the catalog happened to list, but
  // not a short name the document itself invents, which is how every side
  // letter, amendment, SOW, guaranty, and SNDA cites its parent. And MNA-128
  // wanted "only BY a writing" from a letter that says "amended only IN a
  // writing signed by the Company and Kestrel".
  // OBLI-002 joined this row in 9.263.0, when the party extractor learned to
  // read a legal name written the way this document writes it — "Thalassa Marine Robotics, Inc. (the "Company")" with no
  // "a Delaware corporation" appositive behind it. OBLI-002 needs TWO parties
  // before it will compare sides, so until the second one was visible the
  // check was silently inert on this document.
  // Section 6 binds Kestrel alone to keep what it learns confidential; the
  // Company undertakes nothing in return.
  "side-letter.txt": {
    playbook: "side-letter",
    findings: ["FIN-007", "OBLI-002", "OBLI-005", "OBLI-008"],
  },

  // A UCC § 9-104(a)(2) deposit account control agreement. RISK-005 reported
  // no limitation-of-liability clause on a document that excludes the Bank's
  // liability except for gross negligence and waives consequential damages —
  // which is correct as the rule is deliberately written (a bare
  // consequential-damages waiver is not a monetary cap), and wrong for this
  // family, because no bank's control agreement states a dollar cap.
  "daca.txt": {
    playbook: "deposit-account-control-agreement",
    findings: ["OBLI-005", "RISK-007", "STRUCT-006", "TEMP-006", "TEMP-007"],
  },

  // A venture-lender warrant behind the same restrictive-securities legend as
  // the SAFE and the convertible note. It routes correctly; what it found was
  // the empty `rule_overrides` — a unilateral instrument with no payment
  // terms, no IP allocation, no indemnity, no cap, and nothing to terminate.
  "warrant.txt": { playbook: "warrant-agreement", findings: ["OBLI-005", "STRUCT-006"] },

  // A trademark assignment with the goodwill, the § 1060(a) intent-to-use
  // limitation, and a transition-period quality-control covenant. All five of
  // its § 1060 checks are silent on it, which is the compliant direction for
  // that pack.
  "trademark-assignment.txt": { playbook: "trademark-assignment", findings: [] },

  // An M&A indemnity escrow. Its playbook listed "stock purchase agreement"
  // as a negative feature — the agreement every escrow of this kind names in
  // its first recital as the one it secures — and RISK-002 reported the
  // indemnity asymmetric, which it is by design: a three-party escrow
  // indemnifies its agent one way and always has.
  "escrow-agreement.txt": {
    playbook: "escrow-agreement",
    findings: ["OBLI-005", "TEMP-006", "TEMP-007"],
  },

  // A second M&A escrow, drafted the way a bank's own form is: a "Tax
  // Matters" section in place of a "Tax Reporting" one, and the three-verb
  // "indemnify, defend, and hold harmless the Escrow Agent". MNA-052 could
  // not read the first and RISK-011's stakeholder carve-out could not reach
  // past the inserted verb in the second, so the clause that PROTECTS the
  // neutral agent was audited as a commercial indemnity. STRUCT-018 is fair:
  // Schedule 1 (the agent's fees) and Schedule 2 (notice addresses) are named
  // and not attached.
  // A mutual NDA in LETTER form between a Delaware corporation and a
  // Norwegian AS — the shape a business-development contact actually sends.
  // `ENTITY_TYPES` is a US list with three European strays, so the Norwegian
  // side was invisible and the document reported ONE party; a party that is
  // invisible takes its role with it. NDA-D-001 (the § 1833(b) notice),
  // NDA-D-019 and NDA-D-022 are all fair absences. OBLI-008 is fair too: the
  // compelled-disclosure clause says "reasonable efforts" and defines nothing.
  // A Chicago office sublease with a prime-landlord consent condition. Three
  // false findings, all about the same thing — a document that stands between
  // two instruments and names a party to the other one.
  //
  // STRUCT-017 reported the subtenant as having no signature line while
  // standing in its signature block: the label "PELLWORTH & KIRUNA DESIGN
  // LLC, an Illinois limited liability company" is 68 characters and the
  // label bound was 60. With that fixed it reported the PRIME LANDLORD, which
  // never signs a sublease — and it had been reconciling the prime landlord
  // as SIGNED all along, on the one-word alias "FULTON" matching the
  // sublandlord's address at 1130 West Fulton Market. RISK-015 asked a
  // leasehold indemnity for an aggregate cap, which `lease-assignment` — the
  // nearest sibling — has skipped since it was written.
  // A well-drafted US multi-state consumer privacy notice — category-by-
  // category collection, sources, purposes, retention periods, the full rights
  // list, GPC, an appeal path. Clean, and pinned so it stays clean. The PNOT
  // content checks are assertion-gated (`--regime`), so what runs here is the
  // baseline: ADDENDA-020, which 9.364.0 extended to the two notice families
  // — until then the SPECIFIC families got less review than the generic linter
  // by default.
  // A Seattle staff-engineer offer letter with an option grant, an arbitration
  // clause carved for the EFAA, and a Washington RCW 49.44.140 invention
  // carve-out. Four false findings. PERS-001 and PERS-005 read "The Company is
  // not asking you to agree to any noncompetition covenant, and none is a
  // condition of this offer" as a non-compete — the disclaimer guard knew
  // "you are not subject to", which is the incoming-obligations shape, and not
  // the state-law disclaimer offer letters increasingly carry. STRUCT-006
  // asked the letter to define "Staff Mechanical Engineer", the job it exists
  // to offer. TEMP-010 read "This offer expires on August 10, 2026" — the
  // deadline to ACCEPT — as the agreement's expiration and reported the
  // September start date as falling after it. CHOICE-001 asked an offer letter
  // for a governing-law clause, which the family skipped the venue twin of.
  // A statement of work that NUMBERS itself — "This Statement of Work No. 4
  // ('SOW') is entered into under and subject to the Master Services Agreement
  // dated March 9, 2024". The subordination machinery reached none of it: the
  // issued-under reader's window is `[^.;]`, which stops at the period in
  // "No."; the borrows-definitions reader wanted a multi-word instrument title
  // where this one says "the meanings given in the MSA"; and the
  // order-of-precedence reader wanted the NOUN where this one says "If this
  // SOW conflicts with the MSA, the MSA controls". So the SOW was told it has
  // no governing law, no IP allocation, no liability cap, no venue and no
  // effect-of-termination clause — five clauses of the MSA it names in its
  // first sentence. TEMP-002 read the MSA's 2024 date from the header block,
  // where a colon stands in for the determiner.
  // A regulatory-affairs consulting agreement with an individual consultant —
  // work-made-for-hire plus assignment, a background-IP licence back, a
  // debarment representation, and a cap with the usual carve-outs. It is well
  // drafted, and RISK-004 and RISK-015 both reported its Section 11 at
  // `warning`, in the same words: "Indemnity carved out of the liability cap"
  // and "Indemnification carved out of liability cap". Four other specimens
  // carried the pair. Where the CAP ITSELF excepts the indemnity it is
  // RISK-004's finding; RISK-015 keeps the indemnity with no cap anywhere.
  "consulting-regulatory.txt": {
    playbook: "consulting-agreement",
    findings: [
      "OBLI-005",
      "RISK-004",
      "RISK-006",
      "RISK-007",
      "RISK-010",
      "RISK-011",
      "STRUCT-018",
      "TEMP-006",
      "TERM-001",
      "TERM-007",
    ],
  },

  "sow-numbered.txt": {
    playbook: "sow",
    findings: ["OBLI-005", "STRUCT-018"],
  },

  "offer-letter-equity.txt": {
    playbook: "offer-letter",
    findings: ["CHOICE-006", "OBLI-005", "PERS-002"],
  },

  "privacy-notice-multistate.txt": {
    playbook: "privacy-notice-us",
    findings: [],
  },

  // The same company's notice as a startup actually writes it: no retention
  // periods, no rights section, no opt-out mechanism, "any other purpose we
  // consider appropriate". It routes to `privacy-policy-lint`, which is by
  // design — the other two families carry the disclosures themselves as
  // distinguishing phrases, so the policy that makes none of them lands here,
  // and the PNOT pack lists this family for exactly that reason. STRUCT-003
  // reported "No signature block detected" at CRITICAL until 9.364.0: nobody
  // signs a privacy policy, and both sibling families had always skipped it.
  "privacy-policy-thin.txt": {
    playbook: "privacy-policy-lint",
    findings: ["ADDENDA-020"],
  },

  "sublease-office.txt": {
    playbook: "sublease-agreement",
    findings: ["OBLI-005", "OBLI-006", "OBLI-008", "RISK-010", "RISK-011", "STRUCT-018"],
  },

  "mutual-nda-letter.txt": {
    playbook: "mutual-nda-deep",
    findings: ["NDA-D-001", "NDA-D-019", "NDA-D-022", "OBLI-005", "OBLI-008", "RISK-001"],
  },

  "escrow-agreement-indemnity.txt": {
    playbook: "escrow-agreement",
    findings: ["STRUCT-018", "OBLI-005", "RISK-006", "RISK-007", "TEMP-006"],
  },

  // An Idaho payment and performance bond. Three defects, two at `critical`.
  // CON-021's second pillar wanted "AIA A312", "Miller Act", or "Little
  // Miller" — a statutory bond cites the enacting state's code by section, and
  // "Little Miller Act" is a commentator's name for those statutes, not a
  // drafter's. CON-023 could not see the incorporation clause because a bond
  // puts it in the WHEREAS and the shared text helper strips recitals. And the
  // venue extractor could not read a state trial court named for its judicial
  // district ("the District Court of the Fourth Judicial District of the State
  // of Idaho, in and for Ada County") — the capture requires an uppercase
  // start, and that form puts a lowercase "the" there.
  "performance-bond.txt": {
    playbook: "payment-performance-bond",
    findings: ["OBLI-005"],
  },

  // A permanent utility easement. RE-028 reported the maintenance allocation
  // missing at `critical` on the section headed "Maintenance and Standard of
  // Work", because the object of an easement's maintenance covenant is
  // whatever the easement exists for — "Grantee shall maintain the FACILITIES
  // in good repair at its sole expense" — and the recognized objects were
  // "easement / premises / property / area / improvements / surface".
  "easement.txt": {
    playbook: "easement-agreement",
    findings: ["OBLI-005", "RISK-010", "RISK-011"],
  },

  // An Ohio exclusive-right-to-sell listing agreement with the protection
  // period, the agency and dual-agency disclosure, fair housing, the
  // negotiable-commission statement, and the MLS opt-out. Nothing was wrong.
  "listing-agreement-exclusive-right.txt": {
    playbook: "listing-agreement",
    findings: ["OBLI-005", "TEMP-006", "TEMP-007"],
  },

  // An ISO CG 20 10 additional-insured endorsement — the schedule, the
  // ongoing-operations grant, the completed-operations exclusions, primary
  // and non-contributory, and the excess clause.
  //
  // INS-012 is a KNOWN false accusation, filed as task_5a6a52d5 rather than
  // guessed at: it asks this endorsement to be a DIFFERENT endorsement. Its
  // own name says "(where required by contract)" and its description states a
  // condition, but it is an ungated presence check, so it fires on every
  // endorsement that is not itself a waiver of subrogation. Whether the
  // family reviews one endorsement or a package is a product decision.
  "insurance-endorsement-additional-insured.txt": {
    playbook: "insurance-endorsement",
    findings: ["INS-012"],
  },

  // An Ohio participating provider agreement — credentialing, prompt pay with
  // the ORC interest cite, the hold-harmless that survives insolvency, the
  // anti-gag clause, continuity of care, and a BAA by reference.
  //
  // TERM-002 reported no termination-for-cause clause on § 9: "Plan may
  // terminate immediately for Provider's loss of licensure, exclusion from a
  // federal health care program, or conduct posing an imminent risk to
  // Members." A regulated-services agreement names its grounds instead of
  // saying "material breach", and the branch that reads an enumeration wanted
  // a colon-introduced list. This one is inline, with commas and an "or".
  //
  // STRUCT-018 is correct: none of the three exhibits is attached, which is
  // what a specimen of a document that lives on its exhibits looks like.
  //
  // The draft originally left "Covered Services" undefined and STRUCT-006
  // said so. It is defined now, because the undefined version was carrying a
  // defect the document should not have: a real participating provider
  // agreement defines the term its every obligation turns on, and a specimen
  // is only worth what it tells you about a correct document.
  "payer-provider-participation.txt": {
    playbook: "payer-provider-agreement",
    findings: [
      "STRUCT-018",
      "CHOICE-003",
      "OBLI-005",
      "RISK-010",
      "TEMP-006",
      "TEMP-007",
      "TERM-001",
    ],
  },

  // A payment and performance bond from a surety to a school district. Two
  // defects, both about the oldest document shapes there are.
  //
  // CON-021 reported at `critical` that the bond does not say which kind of
  // bond it is — on a document headed PAYMENT AND PERFORMANCE BOND, with a
  // section headed Performance and a section headed Payment. The check
  // required a SECOND pillar: a statutory citation. A common-law bond, which
  // is what a school district takes from a general contractor, names no
  // statute at all because none compels it. The pillar never served the rule
  // either — its name, description, and recommendation are all about the
  // TYPE, and a rule whose own fix does not satisfy it is a broken rule.
  //
  // STRUCT-002 reported no effective date on a bond whose foot reads "SIGNED
  // AND SEALED this 2nd day of February, 2026". The formal-execution branch
  // read only "Dated this Nth day of", so every bond, deed, will, and
  // affidavit that dates itself in the oldest form there is fell through.
  //
  // CHOICE-001 and CHOICE-003 stay and are fair: the bond names Colorado law
  // only as a savings clause on the suit-limitation period, and a surety bond
  // that does not choose its law leaves the claimant to find out where.
  "payment-performance-bond.txt": {
    playbook: "payment-performance-bond",
    findings: ["CHOICE-001", "CHOICE-003", "OBLI-005"],
  },

  // Sweepstakes official rules with no-purchase-necessary, the free alternate
  // method of entry with equal chances, eligibility, the entry period with a
  // timekeeper, the prize ARV, odds, winner selection and notification, the
  // 1099, publicity consent, and the winner list. Nothing was wrong.
  // DARK-005 is correct and expected: § 10 waives class-wide relief, which is
  // lawful and near-universal in official rules, and a reader is entitled to
  // be told it is there.
  "sweepstakes-official-rules.txt": {
    playbook: "sweepstakes-official-rules",
    findings: ["DARK-005"],
  },

  // A UK cookie notice with the category breakdown, a named-cookie table, the
  // legal basis for each category, reject-all as easy as accept-all,
  // withdrawal as easy as consent, the transfer mechanism, and the ICO. It
  // reports NOTHING, which is the point: `cookie-notice` was on the
  // bare-title worklist until 9.350.0, and this is the first document that
  // reaches it by opening with its own name.
  "cookie-notice-uk.txt": {
    playbook: "cookie-notice",
    findings: [],
  },

  // A US export control and sanctions policy — classification, restricted
  // party screening, deemed exports, embargoed destinations, antiboycott,
  // recordkeeping, training, and an anonymous reporting line. Two defects.
  //
  // POL-117 reported no red-flag escalation and no voluntary disclosure, on a
  // policy that stops the transaction on a screening hit until Trade
  // Compliance clears it in writing, requires suspected violations to be
  // reported, and self-discloses. "Red flag" is BIS's term of art and the
  // rule required the NAME; this policy described the MECHANISM.
  //
  // STRUCT-006 reported "Trade Compliance" as a term the policy forgot to
  // define, in the paragraph telling employees to call them. Every policy
  // names the team that administers it and none defines its own org chart.
  "export-control-policy-itar.txt": {
    playbook: "export-control-policy",
    findings: [],
  },

  // A US employee handbook with the at-will disclaimer, EEO, anti-harassment,
  // meal and rest periods, overtime, PTO and sick leave, and a signed
  // acknowledgment page. EMP-050 reported at `critical` that it had no
  // acknowledgment-of-receipt page, on a document whose closing section is
  // headed ACKNOWLEDGMENT and reads "I have received the Employee Handbook."
  //
  // Three patterns and none of them read it. Two wanted the word
  // "acknowledge", which does not match "ACKNOWLEDGMENT" — the literal has an
  // "e" the inflection does not. The third wanted "receipt of this handbook",
  // and this handbook puts the acknowledgment in the HEADING and the receipt
  // in the sentence below it, which is where a signature page puts them.
  //
  // DARK-001 is correct and expected: the Company does reserve the right to
  // change any policy, which is what makes a handbook not a contract, and an
  // employee is entitled to be told so.
  "employee-handbook-us.txt": {
    playbook: "employee-handbook",
    findings: ["DARK-001", "OBLI-005"],
  },

  // A trademark license with the full naked-licensing apparatus — quality
  // standards, sample approval, inspection rights, goodwill inuring to the
  // licensor, prescribed form of use, and a royalty audit. Nothing was wrong.
  // Every finding is a real gap in the document as written: "Net Sales" is
  // the royalty base and is genuinely never defined, "Territory" is defined
  // and then never used again, Schedule 1 is referenced and not attached, and
  // the indemnity is carved out of the cap.
  "trademark-license-food.txt": {
    playbook: "trademark-license",
    findings: [
      "RISK-015",
      "STRUCT-006",
      "STRUCT-018",
      "CHOICE-003",
      "OBLI-005",
      "RISK-003",
      "RISK-006",
      "RISK-007",
      "RISK-011",
      "STRUCT-005",
    ],
  },

  // A payment guaranty by an individual for a company's equipment financing.
  // Nothing was wrong. BNK-026 is correct — the guaranty has no reinstatement
  // clause, so a preference recovery would leave the lender unsecured — and
  // DARK-003 correctly reads § 9 as one-way fee-shifting, which it is.
  "guaranty-payment-individual.txt": {
    playbook: "guaranty",
    findings: ["BNK-026", "DARK-003", "OBLI-005"],
  },

  // A Texas general warranty deed with the habendum, the warranty clause, and
  // a notarial acknowledgment. Nothing was wrong. TEMP-002 is correct and
  // expected: the grantee trust is dated 2019 and the plat is older still,
  // which is what a conveyance's dated references look like.
  "tx-general-warranty-deed.txt": {
    playbook: "warranty-deed",
    findings: ["TEMP-002"],
  },

  // An action by written consent of a board, adopting an equity plan and
  // appointing an officer. STRUCT-006 reported "Written Consent" as a term
  // the document forgot to define — in a document titled ACTION BY WRITTEN
  // CONSENT OF THE BOARD OF DIRECTORS. A document's own name is established
  // by the line at the top of the page, and there is no drafting change that
  // answers the finding short of `this Written Consent (this "Written
  // Consent")`. Reading `sections[0].heading` was not enough: the ingest
  // gives an unstyled document the empty string, so the suppression had to
  // fall back to the opening line to reach any pasted document at all.
  //
  // STRUCT-018 is correct: Exhibit A is referenced and not attached.
  "board-written-consent.txt": {
    playbook: "written-consent",
    findings: ["STRUCT-018"],
  },

  // A first set of Rule 33 interrogatories. DISC-010 reported no definitions
  // and no relevant time period on a document with a DEFINITIONS AND
  // INSTRUCTIONS section that defines "You" and "Shipment" and bounds itself
  // "between January 1, 2024 and December 31, 2025". The pattern wanted the
  // words "time period", or "from <Month> <year>" with no day number — a
  // range nobody writes.
  "first-set-interrogatories.txt": {
    playbook: "interrogatories",
    findings: [],
  },

  // A SECOND tolling agreement, written after `bare-title-reach` opened forty
  // families to their own name. Two defects the first specimen did not carry:
  //
  //   - RISK-001 asked a tolling agreement for an indemnity. The document
  //     allocates no risk at all — it suspends a limitations period and says
  //     so — and `tolling-agreement` had no `rule_overrides` entry for it.
  //   - TERM-005 reported no effect-of-termination clause on "Either party
  //     may terminate the Tolling Period on thirty (30) days' written notice
  //     to the other, AFTER WHICH the limitations period resumes running."
  //     The object is a defined term rather than "this Agreement", and "after
  //     which" is not a termination trigger, so every branch missed it.
  //
  // OBLI-005 is correct: § 1 is a negative covenant, and it is the operative
  // provision of the document.
  "tolling-agreement-standstill.txt": {
    playbook: "tolling-agreement",
    findings: ["OBLI-005"],
  },

  // A litigation hold notice to three departments, with the preservation
  // scope, the suspension of auto-deletion, and a tracked acknowledgment.
  // Nothing was wrong: it routes to its own family at full confidence and the
  // one substantive finding — no privilege reminder — is a fair reading of a
  // notice that tells recipients what to keep and not what not to discuss.
  // It is here because `litigation-hold` was on the bare-title worklist, and
  // a family that could not be reached by its own name had never been shown
  // a document that opens with it.
  //
  // It did find one thing. `litigation-hold` listed "demand letter" as a
  // NEGATIVE feature, and a hold notice routinely says why the hold exists —
  // "Hallowell has received a demand letter from counsel for Vestry Partners
  // LP" — so the family docked itself 0.1 for the sentence that states its own
  // trigger. `self-penalizing-features` caught it the moment the specimen
  // landed.
  "litigation-hold-notice.txt": {
    playbook: "litigation-hold",
    findings: ["SET-030", "OBLI-005"],
  },

  // A tolling agreement suspending a limitations period pending settlement
  // talks. TERM-005 reported no effect-of-termination clause on "On
  // termination, the Tolling Period ENDS and any applicable limitations period
  // RESUMES running" — the plainest consequence there is, and one the
  // recognized-consequence list did not hold. TEMP-002 is correct and expected
  // here: the loss predates the agreement by 627 days, which is the reason a
  // tolling agreement exists.
  "tolling-agreement.txt": {
    playbook: "tolling-agreement",
    findings: ["TEMP-002"],
  },

  // A patent assignment for USPTO recordation. Two defects, both about a
  // conveyance's own vocabulary. IPDATA-001's assignment branch allowed one
  // adverb between "hereby" and "assigns", and a conveyance never uses one
  // verb — "hereby irrevocably SELLS, ASSIGNS, TRANSFERS, AND CONVEYS" — so a
  // document whose entire purpose is to allocate IP ownership was told it
  // allocates none. And `patent-assignment` listed "trademark" as a negative
  // feature, which is inside the name of the office every patent assignment
  // asks to record it: the United States Patent and Trademark Office. It
  // scored 0.4, lost to the general `ip-assignment`, and its five 35 U.S.C.
  // § 261 checks never ran.
  //
  // STRUCT-006 came off this row in 9.265.0. It was reporting the UNITED
  // STATES PATENT AND TRADEMARK OFFICE — the office this assignment exists to
  // be recorded with — as a term the assignment forgot to define. A phrase
  // whose lead word is a state has always been skipped; `PLACE_NAMES` holds
  // "United States" as two words, so only "United" was ever compared.
  "patent-assignment.txt": {
    playbook: "patent-assignment",
    findings: ["OBLI-005"],
  },

  // A subordination, non-disturbance and attornment agreement. RE-047 —
  // the N in SNDA — reported the non-disturbance covenant missing at
  // `critical` on the section headed "Non-Disturbance", because the covenant
  // is written actively and as an enumerated list ("Lender shall not (a) …,
  // (b) terminate or disturb Tenant's leasehold estate") and every branch
  // wanted the passive "shall not be disturbed". RE-051 missed the
  // no-prepayment covenant for the same reason, and again in the lender's
  // mirror of it ("bound by any rent … paid more than one month in advance").
  "snda.txt": { playbook: "snda", findings: ["OBLI-005"] },

  // A DGCL § 145 director indemnification agreement — the document every
  // VC-backed company signs once per director, and the family the catalog
  // did not have. It routed to `indemnification-agreement`, which is the
  // COMMERCIAL anti-indemnity family, and was asked to add a recital
  // identifying its construction indemnity Type (I / II / III). Nine of the
  // ten new checks are silent on it, which is what makes it the compliant
  // direction for the pack; RISK-016 is fair (the D&O covenant is pegged to
  // parity with other directors and states no dollar minimum).
  "do-indemnification.txt": {
    playbook: "director-indemnification-agreement",
    findings: ["OBLI-005", "RISK-016", "TEMP-006"],
  },

  // A restricted stock unit award agreement, under the same plan-header shape
  // as the option grant. `rsu-grant` was the third unilateral equity award
  // shipping with an empty `rule_overrides`. What is left is real: EQT-033 is
  // the § 83(b)-not-available recital an RSU agreement ought to carry, and the
  // stock-plan data-privacy consent names no regime and no retention period.
  "rsu-grant.txt": {
    playbook: "rsu-grant",
    findings: ["EQT-033", "IPDATA-005", "IPDATA-007", "OBLI-005"],
  },

  // A mutual release of claims. Its playbook's distinguishing phrases were
  // written in a register real releases do not use — "known and unknown" for
  // "known or unknown", "no admission of liability" for a section headed "No
  // Admission" — and its negative feature "demand" fires on the release's own
  // operative words, "claims, demands, causes of action". It scored 0.5,
  // lost the lexicographic tie to `mutual-nda-deep`, and collected ten
  // criticals about NDA provisions it is not supposed to have.
  "mutual-release.txt": { playbook: "mutual-release", findings: ["OBLI-005"] },

  // An Article 9 security agreement. Its playbook listed "promissory note"
  // and "loan agreement" as negative features — the instruments every
  // security agreement names in its first recital as the obligations it
  // secures.
  "security-agreement.txt": { playbook: "security-agreement", findings: ["OBLI-005"] },

  // A Wisconsin premarital agreement. Its playbook listed "during the
  // marriage" as a negative feature, which is what a premarital agreement is
  // about — it appears in every property, debt, and support section of one.
  // Penalized on its own subject matter it scored 0.4 and routed to
  // `family-msa`, a DIVORCE settlement, which reported at `critical` that it
  // stated no date of separation. Nobody is separating.
  "prenup.txt": {
    playbook: "prenuptial-agreement",
    findings: ["EST-060"],
  },

  // An employment offer letter, titled in its "Re:" line as an "Offer of
  // Employment" — the standard phrasing, and one the playbook's title
  // keywords did not include. PERS-005 read the incoming-obligations
  // representation ("you represent that you are not subject to any …
  // non-competition … agreement") as a non-compete clause present.
  "offer-letter.txt": {
    playbook: "offer-letter",
    findings: ["OBLI-003", "OBLI-005", "PERS-002", "STRUCT-006"],
  },

  // A statement of work issued under a named master agreement.
  "sow.txt": { playbook: "sow", findings: ["STRUCT-018", "OBLI-005"] },

  // A contractor-favorable construction subcontract.
  // STRUCT-006 came off this row in 9.257.0. The subcontract defines "Contract
  // Documents" by its COMPOSITION — "The Contract Documents consist of the
  // prime contract between Contractor and Owner, the drawings and
  // specifications listed in Exhibit B, and all addenda and change orders" —
  // in its scope-of-work article, where the unquoted definition matcher
  // deliberately does not run.
  "subcontract.txt": {
    playbook: "subcontractor-agreement",
    findings: [
      "IPDATA-001",
      "RISK-005",
      "RISK-015",
      "STRUCT-018",
      "TERM-002",
      "CHOICE-003",
      "FIN-006",
      "OBLI-002",
      "RISK-010",
      "RISK-011",
    ],
  },

  // A qualified domestic relations order, under a domestic-relations caption.
  // Its entry line is the bare "ENTERED:" every state-court order carries, and
  // its signature line is labeled by office alone — "______  Judge   Date" —
  // with no name to print until the bench signs it.
  "qdro.txt": { playbook: "qdro", findings: ["STRUCT-006"] },

  // Minutes of a board meeting: not a contract, no parties, and its only
  // cross-reference points into the company's bylaws.
  "minutes.txt": { playbook: "meeting-minutes", findings: ["STRUCT-018"] },

  // A § 83(b) election, whose statutory citation lives in an ALL-CAPS caption.
  "83b-election.txt": { playbook: "section-83b-election", findings: ["OBLI-005"] },

  // A commercial sublease conditioned on the master landlord's written
  // consent — the genitive reversed, the adjective inserted.
  "sublease.txt": {
    playbook: "sublease-agreement",
    // RISK-005 appeared in v9.348.0. A sublease is subordinate to the prime
    // lease for the SUBLANDLORD's obligations, and carries its own commercial
    // terms between sublandlord and subtenant — including, or not, a limitation
    // of liability. `lease-commercial-multitenant` keeps the same check.
    //
    // RISK-015 came off in 9.363.0 with the family override: a leasehold
    // indemnity is not capped, and `lease-assignment` — the nearest sibling —
    // has skipped the check since it was written.
    findings: ["RE-103", "RISK-005", "STRUCT-018", "OBLI-005", "OBLI-006", "RISK-010", "RISK-011"],
  },

  // Buyer-form purchase order terms: standing terms nobody signs and no two
  // parties execute, accepted by the supplier's performance.
  "po-terms.txt": {
    playbook: "purchase-order-terms",
    findings: [
      "RISK-004",
      "FIN-007",
      "OBLI-005",
      "OBLI-008",
      "RISK-007",
      "RISK-010",
      "RISK-013",
      "RISK-015",
      "TEMP-012",
      "TERM-001",
    ],
  },

  // A public website's terms of use: browsewrap assent in its first sentence,
  // a DMCA agent, and no subscription anywhere in it.
  "website-terms.txt": {
    playbook: "website-terms-of-use",
    findings: [
      "DARK-008",
      "DARK-009",
      "IPDATA-005",
      "IPDATA-010",
      "OBLI-005",
      "RISK-007",
      "RISK-011",
      "TEMP-006",
    ],
  },

  // A consumer SaaS terms of service, with a free trial, automatic renewal,
  // and a cancellation path. Its neighbour above shares the title register, so
  // the pair pins the boundary between the two families in both directions.
  "saas-tos.txt": {
    playbook: "saas-tos",
    findings: [
      "RISK-004",
      "IPDATA-005",
      "OBLI-005",
      "RISK-007",
      "TEMP-004",
      "TEMP-005",
      "TEMP-006",
      "TEMP-008",
    ],
  },

  // A combined advance directive: a health care agent in Part 1 and living-will
  // instructions in Part 2. Its own playbook listed "agent" and "power of
  // attorney" as NEGATIVE features, so it scored 0.5 and fell to
  // generic-fallback — none of the directive's checks ran on a directive.
  "advance-directive.txt": {
    playbook: "advance-directive",
    findings: ["EST-060", "STRUCT-006"],
  },

  // A bank forbearance agreement with a reaffirming guarantor and a release.
  // TEMP-002 came off in 9.360.0: the date it was reading is the Continuing
  // Guaranty's, recited alongside the loan agreement it forbears under.
  "forbearance.txt": {
    playbook: "forbearance-agreement",
    findings: ["CHOICE-008", "OBLI-005"],
  },

  // A consumer cardholder agreement, with a Schumer box and a governing-law
  // clause that names federal law before it names the state.
  "credit-card.txt": {
    playbook: "credit-card-agreement",
    findings: ["CHOICE-006", "CHOICE-008", "DARK-005", "OBLI-005", "STRUCT-006"],
  },

  // Sweepstakes official rules: published, unsigned, and addressed to a class
  // of entrants. Its playbook carried the policy skip profile, which never
  // needed STRUCT-003 — a policy carries a dated adoption recital and official
  // rules do not, so this drew a critical for having no signature block.
  "sweepstakes.txt": {
    playbook: "sweepstakes-official-rules",
    findings: ["OBLI-005", "OBLI-006", "STRUCT-006"],
  },

  // Developer-facing API terms. Its playbook listed the bare word "merger" as a
  // negative feature — the assignment clause every agreement carries — and its
  // total-liability cap names the agreement between the noun and the verb,
  // which is where RISK-015 stopped reading.
  "api-terms.txt": {
    playbook: "api-terms",
    findings: [
      "IPDATA-005",
      "OBLI-005",
      "RISK-007",
      "TEMP-006",
      "TEMP-008",
      "TERM-001",
      "TERM-006",
      "TERM-007",
    ],
  },

  // A general warranty deed, under the recorder's block every recorded
  // instrument opens on. The matcher read the title company's address as the
  // document's title: the commonest recorded instrument there is scored 0.2
  // and fell to generic-fallback, so not one deed check ran on it.
  "warranty-deed.txt": {
    playbook: "warranty-deed",
    findings: ["STRUCT-018", "TEMP-002"],
  },

  // A recorded declaration of covenants, conditions, and restrictions. Not a
  // bargain between two parties: the declarant subjects land to covenants that
  // bind whoever buys it. Its statutory citations are decimal-numbered and
  // come in pairs, which is where the external-citation run stopped reading.
  "ccrs.txt": { playbook: "ccrs", findings: ["OBLI-005", "TEMP-004", "TEMP-008"] },

  // A FAR/DFARS flowdown exhibit to a defense subcontract. An exhibit dropped
  // in on its own is one of the commonest things a reviewer uploads, and it
  // was reported for having no governing law, no venue, no IP allocation, no
  // indemnity, no liability cap, no termination clause, no parties, and no
  // signature block — every one of which lives in the subcontract it is
  // attached to. COMM-159 and COMM-162 are real gaps: this exhibit flows down
  // neither the termination-for-convenience clause nor a prompt-payment term.
  "far-flowdown.txt": {
    playbook: "far-subcontract-flowdown",
    findings: ["COMM-159", "COMM-162", "STRUCT-009"],
  },

  // A privilege log under a federal caption. Every entry names its author and
  // recipients, which is why STRUCT-006 has ten capitalized phrases to report:
  // half of them are people. The routing and the filing skip profile are what
  // this pins.
  "privilege-log.txt": { playbook: "privilege-log", findings: ["STRUCT-006"] },

  // A Form ADV Part 2A firm brochure. Its playbook carried the policy skip
  // profile, which never needed STRUCT-003 — a policy is adopted by a dated
  // board resolution and a brochure is simply filed, so a well-formed brochure
  // drew a critical for having no signature block. Seven sibling disclosure
  // filings had the same omission.
  "form-adv.txt": { playbook: "form-adv-brochure", findings: ["REG-040", "STRUCT-006"] },

  // A UCC-1 financing statement on the national form. The form states § 9-503
  // in its OWN words — "Do not omit, modify, or abbreviate any part of the
  // Debtor's name" above a box labeled "ORGANIZATION'S NAME" — which is not
  // the phrase BNK-045 was looking for. BNK-049 remains, at `info`: no UCC1
  // form has a box for the lapse date, and the § 9-515 calendar lives in the
  // filer's docketing system.
  "ucc-1.txt": {
    playbook: "ucc-1-financing-statement",
    findings: ["BNK-049", "STRUCT-006"],
  },

  // A HIPAA / state-law breach notification letter to one individual, written
  // to the five model headings every state attorney general recommends. The
  // playbook's vocabulary was entirely GDPR Article 33 ("nature of the
  // incident", "likely consequences", "72 hours"), so the commonest breach
  // document there is scored 0.1 and fell to generic-fallback.
  //
  // PRV-035 and PRV-040 are the family's TEMPLATE checks — a record count and
  // a state-AG notification threshold — and both are now gated off a letter
  // that names its addressee, because an issued notice has neither and is not
  // supposed to.
  "incident-notice.txt": { playbook: "incident-notification", findings: [] },

  // A gastroenterologist's employment agreement, with the Stark and
  // anti-kickback recitals a group practice writes. Its arbitration clause
  // names the seat in the bare locative — "before a single arbitrator in
  // Spokane County, Washington" — which is where the seat extractor stopped
  // reading, so CHOICE-006 reported "seat not specified" and CHOICE-003
  // reported no forum at all.
  // OBLI-002 came ONTO this row in 9.248.0. "To the fullest extent permitted
  // by law," was not a recognized fronted adverbial, so the obligor of the
  // clause read as part of the adverbial and matched no party; and a party
  // whose entity type is written "LLC"/"LLP" was found with no ROLE, which
  // is what an obligor is matched against. The asymmetry each of these
  // documents carries is real and was simply invisible.
  "physician-employment.txt": {
    playbook: "physician-employment-agreement",
    findings: [
      "DARK-002",
      "IPDATA-001",
      "PERS-005",
      "STRUCT-006",
      "TEMP-004",
      "TEMP-005",
      "TEMP-012",
      "CHOICE-006",
      "OBLI-002",
      "OBLI-005",
      "PERS-001",
      "PERS-002",
      "RISK-010",
      "TEMP-006",
      "TEMP-007",
      "TEMP-008",
      "TERM-001",
      "TERM-007",
    ],
  },

  // Banking-authority resolutions of a board, with a secretary's certificate.
  // GOV-106 — "Recitals establishing the purpose" — was reading a text the
  // default rule input strips every recital out of, so it reported none on a
  // document whose second paragraph is a whereas clause.
  "board-resolution.txt": { playbook: "board-resolution", findings: [] },

  // An internal litigation hold memorandum. Its title is in the "RE:" line at
  // the bottom of a TO/FROM/DATE/RE block, which plain-text ingest joins into
  // one paragraph beginning "TO:" — so the subject-line reader, anchored to
  // the start of the paragraph, never reached it. The notice scored 0.4 and
  // fell to generic-fallback. Its playbook also listed "release" as a negative
  // feature, which is what a hold says about itself ("until I notify you that
  // it has been released").
  "litigation-hold.txt": {
    playbook: "litigation-hold",
    findings: ["OBLI-005", "TEMP-002"],
  },

  // A California preliminary notice, carrying the statutory NOTICE TO PROPERTY
  // OWNER block verbatim. Its family's one matching phrase was written
  // "mechanic's lien", and California's statute spells it "mechanics lien" —
  // one of thirty catalog features whose apostrophe made them invisible.
  "lien-notice.txt": { playbook: "preliminary-lien-notice", findings: [] },

  // The SAME instrument under the name the other half of the country gives it.
  // Ohio, Michigan, Indiana, Missouri, and Nebraska call it a Notice of
  // Furnishing (R.C. § 1311.05); the family knew only California's names —
  // "preliminary notice", "20-day preliminary notice", "notice to owner" — and
  // spelled the lien "mechanic's" where those states write "mechanics'". A
  // textbook Ohio notice on the sender's letterhead fell to
  // `generic-fallback` at 0.4, so CON-113..117 never ran on it: with the
  // amount, the first-furnishing date, and the statutory legend removed, the
  // same document now draws the critical and the warning that are its point.
  "notice-of-furnishing.txt": { playbook: "preliminary-lien-notice", findings: [] },

  // California civil discovery, which is a different vocabulary from the FRCP
  // one the corpus was written in: a Demand for Inspection under Code Civ.
  // Proc. § 2031.010, not a Rule 34 request. Two gaps it found. DISC-003 could
  // not read a two-ended DATE RANGE as a bounded time period — "between
  // January 1, 2025 and June 30, 2025" satisfied neither pillar, so a demand
  // that bounds every category it propounds was told it bounded none. And the
  // cross-reference extractor's declared-code sibling guard was written for
  // Delaware: a plain integer, and the code named AFTER the section.
  // California numbers with a decimal and names the code first, so
  // "waives objections under section 2031.300" read as a broken reference to a
  // section no demand has.
  "demand-for-inspection.txt": { playbook: "document-requests", findings: [] },

  // A New York residential lease, drafted to the statutes it names: the
  // one-month deposit cap of GOL § 7-108, the fourteen-day itemized return,
  // the § 226-c renewal-notice ladder, the § 235-b warranty of habitability
  // that cannot be waived. It was asked for a LIMITATION OF LIABILITY — a
  // clause GOL § 5-321 makes VOID in a residential lease, so the finding was
  // not merely irrelevant but recommended an unenforceable term. RISK-005 is
  // now declined by the family, the way the same family already declines the
  // IP-ownership and personal-data checks.
  //
  // RISK-001 stays and is recorded rather than argued: a residential lease can
  // carry a tenant indemnity for the tenant's own negligence and many do, so
  // its absence is a fair thing to surface. STRUCT-018 is fair — the three
  // exhibits the lease names really are not attached. The two TERM findings
  // are fair on their face: this lease leaves termination to the RPAPL summary
  // proceeding rather than stating it.
  //
  // FIN-009 found the second defect. Its flat-fee recognizer was written for
  // an INVOICE — "% of the overdue / past-due / outstanding / unpaid amount" —
  // and a lease measures its late fee against the RENT. In New York that is
  // not a drafting choice: RPL § 238-a caps the fee at "the lesser of fifty
  // dollars or five percent of the monthly rent", so a lease drafted to the
  // statutory maximum was told its rate had no stated period, a note asking
  // the drafter to fix the one thing the statute fixed for them. It now reads
  // as the one-time charge it is.
  // An Illinois secured promissory note with a usury savings clause, an express
  // refusal of any confession of judgment, and no jury waiver — the two things
  // Illinois practice watches. Clean.
  "il-secured-promissory-note.txt": {
    playbook: "promissory-note",
    findings: ["FIN-009", "STRUCT-005"],
  },

  // A statement of work issued under a master services agreement, with
  // deliverables, acceptance, key personnel, client dependencies, and change
  // control. It is here as the OTHER side of the parent-agreement guard: the
  // MSA supplies its governing law, its liability cap, and its indemnity, and
  // this document correctly reports none of them missing.
  //
  // FIN-005 was the exception, and it is now the eighth rule to take that
  // guard: the SOW states its fee and its invoicing milestones and leaves "net
  // 45 from invoice date" to the MSA, and was reported as stating no payment
  // term at all.
  "sow-under-msa.txt": {
    playbook: "sow",
    findings: ["OBLI-005", "TEMP-002"],
  },

  // A field-heavy SaaS ORDER FORM under a master agreement — a header block of
  // colon-separated fields, three priced lines, and $940,800 of order value. It
  // drew twelve findings, one of them a `critical`, and five of those were
  // clauses of the MSA rather than of the order form: no indemnification, no
  // governing law, no IP ownership, no limitation of liability, no
  // effect-of-termination.
  //
  // The machinery for that already exists — `amendsParentAgreement` reads a
  // document issued under a named parent — and both halves of its pattern
  // missed this one. It wanted "governed by the TERMS OF", and the order form
  // says "This Order Form is GOVERNED BY THE MSA"; and it wanted a parent
  // ending in "Agreement", where this one is named by its acronym.
  // `PARENT_CONTROLS`, in the same file, already admitted "MSA" as a parent
  // noun.
  //
  // IPDATA-008 then read the residency commitment backwards. "Customer Data is
  // stored and processed in the United States ONLY" confines the location
  // rather than negating a verb, so the prohibition guard could not see it —
  // the confinement word comes after the location and no verb is negated
  // anywhere. That branch exists to catch an EU-perspective document, where
  // processing in the United States IS the transfer; read from a US order form
  // between two US companies it inverts the sentence.
  //
  // What remains is fair. TEMP-004 surfaces the auto-renewal, which is what a
  // reader wants surfaced even with the 5% uplift cap beside it, and the SLA
  // exhibit really is not attached.
  "saas-order-form-fields.txt": {
    playbook: "saas-customer",
    findings: ["IPDATA-007", "STRUCT-018", "TEMP-004", "IPDATA-004", "OBLI-005"],
  },

  // An ENGLISH mutual NDA between two English companies, drafted the way
  // English NDAs are. Five checks could not read it, three of them at
  // `critical`, and all five are one class:
  //
  // NDA-D-007 wanted "already known" or "prior to disclosure"; the exclusion is
  // written as availability BEFORE disclosure. NDA-D-008 wanted "third party";
  // English drafting says "a PERSON who is not under a confidentiality
  // obligation". NDA-D-017 and NDA-D-018 both wanted the PLURAL "laws of" —
  // and NDA-D-018's list of viable jurisdictions already names England, so the
  // most conventional English choice of law was reported both as absent and as
  // not viable, over one letter. NDA-D-012 wanted "solely for the purpose"; the
  // Purpose is defined by a parenthetical in the recitals and used as "except
  // for the Purpose".
  //
  // NDA-D-001 stays and is the jurisdiction question, not a defect in the rule:
  // the DTSA whistleblower-immunity notice is 18 U.S.C. § 1833(b), and two
  // English companies contracting under English law owe no such notice. It is
  // the same shape as MSA-030 on the English MSA, and is filed as its own
  // change. NDA-D-016 is the same in kind — an English court requires a
  // cross-undertaking in damages, not a bond.
  //
  // NDA-D-022 and NDA-D-023 are fair in any jurisdiction: the agreement carries
  // no authority representation and says nothing about assignment.
  "uk-mutual-nda.txt": {
    playbook: "mutual-nda-deep",
    findings: [
      "NDA-D-001",
      "NDA-D-016",
      "NDA-D-022",
      "NDA-D-023",
      "NDA-D-019",
      "OBLI-005",
      "RISK-001",
      "TERM-007",
    ],
  },

  // An English CONTRACT OF EMPLOYMENT — the section 1 particulars required by
  // the Employment Rights Act 1996, the Working Time Regulations opt-out, SSP,
  // garden leave, and covenants stated as no wider than reasonably necessary.
  //
  // Its forum clause was invisible. The chain from "jurisdiction of" to
  // "courts" admitted only court adjectives and court names, and outside the
  // United States the forum is a TRIBUNAL as often as a court — this one names
  // both, "the exclusive jurisdiction of the EMPLOYMENT TRIBUNALS AND COURTS of
  // England and Wales" — so the tribunal noun and its "and" broke it and the
  // contract was reported as stating no forum at all.
  //
  // OBLI-008 got its half right without help: it names the efforts standard as
  // "best endeavours", which is the English term, and asks for it to be
  // defined.
  //
  // The ROUTING is recorded rather than fixed, and it is the honest state of
  // the catalog: this is an at-will family applied to a jurisdiction that has
  // no at-will doctrine and a three-month statutory notice period. There is no
  // UK employment family, and `generic-fallback` would give the reader nothing
  // at all — every finding above is a generic one that holds in either
  // country. The jurisdiction-mismatch disclosure this wants is filed as its
  // own change; see the note on `uk-master-services-agreement.txt`.
  "uk-contract-of-employment.txt": {
    playbook: "employment-at-will-us",
    findings: [
      "IPDATA-001",
      "IPDATA-007",
      "RISK-001",
      "TERM-005",
      "OBLI-004",
      "OBLI-005",
      "OBLI-008",
      "PERS-002",
    ],
  },

  // An ENGLISH-law master services agreement, and the first document in the
  // corpus drafted in English rather than American conventions. The MSA pack
  // reads American drafting, and four of its checks could not read the same
  // clause said the other way:
  //
  // MSA-006 wanted "total liability … limited to" within eighty characters, and
  // English drafting enumerates the causes of action in between — "each party's
  // TOTAL LIABILITY in contract, tort (including negligence), breach of
  // statutory duty or otherwise arising under this Agreement IS LIMITED TO 125%
  // of the Charges" is a hundred and ten. It drew a `critical` for having no
  // cap. MSA-007 wanted carve-outs stated as exceptions to a ceiling; English
  // drafting states them BEFORE the cap as an unlimitable floor — "Nothing in
  // this Agreement limits or excludes … death or personal injury … fraud …".
  // MSA-016 wanted an "SLA"; the service levels are a SCHEDULE to this
  // agreement, not a separate one. MSA-011 wanted "Background IP"; the
  // allocation is made by vesting and retention, over "pre-existing materials".
  //
  // What remains is fair and is the real gap in the draft: it has no indemnity
  // at all, and no compliance-with-laws or non-infringement warranty. MSA-030
  // is recorded rather than argued — it asks an English-law agreement for a
  // UCC § 2-719 limited-remedy escape, which is a jurisdiction-scope question
  // for the pack rather than a defect in this rule.
  "uk-master-services-agreement.txt": {
    playbook: "msa-vendor-deep",
    findings: [
      "MSA-001",
      "MSA-002",
      "MSA-004",
      "MSA-013",
      "MSA-014",
      "RISK-001",
      "STRUCT-006",
      "STRUCT-018",
      "TEMP-012",
      "MSA-003",
      "MSA-020",
      "MSA-022",
      "MSA-023",
      "MSA-025",
      "MSA-028",
      "MSA-030",
      "OBLI-005",
      "STRUCT-005",
      "TERM-007",
    ],
  },

  // A Texas conditional waiver and release on progress payment, in the
  // statutory form: the notice block verbatim, the through-date, the sum, the
  // downstream-payment warranty, and retainage expressly excluded. Completely
  // clean, which for a statutory form is the answer that matters — this one is
  // in the corpus to keep it that way.
  //
  // Adding it made `self-penalizing-features` fire: the family declined
  // "subcontract", and every lien waiver names the claimant's SUBCONTRACTORS
  // in its downstream-payment warranty, which is the statutory form's own
  // language. The negative is narrowed to "this subcontract", which is a
  // subcontract AGREEMENT talking about itself and not a waiver listing who
  // must be paid.
  "tx-conditional-lien-waiver.txt": { playbook: "construction-lien-waiver", findings: [] },

  // A venture side letter granting information rights, pro rata rights, and a
  // board observer seat below the Major Investor thresholds. Short, which is
  // its own test: a one-page letter puts everything in the last three quarters
  // of the document and manufactures false misses in any position-dependent
  // rule.
  //
  // MNA-125 wanted a conflict clause — "in the event of any conflict … this
  // letter shall control" — and a side letter usually states its precedence
  // the other way, which this one does at both ends: "NOTWITHSTANDING ANYTHING
  // TO THE CONTRARY IN the Purchase Agreement or the IRA, the Company agrees
  // as follows", closed by "EXCEPT AS EXPRESSLY PROVIDED HERE, the Purchase
  // Agreement and the IRA REMAIN IN FULL FORCE AND EFFECT". Together those say
  // exactly what the check asks for, and it drew a `critical` for stating no
  // precedence at all.
  "vc-side-letter.txt": { playbook: "side-letter", findings: ["OBLI-005"] },

  // A five-year non-compete given by a founder selling all her equity, with the
  // consideration allocated to goodwill stated, the § 16601 sale-of-business
  // framing in terms, and independent counsel. That is a different legal regime
  // from a post-employment covenant, and § 16601 exists to say so.
  //
  // PERS-009 told it the non-solicit duration was "well beyond the consensus
  // 12-month bound" — a bound drawn from the post-employment authorities the
  // statute displaces. The guard for exactly this case already existed and was
  // PARAGRAPH-scoped, so it stood down on the non-COMPETE paragraph that
  // recites the purchased goodwill and not on the non-SOLICIT one three
  // paragraphs later. A well-drafted seller covenant states its character ONCE,
  // in a recital or a dedicated section, and its operative covenants do not
  // repeat it — so the test is now document-wide.
  //
  // PERS-005 and PERS-001/002 stay: surfacing the covenant and asking the
  // reader to check its scope is the point of reviewing this document.
  "ma-sale-of-goodwill-covenant.txt": {
    playbook: "ma-restrictive-covenant",
    // CHOICE-003 appeared in v9.348.0: the covenant names the Delaware Court of
    // Chancery as its venue, and `amendsParentAgreement` had been standing the
    // check down because the recitals mention the Purchase Agreement once.
    findings: ["PERS-005", "CHOICE-003", "OBLI-005", "PERS-001", "PERS-002"],
  },

  // A New York "good guy" guaranty of a retail lease — the commonest
  // commercial guaranty in the country, universal in New York retail leasing,
  // and one the catalog had never seen. It bounds the guarantor's exposure by
  // TIME rather than by amount: everything accruing "from the Commencement
  // Date THROUGH THE SURRENDER DATE, AND NOT THEREAFTER", with the surrender
  // date defined by ninety days' notice, a broom-clean vacatur, payment
  // through the date of surrender, and no other default.
  //
  // BNK-024 told it that it left the guaranty's scope ambiguous, which is the
  // one thing it does not do: the check wanted either the phrase "continuing
  // guaranty" or a dollar figure, and a good-guy guaranty carries neither
  // while stating its scope more precisely than a cap does.
  //
  // The family also asked a guaranty for an IP-ownership clause, a limitation
  // of liability, a termination-for-cause path, and an effect-of-termination
  // clause, while its closest sibling `promissory-note` — the other one-sided
  // payment instrument — declines all four.
  //
  // BNK-026 stays and is right: the draft has no reinstatement-on-avoidance
  // clause, so a preference payment clawed back from the landlord would not
  // revive the guaranty.
  "ny-good-guy-guaranty.txt": {
    playbook: "guaranty",
    findings: ["BNK-026", "STRUCT-006", "CHOICE-008", "OBLI-005"],
  },

  // A California separation agreement for an employee over 40: the full OWBPA
  // apparatus (written advice to consult counsel, twenty-one days to consider,
  // seven to revoke, not effective until the revocation period expires), the
  // Civil Code § 1542 waiver quoted verbatim, and the CCP § 1001 /
  // Gov. Code § 12964.5 carve-outs that keep the confidentiality and
  // non-disparagement clauses enforceable in California.
  //
  // EMP-022 — the § 626(f)(1)(D) consideration — missed it in BOTH of the ways
  // the document states it. The branch that reads the clause in terms offered
  // "the employee WOULD not otherwise" and "you ARE not otherwise" but not the
  // singular copula the phrase actually takes, "consideration to which the
  // Employee IS not otherwise entitled". And the structural branch, which
  // reads the earned wages being paid "whether or not the Employee signs", had
  // a window two characters short of the sentence a California agreement
  // writes — because Labor Code §§ 201 and 227.3 make it name the accrued
  // vacation as well as the wages.
  //
  // OBLI-002 is fair and worth leaving: the confidentiality obligation really
  // does run one way.
  "ca-separation-agreement.txt": {
    playbook: "separation-agreement",
    findings: ["CHOICE-003", "OBLI-002", "OBLI-005"],
  },

  // A California employment arbitration agreement drafted to Armendariz: a
  // mutual obligation with no carve-out for the claims the employer is likelier
  // to bring, a neutral arbitrator, adequate discovery, every remedy available
  // in court, a written award, the employer paying all costs unique to
  // arbitration, and the CCP §§ 1281.97 / 1281.98 late-payment waiver. Every
  // employment check passes, which is the direction that matters.
  //
  // STRUCT-006 is the one finding, and it is recorded rather than fixed. The
  // agreement defines Covered Claims in a section headed COVERED CLAIMS whose
  // first sentence restates the term and defines it with a copula — "Covered
  // Claims ARE all claims arising out of…" — which nothing in the definitions
  // extractor reads, so the singular "Covered Claim" is reported undefined.
  //
  // A recognizer for that shape was WRITTEN AND REVERTED, and the measurement
  // is here so it is not written again unchanged. Requiring the section heading
  // and the sentence subject to be the same phrase is not tight enough: it also
  // reads "FINAL PAYMENT. Final payment IS due thirty days after…" and
  // "BACKUPS. Backups ARE replicated hourly…" as definitions, which are
  // provisions about a topic and not definitions of a term. Two of the 269
  // specimens grew a spurious defined-term-never-used finding on the first try.
  // A version that works has to tell a definitional predicate from an operative
  // one, or gate on the term being used elsewhere in the document.
  "ca-employment-arbitration.txt": {
    playbook: "arbitration-agreement-employment",
    findings: ["STRUCT-006", "CHOICE-003", "CHOICE-006", "OBLI-005"],
  },

  // A Regulation A Tier 2 offering circular, with the Rule 251(d)(2)(i)(C)
  // investment limitation, the SEC legend verbatim, the Form 1-K / 1-SA / 1-U
  // ongoing-reporting undertaking, and the no-minimum / no-escrow disclosure
  // that is the real risk in a best-efforts Reg A deal.
  //
  // REG-034 told it that it followed none of the Form 1-A item structure, in a
  // document whose table of contents IS that structure in order. An offering
  // circular is Part II of Form 1-A and never says so on its face — the form
  // caption lives on the EDGAR wrapper, not in the document an investor
  // receives. What the circular does carry is the Regulation A vocabulary: the
  // OFFERING STATEMENT that gets qualified, the Form 1-K / 1-SA / 1-U reports,
  // and Part II's own item captions.
  //
  // What remains is fair, and OBLI-004 / OBLI-008 are the useful pair: the
  // offering is made on a "best efforts" basis and the standard is never
  // defined, which is exactly what a purchaser would want defined.
  "reg-a-plus-circular.txt": {
    playbook: "reg-a-plus-circular",
    findings: ["OBLI-004", "OBLI-008", "REG-040", "TEMP-002"],
  },

  // A standalone COMMERCIAL indemnity — a subcontractor indemnifying a
  // developer, with the comparative-fault limitation that keeps it inside Ohio
  // Rev. Code § 2305.31, additional-insured endorsements by ISO form number,
  // and a section headed NO CAP.
  //
  // The same run reported both "Indemnity cap stated" and "Indemnification
  // without aggregate cap". RISK-003's `limited to` branch carried no negation
  // guard, and the sentence it matched is "the indemnity is NOT LIMITED TO the
  // amount of insurance" — the opposite of a cap. Only the phrases that INVERT
  // under negation are now guarded; "shall NOT EXCEED" is a cap and keeps
  // matching, which the rule's tests assert.
  //
  // The family also had an EMPTY `rule_overrides` while all three of its
  // siblings — `director-indemnification-agreement`, `hold-harmless-agreement`,
  // `covenant-not-to-sue` — decline the same commercial checks. A pure
  // indemnity has no payment terms, no IP allocation, no limitation of
  // liability, and is not terminated for cause; it survives.
  //
  // `self-penalizing-features` then caught the third defect, which only became
  // visible once the family had a document: `indemnification-agreement` listed
  // "HOLD HARMLESS" as a NEGATIVE feature. That is one third of the standard
  // triad — "indemnify, defend, and hold harmless" — and appears in every
  // indemnity clause there is, so the family was penalizing its own document's
  // most characteristic phrase. The discriminator for
  // `hold-harmless-agreement` is its TITLE, not a phrase both families carry.
  //
  // RISK-015 stays ON deliberately: an uncapped indemnity is the substantive
  // point of reviewing one, and a negotiated commercial indemnity often IS
  // capped, so the check still discriminates. INS-017 is right — the procedure
  // gives notice, control, and settlement consent but no cooperation covenant.
  "commercial-indemnity-agreement.txt": {
    playbook: "indemnification-agreement",
    findings: ["INS-017", "RISK-015", "TEMP-012", "OBLI-002", "OBLI-005", "RISK-010", "TEMP-007"],
  },

  // A processor-to-SUB-PROCESSOR agreement under Article 28(4) — the downstream
  // half of a DPA, which answers two Article 28 questions differently from the
  // upstream half, and both answers were read as absences at `critical`.
  //
  // DPA-016's own description says the notification and objection right applies
  // "WHERE GENERAL AUTHORISATION IS USED". Art. 28(2) offers two options, and
  // a contract requiring PRIOR SPECIFIC WRITTEN AUTHORISATION for every
  // sub-processor has taken the stricter one — so the recommended fix would
  // have LOOSENED it.
  //
  // DPA-006 wants the obligations and rights of the controller, and a
  // sub-processing agreement states them BY REFERENCE, which is the mechanism
  // Art. 28(4) prescribes: the controller is not a party to that contract, and
  // its rights live in the one it did sign. Both suppressions are confined to
  // documents that carry the specific-authorisation option or cite Art. 28(4),
  // and the corpus's own controller-to-processor DPA still reports DPA-006.
  //
  // The rest are the draft's own: its Article 32 measures and its sub-processor
  // list live in schedules that are not attached (STRUCT-018 says so), and it
  // names no Article 27 representative and no DPO.
  "sub-processing-agreement.txt": {
    playbook: "dpa-processor-subprocessor",
    findings: [
      "DPA-018",
      "DPA-019",
      "DPA-020",
      "DPA-021",
      "DPA-022",
      "DPA-028",
      "DPA-030",
      "DPA-031",
      "DPA-040",
      "DPA-051",
      "DPA-052",
      "DPA-053",
      "DPA-054",
      "DPA-055",
      "IPDATA-001",
      "RISK-001",
      "RISK-005",
      "STRUCT-006",
      "STRUCT-018",
      "TERM-002",
      "TRANSFER-018",
      "TRANSFER-020",
      "CHOICE-003",
      "OBLI-005",
    ],
  },

  // An independent contractor agreement, drafted to the control factors the
  // classification tests turn on: the contractor sets her own hours and
  // methods, supplies her own equipment, bears profit and loss, holds herself
  // out to the public, and is free to work for competitors. `independent-
  // contractor` is a LAUNCH playbook and had never been run against a document
  // until now. Clean: every finding is about the draft's own allocation, not
  // about a clause the family cannot see.
  "independent-contractor.txt": {
    playbook: "independent-contractor",
    findings: [
      "RISK-015",
      "STRUCT-018",
      "OBLI-005",
      "RISK-003",
      "RISK-006",
      "RISK-007",
      "RISK-010",
      "RISK-011",
      "TEMP-006",
      "TERM-001",
    ],
  },

  // A marketing services agreement, with the media-rebate transparency and
  // principal-based-buying disclosure that is the live issue in agency
  // contracting, and the FTC Endorsement Guides monitoring obligation. Also
  // clean, and COMM-035 is the useful catch: the agreement gives an IP
  // INDEMNITY but no rights-CLEARANCE provision — who clears the music, the
  // stock imagery, and the talent releases — which is the classic agency gap
  // and is not answered by an indemnity after the fact.
  //
  // `specimen-routing-margin` caught the genus tie behind it: `msa-general`
  // matched the two-word "services agreement" inside "Marketing Services
  // Agreement" and tied at 1.2, so which family won was the alphabet. The
  // genus now declines the agency register — a media buy, an influencer,
  // campaign assets, a media rebate, the Endorsement Guides — none of which a
  // general master services agreement carries.
  "marketing-services-agreement.txt": {
    playbook: "marketing-services-agreement",
    findings: [
      "COMM-035",
      "STRUCT-018",
      "TEMP-004",
      "OBLI-005",
      "PERS-002",
      "RISK-003",
      "RISK-006",
      "RISK-007",
      "RISK-011",
      "TERM-001",
    ],
  },

  // A limited-scope engagement letter, drafted to Rule 1.2(c): two enumerated
  // lists of what the firm will and will not do, an express statement that the
  // client keeps every deadline outside the scope, and informed consent that
  // can be withdrawn. It drew a `critical` on each of the two things that make
  // it what it is.
  //
  // ENG-027 wanted "the LAWYER will perform"; the letter's two headings are
  // "WHAT WE WILL DO" and "WHAT WE WILL NOT DO", and the actor list held
  // lawyer / attorney / firm / client but not the first person every
  // engagement letter is written in.
  //
  // STRUCT-013 read the client's signature block as two unfilled template
  // placeholders. Two rules on one line over two captions on the next arrive,
  // once the ingest collapses the whitespace between the columns, as "Marcus
  // Ellery Doyle Date" — and every signature test there is anchored to the
  // WHOLE remainder, so the neighbouring column's caption spoiled all of them.
  // STRUCT-003 reads the same construct correctly, and its comments already
  // claimed the parity.
  //
  // ENG-030 stays: the letter is transactional and says nothing about
  // disclosing a limited-scope appearance to a court, which is a fair
  // checklist item even where no court is involved. CHOICE-006 is reading the
  // word "arbitration" inside the list of EXCLUDED matters in section 2(d).
  "limited-scope-representation.txt": {
    playbook: "limited-scope-representation",
    findings: ["CHOICE-001", "ENG-030", "CHOICE-003", "CHOICE-006", "OBLI-005", "STRUCT-004"],
  },

  // A private secondary — a former employee selling 250,000 shares of common
  // to a fund, with the company signing only for the ROFR waiver and the
  // transfer agent instruction. It routed to `stock-purchase-agreement`, the
  // M&A control acquisition, and drew four criticals about a reps-and-
  // warranties article, an MAE definition, a stockholder representative, and a
  // sandbagging clause. None of those belongs to a secondary, and the family
  // for it existed: its title list knew "stock transfer agreement" but not
  // "secondary transfer", which is what such an agreement is captioned.
  //
  // EQT-129, the single most important check on a secondary, then could not
  // read the clause it exists for. The big-boy acknowledgment is written "the
  // Company HAS PROVIDED NO INFORMATION … the Seller MAY POSSESS MATERIAL
  // NON-PUBLIC INFORMATION … NOT OBLIGED TO DISCLOSE … a MATERIAL INDUCEMENT",
  // and the rule wanted the negation before the verb and the word
  // "sophisticated".
  //
  // What stays is fair. EQT-130 is right that the agreement allocates taxes
  // without addressing 409A. STRUCT-018 is right that Exhibit A is not
  // attached.
  "secondary-stock-transfer.txt": {
    playbook: "secondary-stock-transfer",
    findings: ["EQT-130", "RISK-001", "STRUCT-006", "STRUCT-018", "CHOICE-003", "OBLI-005"],
  },

  // A lobbying and political contributions policy. It fell to
  // `generic-fallback` at 0.4 and then, once routed, drew a `critical` on each
  // of the two things it is entirely about.
  //
  // The family knew "political CONTRIBUTION policy" and the document is a
  // "political CONTRIBUTIONS policy" — the matcher tolerates an inflection on
  // a feature's LAST word ("conflicts of interest" finds "Conflicts of
  // Interest Policy") and not on an interior one, so the plural on the middle
  // word was fatal. It knew "lobbying policy" as an adjacent pair, and the
  // document's title separates them.
  //
  // POL-047 wanted the compound noun "pre-approval" or "prior approval"; a
  // policy writes the requirement as a verb phrase, "must be approved in
  // advance", and its whole section 7 was invisible. POL-048 wanted the
  // acronym "FECA" or the Act's full name; a policy that states the corporate
  // ban and cites "52 U.S.C. § 30118" for it has addressed the statute more
  // precisely than one that names it.
  "lobbying-policy.txt": { playbook: "lobbying-policy", findings: ["OBLI-005"] },

  // A properly executed EU SCC MODULE THREE (processor to processor): the
  // Decision's text adopted in full, the Clause 7 / 11 / 17 / 18 options
  // selected, and Annexes I, II, and III completed. It drew THIRTY-NINE
  // findings, EIGHTEEN of them critical.
  //
  // Most were the clauses the adopted text supplies, and the guard that exists
  // for exactly that — `adoptsStandardFormInFull` — missed them because the
  // adoption is written in TWO sentences, which is what reads well: one names
  // the form and adopts it, the next says it is unamended. Requiring all three
  // signals in ONE sentence saw neither. It now reads a sentence PAIR, and
  // "Module Three" counts as naming the form, because the modules exist only
  // inside the Decision.
  //
  // Four survived that fix, each the same shape — the rule reads the template's
  // PROSE and not the COMPLETED FORM. DPA-002 wanted "retention period FOR THE
  // PERSONAL DATA" where the annex is filled in as "Retention period: 90 days
  // from receipt". DPA-043 wanted "By:" where an SCC signs "/s/ …  Name: …
  // Title: …", which STRUCT-003 has read for a long time. DPA-044 wanted the
  // phrase "effective date" from a document that is "dated April 14, 2026" on
  // its face. DPA-046 wanted the PLURAL "laws of" where Clause 17's own
  // wording, and the selection made under it, is "the LAW of Ireland".
  //
  // The nine that remain are fair: no transfer impact assessment is referenced,
  // no Article 27 representative is named, and there is no separate notice
  // clause.
  "scc-module-3.txt": {
    playbook: "scc-module-3",
    findings: [
      "TRANSFER-019",
      "CHOICE-001",
      "DPA-030",
      "DPA-034",
      "DPA-051",
      "DPA-055",
      "STRUCT-007",
      "TRANSFER-018",
      "CHOICE-003",
    ],
  },

  // A D&O liability policy — Side A/B/C, a final-non-appealable-adjudication
  // conduct exclusion, full severability, order of payments, and a six-year
  // run-off. It found the enumeration guard blind in two ways at once.
  // CHOICE-006 already declines a definition that LISTS arbitration among the
  // forums, and this policy's list carries the ADJECTIVE modifying the sibling
  // noun — "a civil, criminal, administrative, regulatory, or ARBITRAL
  // PROCEEDING" — so the comma-adjacency both branches required is never
  // there. And the guard tested `enclosingSentence`, which treats a SEMICOLON
  // as a boundary; a multi-limb definition is semicolon-separated by
  // convention, so the window held the list limb without the "means" the guard
  // is anchored on.
  //
  // What stays is right. STRUCT-006 names "Defense Costs" and "Securities
  // Claim", which this draft uses in Title Case throughout and never defines.
  // STRUCT-003 is the position the corpus already takes on an insurance
  // document (see `insurance-policy-summary.txt`). TEMP-002 is accurate: the
  // prior-litigation date really is six years before the rest.
  "do-liability-policy.txt": {
    playbook: "do-policy",
    findings: ["STRUCT-003", "STRUCT-006", "OBLI-005", "RISK-007", "TEMP-002"],
  },

  // The RISK FACTORS section of an IPO prospectus — and the most severe
  // mis-routing this corpus has recorded. It went to `baa`, the HIPAA Business
  // Associate Agreement, and drew FORTY-EIGHT findings, SEVENTEEN of them
  // critical: no permitted-uses clause, no subcontractor flow-down, no
  // accounting of disclosures, no HHS books-and-records access. One risk factor
  // in the document mentions protected health information, a covered entity,
  // and a business associate, which is the BAA family's whole distinguishing
  // list — a document that TALKS ABOUT HIPAA is not a BAA, and the family now
  // declines the securities register it never carries.
  //
  // The family that should have taken it had no title keyword for its own
  // heading: `s-1-risk-factors` carried "risk factors" as a distinguishing
  // phrase and not as the title the section is actually given.
  //
  // REG-022 was the third defect. The noun phrase INVERTS, and the inverted
  // form is a statute's own wording — "a BREACH OF THE SECURITY OF our
  // systems" is how Cal. Civ. Code § 1798.82 and the state breach-notification
  // laws after it put it — so a risk factor written in that register carried
  // none of the forward-order spellings and was reported as absent.
  //
  // The three that remain are right: no Item 105 risk-factor summary, no PSLRA
  // safe-harbor cross-reference, and no climate risk factor.
  "s1-risk-factors.txt": {
    playbook: "s-1-risk-factors",
    findings: ["REG-017", "REG-021", "REG-023", "FIN-008", "OBLI-005", "REG-040"],
  },

  // A law firm's closing letter — the letter that ENDS a representation — and
  // the worst kind of mis-routing there is. It went to `engagement-letter` and
  // drew NINE findings, every one of them a clause an engagement letter has
  // and a closing letter must not: fee basis and rates, the retainer and where
  // it is held, billing frequency, future-conflict consent. The family for it
  // existed and lost the tie to the alphabet, because the letter's subject
  // line says "Closing OF Representation" and the family knew only "closing
  // letter", "termination of representation", and "disengagement letter". The
  // genus now declines the closing register it never carries.
  //
  // ENG-036 stays and is right: the letter says confidentiality survives but
  // never states the firm's post-engagement conflicts posture.
  "closing-of-representation.txt": {
    playbook: "termination-of-representation",
    findings: ["ENG-036"],
  },

  // A channel-partner referral agreement, with the Anti-Kickback and Stark
  // carve-out a health-care referral arrangement needs. Two of its three
  // criticals were the checks unable to read their own clauses. COMM-032 wanted
  // the word "tail", or "referral fee" within eighty characters of
  // "termination"; the tail is written as what the Company WILL PAY, dated by
  // when the referral was accepted — "the Company will pay fees earned on
  // Referrals accepted before termination". COMM-033 wanted "no representation
  // … product"; the restriction is stated as an absence of AUTHORITY, in the
  // same sentence that disclaims agency, and the noun is as often "claim".
  //
  // COMM-029 stays and is right — there is no non-circumvention clause.
  // IPDATA-001 and RISK-001 are fair on their face.
  "channel-referral-agreement.txt": {
    playbook: "channel-referral-agreement",
    findings: [
      "COMM-029",
      "IPDATA-001",
      "RISK-001",
      "TEMP-004",
      "OBLI-005",
      "RISK-006",
      "RISK-007",
      "TEMP-006",
      "TERM-001",
    ],
  },

  // An annual incentive plan with a funding threshold, a three-point payout
  // curve, documented Committee discretion, the § 409A short-term-deferral
  // intent, and a Rule 10D-1 clawback hook. Clean.
  "annual-incentive-plan.txt": { playbook: "bonus-plan", findings: ["OBLI-005"] },

  // Published loyalty-program terms, with the CCPA § 1798.125(b) financial-
  // incentive notice and its estimate of the value of the personal
  // information, which is the disclosure most programs omit. It found two
  // recognizers written for a NEGOTIATED contract rather than for published
  // terms. TERM-002 read "close THE account" and "close YOUR account" but not
  // "close AN account", which is how terms addressed to a class of members are
  // written — so a section 8 that is a for-cause termination clause was
  // reported as none, over the indefinite article. TERM-005 read "upon
  // termination of the program" but not "when the program ends", which says
  // the same thing with a verb.
  //
  // RISK-001 and RISK-005 stay and are fair: these terms really do carry
  // neither an indemnity nor a limitation of liability, and published consumer
  // terms usually carry both.
  "loyalty-program-terms.txt": {
    playbook: "loyalty-program-terms",
    findings: ["RISK-001", "RISK-005", "OBLI-005", "STRUCT-004"],
  },

  // Three more of the twenty-six families that had never been put through the
  // engine as a real document. Two came back clean, which is worth recording
  // as much as a defect is.
  //
  // A Model A (comprehensive) fiscal sponsorship agreement, with the variance
  // power Treas. Reg. § 1.170A-9(f)(11)(v)(B) requires, the § 170(c)(2)(B)
  // purpose limitation, and the transfer-to-a-qualified-successor clause. The
  // findings are the draft's own: it names a Project Director in Title Case
  // and never defines it, and it has no material-breach termination path
  // (section 9 terminates on notice or on a threat to exempt status).
  "fiscal-sponsorship.txt": {
    playbook: "fiscal-sponsorship-agreement",
    findings: ["FIN-005", "STRUCT-006", "TERM-002", "CHOICE-003", "OBLI-005"],
  },

  // A cohabitation agreement, drafted to the things that make one enforceable:
  // full disclosure by schedule, independent counsel or a knowing waiver of
  // it, voluntariness, a thirty-day consideration period, and an express
  // waiver of Marvin-style palimony claims. Clean on both findings — the two
  // schedules really are not attached, and the 1991 date really is far before
  // the others.
  "cohabitation-agreement.txt": {
    playbook: "cohabitation-agreement",
    findings: ["STRUCT-018", "TEMP-002"],
  },

  // A multi-state US privacy addendum covering CCPA/CPRA, VCDPA, CPA, CTDPA,
  // UCPA, TDPSA, OCPA, and DPDPA. Three criticals on the first draft, and two
  // of them were right — it had no duration-of-processing clause and no duty
  // of confidentiality on the processor's personnel, both of which the state
  // acts require by name. Adding them silenced both, which is the direction
  // that matters.
  //
  // USDPA-013 kept firing on a clause that answers it in terms: "The TYPES of
  // Personal Information Processed are patient name, date of birth, …". The
  // pattern carried `type` with no `s?` and no word boundary, so it matched
  // the first four letters of "types" and then required a space that was not
  // there. Its GDPR sibling had the identical hole and is fixed with it.
  "us-state-privacy-addendum.txt": {
    playbook: "dpa-multi-state-us",
    findings: ["STRUCT-018", "OBLI-005", "TERM-007"],
  },

  // A D&O indemnification agreement of the kind every venture-backed company
  // signs with each director: mandatory indemnification on success,
  // advancement within twenty days, Independent Counsel, a
  // clear-and-convincing burden on the Company, indemnitor-of-first-resort,
  // and six years of run-off insurance.
  //
  // GOV-142 told it that it carried no § 145(e) undertaking to repay. The
  // statute's own sentence is "an undertaking BY OR ON BEHALF OF SUCH DIRECTOR
  // OR OFFICER to repay", and a drafter who names the person writes "an
  // undertaking BY THE INDEMNITEE to repay" — both put an actor between the
  // noun and the verb, which neither branch allowed.
  //
  // `specimen-routing-margin` then caught the genus/species tie behind it:
  // `indemnification-agreement` — the COMMERCIAL indemnity, whose own register
  // is "additional insured", "waiver of subrogation", "duty to defend" — tied
  // the D&O family at 0.9 on the shared title, and which one won was the
  // alphabet. The genus now declines the corporate register it never carries.
  //
  // The rest are fair, and two of them are the point of the review. GOV-139 is
  // right: this draft grants indemnification to the fullest extent the DGCL
  // permits but never states the § 145(a) standard of conduct the grant is
  // measured against. GOV-148 is right: there is no notice, defense, or
  // settlement-consent procedure. RISK-016 notes that the insurance covenant
  // sets no coverage minimum, which is true. CHOICE-003 is fair — "may bring
  // suit in the Delaware Court of Chancery" is permissive, not a venue clause.
  "do-indemnification-agreement.txt": {
    playbook: "director-indemnification-agreement",
    findings: ["GOV-139", "GOV-148", "RISK-016", "CHOICE-003", "OBLI-005"],
  },

  // A Louisiana Act of Cash Sale — the deed used in every property transfer in
  // the state, and the sharpest test of whether the catalog knows more than one
  // jurisdiction's words. It scored 0.0 and reported "No parties identified".
  //
  // `warranty-deed` had never heard of it: Louisiana conveys by an act of sale
  // passed before a notary and two witnesses, not by a "warranty deed". And
  // the party extractor could not see either appearing party, because a human
  // being has no entity type for `PARTY_DECL` to key on and the role
  // parenthetical stands behind a clause of description — "THOMAS AURELIO
  // HARPER, a person of the full age of majority, domiciled in the Parish of
  // Orleans … (the 'Vendor')". STRUCT-006 then reported "Notary Public" as a
  // term the act forgot to define; the state defines it.
  //
  // RE-134 stays and is right: an act of sale made "with full warranty of
  // title" that excepts nothing warrants against every recorded servitude on
  // the parcel, which is exactly the exposure the check exists to name.
  "la-act-of-cash-sale.txt": { playbook: "warranty-deed", findings: ["RE-134"] },

  // An executive employment agreement drafted to the Illinois Freedom to Work
  // Act, 820 ILCS 90 — the fourteen-day review period, the written advice to
  // consult counsel, both earnings thresholds, the public-health-emergency
  // carve-out, the construction and CBA exclusions, garden-leave pay, and the
  // § 1060/2 invention carve-out. It drew two findings its own family cannot
  // answer.
  //
  // RISK-005 asked an employment agreement for a LIMITATION OF LIABILITY. No
  // employment agreement has one, and every other employment family in the
  // catalog already declines the check — `offer-letter`, `employee-handbook`,
  // `pip`, `arbitration-agreement-employment`, `internship-agreement`. The
  // at-will family was the only one keeping it. TERM-002 asked for a path to
  // terminate for MATERIAL BREACH from an agreement whose section 2 says
  // either party may end it at any time with or without cause: an at-will
  // right is strictly broader than a for-cause one, and the family is named
  // for it.
  //
  // What stays is fair. PERS-005/001/002 surface the covenant and its scope,
  // which is the point of reviewing this document at all. RISK-001 is recorded
  // rather than argued — `executive-employment` keeps it too. TERM-005 is a
  // real gap in the draft's own terms: its severance paragraph is written as a
  // condition ("if the Company ends employment without Cause") rather than as
  // an effect of termination.
  "il-employment-noncompete.txt": {
    playbook: "employment-at-will-us",
    findings: ["PERS-005", "RISK-001", "TERM-005", "OBLI-005", "PERS-001", "PERS-002"],
  },

  // A Texas One to Four Family Residential Contract — TREC's resale form, the
  // contract used in every Texas house sale, and a shape the catalog had never
  // seen. It fell to `generic-fallback` at 0.4: the family knew the CAR-style
  // names and not the form names half the country actually uses. Two more
  // defects behind that. The party extractor read no parties at all from a
  // numbered PARTIES paragraph, because `ONE_SIDED_ROLE` — the roles only one
  // party holds — was missing Seller, Buyer, Landlord, and Tenant, though a
  // seller is never also the buyer. And RE-139 wanted the NOUN "financing
  // contingency", which appears in no state's form: they all write the verb,
  // "this contract is contingent on Buyer obtaining a conventional loan".
  //
  // What stays is fair. CHOICE-001 and CHOICE-003: a TREC contract states no
  // governing law or venue, leaning on the property's situs. STRUCT-006:
  // "Option Fee" is used in Title Case and never formally defined.
  "tx-residential-contract.txt": {
    playbook: "residential-purchase-agreement",
    findings: ["CHOICE-001", "STRUCT-006", "CHOICE-003", "CHOICE-006", "FIN-006"],
  },

  "ny-residential-lease.txt": {
    playbook: "lease-residential-us",
    findings: [
      "RISK-001",
      "STRUCT-018",
      "TERM-002",
      "TERM-005",
      "CHOICE-003",
      "FIN-009",
      "OBLI-005",
    ],
  },

  // A telehealth consent, addressed to the patient as "you" throughout — which
  // is what HC-132 could not read. It required "in THE state where THE
  // PATIENT", and a patient-facing consent writes "only when you are
  // physically located in A state where the provider is licensed", so a
  // document whose Section 5 IS the licensure recital drew a critical for
  // having none.
  "telehealth-consent.txt": {
    playbook: "telehealth-consent",
    findings: ["OBLI-005", "STRUCT-006"],
  },

  // A first-party (d)(4)(A) supplemental needs trust with a Medicaid payback.
  // EST-408 wanted "shall not supplant" as three adjacent words; the recital a
  // real trust writes is "the Trustee shall not MAKE ANY DISTRIBUTION THAT
  // WOULD supplant, reduce, or replace any benefit", so a trust whose section
  // is headed "Supplemental, Not Substitute" drew a critical for having none.
  "snt.txt": {
    playbook: "special-needs-trust",
    findings: ["OBLI-005", "OBLI-006", "STRUCT-006", "STRUCT-018"],
  },

  // A master equipment lease under UCC Article 2A. It routed to `complaint` at
  // 0.6 — on "jurisdiction", "venue", and "jury", the three words of its own
  // governing-law section — and was told at critical that it has no caption,
  // no jurisdictional statement, no numbered paragraphs, and no demand for
  // relief. Two things did it: `equipment-lease` penalized its own fixture and
  // landlord-waiver vocabulary ("real property", "landlord"), and `complaint`
  // could not recognize a contract preamble.
  "equipment-lease.txt": {
    playbook: "equipment-lease",
    findings: [
      "CHOICE-008",
      "FIN-009",
      "OBLI-002",
      "OBLI-005",
      "RISK-005",
      "RISK-010",
      "RISK-011",
      "RISK-015",
      "TEMP-004",
      "TEMP-006",
      "TEMP-007",
      "TEMP-008",
      "TERM-007",
    ],
  },

  // A restaurant franchise agreement. Its Section 3 is a renewal OPTION the
  // franchisee exercises by notice, which TEMP-004 read as an auto-renewal;
  // and its dispute clause sends the parties to MEDIATION administered by the
  // American Arbitration Association, whose name CHOICE-006 read as an
  // arbitration clause with the seat unspecified.
  "franchise.txt": {
    playbook: "franchise-agreement",
    findings: [
      "OBLI-002",
      "OBLI-003",
      "OBLI-005",
      "PERS-001",
      "PERS-005",
      "RISK-005",
      "RISK-010",
      "STRUCT-006",
      "TERM-007",
    ],
  },

  // A senior/subordinated intercreditor agreement. Its Bankruptcy Code cites
  // carry a subsection — "Section 1111(b)(2) of the Bankruptcy Code", then a
  // bare "Section 1111(b)." as a later heading — and the corroborating
  // declaration records only "1111", so the bare heading missed the lookup and
  // read as a broken internal reference. FIN-005 stays: the document says
  // "fees" inside the definition of ANOTHER agreement's obligations, and an
  // intercreditor agreement states no payment term of its own.
  "intercreditor.txt": {
    playbook: "intercreditor-agreement",
    findings: ["FIN-005", "BNK-031", "CHOICE-008", "OBLI-005"],
  },

  // Colorado articles of organization, filed electronically. Its statutory
  // cites carry TWO hyphens ("Section 7-80-204 of the Colorado Limited
  // Liability Company Act") where the leading-suffix skip took one, and its
  // Title/Article citation ("C.R.S. Title 7, Article 80") read as a broken
  // internal reference to an "Article 80". GOV-105 wanted the word "organizer"
  // where Colorado's form says "the person forming the limited liability
  // company". STRUCT-006 remains: the organizer is named three times and a
  // person's name is not distinguishable in shape from a defined term.
  "articles-org.txt": { playbook: "articles-of-organization", findings: ["STRUCT-006"] },

  // An earnout agreement ancillary to a membership interest purchase. It says
  // so in the way every ancillary does — "capitalized terms used but not
  // defined in this Agreement have the meanings given in the Purchase
  // Agreement" — which none of the three parent-agreement tests could read, so
  // it was reported for having no IP allocation, no liability cap, no
  // termination-for-cause path, and no effect-of-termination clause. All four
  // live in the purchase agreement whose definitions it borrows.
  "earnout.txt": { playbook: "earnout-agreement", findings: ["MNA-066", "OBLI-005"] },

  // A nonprofit's photograph, video, and voice release. Its family knew only
  // the COMMERCIAL model-release register ("in all media now known or
  // hereafter devised"), so the commonest release there is scored 0.2 and fell
  // to generic-fallback. Its form fields — "Program: ______  Date of event:
  // ______" and a bare "______ Printed name" — were reported at critical as
  // unfilled template placeholders.
  "media-release.txt": { playbook: "media-release", findings: ["IPDATA-010", "OBLI-005"] },

  // A notification, recourse factoring facility. BNK-124 wanted "notify the
  // account debtor" without a determiner and "pay to the factor" with the
  // preposition; the clause writes "notify ANY account debtor of the
  // assignment" and "directing the account debtor to PAY FACTOR". TERM-005
  // could not read the active voice of release — "Factor shall release its
  // security interest and file a termination statement" — where its
  // consequence list held only the passive "is released". BNK-126 stays: the
  // facility states its fee schedule and no effective-APR equivalent, which is
  // the disclosure the rule is about.
  "factoring.txt": {
    playbook: "factoring-agreement",
    findings: [
      "BNK-126",
      "CHOICE-008",
      "OBLI-002",
      "OBLI-005",
      "OBLI-006",
      "RISK-002",
      "RISK-004",
      "RISK-007",
      "TEMP-004",
    ],
  },

  // A continuing guaranty set in CAPITALS from the caption to the signature,
  // as old-form guaranties, bonds, and powers of attorney are. It is the same
  // document as `guaranty.txt` in a different case, and it drew EIGHT extra
  // findings: the parenthetical-definition lead-in, the role-labeled party
  // pattern, the conformed "/s/", and the named-parent tests were all
  // case-sensitive, so an all-caps instrument registered no defined terms, no
  // parties, no signature, and no parent agreement.
  //
  // Capitalization is evidence only where the document offers case contrast.
  "allcaps-guaranty.txt": { playbook: "guaranty", findings: ["CHOICE-008", "OBLI-005"] },
  // A HIPAA business associate agreement supplementing a revenue-cycle
  // services agreement. Every § 164.504(e) element is present, and two of them
  // were reported missing anyway: BAA-038 read only "terminates WHEN all PHI
  // is destroyed" and not the same term stated from the other end ("continues
  // UNTIL … all PHI is returned or destroyed"), and BAA-012 read only "fails
  // to cure" and "cure is not feasible", not the thirty-day "has not cured …
  // or immediately if cure is not possible" that a BAA actually drafts.
  //
  // What remains is fair and is what a reviewer would raise: the BAA has no
  // workforce-training requirement (BAA-031), no sanctions policy (BAA-034),
  // no notices clause (BAA-040), no covered-entity audit right of its own —
  // § 8 gives access to the Secretary, not to the covered entity (BAA-026) —
  // and no indemnity, liability cap, or IP clause, because it leaves them to
  // the underlying agreement without saying so.
  // IPDATA-001, RISK-001, RISK-005 and CHOICE-003 came off this row in
  // 9.256.0. The BAA opens "It SUPPLEMENTS the Revenue Cycle Services
  // Agreement between the parties dated January 12, 2026", which is how every
  // HIPAA BAA, DPA and security addendum opens — and none of them allocates
  // intellectual property, caps liability, names an indemnity, or states a
  // venue, because all four live in the parent. `amendsParentAgreement` knew
  // the ratification and incorporation recitals and not this one.
  "baa.txt": {
    playbook: "baa",
    findings: [
      "BAA-026",
      "BAA-031",
      "BAA-034",
      "BAA-040",
      "STRUCT-006",
      "OBLI-005",
      "TEMP-006",
      "TEMP-007",
      "TERM-007",
    ],
  },
  // A GDPR Article 28 DPA between a German controller and an Irish processor.
  // It drew TWENTY CRITICAL findings, and seventeen of them were unanswerable.
  //
  // Ten were CCPA: the US-state ruleset was scoped to this family, whose own
  // name is "DPA — Controller to Processor (EU/UK)" and whose 55 rules all
  // cite the GDPR. Six more were the SCCs read CLAUSE BY CLAUSE, on a DPA that
  // incorporates them by reference — the commercial pattern — and so can never
  // contain Clause 1's text. The other three were the enumerated Article 28(3)
  // sentence ("the subject matter, duration, nature and purpose of the
  // processing") failing three rules that each demanded two of those nouns be
  // ADJACENT, and the possessive instruction form ("only on the Controller's
  // documented instructions") failing the rule that read only "instructions
  // from the Controller".
  //
  // DPA-006 stays and is fair: the DPA states the processor's obligations at
  // length and never states the controller's, which Article 28(3) requires.
  // So do the seven warnings for clauses it genuinely omits — records of
  // processing, the Article 27 representative, an effective date of its own, a
  // notices clause, a survival clause, onward transfer, and the adequacy
  // fallback — and the generic ones for the term, liability, and IP terms it
  // leaves to the Principal Agreement without saying so.
  // TERM-005 came off this row in 9.251.0. §11 DELETION OR RETURN is the
  // Article 28(3)(g) clause — "the Processor DELETES OR RETURNS all Personal
  // Data … after the END of the provision of services" — and the check read
  // neither the trigger noun "end" nor the third-person "deletes"/"returns".
  "dpa-controller-processor.txt": {
    playbook: "dpa-controller-processor",
    // DPA-044 came off when the effective-date check stopped requiring the
    // phrase "effective date" from a document that carries its date on its
    // face (v9.326.0).
    findings: [
      "DPA-006",
      "DPA-028",
      "DPA-030",
      "DPA-051",
      "DPA-052",
      "DPA-054",
      "DPA-055",
      "IPDATA-001",
      "RISK-001",
      "RISK-005",
      "STRUCT-006",
      "TERM-002",
      "TRANSFER-018",
      "TRANSFER-020",
      "CHOICE-003",
    ],
  },
  // A prime/subcontractor teaming agreement for a federal procurement. It
  // routed to `eula`, at 0.6, on "license to use", "non-exclusive", and
  // "software" — while the family named for it, matching its title exactly,
  // scored 0.3 and never reached the 0.5 threshold. Its six distinguishing
  // phrases were unreachable: four carried a leading "the" or were whole
  // sentence fragments ("if the prime is awarded"), and none appears in a
  // teaming agreement as anyone drafts one.
  //
  // The findings are the negotiation points a reviewer would flag: indemnity
  // and confidentiality are carved out of a $50,000 cap (RISK-004, RISK-015),
  // Exhibit A is referenced but not attached (STRUCT-018), and the survival
  // list omits one sticky obligation (TEMP-012).
  "teaming-agreement.txt": {
    playbook: "teaming-agreement",
    findings: [
      "RISK-004",
      "STRUCT-018",
      "TEMP-012",
      "CHOICE-006",
      "OBLI-005",
      "OBLI-008",
      "RISK-007",
      "TEMP-006",
      "TEMP-007",
    ],
  },
  // A corporate acceptable-use policy. STRUCT-003 already knows a policy is
  // ADOPTED rather than signed — but it read the adoption only as a sentence
  // ("Approved by the Board of Directors on August 15, 2026"), and a policy
  // states it as a LABELLED FIELD in its cover block ("Approved by: the
  // Information Security Steering Committee on December 18, 2025"). One colon
  // was the whole difference between a clean policy and a `critical` "no
  // signature block".
  //
  // POL-111 stays and is the finding this document most needs: a policy that
  // restricts what employees may say on company systems carries an NLRA § 7
  // savings clause, and this one does not.
  "acceptable-use-policy.txt": {
    playbook: "acceptable-use-policy",
    findings: ["POL-111", "IPDATA-007", "STRUCT-006", "IPDATA-004", "IPDATA-005", "OBLI-005"],
  },
  // A post-closing transition services agreement with a five-line Schedule A.
  // MNA-055 reported its scope schedule missing, at `critical`, because it
  // read "Schedule of Services" and "services schedule" but not the lettered
  // form every transaction document uses — "SCHEDULE A - SERVICES", and "each
  // Service described on Schedule A". The rule's own recommendation asks for
  // exactly what the document already had.
  "transition-services-agreement.txt": {
    playbook: "transition-services-agreement",
    findings: [
      "OBLI-005",
      "OBLI-008",
      "RISK-007",
      "STRUCT-009",
      "TEMP-006",
      "TEMP-007",
      "TERM-006",
    ],
  },
};

describe("hand-written specimens", () => {
  it("every specimen on disk has an expectation", () => {
    const onDisk = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(onDisk.length, "no specimens found — the path is wrong").toBeGreaterThan(5);
    expect(onDisk).toEqual(Object.keys(EXPECTED).sort());
  });

  it.each(Object.entries(EXPECTED))(
    "%s",
    async (name, expectation) => {
      const result = await analyzeText(readFileSync(join(DIR, name), "utf8"), name);
      expect(result.run.playbook_id, `routed to ${result.run.playbook_id}`).toBe(
        expectation.playbook,
      );
      // Routing correctly is not the same as routing SAFELY. A family that
      // wins by a hair is one negative feature away from falling below the
      // 0.5 threshold, and when that happens the document goes to
      // `generic-fallback` and NONE of the family's checks run — which is what
      // `covenant-not-to-sue` was doing, at 0.3, on a document titled COVENANT
      // NOT TO SUE. Every specimen clears 0.6 today; pinning the floor makes a
      // change that erodes a margin fail here rather than silently.
      expect(
        result.run.playbook_match_confidence,
        `${expectation.playbook} matched at ${result.run.playbook_match_confidence} — one feature from the 0.5 cliff`,
      ).toBeGreaterThanOrEqual(0.6);
      const ids = result.run.findings.map((f) => f.rule_id).sort();
      expect(ids).toEqual([...expectation.findings].sort());
    },
    120_000,
  );
});

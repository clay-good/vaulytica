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
    findings: ["RISK-015", "RISK-016", "OBLI-005", "RISK-010", "RISK-011", "RISK-013", "TEMP-002"],
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
  // ("Export Control and Trade Sanctions Compliance Policy"). Clean: the two
  // findings are STRUCT-006 on "Trade Compliance" (a department, the same
  // shape the employee handbook's "People Operations" carries) and OBLI-005's
  // tally of the two prohibitions.
  "export-control-policy.txt": {
    playbook: "export-control-policy",
    findings: ["OBLI-005", "STRUCT-006"],
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
  // `codicil`. TEMP-002 is fair: the will it amends is five years older. It
  // exposed STRUCT-007 reporting the WILL's articles as broken references —
  // "I revoke Article VII of my Will", and, in a sentence whose subject is the
  // will, "the tax-apportionment clause in Article VIII".
  "codicil.txt": {
    playbook: "codicil",
    findings: ["TEMP-002"],
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
  // draw, and the statement-and-dispute procedure. STRUCT-006 stays and is
  // fair: Sales Operations is named three times and introduced nowhere.
  "commission-plan.txt": {
    playbook: "commission-plan",
    findings: ["OBLI-005", "OBLI-006", "STRUCT-006"],
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
  "security-addendum.txt": {
    playbook: "vendor-security-addendum",
    findings: ["IPDATA-004", "OBLI-005", "TERM-007"],
  },
  // A general assignment and assumption of a transportation services contract.
  // It routed to `lease-assignment` at 0.9 and drew a `critical` about a
  // LANDLORD'S CONSENT: that family listed "assignor" and "assignee" as
  // distinguishing phrases — words in every assignment of anything — and
  // claimed the bare title keyword "assignment and assumption", which is the
  // other family's own name. MNA-108 then demanded a SCHEDULE of assigned
  // contracts, at `critical`, from a document that names the one contract it
  // assigns: the pattern read only the plural.
  "assignment-assumption.txt": {
    playbook: "assignment-and-assumption-agreement",
    findings: ["STRUCT-018", "OBLI-005", "RISK-011"],
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
  "ai-addendum.txt": {
    playbook: "ai-addendum",
    findings: ["ADDENDA-012", "ADDENDA-016", "RISK-015", "OBLI-005", "STRUCT-009"],
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
  // substantive sentence.
  "handbook.txt": { playbook: "employee-handbook", findings: ["STRUCT-006", "OBLI-005"] },

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
  "legend-nda.txt": {
    playbook: "mutual-nda",
    findings: ["RISK-005", "TERM-002", "TERM-005", "OBLI-005", "RISK-001", "RISK-014"],
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
    findings: ["DISC-010"],
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
  "joint-representation-waiver.txt": {
    playbook: "joint-representation-waiver",
    findings: ["CHOICE-001", "CHOICE-003", "STRUCT-004"],
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

  // A cross-border exclusive distribution agreement: an ICC seat stated in the
  // participle, and the GDPR cited by its regulation number.
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
      "OBLI-002",
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
      "RISK-015",
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
  "lease-assignment.txt": {
    playbook: "lease-assignment",
    findings: ["OBLI-005", "RE-060", "TEMP-002"],
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
  "side-letter.txt": {
    playbook: "side-letter",
    findings: ["FIN-007", "OBLI-005", "OBLI-008"],
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
  "patent-assignment.txt": {
    playbook: "patent-assignment",
    findings: ["OBLI-005", "STRUCT-006"],
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
    findings: ["OBLI-005", "OBLI-006", "RE-103", "RISK-010", "RISK-011", "RISK-015", "STRUCT-018"],
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
      "RISK-015",
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
  "forbearance.txt": {
    playbook: "forbearance-agreement",
    findings: ["CHOICE-008", "OBLI-005", "TEMP-002"],
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
      "RISK-015",
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
    findings: [
      "DPA-006",
      "DPA-028",
      "DPA-030",
      "DPA-044",
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
      "RISK-015",
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

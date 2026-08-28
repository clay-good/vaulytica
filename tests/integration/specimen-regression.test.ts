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

  // An employee handbook: a policy nobody signs, which says so in its first
  // substantive sentence.
  "handbook.txt": { playbook: "employee-handbook", findings: ["STRUCT-006", "OBLI-005"] },

  // A union collective bargaining agreement, with arabic-numbered articles.
  "cba.txt": {
    playbook: "union-cba",
    findings: [
      "RISK-015",
      "STRUCT-006",
      "STRUCT-016",
      "STRUCT-018",
      "CHOICE-006",
      "OBLI-005",
      "RISK-011",
    ],
  },

  // A clinical trial agreement: a payment term behind a hyphenated qualifier,
  // and a survival clause that names its sections by number.
  "cta.txt": {
    playbook: "clinical-trial-agreement",
    findings: [
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-016",
      "STRUCT-018",
      "OBLI-005",
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
    findings: ["DISC-018", "DISC-019", "DISC-020", "STRUCT-006"],
  },

  // A third amendment to an office lease: defines nothing, ratifies the rest.
  "lease-amendment.txt": {
    playbook: "lease-commercial-multitenant",
    findings: ["RISK-015", "STRUCT-016", "STRUCT-018", "OBLI-005", "RISK-011"],
  },

  // A mutual NDA stamped EXECUTION VERSION / CONFIDENTIAL above its title.
  "legend-nda.txt": {
    playbook: "mutual-nda",
    findings: ["RISK-005", "TERM-002", "TERM-005", "OBLI-005", "RISK-001", "RISK-014"],
  },

  // A medical director agreement drafted to the Stark and AKS personal-service
  // exceptions, with a three-year term.
  "medical-director.txt": {
    playbook: "medical-director-agreement",
    findings: [
      "IPDATA-001",
      "RISK-001",
      "RISK-005",
      "STRUCT-018",
      "TERM-002",
      "TERM-005",
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
      "IPDATA-001",
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
      "STRUCT-016",
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
  "eula.txt": {
    playbook: "eula",
    findings: ["ADDENDA-018", "OBLI-005", "RISK-007", "TERM-007"],
  },

  // A Delaware LLC operating agreement: a governance instrument, not a
  // commercial bargain.
  "operating-agreement.txt": {
    playbook: "operating-agreement-llc",
    findings: ["STRUCT-006", "STRUCT-018", "OBLI-005", "RISK-011", "RISK-015"],
  },

  // An executive employment agreement — 409A, 280G, Good Reason, and an
  // arbitration seat behind a named rule set.
  "executive-employment.txt": {
    playbook: "executive-employment",
    findings: [
      "EMP-007",
      "TERM-005",
      "CHOICE-006",
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
      "STRUCT-006",
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
    findings: ["STRUCT-006", "FIN-009", "STRUCT-005"],
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
    findings: ["STRUCT-006", "OBLI-005"],
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
    findings: ["OBLI-008", "STRUCT-006", "STRUCT-009", "STRUCT-014", "STRUCT-016", "STRUCT-018"],
  },

  // A DGCL § 141(f) unanimous written consent of the board. The playbook
  // listed "bylaws" as a negative feature — the recital every such consent
  // opens on ("pursuant to ... the Bylaws of the Corporation").
  "written-consent.txt": {
    playbook: "written-consent",
    findings: ["STRUCT-006", "STRUCT-016", "STRUCT-018"],
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
  "warn-notice.txt": { playbook: "warn-notice", findings: ["STRUCT-006", "TERM-006"] },

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
  "revocable-trust.txt": {
    playbook: "revocable-living-trust",
    findings: ["EST-060", "OBLI-005", "STRUCT-005", "STRUCT-006"],
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
    findings: ["OBLI-005", "STRUCT-016"],
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
    findings: ["OBLI-005", "SET-108", "STRUCT-006", "STRUCT-018"],
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
    findings: ["OBLI-005", "RISK-007", "STRUCT-006", "STRUCT-018", "TEMP-006", "TEMP-007"],
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
  "trademark-assignment.txt": { playbook: "trademark-assignment", findings: ["STRUCT-006"] },

  // An M&A indemnity escrow. Its playbook listed "stock purchase agreement"
  // as a negative feature — the agreement every escrow of this kind names in
  // its first recital as the one it secures — and RISK-002 reported the
  // indemnity asymmetric, which it is by design: a three-party escrow
  // indemnifies its agent one way and always has.
  "escrow-agreement.txt": {
    playbook: "escrow-agreement",
    findings: ["OBLI-005", "STRUCT-006", "STRUCT-018", "TEMP-006", "TEMP-007"],
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
    findings: ["OBLI-005", "STRUCT-006"],
  },

  // A permanent utility easement. RE-028 reported the maintenance allocation
  // missing at `critical` on the section headed "Maintenance and Standard of
  // Work", because the object of an easement's maintenance covenant is
  // whatever the easement exists for — "Grantee shall maintain the FACILITIES
  // in good repair at its sole expense" — and the recognized objects were
  // "easement / premises / property / area / improvements / surface".
  "easement.txt": {
    playbook: "easement-agreement",
    findings: ["OBLI-005", "RISK-010", "RISK-011", "STRUCT-006", "STRUCT-018"],
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
    findings: ["STRUCT-006", "TEMP-002"],
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
    findings: ["OBLI-005", "STRUCT-006", "STRUCT-018"],
  },

  // A subordination, non-disturbance and attornment agreement. RE-047 —
  // the N in SNDA — reported the non-disturbance covenant missing at
  // `critical` on the section headed "Non-Disturbance", because the covenant
  // is written actively and as an enumerated list ("Lender shall not (a) …,
  // (b) terminate or disturb Tenant's leasehold estate") and every branch
  // wanted the passive "shall not be disturbed". RE-051 missed the
  // no-prepayment covenant for the same reason, and again in the lender's
  // mirror of it ("bound by any rent … paid more than one month in advance").
  "snda.txt": { playbook: "snda", findings: ["OBLI-005", "STRUCT-006"] },

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
    findings: ["EST-060", "STRUCT-006", "STRUCT-016", "STRUCT-018"],
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
  "sow.txt": { playbook: "sow", findings: ["STRUCT-016", "STRUCT-018", "OBLI-005"] },

  // A contractor-favorable construction subcontract.
  "subcontract.txt": {
    playbook: "subcontractor-agreement",
    findings: [
      "IPDATA-001",
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
      "STRUCT-016",
      "STRUCT-018",
      "TERM-002",
      "CHOICE-003",
      "FIN-006",
      "OBLI-002",
      "RISK-010",
      "RISK-011",
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
      const ids = result.run.findings.map((f) => f.rule_id).sort();
      expect(ids).toEqual([...expectation.findings].sort());
    },
    120_000,
  );
});

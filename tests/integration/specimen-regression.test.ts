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
    findings: ["RISK-015", "STRUCT-006", "STRUCT-018", "CHOICE-006", "OBLI-005", "RISK-011"],
  },

  // A clinical trial agreement: a payment term behind a hyphenated qualifier,
  // and a survival clause that names its sections by number.
  "cta.txt": {
    playbook: "clinical-trial-agreement",
    findings: ["RISK-005", "RISK-015", "STRUCT-006", "STRUCT-018", "OBLI-005", "TEMP-006"],
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
  "interrogatories.txt": {
    playbook: "interrogatories",
    findings: ["DISC-010", "STRUCT-005"],
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
    findings: ["STRUCT-006", "STRUCT-018", "OBLI-005", "RISK-011", "RISK-015"],
  },

  // An executive employment agreement — 409A, 280G, Good Reason, and an
  // arbitration seat behind a named rule set.
  "executive-employment.txt": {
    playbook: "executive-employment",
    // TERM-005 came off this row in 9.119.0: the agreement has a full
    // severance clause — "If the Company terminates Executive without Cause …
    // the Company shall pay Executive twelve (12) months of base salary" —
    // and was being told it does not state what happens on termination.
    findings: ["EMP-007", "CHOICE-006", "OBLI-005", "PERS-002", "RISK-011", "RISK-015", "TEMP-008"],
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
    findings: ["EST-060", "OBLI-005", "STRUCT-005"],
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
  "hold-harmless.txt": {
    playbook: "hold-harmless-agreement",
    findings: ["OBLI-005", "RISK-010", "TEMP-006", "TEMP-007"],
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
  "subcontract.txt": {
    playbook: "subcontractor-agreement",
    findings: [
      "IPDATA-001",
      "RISK-005",
      "RISK-015",
      "STRUCT-006",
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
      "TEMP-007",
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
      "TEMP-007",
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
  "physician-employment.txt": {
    playbook: "physician-employment-agreement",
    findings: [
      "CHOICE-006",
      "DARK-002",
      "IPDATA-001",
      "OBLI-005",
      "PERS-001",
      "PERS-002",
      "PERS-005",
      "RISK-010",
      "STRUCT-006",
      "TEMP-004",
      "TEMP-005",
      "TEMP-006",
      "TEMP-007",
      "TEMP-008",
      "TEMP-012",
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
      "IPDATA-001",
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
    findings: ["BNK-031", "CHOICE-008", "FIN-005", "OBLI-005"],
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
      "IPDATA-001",
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

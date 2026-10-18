/**
 * v7 — the startup advisor agreement (spec-v49.md §3).
 *
 * An advisor is paid in equity for a few hours a month. Five columns are
 * practice. The sixth has an authority: a stock option whose exercise price
 * can never be less than the stock's fair market value on the grant date is
 * not deferred compensation under section 409A, and the rule is written for a
 * "service provider", so it covers an advisor as it covers an employee
 * (Treas. Reg. § 1.409A-1(b)(5)(i)(A), read at ecfr.gov on 2026-10-10). The
 * check is gated on the grant being an option, and it reads only whether the
 * agreement prices the option at fair market value or under the company's
 * plan — not whether the price is in fact fair market value.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice, v4Cite } from "../v5/_helpers.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";

const ADVISOR = pack("advisor-agreement", "equity", [
  {
    id: "ADV-001",
    name: "The amount of equity",
    cite: practice("advisor-equity-amount", "a number of shares or a percentage"),
    pat: [
      /(?<!\d)(?<!\d,)\b\d[\d,]*\s+shares\b/i,
      /\b(options?|shares|restricted\s+stock|equity|warrants?)\b[^.]{0,160}?\d+(\.\d+)?\s?(%|percent)/i,
      /(?<!\d)\d+(\.\d+)?\s?(%|percent)\b[^.]{0,120}?\b(fully[-\s]diluted|outstanding\s+shares|capital\s+stock|equity)\b/i,
    ],
    why: "Equity is the advisor's pay. A promise of 'an equity grant' with no number of shares or percentage is a promise to agree later, and a percentage with no statement of what it is a percentage of is nearly as open.",
    fix: "State the grant as a number of shares, or as a percentage of the company's fully diluted capitalization on a named date, and say whether it is an option or restricted stock.",
  },
  {
    id: "ADV-002",
    name: "Vesting schedule and cliff",
    cite: practice("advisor-vesting", "how the equity is earned over time"),
    all: true,
    pat: [
      /\bvest\w*/i,
      new RegExp(
        String.raw`\b(cliff|monthly|quarterly|each\s+month|per\s+month|${PERIOD_COUNT}[-\s]+(month|year)s?)\b`,
        "i",
      ),
    ],
    why: "Advisor relationships often fade within a year. Vesting ties the equity to the time the advisor actually serves, and a cliff decides whether an advisor who leaves in the first months keeps anything.",
    fix: "State the vesting period and frequency — for example, monthly over two years — whether there is a cliff, and what happens to unvested equity when the relationship ends or the company is acquired.",
  },
  {
    id: "ADV-003",
    name: "Assignment of what the advisor creates",
    cite: practice(
      "advisor-ip-assignment",
      "the company owns ideas given in the course of advising",
    ),
    pat: [
      /\bassign\w*\b[^.]{0,200}?\b(inventions?|intellectual\s+property|work\s+product|ideas|right,?\s+title)\b/i,
      /\b(inventions?|intellectual\s+property|work\s+product|ideas)\b[^.]{0,200}?\b(assign\w*|(?:shall|will|must)\s+(be\s+)?(owned|belong))\b/i,
    ],
    why: "An advisor is not an employee, so nothing the advisor contributes belongs to the company unless the agreement assigns it. An investor's diligence will ask whether everyone who shaped the product has assigned their rights.",
    fix: "Add an assignment to the company of the inventions and work product the advisor creates in the course of the advisory services, limited to the company's business so that it does not reach the advisor's other work.",
  },
  {
    id: "ADV-004",
    name: "Confidentiality",
    cite: practice("advisor-confidentiality", "the advisor sees what outsiders do not"),
    pat: [/\bconfidential\w*/i, /\bnon-?disclosure\b/i, /\bproprietary\s+information\b/i],
    why: "An advisor is shown plans, numbers and technology that the company shows no one else outside it. The advisor usually signs no separate confidentiality agreement, so this one has to carry the obligation.",
    fix: "Add the advisor's agreement to keep the company's confidential information confidential and to use it only to advise the company.",
  },
  {
    id: "ADV-005",
    name: "No conflict with the advisor's other obligations",
    cite: practice("advisor-no-conflict", "an employer or another company may have a claim"),
    pat: [
      /\bconflict\w*\b/i,
      /\b(not|no)\b[^.]{0,80}?\b(breach|violat\w+)\b[^.]{0,160}?\b(other|another|employer|third\s+part\w+|prior)\b/i,
    ],
    why: "Most advisors have a day job, and many advise more than one company. If the advisor's employer has a claim on what the advisor invents, or the advisor is bound to a competitor, the company's title to the advisor's contributions is in doubt.",
    fix: "Have the advisor state that advising the company does not breach any agreement with an employer or anyone else, that the advisor will not use anyone else's confidential information, and that the advisor will tell the company if a conflict arises.",
  },
  {
    id: "ADV-006",
    name: "Option priced at fair market value, or under the company's plan",
    cite: v4Cite({
      id: "cfr-26-1-409a-1-b-5-i-a",
      source:
        "Treas. Reg. § 1.409A-1(b)(5)(i)(A) — a stock option is not deferred compensation where the exercise price may never be less than the fair market value of the stock on the grant date",
      source_url: "https://www.ecfr.gov/current/title-26/section-1.409A-1",
      retrieved_at: "2026-10-10T00:00:00Z",
    }),
    when: [/\boptions?\s+to\s+(purchase|acquire|buy)\b|\bstock\s+options?\b|\boption\s+grant\b/i],
    pat: [
      /\bfair\s+market\s+value\b/i,
      /\b(stock|equity|option|incentive)\s+((option|incentive)\s+)?plan\b/i,
    ],
    why: "An option granted to a service provider with an exercise price below the stock's fair market value on the grant date is deferred compensation under section 409A, which can tax the advisor as the option vests and add a penalty. An agreement that grants an option and says nothing about its price, or about the plan that sets it, leaves that open.",
    fix: "State that the option's exercise price per share will be no less than the fair market value of the common stock on the date of grant, as determined by the board, or that the option is granted under and governed by the company's equity incentive plan.",
  },
]);

export const ADVISOR_RULES: readonly Rule[] = ADVISOR;

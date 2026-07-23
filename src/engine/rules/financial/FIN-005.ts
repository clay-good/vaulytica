import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

const NUM_WORDS =
  "(?:\\d{1,3}|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|one\\s+hundred|hundred)";
// Capture the common formulations of payment terms. Each branch is
// anchored on a recognizable verb / noun phrase so we don't catch
// stray numbers. Real-world drafting we want to recognize:
//
//   - "Net 30"
//   - "payment is due within 30 days"
//   - "due within fifteen (15) days of the invoice date"
//   - "due and payable within 15 days of the invoice date"
//   - "payable within thirty (30) days"
//   - "invoices shall be paid within 30 days"
//   - "payment terms: 30 days"
const PAYMENT_TERMS = new RegExp(
  [
    `\\bNet\\s+\\d{1,3}\\b`,
    `\\bpayment\\s+terms?\\s*[:–-]\\s*${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*days?`,
    `\\b(?:payment|invoice|invoices|amount[s]?\\s+(?:due|owed)|fees?)\\s+[\\s\\w,]{0,40}?(?:is|are|shall\\s+be|must\\s+be|to\\s+be)?\\s*(?:due\\s+(?:and\\s+payable\\s+)?|payable\\s+|paid\\s+)within\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*days?`,
    `\\b(?:due\\s+(?:and\\s+payable\\s+)?|payable\\s+|paid\\s+)within\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*days?\\s+(?:of|from|after)\\s+(?:the\\s+)?(?:invoice|receipt)`,
    // Active voice — "Customer shall pay the fees … within 15 days of
    // invoice" — arguably the most common formulation; its absence made
    // the rule warn 'no payment-term clause' on a plainly stated term
    // (audit).
    `\\bshall\\s+pay\\b[\\s\\w,()$.]{0,80}?within\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*days?`,
    // A recurring charge states its term as a DUE DATE, not an interval from
    // an invoice: "Base Rent: $20,000 per month, payable in advance on the
    // first of each month" is a payment term, and every branch above is
    // invoice-shaped, so the rule reported none was stated.
    `\\b(?:due|payable|paid)\\s+(?:in\\s+advance\\s+)?on\\s+(?:or\\s+before\\s+)?the\\s+(?:first|1st|last|\\d{1,2}(?:st|nd|rd|th))\\s+(?:day\\s+)?of\\s+(?:each|every|the)\\b`,
    `\\b(?:due|payable|paid)\\s+(?:monthly|quarterly|annually|weekly|bi-?weekly|semi-?annually)\\b`,
    `\\b(?:monthly|quarterly|annually)\\s+in\\s+(?:advance|arrears)\\b`,
    `\\bdue\\s+upon\\s+receipt\\b`,
  ].join("|"),
  "i",
);
const ANY_PAYMENT = /\b(fee|payment|invoice|amount\s+due|payable)\b/i;

/** FIN-005 — Payment terms presence and parseability (warning). */
export const rule: Rule = {
  id: "FIN-005",
  version: "1.0.0",
  name: "Payment terms presence and parseability",
  category: "financial",
  default_severity: "warning",
  description: "Checks that a commercial contract has 'Net X' or equivalent payment-term language.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, PAYMENT_TERMS)) return null;
    if (!firstParagraphMatch(ctx, ANY_PAYMENT)) return null;
    return emit(ctx, rule, {
      title: "No payment-term clause detected",
      description: "The document references fees but no 'Net X' or 'due within' clause was found.",
      excerpt: "(no payment-term clause)",
      explanation:
        "Commercial contracts should state when payment is due. 'Net 30' or 'due within X days of invoice' is the typical formulation. Without it, payment timing defaults to the governing-law rule.",
      position: topPosition(ctx),
    });
  },
};

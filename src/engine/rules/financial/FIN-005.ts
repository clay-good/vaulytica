import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

// The hyphenated compound ("forty-five") comes FIRST: alternation is ordered,
// so listing the bare ten ("forty") before it would match only "forty" and
// strand "-five (45) days", making "due within forty-five (45) days" read as
// having no payment term (v1.4.2).
const NUM_WORDS =
  "(?:\\d{1,3}|(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)-(?:one|two|three|four|five|six|seven|eight|nine)|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|one\\s+hundred|hundred)";
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
//   - "payable no later than 15 days after the invoice date" — the "no
//     later than N days" window is as conventional as "within N days" but
//     the branches only led on "within", so a plainly stated term warned
//     'no payment-term clause' (v1.4.1).
//   - "payment terms: 30 days"
const PAYMENT_TERMS = new RegExp(
  [
    `\\bNet\\s+\\d{1,3}\\b`,
    `\\bpayment\\s+terms?\\s*[:–-]\\s*${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?`,
    `\\b(?:payment|invoice|invoices|amount[s]?\\s+(?:due|owed)|fees?|royalt(?:y|ies))\\s+[\\s\\w,%]{0,40}?(?:is|are|shall\\s+be|must\\s+be|to\\s+be)?\\s*(?:due\\s+(?:and\\s+payable\\s+)?|payable\\s+|paid\\s+|made\\s+)(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?`,
    `\\b(?:due\\s+(?:and\\s+payable\\s+)?|payable\\s+|paid\\s+)(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?\\s+(?:of|from|after)\\s+(?:the\\s+)?(?:invoice|receipt)`,
    // Active voice — "Customer shall pay the fees … within 15 days of
    // invoice" — arguably the most common formulation; its absence made
    // the rule warn 'no payment-term clause' on a plainly stated term
    // (audit). The window admits quote marks and runs to 160 chars: a
    // settlement's "shall pay Meridian the total sum of $425,000 (the
    // \"Settlement Payment\") by wire transfer to the trust account of
    // Meridian's counsel within thirty (30) days" names the amount as a
    // quoted defined term and routes the payment before stating the
    // deadline, and the old 80-char quote-free window never reached it.
    // The window's character class omitted the HYPHEN, and hyphenated words
    // are everywhere in the run-up to the deadline: "shall pay Institution in
    // accordance with the budget attached as Exhibit A, on a PER-SUBJECT basis
    // upon completion and monitoring of each visit, within forty-five (45)
    // days after receipt of a proper invoice" is a plainly stated payment
    // term, and one hyphen stopped the branch from reaching it.
    `\\bshall\\s+pay\\b[\\s\\w,()$."'“”’\\-/:;&%–—]{0,160}?(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?`,
    // A recurring charge states its term as a DUE DATE, not an interval from
    // an invoice: "Base Rent: $20,000 per month, payable in advance on the
    // first of each month" is a payment term, and every branch above is
    // invoice-shaped, so the rule reported none was stated.
    `\\b(?:due|payable|paid)\\s+(?:in\\s+(?:advance|arrears)\\s+)?on\\s+(?:or\\s+before\\s+)?the\\s+(?:first|1st|last|\\d{1,2}(?:st|nd|rd|th))\\s+(?:day\\s+)?of\\s+(?:each|every|the)\\b`,
    `\\b(?:due|payable|paid)\\s+(?:monthly|quarterly|annually|weekly|bi-?weekly|semi-?annually)\\b`,
    `\\b(?:monthly|quarterly|annually)\\s+in\\s+(?:advance|arrears)\\b`,
    // "payable on a monthly basis" — the cadence carries an "on a … basis"
    // wrapper the bare-cadence branch above does not reach.
    `\\b(?:due|payable|paid)\\s+on\\s+a\\s+(?:monthly|quarterly|weekly|annual|semi-?annual|bi-?weekly)\\s+basis\\b`,
    // "due and payable upon presentation of an invoice" is the same term as
    // "due upon receipt".
    `\\b(?:due|amounts?\\s+(?:are|is)\\s+due)\\s+(?:and\\s+payable\\s+)?upon\\s+(?:receipt|presentation)\\b`,
    // A SPELLED "Net" window — "payable net sixty (60) days" — that the
    // digits-only "Net 30" branch above never saw.
    `\\bnet\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\)\\s*)?days?\\b`,
    // Active voice with "remit" — "Customer will remit payment within fifteen
    // (15) business days" — a sibling of the "shall pay … within N days" branch.
    `\\b(?:remit|make)\\s+(?:payment|remittance)\\b[\\s\\w,()$."'“”’]{0,120}?(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?`,
    // "Payment shall be made within thirty days following the end of each
    // month" — a period-relative window the invoice-anchored branches missed.
    `\\b(?:payment|pay|paid|payable)\\b[\\s\\w,]{0,40}?(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?\\s+(?:following|after)\\s+(?:the\\s+end\\s+of\\s+)?(?:each|the|every)\\b`,
    // A purchase-price schedule is a payment term: "payable as follows:
    // (a) $41,000 … within three (3) business days …" / "payable in twelve
    // (12) equal monthly installments". Tight anchors only — FIN-005's
    // conservatism is load-bearing (see the rejected plural-money-word
    // broadening).
    // A promissory note's payment term is its maturity DATE, not an interval:
    // "due and payable on May 15, 2028" / "due and payable on the Maturity
    // Date". Every branch above is interval- or cadence-shaped, so a
    // perfectly conventional note was told it has no payment term.
    `\\b(?:due|payable|paid)\\s+(?:and\\s+payable\\s+)?on\\s+(?:or\\s+before\\s+)?(?:(?:January|February|March|April|May|June|July|August|September|October|November|December)\\s+\\d{1,2},?\\s+\\d{4}|the\\s+(?:Maturity|Effective|Closing)\\s+Date\\b|each\\s+anniversary\\b)`,
    // An M&A or real-estate purchase price states its term as the CLOSING
    // event, not an interval or a fixed date: "the Purchase Price … payable in
    // cash at the Closing", "the balance is due and payable at closing". The
    // Closing-Date branch above requires "on the Closing DATE"; the bare
    // event ("at the Closing") went unrecognized, warning a plain payment term.
    `\\b(?:due|payable|paid)\\s+(?:and\\s+payable\\s+)?(?:in\\s+cash\\s+)?(?:at|on)\\s+(?:the\\s+)?closing\\b`,
    // A retainer or deposit states its term as the SIGNING / EXECUTION of the
    // agreement — "the fee is due at signing", "payable upon execution of this
    // Agreement" — a sibling of the "at closing" branch above. "execution" is
    // scoped to the agreement itself ("of this Agreement" / "hereof") so a
    // milestone "due upon execution of Phase 1" is not read as a payment term.
    `\\b(?:due|payable|paid)\\s+(?:and\\s+payable\\s+)?(?:in\\s+cash\\s+)?(?:at|upon|on)\\s+(?:the\\s+)?(?:signing|execution\\s+(?:of\\s+this\\s+\\w+|hereof))\\b`,
    // The deadline FRONTED ahead of the verb — "Within ten (10) business days
    // after the Effective Date, Kanaan shall pay Pelagic $265,000" — is as
    // conventional as the trailing form, and every branch above reads left to
    // right from the verb, so a plainly stated payment term was reported as
    // none. Same window and same character class as the "shall pay … within"
    // branch, read the other way.
    `\\b(?:within|no\\s+later\\s+than)\\s+${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\))?\\s*(?:business\\s+|calendar\\s+)?days?\\b[\\s\\w,()$."'“”’\\-/:;&%–—]{0,160}?\\bshall\\s+(?:pay|remit)\\b`,
    `\\bpayable\\s+as\\s+follows\\b`,
    // The installment count is optional: a lease states "annual base rent …
    // payable in equal monthly installments" with no number, and that cadence
    // + "installments" is a payment term as much as "in twelve (12) … monthly
    // installments". A cadence word is still required, so this stays tight.
    `\\bpayable\\s+in\\s+(?:${NUM_WORDS}\\s*(?:\\(\\d{1,3}\\)\\s*)?)?(?:equal\\s+)?(?:monthly|quarterly|weekly|annual|semi-?annual)\\s+installments\\b`,
    // An employment agreement states its payment term as the payroll cadence:
    // "payable in accordance with the Company's regular payroll practices". The
    // salary / bonus / severance is paid on the normal payroll cycle, which is
    // this contract's when-payment-is-due. "payroll" is employment-specific, so
    // this only reduces false-absences and cannot fire in a commercial context;
    // "payroll taxes" / "payroll records" stay out (only cadence nouns listed).
    `\\bpayroll\\s+(?:practices?|schedule|cycle|dates?|periods?|procedures?)\\b`,
  ].join("|"),
  "i",
);
// The "does this document opine on payment at all" gate. The fee token is
// deliberately the SINGULAR `fee`, not `fees?`: widening it to the plural
// makes the gate match "reasonable attorneys' fees" in an indemnity clause,
// which fires "no payment-term clause" on BAAs and addenda that state no
// commercial payment term because they are not supposed to (the term lives in
// the master agreement). The singular form is the load-bearing conservatism.
const ANY_PAYMENT = /\b(fee|payment|invoice|amount\s+due|payable)\b/i;

/** FIN-005 — Payment terms presence and parseability (warning). */
export const rule: Rule = {
  id: "FIN-005",
  version: "1.8.0",
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

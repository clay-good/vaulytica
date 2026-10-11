/**
 * v7 — the training repayment ("stay-or-pay") agreement (spec-v49.md §3).
 *
 * No federal rule lists what a training repayment agreement must say, so the
 * six checks here are practice. The state that regulates the term itself is
 * California: Bus. & Prof. Code § 16608 makes most repayment-on-separation
 * terms unlawful in contracts entered into on or after January 1, 2027, and
 * its tuition exception names the same features these checks read for — a
 * stated amount no greater than the employer's cost, proration, no
 * acceleration, and no repayment on a termination without misconduct. It is
 * carried as a governing-law overlay (`trn-repayment-us-ca`), read at
 * leginfo.legislature.ca.gov on 2026-10-10, and appears only on a document
 * that names California law. `PERS-008` flags the clause wherever it appears.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice } from "../v5/_helpers.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

const SUM = String.raw`(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`;
const LEAVES = String.raw`(?:resign\w*|quits?|leav\w+|separat\w+|terminat\w+|departs?|ceases?\s+to\s+be\s+employed|ends?)`;
const REPAY = String.raw`(?:repa(?:y|ys|id|yment)|reimburs\w+|pay\s+back)`;

const TRAINING_REPAYMENT = pack("training-repayment-agreement", "employment", [
  {
    id: "TRA-001",
    name: "What triggers repayment",
    cite: practice("training-repayment-trigger", "the events on which the employee must repay"),
    pat: [
      new RegExp(String.raw`\b${LEAVES}\b[^.]{0,200}?\b${REPAY}\b`, "i"),
      new RegExp(
        String.raw`\b${REPAY}\b[^.]{0,200}?\b(if|upon|on|when|in\s+the\s+event)\b[^.]{0,120}?\b${LEAVES}\b`,
        "i",
      ),
    ],
    why: "The agreement is a promise to repay on a stated event. Which departures count — a resignation only, or any separation — and within what period decides whether the employee can ever be asked to pay.",
    fix: "State the events that require repayment, such as a voluntary resignation within a stated number of months after the training ends, and the events that do not.",
  },
  {
    id: "TRA-002",
    name: "The amount, and that it is no more than the employer's cost",
    cite: practice("training-repayment-amount", "a stated sum tied to what the training cost"),
    all: true,
    pat: [
      new RegExp(SUM, "i"),
      /\b(actual|out-of-pocket|direct)\s+costs?\b|\bcosts?\s+(to|paid\s+by|incurred\s+by|borne\s+by)\s+(the\s+)?(employer|company)\b|\b(not|never|no\s+event)\b[^.]{0,40}?\b(exceed|more\s+than|greater\s+than)\b/i,
    ],
    why: "An employee should know the most that can be owed before agreeing, and the figure should be what the employer actually paid a third party — not a rate that includes wages paid during training or a profit. A repayment sum above the employer's cost reads as a penalty for leaving.",
    fix: "State the repayment amount in dollars, and state that it does not exceed the employer's actual out-of-pocket cost of the training.",
  },
  {
    id: "TRA-003",
    name: "Proration over the commitment period",
    cite: practice("training-repayment-proration", "the amount falls as the employee stays"),
    pat: [
      /\bpro-?\s?rat\w+|\bproportion\w+/i,
      /\breduc\w+\b[^.]{0,120}?\b(each|every|per)\s+(full\s+)?(month|year|quarter)\b/i,
      /\b(1\/\d+|one-\w+)\b[^.]{0,60}?\b(each|every|per)\s+(full\s+)?(month|year)\b/i,
    ],
    why: "An employee who leaves in month 23 of a 24-month commitment has given the employer nearly all the service the training was meant to secure. Without proration the amount owed is the same as on day one.",
    fix: "Reduce the repayment amount in proportion to the part of the commitment period the employee has worked — for example, by one twenty-fourth for each full month.",
  },
  {
    id: "TRA-004",
    name: "How repayment is made after leaving",
    cite: practice("training-repayment-schedule", "installments, not the whole sum at once"),
    pat: [
      /\binstal?lments?\b|\bpayment\s+plan\b|\brepayment\s+schedule\b|\bmonthly\s+payments?\b/i,
      /\b(not|no|without)\b[^.]{0,40}?\baccelerat\w+/i,
    ],
    why: "A demand for the whole amount on the last day of work, or a clause that makes it all due at once, is the term that turns a reimbursement into a barrier to leaving. A schedule lets the employee repay from the next job's pay.",
    fix: "Let the employee repay in installments over a stated period after leaving, and state that the amount is not accelerated because the employment ended.",
  },
  {
    id: "TRA-005",
    name: "Whether repayment may be taken from pay",
    cite: practice(
      "training-repayment-deduction",
      "a deduction from wages needs its own authorization and its own limits",
    ),
    pat: [
      /\bdeduct\w*\b[^.]{0,200}?\b(wages?|pay(check)?|salary|compensation|final\s+pay)\b/i,
      /\b(wages?|pay(check)?|salary|final\s+pay)\b[^.]{0,200}?\bdeduct\w*\b/i,
    ],
    why: "Employers often collect by deducting from the final paycheck, and wage laws limit when and how much may be deducted. An agreement silent on deductions leaves the employee not knowing whether the last paycheck will arrive, and the employer without the written authorization most wage laws require.",
    fix: "Say whether any amount owed may be deducted from the employee's pay. If it may, have the employee authorize the deduction in writing and state that no deduction will reduce pay below the minimum wage or exceed what the law of the place of work allows.",
    sev: "info",
  },
  {
    id: "TRA-006",
    name: "No repayment when the employer ends the employment without misconduct",
    cite: practice("training-repayment-termination-carve-out", "a layoff is not a resignation"),
    pat: [
      /\b(no|not|nothing)\b[^.]{0,120}?\b(repa\w+|reimburs\w+|owe[sd]?|due)\b[^.]{0,240}?\b(terminat\w+|laid\s+off|lay-?off|dismiss\w+|eliminat\w+|reduction\s+in\s+force)\b/i,
      /\b(terminat\w+|laid\s+off|lay-?off|dismiss\w+|eliminat\w+|reduction\s+in\s+force)\b[^.]{0,240}?\b(no|not|nothing)\b[^.]{0,120}?\b(repa\w+|reimburs\w+|owe[sd]?|due)\b/i,
      /\b(repa\w+|reimburs\w+)\b[^.]{0,120}?\b(is|are|(?:shall|will|must)\s+be)\s+(waived|forgiven)\b/i,
    ],
    why: "The training was paid for on the expectation that the employee would stay. When the employer ends the employment for a reason other than the employee's misconduct, the employee did not break that expectation, and an agreement that still demands repayment charges the employee for the employer's decision.",
    fix: "State that nothing is owed if the employer ends the employment for any reason other than the employee's misconduct, including a layoff or the elimination of the position.",
  },
]);

export const TRAINING_REPAYMENT_RULES: readonly Rule[] = TRAINING_REPAYMENT;

/**
 * v7 — the merchant cash advance (spec-v49.md §3).
 *
 * A purchase of future receivables is commercial, so the consumer-credit rules
 * that ban a confession of judgment do not reach it (16 C.F.R. Part 444 is
 * consumer-only), and no federal rule lists what the contract must say. Every
 * check here is therefore cited as practice. The one state that regulates the
 * contract's own terms is Texas, and it is carried as a governing-law overlay
 * (`sbf-contract-terms-us-tx` in `src/dkb/state-overlays.ts`), so it appears
 * only on a document that names Texas law.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { languageRule, practice } from "../v5/_helpers.js";
import { COGNOVIT_DISCLAIMED, COGNOVIT_PATTERNS } from "../v4/banking/rules.js";

const PLAYBOOK = "merchant-cash-advance";
const C = "banking";

const CONFESSION = languageRule({
  id: "MCA-001",
  name: "Confession of judgment",
  category: C,
  description:
    "A confession of judgment lets the funder obtain a judgment against the merchant without notice or a hearing.",
  citation: practice(
    "mca-confession-of-judgment",
    "a confession of judgment in commercial financing (enforceability is set state by state)",
  ),
  playbooks: [PLAYBOOK],
  bad_patterns: [...COGNOVIT_PATTERNS],
  exclude_if: COGNOVIT_DISCLAIMED,
  bad_title: "Confession of judgment present",
  bad_description:
    "The agreement authorizes a judgment to be entered against the merchant without prior notice or a hearing.",
  explanation:
    "A confession of judgment gives up the merchant's right to notice and a hearing before a judgment is entered, and with it the chance to dispute the amount or raise a defense. Whether the clause can be enforced depends on the state: some void it in this kind of financing, some limit where and against whom it can be filed, and some allow it. This is a commercial transaction, so the federal consumer-credit ban does not apply.",
  recommendation:
    "Remove the confession of judgment. If the funder will not, find out before signing whether the governing state enforces one in this kind of financing, and limit it to a stated amount after a stated default.",
  default_severity: "warning",
});

const COLUMNS = pack(PLAYBOOK, C, [
  {
    id: "MCA-002",
    name: "Right to reconcile payments to actual receipts",
    cite: practice("mca-reconciliation", "adjusting a fixed payment to the agreed share of sales"),
    pat: [
      /\breconcil\w+/i,
      /\b(adjust\w*|true[-\s]?up)\b[^.]{0,160}?\b(actual|receipts|revenue|sales)\b/i,
    ],
    why: "The funder is buying a share of future sales, not lending a sum to be repaid on a schedule. Where the merchant pays a fixed daily or weekly amount, the right to have that amount adjusted to the agreed percentage of actual receipts is what keeps the payment tied to sales — and its absence is the term most often pointed to when an advance is argued to be a loan.",
    fix: "Add a reconciliation clause: on the merchant's request, with bank statements, the funder will adjust the payment to the agreed percentage of actual receipts within a stated number of days, and refund any excess collected.",
  },
  {
    id: "MCA-003",
    name: "The percentage of receipts purchased",
    cite: practice("mca-specified-percentage", "the share of sales the funder is buying"),
    pat: [
      /\b(specified|purchased|holdback|remittance|retrieval)\s+(percentage|rate)\b/i,
      /(?<!\d)\d+(\.\d+)?\s?(%|percent)\s+of\s+[\w\s'’]{0,60}?\b(receipts|receivables|revenues?|sales|deposits)\b/i,
    ],
    why: "The percentage of receipts is the price term of the deal: it sets how fast the purchased amount is delivered and is the figure a fixed payment is reconciled against. An agreement that states only a daily dollar amount has no share of sales to reconcile to.",
    fix: "State the percentage of the merchant's receipts that the funder is purchasing, and how any fixed payment was estimated from it.",
  },
  {
    id: "MCA-004",
    name: "What a personal guaranty covers",
    cite: practice("mca-guaranty-scope", "a guaranty of performance, not of the business's sales"),
    when: [/\bguarant(y|ee|ees|ies|or|ors)\b/i],
    pat: [
      /\bguarant\w+\b[\s\S]{0,300}?\b(performance|limited\s+to|only\s+(if|in\s+the\s+event|for|to\s+the\s+extent)|breach\s+of|representations|covenants|not\s+a\s+guarant\w+\s+of\s+(payment|collection))\b/i,
    ],
    why: "The funder takes the risk that the business's sales fall or the business fails. A personal guaranty limited to the merchant's performance — not diverting receipts, not misstating its finances — leaves that risk with the funder. An unconditional guaranty of payment moves it to the owner.",
    fix: "Limit the personal guaranty to the merchant's performance of its covenants and the truth of its statements, and say that the guarantor does not guarantee that the business will generate receipts.",
  },
  {
    id: "MCA-005",
    name: "Authorization to debit the merchant's account",
    cite: practice("mca-debit-authorization", "what may be debited, how often, and how it ends"),
    pat: [
      /\b(ACH|automatic(ally)?\s+debit\w*|electronic\s+debit\w*|debit\w*)\b[^.]{0,200}?\b(authori[sz]\w+|account)\b/i,
      /\bauthori[sz]\w+\b[^.]{0,200}?\b(ACH|debit\w*|withdraw\w*)\b/i,
    ],
    why: "The funder collects by debiting the merchant's bank account, usually every business day. The authorization should say what may be debited and how often, and what happens to it once the purchased amount has been delivered.",
    fix: "State the account, the amount or percentage and the frequency of each debit, and that the authorization ends when the purchased amount has been delivered.",
  },
]);

export const MERCHANT_CASH_ADVANCE_RULES: readonly Rule[] = [CONFESSION, ...COLUMNS];

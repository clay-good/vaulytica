import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * TEMP-003 — Deadline-to-term inconsistency (warning).
 *
 * Detection honesty (fix-rule-detection-fidelity): the original check
 * matched "term of N ..." and "N days notice" independently anywhere in
 * the document, so an ordinary month-to-month auto-renewing agreement
 * with a 60-day non-renewal notice was flagged "notice period exceeds
 * the contract term." Now: an auto-renewing term suppresses the rule
 * (the stated initial term is not the outer bound of the relationship),
 * a term/notice pair drawn from the same paragraph is preferred, and a
 * document-wide pairing — where the two numbers may belong to unrelated
 * clauses — fires at reduced (info) severity saying so.
 */

const TERM_RE = /\bterm\s+of\s+(\d{1,4})\s+(day|days|month|months|year|years)\b/i;
const NOTICE_RE = /\b(\d{1,3})\s+days?\s+(?:prior\s+)?(?:written\s+)?notice\b/i;
const AUTO_RENEW_RE =
  /\bauto(?:matic(?:ally)?)?[- ]?renew|\bsuccessive\s+(?:renewal\s+)?(?:terms?|periods?)\b|\brenews?\s+for\s+successive\b|\bmonth[- ]to[- ]month\b/i;

export const rule: Rule = {
  id: "TEMP-003",
  version: "1.1.0",
  name: "Deadline-to-term inconsistency",
  category: "temporal",
  default_severity: "warning",
  description:
    "Flags when a notice period exceeds the stated contract term; suppressed for auto-renewing terms, and downgraded to info when the term and notice come from different paragraphs.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const term = firstParagraphMatch(ctx, TERM_RE);
    if (!term) return null;
    // Auto-renewal in the term clause: the initial term is a billing /
    // renewal cadence, not the life of the contract, so a longer notice
    // (e.g. 60-day non-renewal notice on a month-to-month term) is
    // ordinary drafting, not an inconsistency.
    if (AUTO_RENEW_RE.test(term.text)) return null;

    const termDays = toDays(parseInt(term.match[1]!, 10), term.match[2]!);

    // Prefer a notice drawn from the SAME paragraph as the term — those
    // two numbers are actually talking about each other.
    const sameParaNotice = NOTICE_RE.exec(term.text);
    if (sameParaNotice) {
      const noticeDays = parseInt(sameParaNotice[1]!, 10);
      if (noticeDays <= termDays) return null;
      return emit(ctx, rule, {
        title: "Notice period exceeds the contract term",
        description: `Notice period ${noticeDays} days > term ${termDays} days (same clause).`,
        excerpt: sameParaNotice[0],
        explanation:
          "If the notice required to terminate is longer than the contract itself, the termination right is effectively unavailable.",
        position: term.position,
      });
    }

    // Document-wide fallback: the term and the notice come from different
    // paragraphs and may govern unrelated obligations — reduced confidence,
    // reduced severity.
    const notice = firstParagraphMatch(ctx, NOTICE_RE);
    if (!notice) return null;
    if (AUTO_RENEW_RE.test(notice.text)) return null;
    const noticeDays = parseInt(notice.match[1]!, 10);
    if (noticeDays <= termDays) return null;
    return emit(ctx, rule, {
      severity: "info",
      title: "Notice period may exceed the contract term",
      description: `A ${noticeDays}-day notice period appears elsewhere in the document than the ${termDays}-day term — the two may govern unrelated obligations, so verify they refer to the same relationship.`,
      excerpt: notice.match[0],
      explanation:
        "If the notice required to terminate is longer than the contract itself, the termination right is effectively unavailable. Because the term and the notice were found in different clauses, this is a lower-confidence signal: confirm both numbers describe the same obligation before acting.",
      position: notice.position,
    });
  },
};

function toDays(n: number, unit: string): number {
  const u = unit.toLowerCase();
  if (u.startsWith("day")) return n;
  if (u.startsWith("month")) return n * 30;
  if (u.startsWith("year")) return n * 365;
  return n;
}

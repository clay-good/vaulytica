/**
 * Three clauses worth naming on a document no type matched (spec-v50.md §11).
 *
 * The generic fallback ran no check that could see a confession of judgment,
 * an authorization to deduct from wages, or an acceleration clause: the rules
 * that know those clauses belong to the note, loan and employment types, and
 * they are ABSENCE checks there — "no acceleration clause" is a defect in a
 * promissory note and means nothing on an unrecognized document. So these are
 * separate notes, gated to the fallback alone, and they say only that the
 * clause is present and where. Whether it can be enforced varies by state and
 * by the kind of transaction, which an unmatched document has not told us.
 *
 * `info`, practice citations, and "this document" — never "this Agreement"
 * (`fallback-prose-neutrality.test.ts`).
 */

import type { Rule } from "../../finding.js";
import { languageRule, practice } from "../v5/_helpers.js";
import { COGNOVIT_DISCLAIMED, COGNOVIT_PATTERNS } from "../v4/banking/rules.js";

const PLAYBOOK = "generic-fallback";
const C = "risk-allocation";

export const FALLBACK_RULES: readonly Rule[] = [
  languageRule({
    id: "GEN-001",
    name: "Confession of judgment (unrecognized document)",
    category: C,
    description: "Names a confession of judgment in a document no type matched.",
    citation: practice(
      "fallback-confession-of-judgment",
      "a confession of judgment (enforceability is set state by state, and by the kind of transaction)",
    ),
    playbooks: [PLAYBOOK],
    bad_patterns: [...COGNOVIT_PATTERNS],
    exclude_if: COGNOVIT_DISCLAIMED,
    bad_title: "This document contains a confession of judgment",
    bad_description:
      "A clause authorizes a judgment to be entered against the signer without prior notice or a hearing.",
    explanation:
      "A confession of judgment gives up the signer's right to notice and a hearing before a judgment is entered. Whether it can be enforced depends on the state and on whether the transaction is a consumer or a commercial one, and this document was not recognized as any particular type.",
    recommendation:
      "Find out whether the governing state enforces a confession of judgment in this kind of transaction before signing, and ask for the clause to be removed.",
    default_severity: "info",
  }),
  languageRule({
    id: "GEN-002",
    name: "Authorization to deduct from wages (unrecognized document)",
    category: C,
    description: "Names an authorization to deduct from wages in a document no type matched.",
    citation: practice(
      "fallback-wage-deduction",
      "an authorization to deduct from wages (limited by state wage law)",
    ),
    playbooks: [PLAYBOOK],
    bad_patterns: [
      /\b(?:authori[sz]\w+|consents?\s+to|agrees?\s+(?:that|to))\b[^.]{0,200}?\bdeduct\w*\b[^.]{0,200}?\b(?:wages?|paychecks?|pay|salary|compensation)\b/i,
      /\bdeduct\w*\b[^.]{0,120}?\bfrom\b[^.]{0,60}?\b(?:final\s+)?(?:wages|paychecks?|salary)\b/i,
    ],
    exclude_if: [/\b(?:not|no|never)\b[^.]{0,60}?\bdeduct\w*\b/i],
    bad_title: "This document authorizes deductions from wages",
    bad_description: "A clause lets an amount owed be taken out of the signer's pay.",
    explanation:
      "Wage laws limit when an employer may deduct from pay, how much, and what written authorization it needs; some states prohibit a deduction that recovers a cost of doing business. Which rule applies depends on the state where the work is done.",
    recommendation:
      "Check the deduction against the wage law of the state where the work is done, including whether it could take pay below the minimum wage.",
    default_severity: "info",
  }),
  languageRule({
    id: "GEN-003",
    name: "Acceleration clause (unrecognized document)",
    category: C,
    description: "Names an acceleration clause in a document no type matched.",
    citation: practice(
      "fallback-acceleration",
      "a clause making the whole balance due at once on a stated event",
    ),
    playbooks: [PLAYBOOK],
    bad_patterns: [
      /\baccelerat(?:e|es|ed|ion)\b/i,
      /\b(?:entire|whole|full|unpaid|remaining|outstanding)\b[^.]{0,80}?\b(?:immediately\s+)?due\s+and\s+payable\b/i,
    ],
    exclude_if: [/\b(?:not|no|without|never)\b[^.]{0,40}?\baccelerat\w+/i],
    bad_title: "This document contains an acceleration clause",
    bad_description:
      "A clause makes the whole remaining amount due at once when a stated event occurs.",
    explanation:
      "An acceleration clause turns a missed payment, or another stated event, into a demand for everything still owed. The events that trigger it, and whether there is notice and a chance to cure first, decide how much it matters.",
    recommendation:
      "Read which events trigger acceleration, and ask for written notice and a period to cure before the balance can be called.",
    default_severity: "info",
  }),
];

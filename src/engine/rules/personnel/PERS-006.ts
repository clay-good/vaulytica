import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, excerptWindow, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * PERS-006 — Mandatory non-disparagement on separation (warning,
 * personnel).
 *
 * Surfaces non-disparagement clauses that bind a departing party
 * (Employee / Contractor / Consultant) without a corresponding
 * obligation on the company. The NLRB's *McLaren Macomb* decision
 * (Feb 2023) held that offering severance terms that broadly restrict
 * Section 7 rights violates NLRA § 8(a)(1); SEC Rule 21F-17 prohibits
 * any action, including enforcing or threatening to enforce a
 * confidentiality agreement, that impedes communicating with the SEC
 * about a possible securities violation. Silence on these carve-outs
 * is a real drafting risk for the employer.
 *
 * The rule fires on the presence of `non-disparagement` /
 * `disparage` language in a personnel context. Reviewers should
 * confirm carve-outs for (a) NLRA-protected speech, (b) SEC /
 * agency whistleblower reports, and (c) truthful testimony under
 * subpoena.
 */
export const rule: Rule = {
  id: "PERS-006",
  version: "1.2.0",
  name: "Non-disparagement clause present",
  category: "personnel",
  default_severity: "warning",
  description:
    "Surfaces non-disparagement language for review against McLaren Macomb (NLRB Feb 2023) and SEC Rule 21F-17 carve-out requirements.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // "disparage" is a distinctive word that appears almost only in this
      // clause; requiring a negation ("not"/"no"/"refrain from"/"prohibited
      // from") within a short window before the VERB / adjective form catches
      // the many verb forms the enumerated list missed — "will not disparage",
      // "refrain from disparaging", "make no disparaging statements",
      // "prohibited from disparaging". The verb branch matches only
      // disparage/disparages/disparaging (NOT the noun "disparagement"), so it
      // cannot span "does not include a non-disparagement obligation" and move
      // the match off the noun — that disclaimed form stays with the noun
      // branch, where the presence-disclaimer guard suppresses it.
      /\b(?:non|no)[-\s]?disparagement\b|\b(?:not|no|never|refrain\s+from|prohibited\s+from|cease\s+to)\b[^.]{0,24}?\bdisparag(?:e|es|ing)\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Non-disparagement clause present",
      description: hit.match[0],
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "A non-disparagement clause that binds an employee or contractor at separation is enforceable in most US jurisdictions, but the NLRB's McLaren Macomb decision (Feb 2023) held that offering severance terms that broadly restrict Section 7 rights violates NLRA § 8(a)(1); it remains Board law, though the General Counsel's 2023 enforcement guidance was rescinded in February 2025 (GC 25-05). SEC Rule 21F-17 separately prohibits any action, including enforcing or threatening to enforce a confidentiality agreement, that impedes communicating with the SEC about a possible securities violation. A non-disparagement provision without carve-outs for protected speech / agency reports / truthful testimony is increasingly indefensible.",
      recommendation:
        "Add explicit carve-outs for: (1) NLRA-protected concerted activity, (2) SEC, DOL, EEOC, or other agency whistleblower reports, (3) truthful testimony in legal proceedings, and (4) statements required by law. Consider also whether the clause should be bilateral.",
      position: hit.position,
    });
  },
};

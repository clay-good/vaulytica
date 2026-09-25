import type { Rule, RuleContext, Finding } from "../../finding.js";
import {
  emit,
  excerptWindow,
  firstParagraphMatch,
  isPresenceDisclaimed,
  matchedSentence,
} from "../_helpers.js";
import { fullText } from "../v4/_helpers.js";

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
/**
 * The four carve-outs the recommendation names, each read across the WHOLE
 * document — they usually sit in a separate "Protected Rights" section. The
 * explanation says a clause WITHOUT them is indefensible, so the rule has to
 * look: a clean severance agreement carving out NLRA Section 7 speech, beside
 * a section preserving EEOC, NLRB and SEC charges, was told to add both.
 */
const CARVE_OUTS: ReadonlyArray<{ key: string; re: RegExp; ask: string }> = [
  {
    key: "NLRA-protected activity",
    re: /\bNational\s+Labor\s+Relations\s+Act\b|\bNLRA\b|\bconcerted\s+activit/i,
    ask: "NLRA-protected concerted activity",
  },
  {
    key: "agency reports",
    re: /\bSecurities\s+and\s+Exchange\s+Commission\b|\bSEC\b|\bEqual\s+Employment\s+Opportunity\s+Commission\b|\bEEOC\b|\bNational\s+Labor\s+Relations\s+Board\b|\bNLRB\b|\bgovernment(?:al)?\s+agenc|\bwhistleblow/i,
    ask: "SEC, DOL, EEOC, or other agency whistleblower reports",
  },
  {
    key: "truthful testimony",
    re: /\btestif(?:y|ies|ying)\b|\btestimony\b|\bsubpoena/i,
    ask: "truthful testimony in legal proceedings",
  },
  {
    key: "statements required by law",
    re: /\b(?:required|compelled)\s+by\s+(?:applicable\s+)?(?:law|court|legal\s+process)\b/i,
    ask: "statements required by law",
  },
];

export const rule: Rule = {
  id: "PERS-006",
  version: "1.3.0",
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
    const text = fullText(ctx);
    const present = CARVE_OUTS.filter((c) => c.re.test(text));
    const missing = CARVE_OUTS.filter((c) => !c.re.test(text));
    // The two the explanation turns on — McLaren Macomb and Rule 21F-17.
    const covered =
      present.some((c) => c.key === "NLRA-protected activity") &&
      present.some((c) => c.key === "agency reports");
    const presentNote = present.length
      ? ` Carve-outs found in the document: ${present.map((c) => c.key).join(", ")}.`
      : " No protected-activity carve-out was found anywhere in the document.";
    return emit(ctx, rule, {
      severity: covered ? "info" : "warning",
      title: covered
        ? "Non-disparagement clause present, with protected-activity carve-outs"
        : "Non-disparagement clause present",
      description: matchedSentence(hit.text, hit.match),
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "A non-disparagement clause that binds an employee or contractor at separation is enforceable in most US jurisdictions, but the NLRB's McLaren Macomb decision (Feb 2023) held that offering severance terms that broadly restrict Section 7 rights violates NLRA § 8(a)(1); it remains Board law, though the General Counsel's 2023 enforcement guidance was rescinded in February 2025 (GC 25-05). SEC Rule 21F-17 separately prohibits any action, including enforcing or threatening to enforce a confidentiality agreement, that impedes communicating with the SEC about a possible securities violation. A non-disparagement provision without carve-outs for protected speech / agency reports / truthful testimony is increasingly indefensible." +
        presentNote,
      recommendation:
        (missing.length
          ? `Add explicit carve-outs for: ${missing.map((c, i) => `(${i + 1}) ${c.ask}`).join(", ")}.`
          : "Confirm the carve-outs reach this clause as written.") +
        " Consider also whether the clause should be bilateral.",
      position: hit.position,
    });
  },
};

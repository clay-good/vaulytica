/**
 * v3 audit-rights / inspection-clause detector (spec-v3.md §23).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { AuditCostAllocation, AuditMethod, AuditRights } from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

/**
 * A clause granting an AUDIT RIGHT — not any sentence containing the word.
 *
 * 🚨 This was `/\b(?:audit|inspect|inspection)[^.]{0,400}\./i`, the bare word,
 * so it produced an `AuditRights` record for **107 of 327 specimens** and
 * **80% of those records carried no detail at all** — every field null or
 * "unspecified", because there were no audit terms to read. What it had found
 * was the word:
 *
 *   - a board's **"Audit Committee."** (a governance body, not a right);
 *   - an architect **disclaiming** site duty — "inspections, and does not
 *     control or have charge of construction means…";
 *   - a stockholder's DGCL § 220 right to **inspect the stock ledger**;
 *   - a lessee's acceptance duty — "Lessee shall **inspect** each item of
 *     Equipment on delivery".
 *
 * An audit right is an ENTITLEMENT: a party may audit, has the right to audit,
 * shall permit an audit, or must make records available for one.
 *
 * 🥇 **The entitlement marker and the audit verb sit far apart**, because the
 * notice period, the frequency cap and the scope all go between them —
 * "Business Associate **may**, on thirty (30) days' written notice and not more
 * than once in any twelve-month period, **audit** Subcontractor's handling of
 * PHI". A tight window loses exactly the well-drafted clauses this exists for,
 * so the gap is generous and the alternation carries the weight.
 *
 * ⚠️ And the noun is routinely PLURAL: GDPR Art. 28(3)(h) is "allow for and
 * contribute to **audits**, including **inspections**". `\baudit\b` cannot
 * match "audits" — the boundary falls between "t" and "s", where there is
 * none. Every branch reads `audits?` / `inspections?`.
 *
 * 107 → 56 documents. The ones dropped are the word without the right; the
 * ones kept include every DPA, BAA and service-provider agreement in the
 * corpus.
 */
const AUDIT_RX = new RegExp(
  "\\b(?:" +
    "rights?\\s+to\\s+(?:audit|inspect)|" +
    "audit\\s+rights?|" +
    "(?:may|(?:shall|will|must)\\s+(?:have|be\\s+entitled|permit|allow|afford)|" +
    "is\\s+entitled|reserves?\\s+the\\s+right)[^.]{0,200}?\\b(?:audits?|inspects?|inspections?)\\b|" +
    "(?:permit|allow|afford|grant)s?[^.]{0,120}?\\b(?:audits?|inspections?)\\b|" +
    "subject\\s+to\\s+(?:an?\\s+)?audit|" +
    // The PASSIVE form, which names no entitled party at all: "Processor shall
    // be audited annually by an independent auditor." Caught by the extractor's
    // own existing test, not by the corpus — a reminder that a suite written
    // before a pattern is narrowed is the cheapest review of the narrowing.
    "(?:shall|will|must|is|are|be)\\s+(?:be\\s+)?audited\\b|" +
    "make[^.]{0,40}?available[^.]{0,120}?\\b(?:audits?|inspects?|inspections?)\\b|" +
    "\\b(?:audits?|inspects?|inspections?)[^.]{0,120}?\\b(?:upon|on)\\s+[^.]{0,40}?notice" +
    ")[^.]{0,400}\\.",
  "i",
);

// Audit-frequency drafting has several equivalent annual forms: "once per
// year", "once annually", "an annual audit", "once in any twelve (12) month
// period", "once every twelve months". Each states a count (once=1, twice=2, or
// a bare "N times") over a one-year window; the parenthesized numeral in the
// "twelve (12) month" form is incidental. A sub-annual window (per quarter, per
// month) is left vague rather than normalized, and a spelled count other than
// once/twice ("two times") is not read.
const YEAR_WINDOW = String.raw`(?:year|calendar\s+year|annum|(?:twelve|12)(?:\s*\(\d{1,2}\))?[-\s]months?(?:\s+period)?)`;
const FREQUENCY_RX = new RegExp(
  String.raw`\b(?:once|twice|(\d{1,2})\s*times?)\s+(?:per|a|in\s+any|every)\s+${YEAR_WINDOW}\b` +
    String.raw`|\b(?:once|twice)\s+annually\b` +
    String.raw`|\bannual(?:ly)?\s+(?:\w+\s+){0,2}(?:audit|inspection|assessment|review)\b` +
    String.raw`|\baudit(?:s|ed)?\b[^.]{0,20}?\bannually\b`,
  "i",
);

// `(?:[^.()\d\n]*?\()?` reads the "word (numeral)" form — "upon thirty (30)
// days' prior written notice" — whose parenthesized numeral is authoritative;
// a bare-digit anchor dropped it to null. Bounded by the sentence and by parens
// so no unrelated parenthetical is consumed; a plain "30 days" still matches.
const NOTICE_RX =
  /\b(?:upon |with )?(?:no less than |at least |minimum |no fewer than )?(?:[^.()\d\n]*?\()?(\d{1,3})\)?\s+(?:business days?|calendar days?|days?)['’]?\s+(?:prior )?(?:written )?notice\b/i;

const METHOD_RX: { rx: RegExp; method: AuditMethod }[] = [
  { rx: /\bonsite\b|\bon[- ]site\b|\bon premises\b/i, method: "onsite" },
  { rx: /\bremote\b/i, method: "remote" },
  { rx: /\bquestionnaire\b/i, method: "questionnaire-only" },
  { rx: /\bSOC\s*2\b/i, method: "soc2-substitution" },
  { rx: /\bthird[- ]party auditor\b|\bindependent auditor\b/i, method: "third-party-auditor" },
];

const COST_RX: { rx: RegExp; cost: AuditCostAllocation }[] = [
  { rx: /\bat (?:vendor|processor|supplier)['’]?s? (?:own )?expense\b/i, cost: "auditee" },
  { rx: /\bat (?:customer|controller|covered entity)['’]?s? (?:own )?expense\b/i, cost: "auditor" },
  {
    rx: /\bcost(?:s)? (?:(?:shall|will|must) be )?borne by the (?:audited|audit) party (?:if|when|where) (?:material )?(?:findings|non-compliance)/i,
    cost: "cost-shift-on-findings",
  },
];

export function extractAuditRights(tree: DocumentTree): AuditRights[] {
  const out: AuditRights[] = [];
  forEachParagraph(tree, (ctx) => {
    const m = AUDIT_RX.exec(ctx.text);
    if (!m) return;
    const window = m[0];

    // The window starts at the audit keyword, so an adjective-before-noun form
    // ("conduct an annual audit") sits just before it; fall back to the whole
    // paragraph, which AUDIT_RX has already confirmed is an audit clause.
    const freqMatch = FREQUENCY_RX.exec(window) ?? FREQUENCY_RX.exec(ctx.text);
    let frequency: number | null = null;
    if (freqMatch) {
      if (freqMatch[1]) frequency = Number(freqMatch[1]);
      else if (/twice/i.test(freqMatch[0])) frequency = 2;
      else frequency = 1;
    }

    const noticeMatch = NOTICE_RX.exec(window);
    const notice = noticeMatch ? Number(noticeMatch[1]) : null;

    const methods: AuditMethod[] = [];
    for (const mm of METHOD_RX) if (mm.rx.test(window)) methods.push(mm.method);

    const cost =
      COST_RX.find((c) => c.rx.test(window))?.cost ?? ("unspecified" as AuditCostAllocation);

    const scope = /\bproduction\b/i.test(window)
      ? "production"
      : /\ball systems\b/i.test(window)
        ? "all-systems"
        : /\bin[- ]scope\b/i.test(window)
          ? "in-scope-systems"
          : "unspecified";

    out.push({
      frequency_per_year: frequency,
      notice_days: notice,
      scope_phrase: scope,
      methods,
      cost_allocation: cost,
      confidentiality_required: /\bconfidentialit/i.test(window),
      third_party_auditor_permitted: /\bthird[- ]party auditor\b|\bindependent auditor\b/i.test(
        window,
      ),
      raw_text: window,
      position: posInParagraph(ctx, m.index, m.index + window.length),
    });
  });
  out.sort((a, b) => a.position.start - b.position.start);
  return out;
}

import type { Rule, RuleContext, Finding } from "../../finding.js";
import type { ParagraphHit } from "../_helpers.js";
import { allMatches, emit, enclosingSentence, excerptWindow, isNonOperative } from "../_helpers.js";

/**
 * IPDATA-010 — Perpetual / irrevocable license over user-side content
 * (warning, ip-and-data).
 *
 * Detects clauses where one party grants the other a license that is
 * perpetual, irrevocable, royalty-free, sublicensable, and/or
 * transferable — without time bounds or termination rights — over
 * material the granting party would normally retain rights in:
 *
 *   - Feedback (suggestions, improvements, ideas) — "feedback license"
 *     overreach is the most common and least negotiated form.
 *   - Customer Data / Content / Materials — broadest scope risk.
 *   - User-Generated Content / Submissions — common in consumer ToS.
 *   - Likeness / name / image — publicity-rights overreach.
 *
 * The license itself is often legitimate (vendors do need rights to
 * improve their products based on feedback). The problem is the
 * scope: "perpetual, irrevocable, worldwide, royalty-free,
 * sublicensable, transferable, fully paid-up" is a slug that
 * surrenders every conceivable lever. Best practice limits the grant
 * to what the vendor actually needs: a non-exclusive, non-transferable
 * license to use feedback for product improvement, terminating on
 * termination of the agreement.
 *
 * Trigger: ≥3 of (perpetual, irrevocable, royalty-free, worldwide,
 * sublicensable, transferable, fully paid-up) in a clause that
 * grants a license over a counterparty-side subject.
 */
/** The grant verb, with the fixed phrases that carry it. */
const GRANT_VERB = /\b(?:hereby\s+grants?|assigns?\s+and\s+grants?|grant(?:s|ed)?)\b/i;

/** The grant clause, read from the verb: a license or right, and its scope. */
const GRANT_CLAUSE =
  /\b(?:hereby\s+grants?|assigns?\s+and\s+grants?|grant(?:s|ed)?)\b[\s\S]{0,200}\b(?:licen[cs]e|right)\b[\s\S]{0,400}/i;

export const rule: Rule = {
  id: "IPDATA-010",
  version: "1.2.0",
  name: "Perpetual / irrevocable license overreach",
  category: "ip-and-data",
  default_severity: "warning",
  description:
    "Flags license grants whose scope reads as perpetual + irrevocable + royalty-free + sublicensable over Feedback / Customer Data / User Content / Likeness.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // EVERY grant in the document, not just the first, and anchored on the
    // grant VERB rather than on the whole clause.
    //
    // A release states its broad grant a section in, after a narrow one — "I
    // grant Riverbend … the following permissions" — and a run-in heading
    // supplies a "Grant" of its own: "1. Grant of Rights. I grant Riverbend
    // the irrevocable, perpetual, worldwide, royalty-free right …". Matching
    // the whole clause from the first "grant" consumed four hundred
    // characters, which swallowed the operative grant behind the heading that
    // announces it, and the sentence examined was the heading. A media
    // release lost the finding as soon as its blank lines went.
    for (const hit of allMatches(ctx, GRANT_VERB)) {
      if (isNonOperative(hit.text)) continue;
      const clause = new RegExp(GRANT_CLAUSE.source, "iy");
      clause.lastIndex = hit.match.index;
      const m = clause.exec(hit.text);
      if (!m) continue;
      const finding = evaluate(ctx, { ...hit, match: m });
      if (finding) return finding;
    }
    return null;
  },
};

/** The one grant under examination: its subject, then its modifier tally. */
function evaluate(ctx: RuleContext, hit: ParagraphHit): Finding | null {
  const para = hit.text;
  // Scope the subject + modifier tally to the SENTENCE that holds the grant,
  // not the whole paragraph: otherwise a separate, deliberately narrow
  // Feedback license ("non-exclusive, non-transferable, non-sublicensable")
  // in the same paragraph as an unrelated broad Documentation license was
  // flagged by summing the Documentation clause's modifiers with the Feedback
  // clause's subject. Display (excerpt) still uses the full paragraph.
  const clause = enclosingSentence(para, hit.match.index);

  // Must reference a counterparty-side subject (otherwise this is
  // probably the regular Vendor → Customer software license).
  // Consumer terms of service address the reader in the second person and
  // grant the license over "YOUR content / data / photos / posts" — the
  // dominant UGC-license phrasing, which a Capitalized-defined-term-only
  // subject list missed entirely. The ≥3-overreach-modifier gate below keeps
  // an ordinary "worldwide license to process your data" from firing.
  const SUBJECT =
    /\b(?:Feedback|Suggestions?|Comments?|Ideas?|Improvements?|Customer\s+Data|Customer\s+Content|User\s+(?:Content|Generated\s+Content|Submissions?)|Submissions?|Likeness|Name\s+and\s+(?:image|likeness)|Image\s+and\s+likeness|your\s+(?:content|data|materials|submissions?|posts?|photos?|videos?|recordings?))\b/i;
  if (!SUBJECT.test(clause)) return null;

  // Tally the overreach modifiers. Three or more is the signal. A leading
  // `\b` treats a hyphen as a word boundary, so `\bperpetual\b` would match
  // inside `non-perpetual` — the NARROWING opposite. The `(?<!non[- ])`
  // guards keep a favorable "non-perpetual, non-transferable, non-
  // sublicensable" grant from being read as overreach.
  const MODIFIERS = [
    /(?<!non[- ])\bperpetual\b/i,
    /(?<!non[- ])\birrevocable\b/i,
    /\broyalty[- ]free\b/i,
    /\bworldwide\b/i,
    /(?<!non[- ])\bsublicen(?:[cs]e|sable|sed)\b/i,
    /(?<!non[- ])\btransferable\b/i,
    /\bfully\s+paid[- ]up\b/i,
    /(?<!non[- ])\bunrestricted\b/i,
    /\bin\s+perpetuity\b/i,
  ];
  const matched = MODIFIERS.filter((re) => re.test(clause));
  if (matched.length < 3) return null;

  return emit(ctx, rule, {
    title: "License grant is perpetual / irrevocable / royalty-free / sublicensable",
    description: hit.match[0].slice(0, 240),
    excerpt: excerptWindow(para, hit.match.index, 40, 320),
    explanation:
      "License grants that pile up perpetual / irrevocable / royalty-free / worldwide / sublicensable / transferable / fully paid-up modifiers over Feedback, Customer Data, User Content, or likeness surrender every lever a customer would ordinarily retain. The scope is often broader than the vendor needs and broader than the customer realizes. Especially for Feedback, the broadly-scoped grant means anything the customer ever says to support — even suggestions for entirely separate products — becomes free fodder for the vendor's roadmap, transferable to acquirers, and unrecoverable.",
    recommendation:
      "Narrow the license to what the vendor actually needs. For Feedback, a non-exclusive, non-transferable license to use Feedback for the limited purpose of improving the Service, terminating on termination of the Agreement, is the standard balanced position. Strike 'sublicensable' and 'transferable' unless the use case genuinely requires sharing the grant with third parties.",
    position: hit.position,
  });
}

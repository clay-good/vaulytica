/**
 * Shared helpers for the BAA ruleset (spec-v3.md §28 / Step 23).
 *
 * Most BAA rules are *clause-presence* checks: did the drafter include
 * the §164.504(e)(2) sub-requirement? Or *language-quality* checks: is
 * the breach-notice clause looser than the §164.410 60-day outer bound?
 *
 * The helpers below produce a `Rule` from a compact spec so each rule
 * file (or the rule list) stays declarative and reviewable. Citations
 * are pinned by HIPAA CFR id rather than by DKB-statute id so the rule
 * stays usable even before the v2 starter DKB ships the Title 45
 * entries (we degrade to an empty `source_citations` if the DKB does
 * not carry the cite yet).
 */

import type { Finding, Rule, RuleContext, Severity } from "../../../finding.js";
import type { SourceCitation } from "../../../../dkb/types.js";
import { makeFinding } from "../../../finding.js";
import { forEachParagraph, forEachSection } from "../../../../extract/walk.js";
import type { DocPosition } from "../../../../extract/types.js";

const BAA_PLAYBOOKS = ["baa", "baa-deep", "baa-subcontractor"] as const;

/**
 * Concatenate every section heading + paragraph text — used as the
 * input to detection regexes. Headings are included because BAAs
 * commonly carry the matchable phrase in the heading ("Permitted
 * Uses and Disclosures") rather than the body.
 */
export function fullText(ctx: RuleContext): string {
  const parts: string[] = [];
  forEachSection(ctx.tree, (s) => {
    if (s.heading) parts.push(s.heading);
  });
  forEachParagraph(ctx.tree, (p) => parts.push(p.text));
  return parts.join("\n");
}

/** Position helper — the first section anchor when no specific paragraph applies. */
export function docTop(ctx: RuleContext): DocPosition {
  return { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 };
}

/** Build a SourceCitation from a HIPAA citation string + URL. */
export function hipaaCite(
  citation: string,
  source_url = "https://www.ecfr.gov/current/title-45",
): SourceCitation {
  return {
    id: `hipaa-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: citation,
    source_url,
    retrieved_at: "2026-05-12T00:00:00Z",
    license: "Public domain (US government work)",
    license_url: "https://www.usa.gov/government-works",
  };
}

export type BaaPresenceSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  /** HIPAA citation, e.g. "45 C.F.R. § 164.504(e)(2)(ii)(C)". */
  citation: string;
  /** Title shown when the clause is MISSING. */
  missing_title: string;
  /** One-sentence finding description. */
  missing_description: string;
  /** Plain-language explanation. */
  explanation: string;
  /** Suggestion text. */
  recommendation: string;
  /** Regexes that, if any match, indicate the clause IS present (pass). */
  present_patterns: RegExp[];
  /** Optional severity override. Default: critical. */
  default_severity?: Severity;
};

/**
 * Builds a presence-check rule. Fires when none of the `present_patterns`
 * matches the full document text.
 */
export function buildBaaPresenceRule(spec: BaaPresenceSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: "baa",
    default_severity: spec.default_severity ?? "critical",
    description: spec.description,
    dkb_citations: [`hipaa-${spec.citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`],
    applies_to_playbooks: Array.from(BAA_PLAYBOOKS),
    check(ctx: RuleContext): Finding | null {
      const text = fullText(ctx);
      if (spec.present_patterns.some((re) => re.test(text))) return null;
      return makeFinding({
        rule: this as Rule,
        title: spec.missing_title,
        description: spec.missing_description,
        excerptText: "(clause absent from the document)",
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: docTop(ctx),
        source_citations: [hipaaCite(spec.citation)],
      });
    },
  };
}

export type BaaLanguageSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: string;
  /** Regexes that, if any match, indicate problematic language (fail). */
  bad_patterns: RegExp[];
  /**
   * Carve-out guards. When a paragraph matches a `bad_pattern` but ALSO matches
   * any `exclude_if` pattern, the finding is suppressed — the paragraph states
   * the flagged pattern in its COMPLIANT form (HIPAA's own "attempted or
   * successful" Security Incident definition; a return-or-destroy clause that
   * does carry a definite day count). Firing on the compliant form is a
   * confident false accusation. Optional; rules without it are unchanged.
   */
  exclude_if?: readonly RegExp[];
  bad_title: string;
  bad_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
};

/**
 * Builds a language-quality rule. Fires when ANY of the `bad_patterns`
 * matches — the rule reports the matched paragraph as the excerpt.
 */
export function buildBaaLanguageRule(spec: BaaLanguageSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: "baa",
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [`hipaa-${spec.citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`],
    applies_to_playbooks: Array.from(BAA_PLAYBOOKS),
    check(ctx: RuleContext): Finding | null {
      type Hit = { text: string; position: DocPosition; match: string };
      let hit: Hit | null = null;
      forEachParagraph(ctx.tree, (p) => {
        if (hit) return;
        for (const re of spec.bad_patterns) {
          const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
          r.lastIndex = 0;
          const m = r.exec(p.text);
          if (m) {
            // Skip a paragraph that states the flagged pattern in its COMPLIANT
            // form. Skipping this paragraph still lets a genuine violation in a
            // later paragraph fire.
            if (spec.exclude_if?.some((ex) => ex.test(p.text))) return;
            hit = {
              text: p.text,
              match: m[0],
              position: {
                section_id: p.section.id,
                paragraph_id: p.paragraph.id,
                start: p.start + m.index,
                end: p.start + m.index + m[0].length,
              },
            };
            return;
          }
        }
      });
      if (!hit) return null;
      const h: Hit = hit;
      return makeFinding({
        rule: this as Rule,
        title: spec.bad_title,
        description: spec.bad_description,
        excerptText: h.text.slice(0, 280),
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: h.position,
        source_citations: [hipaaCite(spec.citation)],
      });
    },
  };
}

export const BAA_PLAYBOOK_IDS = BAA_PLAYBOOKS;

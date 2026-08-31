/**
 * Generic regulated-rule factory used by all v3 rulesets (BAA, DPA-GDPR,
 * DPA-US-state, etc.). Each consumer wires `category`, `applies_to_playbooks`,
 * and a `cite_url_for(citation)` mapper.
 *
 * Two rule kinds:
 *
 *   - `buildPresenceRule(spec)` — fires when none of `present_patterns`
 *     match the concatenated section-heading + paragraph text.
 *   - `buildLanguageRule(spec)` — fires when any of `bad_patterns`
 *     matches a paragraph; the matched paragraph is the excerpt.
 *
 * The two BAA-specific factories in `baa/_helpers.ts` delegate to these.
 */

import type { Finding, Rule, RuleContext, Severity } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";
import type { DocPosition } from "../../../extract/types.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { enclosingSentence } from "../_helpers.js";

export type RegulatedRuleConfig = {
  category: string;
  applies_to_playbooks: string[];
  /** Maps a citation string to (id, url) for the SourceCitation. */
  cite_for(citation: string): { id: string; source_url: string };
  /**
   * Opt-in: the ids of the rules in this pack whose clause is supplied BY
   * REFERENCE when the document adopts a standard form in full. Listed per
   * rule, not per pack: the same ruleset also holds the checks for the form's
   * own annexes, and those are exactly what must still fire.
   */
  supplied_by_standard_form?: ReadonlySet<string>;
  /**
   * Opt-in (privacy-notice pack): a presence-pattern match immediately
   * governed by a negator ("You have NO right to access", "you may NOT
   * request a correction") is a DENIAL of the item, not its disclosure —
   * without this guard, a notice that affirmatively strips rights scores
   * as disclosing them. The negator window is deliberately short so a
   * nearby unrelated negation ("we will not discriminate against you for
   * exercising the right to …") does not suppress a genuine disclosure.
   * Off by default: other regulated packs keep their exact behavior.
   */
  negation_guarded?: boolean;
};

/** Negator directly governing an upcoming match: short same-sentence window. */
const NEGATION_PREFIX = /\b(?:no|not|cannot|can['’]?t|never|nor)\b[^.;\n]{0,20}$/i;

/** True when some match of some pattern is NOT negation-prefixed. */
function presentUnnegated(patterns: readonly RegExp[], text: string): boolean {
  for (const re of patterns) {
    const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    for (const m of text.matchAll(global)) {
      const prefix = text.slice(Math.max(0, m.index - 40), m.index);
      if (!NEGATION_PREFIX.test(prefix)) return true;
    }
  }
  return false;
}

export type PresenceSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: string;
  missing_title: string;
  missing_description: string;
  explanation: string;
  recommendation: string;
  present_patterns: RegExp[];
  /**
   * Express-denial patterns. A presence rule looks for the words the required
   * clause would use, so a document that AFFIRMATIVELY DISCLAIMS the clause
   * matches the topic words and the rule stays SILENT — while a document that
   * merely omits the topic is flagged. The disclaimer is the worse document.
   * When any of these matches, the rule fires on the denying sentence
   * regardless of `present_patterns`. Build them with `expressDenial()`.
   *
   * Do NOT set this on a rule whose required clause is ITSELF a negation or
   * waiver — a denial frame would flag the compliant drafting as its own
   * violation. This is a narrower, opt-in alternative to the family-wide
   * `negation_guarded` flag, which cannot make that distinction per rule.
   */
  denied_if?: readonly RegExp[];
  /** Title used when `denied_if` fires. Defaults to the missing_title. */
  denied_title?: string;
  /** Description used when `denied_if` fires. Defaults to the missing_description. */
  denied_description?: string;
  default_severity?: Severity;
};

export type LanguageSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: string;
  bad_patterns: RegExp[];
  /**
   * Carve-out / disclaimer guards, mirroring the v4 language builder. When a
   * paragraph matches a `bad_pattern` but ALSO matches any `exclude_if`
   * pattern, the finding is suppressed — the paragraph states the flagged
   * pattern in its COMPLIANT form (HIPAA's own "attempted or successful"
   * Security Incident definition, a return-or-destroy clause that does carry a
   * definite day count, an "appropriate measures" clause that does cite an
   * Annex). Firing on the compliant form is a confident false accusation.
   * Optional; rules without it are unchanged.
   */
  exclude_if?: readonly RegExp[];
  bad_title: string;
  bad_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
};

export function fullText(ctx: RuleContext): string {
  const parts: string[] = [];
  forEachSection(ctx.tree, (s) => {
    if (s.heading) parts.push(s.heading);
  });
  forEachParagraph(ctx.tree, (p) => parts.push(p.text));
  return parts.join("\n");
}

export function docTop(ctx: RuleContext): DocPosition {
  return { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 };
}

function cite(config: RegulatedRuleConfig, citation: string): SourceCitation {
  const { id, source_url } = config.cite_for(citation);
  return {
    id,
    source: citation,
    source_url,
    retrieved_at: "2026-05-12T00:00:00Z",
    license: "Public domain or regulator re-use",
    license_url: "https://www.usa.gov/government-works",
  };
}

/**
 * The SCC / IDTA families, whose documents ARE a completed standard form.
 */
const STANDARD_FORM_PLAYBOOKS = new Set(["scc-module-2", "scc-module-3", "uk-idta-addendum"]);

/**
 * A reference to the standard form the document is executing, in the same
 * sentence as an adoption verb and an IN-FULL qualifier. All three are
 * required: a DPA that merely says the parties "will enter into the SCCs if a
 * transfer occurs" has adopted nothing, and must still carry its own Article
 * 28(3) terms.
 */
const ADOPTS_STANDARD_FORM =
  /\b(?:adopt(?:s|ed)?|incorporat(?:e|es|ed)|enter(?:s|ed)?\s+into|agree\s+to|appl(?:y|ies)|form\s+part\s+of)\b[^.;]{0,160}?\b(?:standard\s+contractual\s+clauses|(?:commission\s+)?implementing\s+decision\s*\(?eu\)?\s*2021\/914|international\s+data\s+transfer\s+addendum|idta)\b[^.;]{0,160}?\b(?:in\s+full|in\s+(?:their|its)\s+entirety|without\s+(?:any\s+)?(?:amendment|modification|change)|unamended|unmodified)\b|\b(?:standard\s+contractual\s+clauses|international\s+data\s+transfer\s+addendum)\b[^.;]{0,160}?\b(?:in\s+full|in\s+(?:their|its)\s+entirety|without\s+(?:any\s+)?(?:amendment|modification|change)|unamended|unmodified)\b[^.;]{0,80}?\b(?:adopt(?:s|ed)?|incorporat(?:e|es|ed)|appl(?:y|ies))\b/i;

/**
 * True when the clause this rule looks for is supplied by a standard form the
 * document adopts IN FULL rather than restates.
 *
 * An executed EU SCC Module Two is a cover page, a set of option selections,
 * and three completed annexes. Clause 8's documented-instructions obligation,
 * Clause 8.5's deletion-or-return, Clause 8.6's breach notification and the
 * rest of Article 28(3) live in the Commission Implementing Decision the
 * document adopts — restating them is what Clause 2 (invariability) exists to
 * discourage. The Article 28(3) ruleset was re-run against such a document
 * looking for the words, found none, and reported TEN of them missing at
 * CRITICAL on a form that satisfies every one. Same idea as
 * `amendsParentAgreement()`, with the Decision as the parent.
 *
 * Deliberately scoped to the families whose documents ARE the form. A DPA that
 * name-drops the SCCs for its transfer clause is not excused from stating its
 * own Article 28(3) terms, and is what an unscoped version would excuse.
 */
export function adoptsStandardFormInFull(ctx: RuleContext): boolean {
  if (!STANDARD_FORM_PLAYBOOKS.has(ctx.playbook.id)) return false;
  return ADOPTS_STANDARD_FORM.test(fullText(ctx));
}

export function buildPresenceRule(spec: PresenceSpec, config: RegulatedRuleConfig): Rule {
  const { id: dkb_id } = config.cite_for(spec.citation);
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: config.category,
    default_severity: spec.default_severity ?? "critical",
    description: spec.description,
    dkb_citations: [dkb_id],
    applies_to_playbooks: [...config.applies_to_playbooks],
    check(ctx: RuleContext): Finding | null {
      if (config.supplied_by_standard_form?.has(spec.id) && adoptsStandardFormInFull(ctx))
        return null;
      const text = fullText(ctx);
      if (spec.denied_if) {
        // An express denial outranks the presence check: the topic words are
        // present precisely because the document is disclaiming the clause.
        const denial = findDenial(ctx, spec.denied_if);
        if (denial) {
          return makeFinding({
            rule: this as Rule,
            title: spec.denied_title ?? spec.missing_title,
            description: spec.denied_description ?? spec.missing_description,
            excerptText: denial.sentence.slice(0, 280),
            explanation: spec.explanation,
            recommendation: spec.recommendation,
            position: denial.position,
            source_citations: [cite(config, spec.citation)],
          });
        }
      }
      const present = config.negation_guarded
        ? presentUnnegated(spec.present_patterns, text)
        : spec.present_patterns.some((re) => re.test(text));
      if (present) return null;
      return makeFinding({
        rule: this as Rule,
        title: spec.missing_title,
        description: spec.missing_description,
        excerptText: "(clause absent from the document)",
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: docTop(ctx),
        source_citations: [cite(config, spec.citation)],
      });
    },
  };
}

export function buildLanguageRule(spec: LanguageSpec, config: RegulatedRuleConfig): Rule {
  const { id: dkb_id } = config.cite_for(spec.citation);
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: config.category,
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [dkb_id],
    applies_to_playbooks: [...config.applies_to_playbooks],
    check(ctx: RuleContext): Finding | null {
      if (config.supplied_by_standard_form?.has(spec.id) && adoptsStandardFormInFull(ctx))
        return null;
      type Hit = { text: string; position: DocPosition };
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
        source_citations: [cite(config, spec.citation)],
      });
    },
  };
}

/** First denying sentence in the document, with its position. */
function findDenial(
  ctx: RuleContext,
  patterns: readonly RegExp[],
): { sentence: string; position: DocPosition } | null {
  let found: { sentence: string; position: DocPosition } | null = null;
  forEachParagraph(ctx.tree, (p) => {
    if (found) return;
    for (const re of patterns) {
      const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      r.lastIndex = 0;
      const m = r.exec(p.text);
      if (m) {
        found = {
          sentence: enclosingSentence(p.text, m.index).trim(),
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
  return found;
}

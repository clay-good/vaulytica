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

export type RegulatedRuleConfig = {
  category: string;
  applies_to_playbooks: string[];
  /** Maps a citation string to (id, url) for the SourceCitation. */
  cite_for(citation: string): { id: string; source_url: string };
};

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
  default_severity?: Severity;
};

export type LanguageSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: string;
  bad_patterns: RegExp[];
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
      type Hit = { text: string; position: DocPosition };
      let hit: Hit | null = null;
      forEachParagraph(ctx.tree, (p) => {
        if (hit) return;
        for (const re of spec.bad_patterns) {
          const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
          r.lastIndex = 0;
          const m = r.exec(p.text);
          if (m) {
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

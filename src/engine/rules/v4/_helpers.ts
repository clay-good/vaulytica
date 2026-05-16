/**
 * Shared rule-builder helpers for v4 sub-domain rulesets
 * (spec-v4.md §6, Steps 45–59).
 *
 * v4 expands the catalog of recognized document families. The new rule
 * families follow the same two shapes used by v3 (BAA, NDA-deep,
 * MSA-deep): **clause-presence** (the clause MUST appear) and
 * **language-quality** (a problematic pattern MUST NOT appear), plus a
 * **compound** presence form (N-of-M sub-pillars must match). The
 * helpers below produce a `Rule` from a compact spec so each
 * sub-domain's rule list stays declarative and reviewable.
 *
 * Each spec carries its own `applies_to_playbooks` so the rule is
 * scoped to the v4 playbook ids that should fire it; this preserves the
 * v2/v3 hash boundary because the runner filters by playbook before
 * executing each rule.
 */

import type { Finding, Rule, RuleContext, Severity } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";
import type { DocPosition } from "../../../extract/types.js";

/** Concatenate every section heading + paragraph text. */
export function fullText(ctx: RuleContext): string {
  const parts: string[] = [];
  forEachSection(ctx.tree, (s) => {
    if (s.heading) parts.push(s.heading);
  });
  forEachParagraph(ctx.tree, (p) => parts.push(p.text));
  return parts.join("\n");
}

/** Position helper — the first section anchor. */
export function docTop(ctx: RuleContext): DocPosition {
  return { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 };
}

/** Build a SourceCitation from a free-form citation string. */
export function v4Cite(args: {
  id: string;
  source: string;
  source_url: string;
  license?: string;
  license_url?: string;
  retrieved_at?: string;
}): SourceCitation {
  return {
    id: args.id,
    source: args.source,
    source_url: args.source_url,
    retrieved_at: args.retrieved_at ?? "2026-05-12T00:00:00Z",
    license: args.license ?? "Public domain (US government work)",
    license_url: args.license_url ?? "https://www.usa.gov/government-works",
  };
}

/** A presence-check rule: fires when none of the present_patterns match. */
export type V4PresenceSpec = {
  id: string;
  version?: string;
  name: string;
  category: string;
  description: string;
  citation: SourceCitation;
  playbooks: readonly string[];
  missing_title: string;
  missing_description: string;
  explanation: string;
  recommendation: string;
  present_patterns: RegExp[];
  default_severity?: Severity;
};

export function buildV4PresenceRule(spec: V4PresenceSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: spec.category,
    default_severity: spec.default_severity ?? "critical",
    description: spec.description,
    dkb_citations: [spec.citation.id],
    applies_to_playbooks: [...spec.playbooks],
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
        source_citations: [spec.citation],
      });
    },
  };
}

/** A language-quality rule: fires when any bad pattern matches some paragraph. */
export type V4LanguageSpec = {
  id: string;
  version?: string;
  name: string;
  category: string;
  description: string;
  citation: SourceCitation;
  playbooks: readonly string[];
  bad_patterns: RegExp[];
  bad_title: string;
  bad_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
};

export function buildV4LanguageRule(spec: V4LanguageSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: spec.category,
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [spec.citation.id],
    applies_to_playbooks: [...spec.playbooks],
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
        source_citations: [spec.citation],
      });
    },
  };
}

/**
 * Compound presence: fires unless at least `min_match` of
 * `required_patterns` match the full text. Used for clauses that have
 * multiple required pillars (e.g., committee charter must cover
 * composition + duties + meetings).
 */
export type V4CompoundSpec = {
  id: string;
  version?: string;
  name: string;
  category: string;
  description: string;
  citation: SourceCitation;
  playbooks: readonly string[];
  required_patterns: RegExp[];
  min_match: number;
  missing_title: string;
  missing_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
};

export function buildV4CompoundRule(spec: V4CompoundSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: spec.category,
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [spec.citation.id],
    applies_to_playbooks: [...spec.playbooks],
    check(ctx: RuleContext): Finding | null {
      const text = fullText(ctx);
      const matches = spec.required_patterns.filter((re) => re.test(text)).length;
      if (matches >= spec.min_match) return null;
      return makeFinding({
        rule: this as Rule,
        title: spec.missing_title,
        description: spec.missing_description,
        excerptText: "(required components not all present)",
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: docTop(ctx),
        source_citations: [spec.citation],
      });
    },
  };
}

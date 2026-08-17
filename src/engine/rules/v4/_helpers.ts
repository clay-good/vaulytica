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
import { enclosingSentence } from "../_helpers.js";
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
  /**
   * Applicability gate. When provided and NONE of these patterns match the
   * document, the rule is inapplicable and its absence is not a defect — a
   * New York commercial settlement is not missing a California § 1542
   * waiver, and a freight dispute is not missing a § 162(q)
   * sexual-harassment recital. Reporting an "(if applicable)" absence the
   * document itself shows is inapplicable is a false positive. Optional;
   * rules without it are unchanged.
   */
  applicable_if?: readonly RegExp[];
  /**
   * Express-denial patterns. A presence rule reads the document for the
   * words the required clause would use, so a document that AFFIRMATIVELY
   * DISCLAIMS the clause ("the Company performs no OFAC screening") is
   * silent — the topic words are all there, so the rule scores it as
   * compliant. That is backwards: an express denial is strictly worse than
   * an omission, and it is the one the rule must not miss.
   *
   * When any of these patterns match, the rule fires on the denying
   * paragraph regardless of `present_patterns`. Build them with
   * `expressDenial()` so the frames stay consistent across rules.
   * Optional; rules without it are unchanged.
   */
  denied_if?: readonly RegExp[];
  /** Title used when `denied_if` fires. Defaults to the missing_title. */
  denied_title?: string;
  /** Description used when `denied_if` fires. Defaults to the missing_description. */
  denied_description?: string;
  default_severity?: Severity;
};

/**
 * Build express-disclaimer patterns for a presence rule's `denied_if`.
 *
 * `topic` is a regex source fragment naming the required clause (e.g.
 * `"ofac|sanctions\\s+screening"`). The frames below wrap it in the ways a
 * document actually disclaims an obligation. The word gap refuses to cross
 * a conditional connective, so a COMPLIANT sentence that pairs a negation
 * with the topic — "no customer shall be onboarded WITHOUT OFAC screening"
 * — is not read as a denial.
 */
export function expressDenial(topic: string): RegExp[] {
  const t = `(?:${topic})`;
  // Up to three filler words — four was measured to be too many: "this
  // Agreement shall not become effective until the REVOCATION PERIOD expires"
  // (the compliant OWBPA drafting) then reads as a denial of the revocation
  // right. The gap refuses to cross a conditional
  // connective ("...not onboard a customer WITHOUT OFAC screening") or a
  // scope verb ("this policy does not APPLY TO OFAC screening by third
  // parties"), because neither sentence denies that the clause exists.
  const gap = String.raw`(?:(?!\b(?:without|unless|except|absent|failing|prior|appl(?:y|ies)|affect|affects|limit|limits|waive|waives|relieve|relieves|supersede|supersedes|alter|alters|modify|modifies|excuse|excuses|prevent|prevents|preclude|precludes|restrict|restricts)\b)\w+[\s,]+){0,3}`;
  const verb =
    "(?:perform|conduct|provide|maintain|require|undertake|implement|operate|run|have|has|make)";
  // Past participles a denial lands on. Deliberately excludes "permitted" /
  // "allowed": "failure to file a SAR is not permitted" is a PROHIBITION of
  // the failure, i.e. the compliant drafting, not a denial of the clause.
  const done =
    "(?:required|performed|conducted|maintained|provided|undertaken|implemented|applicable|filed|retained|kept|screened|collected|identified|obtained|established|withdrawn|revoked|honored|honoured|granted|issued|suspended|available|offered|encrypted|appointed|designated|reviewed|notified)";
  return [
    // "does not perform OFAC screening" / "is not required to conduct AML training"
    new RegExp(
      String.raw`\b(?:do|does|did|shall|will|is|are|was|were|has|have|had|can|may|need)\s+not\s+(?:be\s+)?${gap}${t}`,
      "i",
    ),
    // "cannot revoke this authorization"
    new RegExp(String.raw`\bcan\s?not\s+(?:be\s+)?${gap}${t}`, "i"),
    // "performs no OFAC screening" / "maintains no SAR procedures"
    new RegExp(String.raw`\b${verb}(?:s|es|ed)?\s+no\s+${gap}${t}`, "i"),
    // "OFAC screening is not required" / "consent may not be withdrawn"
    new RegExp(
      String.raw`\b${t}\b[^.]{0,80}?\b(?:is|are|shall\s+be|will\s+be|shall|will|may|can|must)\s+not\s+(?:be\s+)?${done}`,
      "i",
    ),
    // "consent cannot be withdrawn"
    new RegExp(String.raw`\b${t}\b[^.]{0,80}?\bcan\s?not\s+(?:be\s+)?${done}`, "i"),
    // "no OFAC screening is performed"
    new RegExp(
      String.raw`\bno\s+${gap}${t}\b[^.]{0,80}?\b(?:is|are|shall\s+be|will\s+be)\s+${done}`,
      "i",
    ),
  ];
}

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
      if (spec.applicable_if && !spec.applicable_if.some((re) => re.test(text))) return null;
      if (spec.denied_if) {
        // An express denial outranks the presence check: the topic words are
        // present precisely because the document is disclaiming the clause.
        const denial = findDenial(ctx, spec.denied_if);
        if (denial) {
          return makeFinding({
            rule: this as Rule,
            title: spec.denied_title ?? spec.missing_title,
            description: spec.denied_description ?? spec.missing_description,
            // Excerpt the denying SENTENCE. A policy states its disclaimer deep
            // inside a long clause, so the paragraph's leading 280 characters
            // would show everything except the sentence being reported.
            excerptText: denial.sentence.slice(0, 280),
            explanation: spec.explanation,
            recommendation: spec.recommendation,
            position: denial.position,
            source_citations: [spec.citation],
          });
        }
      }
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
  /**
   * Carve-out / disclaimer guards. When a paragraph matches a `bad_pattern`
   * but ALSO matches any `exclude_if` pattern, the finding is suppressed — the
   * paragraph states the flagged pattern in its DISCLAIMED or COMPLIANT form
   * ("royalties shall NOT extend beyond expiration", "this release does NOT
   * apply to gross negligence"). Firing on the compliant form is a confident
   * false accusation. Optional; rules without it are unchanged.
   */
  exclude_if?: readonly RegExp[];
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
            // Skip a paragraph that DISCLAIMS or CARVES OUT the flagged pattern
            // (the compliant/negated form) — reporting it as the violation is a
            // false accusation. Skipping this paragraph still lets a genuine
            // violation in a later paragraph fire.
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

/**
 * Shared helpers for the NDA-deep ruleset (spec-v3.md §32 / Step 27).
 *
 * Two rule shapes parallel the BAA pattern: clause-presence (the clause
 * must appear) and language-quality (a problematic pattern must NOT
 * appear). Citations attach to DTSA (18 U.S.C. § 1833(b)) and to UTSA /
 * standard NDA-drafting consensus.
 */

import type { Finding, Rule, RuleContext, Severity } from "../../../finding.js";
import type { SourceCitation } from "../../../../dkb/types.js";
import { makeFinding } from "../../../finding.js";
import { forEachParagraph, forEachSection } from "../../../../extract/walk.js";
import type { DocPosition } from "../../../../extract/types.js";
import { enclosingSentence } from "../../_helpers.js";

const NDA_PLAYBOOKS_ALL = ["mutual-nda-deep", "unilateral-nda-deep"] as const;
const NDA_PLAYBOOKS_MUTUAL = ["mutual-nda-deep"] as const;
const NDA_PLAYBOOKS_UNILATERAL = ["unilateral-nda-deep"] as const;

export const NDA_PLAYBOOK_IDS = NDA_PLAYBOOKS_ALL;
export const NDA_MUTUAL_PLAYBOOK_IDS = NDA_PLAYBOOKS_MUTUAL;
export const NDA_UNILATERAL_PLAYBOOK_IDS = NDA_PLAYBOOKS_UNILATERAL;

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

export function dtsaCite(): SourceCitation {
  return {
    id: "dtsa-18-usc-1833-b",
    source: "18 U.S.C. § 1833(b) (DTSA whistleblower immunity / notice)",
    source_url: "https://www.law.cornell.edu/uscode/text/18/1833",
    retrieved_at: "2026-05-12T00:00:00Z",
    license: "Public domain (US government work)",
    license_url: "https://www.usa.gov/government-works",
  };
}

export function utsaCite(): SourceCitation {
  return {
    id: "utsa-1985",
    source: "Uniform Trade Secrets Act (UTSA) (1985 amended)",
    source_url:
      "https://www.uniformlaws.org/committees/community-home?CommunityKey=3a2538fb-e030-4e2d-a9e2-90373dc05792",
    retrieved_at: "2026-05-12T00:00:00Z",
    license: "Public uniform-law text",
    license_url:
      "https://www.uniformlaws.org/HigherLogic/System/DownloadDocumentFile.ashx?DocumentFileKey=e19b2528-e0b1-0054-23c4-8069701a4b62",
  };
}

export function genericNdaCite(): SourceCitation {
  return {
    id: "nda-consensus-drafting",
    source: "Consensus NDA drafting practice (Common Paper, ACC, ABA practice notes)",
    source_url: "https://commonpaper.com/standards/mutual-nda/",
    retrieved_at: "2026-05-12T00:00:00Z",
    license: "Common Paper Standard NDA, CC BY 4.0",
    license_url: "https://creativecommons.org/licenses/by/4.0/",
  };
}

type PlaybookScope = "all" | "mutual" | "unilateral";

function playbookList(scope: PlaybookScope): string[] {
  if (scope === "mutual") return Array.from(NDA_PLAYBOOKS_MUTUAL);
  if (scope === "unilateral") return Array.from(NDA_PLAYBOOKS_UNILATERAL);
  return Array.from(NDA_PLAYBOOKS_ALL);
}

export type NdaPresenceSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: SourceCitation;
  missing_title: string;
  missing_description: string;
  explanation: string;
  recommendation: string;
  /** Regexes that, if any match, indicate the clause IS present (pass). */
  present_patterns: RegExp[];
  /**
   * Express-denial patterns. A presence rule looks for the words the required
   * clause would use, so an NDA that AFFIRMATIVELY DISCLAIMS the clause
   * ("this Agreement provides no immunity under the DTSA") matches the topic
   * words and the rule stays SILENT — while an NDA that merely omits the topic
   * is flagged. The disclaimer is the worse document. Build with
   * `expressDenial()`. Do NOT set this on a rule whose required clause is
   * ITSELF a carve-out or exclusion.
   */
  denied_if?: readonly RegExp[];
  /** Title used when `denied_if` fires. Defaults to the missing_title. */
  denied_title?: string;
  /** Description used when `denied_if` fires. Defaults to the missing_description. */
  denied_description?: string;
  default_severity?: Severity;
  scope?: PlaybookScope;
  dkb_citation_id?: string;
};

export function buildNdaPresenceRule(spec: NdaPresenceSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: "nda",
    default_severity: spec.default_severity ?? "critical",
    description: spec.description,
    dkb_citations: [spec.dkb_citation_id ?? spec.citation.id],
    applies_to_playbooks: playbookList(spec.scope ?? "all"),
    check(ctx: RuleContext): Finding | null {
      const text = fullText(ctx);
      if (spec.denied_if) {
        // An express denial outranks the presence check: the topic words are
        // present precisely because the document is disclaiming the clause.
        const denial = findNdaDenial(ctx, spec.denied_if);
        if (denial) {
          return makeFinding({
            rule: this as Rule,
            title: spec.denied_title ?? spec.missing_title,
            description: spec.denied_description ?? spec.missing_description,
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

export type NdaLanguageSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: SourceCitation;
  bad_patterns: RegExp[];
  /**
   * Carve-out guards, mirroring the v4 and shared-v3 language builders. When a
   * paragraph matches a `bad_pattern` but ALSO matches any `exclude_if`
   * pattern, the finding is suppressed — the paragraph states the flagged
   * pattern in its COMPLIANT form ("for any purpose OTHER THAN the Purpose", a
   * general-solicitation carve-out sitting BEFORE the non-solicit trigger).
   * Firing on the compliant form is a confident false accusation. Because it is
   * tested against the whole paragraph, it also fixes carve-outs that a
   * forward-only negative lookahead in `bad_patterns` cannot see. Optional;
   * rules without it are unchanged.
   */
  exclude_if?: readonly RegExp[];
  /**
   * Document-scoped carve-out guards. Same idea as `exclude_if`, but tested
   * against the WHOLE document rather than the matched paragraph — for rules
   * whose finding asserts something about the agreement as a whole ("imposes an
   * obligation solely on the Receiving Party"). A mutual NDA defines the
   * reciprocal roles once, in a different paragraph from the obligations that
   * use them, so a paragraph-scoped guard can never see it. Optional; rules
   * without it are unchanged.
   */
  exclude_if_document?: readonly RegExp[];
  bad_title: string;
  bad_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
  scope?: PlaybookScope;
  dkb_citation_id?: string;
};

export function buildNdaLanguageRule(spec: NdaLanguageSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: "nda",
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [spec.dkb_citation_id ?? spec.citation.id],
    applies_to_playbooks: playbookList(spec.scope ?? "all"),
    check(ctx: RuleContext): Finding | null {
      type Hit = { text: string; position: DocPosition; match: string };
      if (spec.exclude_if_document?.length) {
        const whole = fullText(ctx);
        if (spec.exclude_if_document.some((ex) => ex.test(whole))) return null;
      }
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
        source_citations: [spec.citation],
      });
    },
  };
}

/**
 * Builds a rule that fires when ALL of the `required_patterns` fail to
 * match. Used for compound presence (e.g., DTSA notice must include all
 * three pillars: immunity, government, trade secret).
 */
export type NdaCompoundSpec = {
  id: string;
  version?: string;
  name: string;
  description: string;
  citation: SourceCitation;
  /**
   * Locates the clause whose components are being counted. Without it, the
   * components are counted across the WHOLE document — see the note on
   * {@link buildNdaCompoundRule}.
   */
  anchor: RegExp;
  required_patterns: RegExp[];
  /** How many of the required_patterns must match to count as PRESENT. */
  min_match: number;
  missing_title: string;
  missing_description: string;
  explanation: string;
  recommendation: string;
  default_severity?: Severity;
  scope?: PlaybookScope;
  dkb_citation_id?: string;
};

/**
 * A rule that asks whether ONE clause carries all of its required components.
 *
 * The components are counted inside the paragraph the `anchor` matches, not
 * across the document. Counting document-wide was wrong in both directions,
 * because the individual component patterns are deliberately loose — for the
 * DTSA notice they are "immunity", "government official|attorney" and "under
 * seal":
 *
 *  - FALSE COMPLIANCE. Three unrelated clauses satisfied all three: a
 *    limitation-of-liability clause saying "immunity", a notices clause naming
 *    an "attorney", and an exhibit "filed under seal". An agreement with no
 *    DTSA notice anywhere scored as having a complete one, and the rule went
 *    silent. Under 18 U.S.C. § 1833(b) that silence costs the employer its
 *    exemplary-damages and fees remedy.
 *  - WRONG ACCUSATION. On a plain NDA with no notice at all, the count fell
 *    short and the rule reported "DTSA notice is incomplete" — describing a
 *    notice that does not exist. Absence is NDA-D-001's job, and its finding
 *    says so properly.
 *
 * With no anchor match there is no clause to judge, so the rule is silent and
 * leaves absence to the presence rule.
 */
export function buildNdaCompoundRule(spec: NdaCompoundSpec): Rule {
  return {
    id: spec.id,
    version: spec.version ?? "1.0.0",
    name: spec.name,
    category: "nda",
    default_severity: spec.default_severity ?? "warning",
    description: spec.description,
    dkb_citations: [spec.dkb_citation_id ?? spec.citation.id],
    applies_to_playbooks: playbookList(spec.scope ?? "all"),
    check(ctx: RuleContext): Finding | null {
      // Collect paragraphs in document order so a clause that spans two of
      // them can be judged as one clause.
      const paras: { text: string; sectionId: string; position: DocPosition }[] = [];
      forEachParagraph(ctx.tree, (p) => {
        paras.push({
          text: p.text,
          sectionId: p.section.id,
          position: {
            section_id: p.section.id,
            paragraph_id: p.paragraph.id,
            start: p.start,
            end: p.end,
          },
        });
      });

      // Judge the BEST candidate, not the first. A document can mention the
      // topic in more than one place — an NDA names trade secrets in its
      // perpetuity carve-out as well as in the notice — and taking the first
      // match accused a compliant agreement, because the carve-out quite
      // properly carries none of the pillars.
      //
      // The components are counted over the anchor paragraph AND its immediate
      // neighbours WITHIN THE SAME SECTION, because drafters legitimately split
      // one notice across two paragraphs — citation and immunity in the first,
      // the sealed-filing carve-out in the second — and judging the anchor
      // paragraph alone accused that drafting of being incomplete. The window
      // is deliberately three paragraphs and section-bounded rather than the
      // whole section: a document with few headings is one enormous section,
      // and widening to it would reopen the document-wide counting this rule
      // was fixed to stop.
      let best: { text: string; position: DocPosition; matches: number } | null = null;
      for (let i = 0; i < paras.length; i++) {
        const here = paras[i]!;
        if (!spec.anchor.test(here.text)) continue;
        const parts = [here.text];
        const prev = paras[i - 1];
        const next = paras[i + 1];
        if (prev && prev.sectionId === here.sectionId) parts.unshift(prev.text);
        if (next && next.sectionId === here.sectionId) parts.push(next.text);
        const windowText = parts.join("\n");
        const matches = spec.required_patterns.filter((re) => re.test(windowText)).length;
        if (best && matches <= best.matches) continue;
        best = { text: here.text, position: here.position, matches };
      }
      // No clause of this kind in the document: nothing to judge complete or
      // incomplete. The presence rule reports the absence.
      if (!best) return null;
      const found = best as { text: string; position: DocPosition; matches: number };
      if (found.matches >= spec.min_match) return null;
      return makeFinding({
        rule: this as Rule,
        title: spec.missing_title,
        description: spec.missing_description,
        excerptText: found.text.slice(0, 280),
        explanation: spec.explanation,
        recommendation: spec.recommendation,
        position: found.position,
        source_citations: [spec.citation],
      });
    },
  };
}

/** First denying sentence in the document, with its position. */
function findNdaDenial(
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

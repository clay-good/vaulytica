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

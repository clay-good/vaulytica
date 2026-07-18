/**
 * FILE-### — litigation-filing format lint (add-filing-format-lint).
 *
 * The pack is gated two ways: every rule declares
 * `applies_to_playbooks: FILING_PLAYBOOK_IDS` (it runs only for filing
 * families), and every rule returns `null` unless the run carries a selected
 * court profile in `ctx.options.filing` — so with no `--court` chosen the pack
 * is fully dormant and existing hashes are untouched.
 *
 * Honesty posture: the type-volume check reports a violation only when the
 * post-exclusion lower bound exceeds the limit and always states that the
 * filer's word-processor count governs for certification; the page-limit check
 * runs only where a real page count exists; presence checks report a block as
 * found or not detected and never certify the filing compliant.
 */

import type { Finding, Rule, RuleContext } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { detectFilingBlocks } from "../../../filing/detect.js";
import type { FilingBlock } from "../../../filing/court-profile.js";
import { profileCitation, readFilingOptions } from "../../../filing/run-options.js";

/** The playbooks the filing pack is gated to. */
export const FILING_PLAYBOOK_IDS = ["appellate-brief", "trial-motion", "petition"] as const;

const GATE = Array.from(FILING_PLAYBOOK_IDS);

/**
 * Max words in a section for it to count as an excludable block. A cover, TOC,
 * TOA, certificate, or signature block is short; a section larger than this is
 * treated as substantive text that merely mentions the phrase, so it is not
 * subtracted from the type-volume count. (add-filing-format-lint.)
 */
const EXCLUSION_SECTION_CAP = 600;

function topPosition(ctx: RuleContext): { section_id: string; start: number; end: number } {
  return { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 };
}

function finding(
  ctx: RuleContext,
  rule: Rule,
  args: {
    severity: "critical" | "warning" | "info";
    title: string;
    description: string;
    explanation: string;
    recommendation?: string;
    citations: SourceCitation[];
  },
): Finding {
  return makeFinding({
    rule,
    severity: args.severity,
    title: args.title,
    description: args.description,
    excerptText: "",
    explanation: args.explanation,
    recommendation: args.recommendation,
    position: topPosition(ctx),
    source_citations: args.citations,
  });
}

// FILE-001 — Type-volume (word limit), honest about measurement.
export const FILE_001: Rule = {
  id: "FILE-001",
  version: "1.1.0",
  name: "Type-volume within the word limit",
  category: "filing",
  default_severity: "critical",
  description:
    "Compares the document's word count (total and after subtracting detected excludable blocks) against the selected court profile's word limit. Fires only when the post-exclusion lower bound exceeds the limit; the filer's word-processor count governs for certification.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const opts = readFilingOptions(ctx);
    if (!opts) return null;
    const limit =
      opts.brief_kind === "reply"
        ? opts.profile.limits.reply_words
        : opts.profile.limits.principal_words;
    if (!limit) return null;
    const total = opts.word_count;
    const excludable: Set<string> = new Set(opts.profile.count_exclusions);
    // Sum excludable blocks, deduped by section and capped per section: a real
    // cover / TOC / TOA / certificate / signature block is short, so a "block"
    // detected inside a large section is almost certainly the argument body
    // merely mentioning the phrase — excluding it would understate the count
    // and could falsely clear an over-length brief. When blocks can't be
    // isolated (a flat document), nothing is subtracted and the rule falls
    // back to the total, which is the safe direction for a compliance check.
    const excludableSections = new Map<string, number>();
    let unisolatable = false;
    for (const b of detectFilingBlocks(ctx.tree)) {
      if (!excludable.has(b.block)) continue;
      if (b.words <= EXCLUSION_SECTION_CAP) {
        excludableSections.set(b.section_id, b.words);
      } else {
        unisolatable = true;
      }
    }
    const excluded = [...excludableSections.values()].reduce((a, b) => a + b, 0);
    const lower = Math.max(0, total - excluded);
    const cite = profileCitation(limit);
    const kind = opts.brief_kind === "reply" ? "reply" : "principal";
    if (lower > limit.value) {
      // Excludable blocks were DETECTED but share an over-cap section (the
      // single-section text-ingest shape), so nothing could be subtracted —
      // the countable total may be under the limit. A critical verdict here
      // was a false accusation on a compliant brief with a large ToA
      // (audit); the honest verdict is a warning naming the uncertainty.
      if (excluded === 0 && unisolatable) {
        return finding(ctx, FILE_001, {
          severity: "warning",
          title: `Measured ${total.toLocaleString("en-US")} words against the ${limit.value.toLocaleString("en-US")}-word limit — excludable blocks could not be isolated`,
          description: `The total measured count (${total.toLocaleString("en-US")}) exceeds the ${limit.value.toLocaleString("en-US")}-word limit for a ${kind} brief, but detected excludable blocks (cover / tables / certificate) share a section with the body and could not be subtracted — the countable total may be lower.`,
          explanation: `This ingest carries no section boundaries around the excludable blocks, so the post-exclusion count cannot be computed. The filer's word-processing software count governs for the ${cite.source} certification.`,
          recommendation: `Verify the ${cite.source} count with the word processor (excluding the items the rule excludes) — this measure cannot confirm a violation.`,
          citations: [cite],
        });
      }
      return finding(ctx, FILE_001, {
        severity: "critical",
        title: `Over the ${limit.value.toLocaleString("en-US")}-word limit`,
        description: `Even after subtracting ${excluded.toLocaleString("en-US")} words of detected excludable blocks, the ${kind} brief's word count (${lower.toLocaleString("en-US")}) exceeds the ${limit.value.toLocaleString("en-US")}-word limit.`,
        explanation: `Total measured words: ${total.toLocaleString("en-US")}; post-exclusion lower bound: ${lower.toLocaleString("en-US")}. This tool's count is an estimate — the filer's word-processing software count governs for the ${cite.source} certification.`,
        recommendation: `Reduce the brief or confirm the word-processor count against ${cite.source}.`,
        citations: [cite],
      });
    }
    return finding(ctx, FILE_001, {
      severity: "info",
      title: `Word count within the ${limit.value.toLocaleString("en-US")}-word limit (by this tool's measure)`,
      description: `Measured ${total.toLocaleString("en-US")} words total, ${lower.toLocaleString("en-US")} after subtracting ${excluded.toLocaleString("en-US")} words of detected excludable blocks — a margin of ${(limit.value - lower).toLocaleString("en-US")} words under the limit.`,
      explanation: `This tool's count is an estimate; the filer's word-processing software count governs for the ${cite.source} certification.`,
      citations: [cite],
    });
  },
};

// FILE-002 — Page limit, only where pages are measurable.
export const FILE_002: Rule = {
  id: "FILE-002",
  version: "1.0.0",
  name: "Page limit within the profile",
  category: "filing",
  default_severity: "critical",
  description:
    "Checks the page count against the profile's page limit. Evaluates only when the ingest carries a real page count (PDF); for DOCX it reports that page count is not measurable rather than estimating.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const opts = readFilingOptions(ctx);
    if (!opts) return null;
    const limit =
      opts.brief_kind === "reply"
        ? opts.profile.limits.reply_pages
        : opts.profile.limits.principal_pages;
    if (!limit) return null;
    const cite = profileCitation(limit);
    if (opts.source !== "pdf" || opts.page_count === undefined) {
      return finding(ctx, FILE_002, {
        severity: "info",
        title: "Page count not measurable for this input",
        description: `The profile carries a ${limit.value}-page limit, but page count is not measurable from a ${opts.source.toUpperCase()} file — only a PDF's rendered pages are counted.`,
        explanation: `Vaulytica does not estimate page count from reflowable text; verify the page limit against the filed PDF per ${cite.source}.`,
        citations: [cite],
      });
    }
    if (opts.page_count > limit.value) {
      return finding(ctx, FILE_002, {
        severity: "critical",
        title: `Over the ${limit.value}-page limit`,
        description: `The PDF has ${opts.page_count} pages, over the ${limit.value}-page limit.`,
        explanation: `Page-limit briefs must fit the profile's page safe harbor per ${cite.source}.`,
        recommendation: `Reduce to ${limit.value} pages or use the word-count safe harbor with a certificate of compliance.`,
        citations: [cite],
      });
    }
    return finding(ctx, FILE_002, {
      severity: "info",
      title: `Within the ${limit.value}-page limit`,
      description: `The PDF has ${opts.page_count} pages, within the ${limit.value}-page limit.`,
      explanation: `Page count read from the rendered PDF; verify against ${cite.source}.`,
      citations: [cite],
    });
  },
};

/** Presence check for one required block, built as a FILE-### rule. */
function presenceRule(id: string, block: FilingBlock, name: string, label: string): Rule {
  const rule: Rule = {
    id,
    version: "1.0.0",
    name,
    category: "filing",
    default_severity: "warning",
    description: `Presence check: reports whether a ${label} was detected, when the selected court profile requires one. Never certifies the filing compliant.`,
    dkb_citations: [],
    applies_to_playbooks: GATE,
    check(ctx: RuleContext): Finding | null {
      const opts = readFilingOptions(ctx);
      if (!opts) return null;
      const req = opts.profile.required_blocks.find((b) => b.block === block);
      if (!req) return null; // this profile does not require the block
      const present = detectFilingBlocks(ctx.tree).some((b) => b.block === block);
      const cite = profileCitation(req);
      if (present) {
        return finding(ctx, rule, {
          severity: "info",
          title: `${label} — found`,
          description: `A ${label} was detected by heading/text pattern.`,
          explanation: `Detected by pattern; confirm it satisfies ${req.cite}. Presence here is not a compliance certification.`,
          citations: [cite],
        });
      }
      return finding(ctx, rule, {
        severity: "warning",
        title: `${label} — not detected`,
        description: `No ${label} was detected; ${req.cite} requires one.`,
        explanation: `A ${label} could not be located by pattern match. Confirm one is present and correctly labeled.`,
        recommendation: `Add a ${label} per ${req.cite}.`,
        citations: [cite],
      });
    },
  };
  return rule;
}

export const FILE_003 = presenceRule(
  "FILE-003",
  "certificate-of-compliance",
  "Certificate of compliance present",
  "certificate of compliance",
);
export const FILE_004 = presenceRule(
  "FILE-004",
  "certificate-of-service",
  "Certificate of service present",
  "certificate of service",
);
export const FILE_005 = presenceRule(
  "FILE-005",
  "table-of-contents",
  "Table of contents present",
  "table of contents",
);
export const FILE_006 = presenceRule(
  "FILE-006",
  "table-of-authorities",
  "Table of authorities present",
  "table of authorities",
);
export const FILE_007 = presenceRule(
  "FILE-007",
  "caption",
  "Caption block present",
  "caption block",
);
export const FILE_008 = presenceRule(
  "FILE-008",
  "signature-block",
  "Signature block present",
  "signature block",
);

export const FILING_RULES: readonly Rule[] = [
  FILE_001,
  FILE_002,
  FILE_003,
  FILE_004,
  FILE_005,
  FILE_006,
  FILE_007,
  FILE_008,
];

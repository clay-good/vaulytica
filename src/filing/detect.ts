/**
 * Deterministic detection of filing blocks (caption, tables, certificates,
 * signature) in a document outline, for the filing-format-lint pack. Detection
 * is heading/text-pattern based over the flattened tree — the same machinery
 * STRUCT-003/016/018 use — never a language model. A block is reported as
 * found (with its section) or not detected; nothing is inferred beyond the
 * pattern match, and the type-volume rule uses the detected excludable blocks
 * to compute a post-exclusion lower bound.
 */

import type { DocumentTree, Section } from "../ingest/types.js";
import { forEachSection } from "../extract/walk.js";
import type { FilingBlock } from "./court-profile.js";

/** Block kinds detection can surface — the required blocks plus excludables. */
export type DetectableBlock = FilingBlock | "cover" | "disclosure-statement";

export type DetectedBlock = {
  block: DetectableBlock;
  section_id: string;
  /** The heading (or matched line) that located the block. */
  where: string;
  /** Words in the block's section (heading + own paragraphs), for exclusion math. */
  words: number;
};

const PATTERNS: ReadonlyArray<{ block: DetectableBlock; re: RegExp }> = [
  { block: "table-of-contents", re: /\btable of contents\b/i },
  { block: "table-of-authorities", re: /\btable of authorities\b/i },
  { block: "certificate-of-compliance", re: /\bcertificate of compliance\b/i },
  { block: "certificate-of-service", re: /\b(?:certificate|proof) of service\b/i },
  { block: "disclosure-statement", re: /\b(?:corporate )?disclosure statement\b/i },
];

/** A court-caption line: a court name or a docket number near the top. */
const CAPTION_RE =
  /\b(?:in the .{0,40}court|court of appeal|supreme court|united states .{0,30}court)\b|\b(?:case|docket|no\.)\s*[:.]?\s*[\dcvCV]/i;

/** A cover-page signal: the brief's own title / party role. */
const COVER_RE = /\bbrief (?:of|for)\b|\b(?:appellant|appellee|petitioner|respondent)\b/i;

/** A signature block: a submission line plus a signer. */
const SIG_RE = /\brespectfully submitted\b|(?:^|\n)\s*\/s\/|\b(?:attorney|counsel) for\b/i;

/** Word count of a section's own heading + paragraphs (mirrors countWords). */
function wordsInSection(s: Section): number {
  let n = 0;
  if (s.heading) n += s.heading.trim().split(/\s+/).filter(Boolean).length;
  for (const p of s.paragraphs) {
    for (const r of p.runs) n += r.text.trim().split(/\s+/).filter(Boolean).length;
  }
  return n;
}

/** Full text of a section (heading + paragraphs), for pattern matching. */
function sectionText(s: Section): string {
  const parts: string[] = [];
  if (s.heading) parts.push(s.heading);
  for (const p of s.paragraphs) parts.push(p.runs.map((r) => r.text).join(""));
  return parts.join("\n");
}

/**
 * Detect every filing block present in the document. Returns at most one entry
 * per block kind (first match in document order). Caption, cover, and the
 * signature block are located by content signal; the tabular/certificate
 * blocks by their canonical headings.
 */
export function detectFilingBlocks(tree: DocumentTree): DetectedBlock[] {
  const found = new Map<DetectableBlock, DetectedBlock>();
  const sections: Section[] = [];
  forEachSection(tree, (s) => sections.push(s));

  const record = (block: DetectableBlock, s: Section, where: string): void => {
    if (found.has(block)) return;
    found.set(block, { block, section_id: s.id, where: where.slice(0, 120), words: wordsInSection(s) });
  };

  sections.forEach((s, i) => {
    const text = sectionText(s);
    for (const { block, re } of PATTERNS) {
      const m = re.exec(text);
      if (m) record(block, s, s.heading || m[0]);
    }
    // Caption / cover live in the first few sections.
    if (i < 3) {
      if (CAPTION_RE.test(text)) record("caption", s, s.heading || "caption");
      if (COVER_RE.test(text)) record("cover", s, s.heading || "cover");
    }
    if (SIG_RE.test(text)) record("signature-block", s, s.heading || "signature");
  });

  return [...found.values()];
}

/** Convenience: the set of block kinds detected. */
export function detectedBlockSet(tree: DocumentTree): Set<DetectableBlock> {
  return new Set(detectFilingBlocks(tree).map((b) => b.block));
}

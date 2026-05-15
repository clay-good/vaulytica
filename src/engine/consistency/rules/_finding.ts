/**
 * Helpers for shaping {@link ConsistencyFinding}s from cross-document
 * rules. Keeps the rule files focused on the *what* (the conflict) rather
 * than the *how* (the serialization shape).
 */

import type { ParagraphContext } from "../../../extract/walk.js";
import type {
  ConsistencyDocument,
  ConsistencyExcerpt,
  ConsistencyFinding,
  ConsistencyRule,
} from "../types.js";
import type { SourceCitation } from "../../../dkb/types.js";

export function paragraphExcerpt(
  doc: ConsistencyDocument,
  p: ParagraphContext,
): ConsistencyExcerpt {
  return {
    doc_id: doc.doc_id,
    source_file_name: doc.source_file_name,
    text: p.text,
    section_id: p.section.id || undefined,
    start_offset: p.start,
    end_offset: p.end,
  };
}

export function textExcerpt(
  doc: ConsistencyDocument,
  text: string,
  start_offset: number = 0,
  end_offset: number = text.length,
): ConsistencyExcerpt {
  return {
    doc_id: doc.doc_id,
    source_file_name: doc.source_file_name,
    text,
    start_offset,
    end_offset,
  };
}

export function makeConsistencyFinding(args: {
  rule: ConsistencyRule;
  title: string;
  description: string;
  explanation: string;
  recommendation?: string;
  source_citations?: SourceCitation[];
  excerpts: ConsistencyExcerpt[];
}): ConsistencyFinding {
  const first = args.excerpts[0]!;
  return {
    id: `${args.rule.id}-${first.doc_id}-${first.start_offset}`,
    rule_id: args.rule.id,
    rule_version: args.rule.version,
    severity: args.rule.default_severity,
    title: args.title,
    description: args.description,
    explanation: args.explanation,
    recommendation: args.recommendation,
    source_citations: args.source_citations ?? [],
    excerpts: args.excerpts,
  };
}

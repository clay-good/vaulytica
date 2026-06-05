import type { DocumentTree } from "../ingest/types.js";
import type { Obligation, Party } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Extract every modal-verb obligation from the document.
 *
 * For each sentence containing a deontic modal we parse:
 *   - obligor: the subject of the modal verb (typically a party name or
 *     a defined role like "Provider" / "Customer");
 *   - action: the verb phrase following the modal;
 *   - trigger: any leading `upon`, `if`, `when`, `promptly after` clause;
 *   - qualifier: any `subject to`, `except`, `provided that` clause.
 *
 * This is the LEXDEMOD pattern simplified to deterministic regex. It is
 * intentionally conservative — when we cannot pull a clean obligor, we
 * emit the obligation with `obligor: ""` so the rule engine can flag it
 * via OBLI-001.
 */

// Order matters: multi-word and negative/permissive boundary modals
// precede the bare modals so "may not" / "is required to" win over a
// shorter overlap. (v7 §8: modal completeness.)
const MODALS = [
  "may not",
  "is required to",
  "is permitted to",
  "is prohibited from",
  "cannot",
  "shall",
  "must",
  "will",
  "agrees to",
  "is responsible for",
  "is obligated to",
  "undertakes to",
  "hereby covenants",
];

const MODAL_RE = new RegExp(
  String.raw`\b(${MODALS.join("|").replace(/ /g, "\\s+")})\b`,
  "gi",
);

const TRIGGER_RE =
  /\b(upon\s[^,;.]+|if\s[^,;.]+|when\s[^,;.]+|promptly\s+after\s[^,;.]+|within\s+(?:\d+|\w+(?:[-\s]\w+)?)\s*(?:\(\d+\)\s*)?(?:business\s+)?(?:days?|weeks?|months?|years?)\b[^,;.]*)/i;

const QUALIFIER_RE =
  /\b(subject\s+to\s[^,;.]+|except\s[^,;.]+|provided\s+that\s[^,;.]+|provided,\s+however,\s+that\s[^,;.]+)/i;

export function extractObligations(tree: DocumentTree, parties: Party[]): Obligation[] {
  const partyNames = new Set(parties.map((p) => p.name.toLowerCase()));
  const partyRoles = new Set(
    parties.flatMap((p) => (p.role ? [p.role.toLowerCase()] : [])),
  );

  const out: Obligation[] = [];
  let counter = 0;
  const nextId = (): string => `obli-${++counter}`;

  forEachParagraph(tree, (ctx) => {
    const sentences = splitSentences(ctx.text);
    for (const { text: sentence, start } of sentences) {
      MODAL_RE.lastIndex = 0;
      const m = MODAL_RE.exec(sentence);
      if (!m) continue;
      const modal = m[1]!.toLowerCase().replace(/\s+/g, " ");
      const subject = sentence.slice(0, m.index).trim();
      const predicate = sentence.slice(m.index + m[0].length).trim();
      const obligor = resolveObligor(subject, partyNames, partyRoles);
      const obligorExclusion = scopeExclusion(subject);
      const trigger = TRIGGER_RE.exec(predicate)?.[0]?.trim();
      const nested = trigger ? decomposeNestedTriggers(trigger) : undefined;
      const qualifier = QUALIFIER_RE.exec(predicate)?.[0]?.trim();
      let action = predicate;
      if (trigger) action = action.replace(trigger, "").trim();
      if (qualifier) action = action.replace(qualifier, "").trim();
      action = action.replace(/[.,;]$/, "").trim();

      out.push({
        id: nextId(),
        obligor,
        action,
        trigger,
        qualifier,
        ...(nested ? { nested_triggers: nested } : {}),
        ...(obligorExclusion ? { obligor_exclusion: obligorExclusion } : {}),
        modal,
        raw_text: sentence.trim(),
        position: posInParagraph(ctx, start, start + sentence.length),
      });
    }
  });

  return out;
}

/**
 * Decompose a nested trigger into its chain of sub-conditions. A
 * trigger like "within 60 days of the date that the other party
 * provides notice that it has received the goods" carries two embedded
 * "that …" conditions; extraction otherwise keeps only the top level.
 * Returns the ordered sub-clauses, or undefined when there is no nesting.
 */
function decomposeNestedTriggers(trigger: string): string[] | undefined {
  const parts = trigger
    .split(/\bthat\b/i)
    .map((p) => p.replace(/^[\s,]+|[\s,]+$/g, ""))
    .filter((p) => p.length > 0);
  return parts.length >= 2 ? parts : undefined;
}

/**
 * Capture a scope-narrowing exclusion in the obligor subject:
 * "Each party except the Provider shall …" → "Provider".
 */
function scopeExclusion(subject: string): string | undefined {
  const m = /\bexcept\s+(?:for\s+)?(?:the\s+)?([A-Za-z][\w .'’-]{1,40}?)\s*$/i.exec(
    subject.replace(/[,;]\s*$/, "").trim(),
  );
  if (!m) return undefined;
  return m[1]!.replace(/[\s.]+$/, "").trim() || undefined;
}

function splitSentences(text: string): { text: string; start: number }[] {
  const out: { text: string; start: number }[] = [];
  const re = /[^.!?]+[.!?]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({ text: m[0], start: m.index });
  }
  if (out.length === 0 && text.trim().length > 0) {
    out.push({ text, start: 0 });
  }
  return out;
}

function resolveObligor(
  subject: string,
  partyNames: Set<string>,
  partyRoles: Set<string>,
): string {
  const trimmed = subject.replace(/^[,;.\s]+|[,;.\s]+$/g, "");
  const lower = trimmed.toLowerCase();
  // Direct party-name match.
  for (const name of partyNames) {
    if (lower.endsWith(name)) {
      return findOriginalCasing(trimmed, name);
    }
  }
  for (const role of partyRoles) {
    if (lower.endsWith(role) || lower.endsWith(`the ${role}`)) {
      return findOriginalCasing(trimmed, role);
    }
  }
  if (/\b(?:the\s+parties|each\s+party|either\s+party)\b/i.test(trimmed)) {
    return "the parties";
  }
  // Last-resort: the last 2–6 words of the subject.
  const words = trimmed.split(/\s+/).filter(Boolean);
  if (words.length === 0) return "";
  return words.slice(Math.max(0, words.length - 6)).join(" ");
}

function findOriginalCasing(source: string, lowerNeedle: string): string {
  const idx = source.toLowerCase().lastIndexOf(lowerNeedle);
  if (idx < 0) return lowerNeedle;
  return source.slice(idx, idx + lowerNeedle.length);
}

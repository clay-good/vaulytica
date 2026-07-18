import type { DocumentTree } from "../ingest/types.js";
import type { Obligation, Party } from "./types.js";
import { forEachParagraph, posInParagraph, trimEdges } from "./walk.js";

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

const MODAL_RE = new RegExp(String.raw`\b(${MODALS.join("|").replace(/ /g, "\\s+")})\b`, "gi");

const TRIGGER_RE =
  /\b(upon\s[^,;.]+|if\s[^,;.]+|when\s[^,;.]+|promptly\s+after\s[^,;.]+|within\s+(?:\d+|\w+(?:[-\s]\w+)?)\s*(?:\(\d+\)\s*)?(?:business\s+)?(?:days?|weeks?|months?|years?)\b[^,;.]*)/i;

const QUALIFIER_RE =
  /\b(subject\s+to\s[^,;.]+|except\s[^,;.]+|provided\s+that\s[^,;.]+|provided,\s+however,\s+that\s[^,;.]+)/i;

export function extractObligations(tree: DocumentTree, parties: Party[]): Obligation[] {
  const partyNames = new Set(parties.map((p) => p.name.toLowerCase()));
  const partyRoles = new Set(parties.flatMap((p) => (p.role ? [p.role.toLowerCase()] : [])));

  const out: Obligation[] = [];
  let counter = 0;
  const nextId = (): string => `obli-${++counter}`;

  forEachParagraph(tree, (ctx) => {
    const sentences = splitSentences(ctx.text);
    for (const { text: sentence, start } of sentences) {
      // A single sentence can carry more than one obligation when independent
      // clauses are coordinated ("Provider shall deliver …, and Customer shall
      // pay …"). Split into per-modal clauses so the second obligation is not
      // dropped and its text absorbed into the first (v7 §8 follow-up).
      for (const cl of splitModalClauses(sentence)) {
        const modal = cl.modal.toLowerCase().replace(/\s+/g, " ");
        const subject = cl.subject;
        const predicate = cl.predicate;
        const obligorExclusion = scopeExclusion(subject);
        // Resolve the obligor from the subject with any "except <party>"
        // carve-out removed — otherwise the trailing excluded name wins the
        // `endsWith` match and the EXCLUDED party is reported as the obligor
        // ("Each party except the Provider" → obligor "Provider").
        const subjectForObligor = obligorExclusion
          ? subject.replace(/\bexcept\b[\s\S]*$/i, "").trim()
          : subject;
        const obligor = resolveObligor(subjectForObligor, partyNames, partyRoles);
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
    }
  });

  return out;
}

/**
 * Split a sentence into independent modal-verb clauses. A single modal yields
 * one clause byte-identical to the pre-split behavior (subject before the
 * modal, predicate after). A second modal starts a NEW clause only when a
 * comma-and / semicolon boundary separates it from the previous clause AND a
 * non-empty new subject sits between that boundary and the modal — so a bare
 * "goods and services" or an elided subject ("shall deliver and shall install")
 * does not over-split, and a subordinate "goods that the Customer shall inspect"
 * is kept with the first obligation. Conservative by design: an ambiguous
 * coordination stays one obligation rather than fabricating a second.
 */
function splitModalClauses(
  sentence: string,
): { subject: string; predicate: string; modal: string }[] {
  const modals: { index: number; len: number; text: string }[] = [];
  MODAL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MODAL_RE.exec(sentence)) !== null) {
    modals.push({ index: m.index, len: m[0].length, text: m[1]! });
  }
  if (modals.length === 0) return [];

  const CONJ = /(?:,\s+and\s+|;\s+and\s+|;\s+)/gi;
  // Each clause records where its subject starts and which modal it owns.
  const clauses: { subjectStart: number; modal: (typeof modals)[number]; predEnd?: number }[] = [
    { subjectStart: 0, modal: modals[0]! },
  ];
  for (let k = 1; k < modals.length; k += 1) {
    const prev = clauses[clauses.length - 1]!.modal;
    const regionStart = prev.index + prev.len;
    const region = sentence.slice(regionStart, modals[k]!.index);
    CONJ.lastIndex = 0;
    let last: RegExpExecArray | null = null;
    let cm: RegExpExecArray | null;
    while ((cm = CONJ.exec(region)) !== null) last = cm;
    if (!last) continue; // no clause boundary → subordinate modal, keep merged
    const subjectStart = regionStart + last.index + last[0].length;
    if (sentence.slice(subjectStart, modals[k]!.index).trim().length === 0) continue; // elided subject
    clauses[clauses.length - 1]!.predEnd = regionStart + last.index;
    clauses.push({ subjectStart, modal: modals[k]! });
  }

  return clauses.map((c) => ({
    subject: sentence.slice(c.subjectStart, c.modal.index).trim(),
    predicate: sentence.slice(c.modal.index + c.modal.len, c.predEnd ?? sentence.length).trim(),
    modal: c.modal.text,
  }));
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
    .map((p) => trimEdges(p, /[\s,]/))
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
  return trimEdges(m[1]!, /[\s.]/).trim() || undefined;
}

function splitSentences(text: string): { text: string; start: number }[] {
  // An O(n) manual scan, byte-for-byte equivalent to the prior
  // `/[^.!?]+[.!?]+/g` (a maximal run of non-terminators followed by ≥1
  // terminator). That global regex is O(n²) on a paragraph with NO `.!?`
  // terminator (a long clause, or a hostile run of commas/hyphens/digits): at
  // every start position the greedy `[^.!?]+` scans to end, then the required
  // `[.!?]+` fails and backtracks uselessly — a ReDoS hang (spec-v8 §5). The
  // scan emits the same spans: leading terminators are skipped, a span needs ≥1
  // non-terminator then ≥1 terminator, and an unterminated trailing remainder is
  // dropped (the whole-text fallback below covers the no-sentence case).
  const out: { text: string; start: number }[] = [];
  const isTerm = (c: string): boolean => c === "." || c === "!" || c === "?";
  let i = 0;
  const n = text.length;
  while (i < n) {
    while (i < n && isTerm(text[i]!)) i += 1; // skip leading terminators
    if (i >= n) break;
    const start = i;
    while (i < n && !isTerm(text[i]!)) i += 1; // [^.!?]+
    if (i >= n) break; // no terminator follows → unterminated remainder, dropped
    while (i < n && isTerm(text[i]!)) i += 1; // [.!?]+
    out.push({ text: text.slice(start, i), start });
  }
  if (out.length === 0 && text.trim().length > 0) {
    out.push({ text, start: 0 });
  }
  return out;
}

function resolveObligor(subject: string, partyNames: Set<string>, partyRoles: Set<string>): string {
  const trimmed = trimEdges(subject, /[,;.\s]/);
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

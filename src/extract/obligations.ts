import type { DocumentTree } from "../ingest/types.js";
import type { Obligation, Party } from "./types.js";
import {
  ABBREV_BEFORE_NUMBER,
  forEachParagraph,
  posInParagraph,
  trimEdges,
  trimEnd,
} from "./walk.js";

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
  // Plural subjects state the same duty in the "are …" form — "the parties are
  // required to maintain insurance". Only the singular forms were listed, so a
  // plainly-stated multi-party obligation went unextracted.
  "are required to",
  "is permitted to",
  "are permitted to",
  "is prohibited from",
  "are prohibited from",
  "cannot",
  "shall",
  "must",
  "will",
  // "agrees to" (substantive: "Provider agrees to defend"). The PLURAL "agree
  // to" is deliberately NOT here — "the parties agree to the following terms"
  // is contract-formation boilerplate, not a substantive obligation.
  "agrees to",
  "is responsible for",
  "are responsible for",
  "is obligated to",
  "are obligated to",
  "undertakes to",
  // A covenant IS a binding promise, so "covenants to <verb>" is always a
  // substantive obligation. The multi-verb "covenants and agrees to" form is
  // listed first so the obligor is not truncated to "… covenants and".
  "covenants and agrees to",
  "covenant and agree to",
  "covenants to",
  "covenant to",
  "hereby covenants",
];

const MODAL_RE = new RegExp(String.raw`\b(${MODALS.join("|").replace(/ /g, "\\s+")})\b`, "gi");

const TRIGGER_RE =
  /\b(upon\s[^,;.]+|if\s[^,;.]+|when\s[^,;.]+|promptly\s+after\s[^,;.]+|within\s+(?:\d+|\w+(?:[-\s]\w+)?)\s*(?:\(\d+\)\s*)?(?:business\s+)?(?:hours?|days?|weeks?|months?|years?)\b[^,;.]*)/i;

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
        // A run, not one character: excising the trigger clause leaves behind
        // the comma that separated it from the main clause, so a sentence with
        // BOTH a trigger and a qualifier ("…shall deliver the Deliverables
        // within thirty (30) days of the Effective Date, subject to …") ended
        // up as "deliver the Deliverables ," — the single-character strip took
        // the sentence's own period and left the stranded comma behind it.
        //
        // Trimmed by scan rather than by `/[\s.,;]+$/`, which is quadratic: an
        // unanchored trailing-run pattern retries from every index, so a
        // pathological all-commas paragraph took ~19s where the budget is 2s.
        // The fuzz-boundary guard (spec-v8 §5) catches exactly this.
        action = trimEnd(action, /[\s.,;]/);
        // The mirror image: a modal followed by a fronted clause ("Provider
        // shall, no later than 5:00 p.m. …, deliver the Deliverables") starts
        // the predicate at the comma, so the action read ", no later than …".
        // Only leading separators are trimmed — a leading "." never occurs
        // here, and trimming one would eat a decimal.
        action = trimEdges(action, /[\s,;]/);
        // The same excision leaves a seam MID-string when the cut clause sat
        // between two others: "shall deliver the Deliverables, provided that
        // the Client has paid the Deposit, no later than 30 days after
        // execution" loses the middle clause and reads "deliver the
        // Deliverables, , no later than …". Collapse the doubled separator.
        action = action.replace(/,\s*,/g, ",");

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

  // The `.\s+` alternative recovers a duty stranded when splitSentences kept an
  // ambiguous abbreviation ("5:00 p.m. The Provider shall …") in one sentence.
  // It has to know the same abbreviations splitSentences does, or it undoes that
  // work one stage later: "described in Ex. 4 of this Agreement and Client shall
  // pay …" split at "Ex." and handed the second duty the obligor "4 of this
  // Agreement and Client".
  const CONJ = new RegExp(
    String.raw`(?:,\s+and\s+|;\s+and\s+|;\s+|(?<!\b(?:${ABBREV_BEFORE_NUMBER})\b)\.\s+)`,
    "gi",
  );
  // Anchored, so it fires only when the candidate new subject BEGINS with the
  // proviso — "the fee, provided that …" mid-subject is untouched.
  const PROVISO_LEAD = /^provided\s*,?\s*(?:however\s*,?\s*)?that\b/i;
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
    // A proviso carries its own modal, so the semicolon boundary split it into
    // a second obligation — and the split dropped the negation with it.
    // "Customer shall have the right to inspect Provider's records; provided
    // that any such inspection shall not unreasonably interfere with
    // Provider's business operations" produced a phantom duty whose obligor
    // was the literal words "provided that any such inspection" and whose
    // action read as an affirmative duty TO interfere — the inversion of what
    // the clause says.
    //
    // Which repair is right depends on the proviso. A NEGATED one restricts
    // the clause before it and states no duty of its own, so it is kept merged
    // and QUALIFIER_RE records it as the first obligation's `qualifier`. An
    // AFFIRMATIVE one ("; provided that Customer shall pay all undisputed fees
    // within thirty days") is a genuine second duty, so it still splits —
    // suppressing that would lose a real obligation, as an adversarial pass
    // showed. Either way the lead-in is stripped off the subject, which also
    // fixes the obligor it used to corrupt ("provided that Customer").
    const provisoLead = PROVISO_LEAD.exec(sentence.slice(subjectStart, modals[k]!.index));
    let clauseStart = subjectStart;
    if (provisoLead) {
      const after = sentence.slice(modals[k]!.index + modals[k]!.len);
      if (/^\s*(?:not|never)\b/i.test(after)) continue; // restriction → qualifier
      clauseStart = subjectStart + provisoLead[0].length;
    }
    if (sentence.slice(clauseStart, modals[k]!.index).trim().length === 0) continue; // elided subject
    clauses[clauses.length - 1]!.predEnd = regionStart + last.index;
    clauses.push({ subjectStart: clauseStart, modal: modals[k]! });
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
  const n = text.length;
  // `!`/`?` always end a sentence. A `.` does NOT: it also writes decimals
  // ("$5.00"), hosts ("vendor.com") and abbreviations ("5:00 p.m.", "123 Main
  // St.", "U.S."), and treating every one as a terminator truncated real
  // obligations. "Provider shall deliver notice no later than 5:00 p.m.
  // Eastern Time on the Delivery Date" recorded the action as "deliver notice
  // no later than 5:00 p" and silently DROPPED the rest as an unterminated
  // remainder; worse, a split at "St." in an address left the next "sentence"
  // starting mid-clause, so a following obligation resolved its obligor to the
  // fragment "Suite 400, and".
  //
  // The rule, shared in spirit with `SENTENCE_END` in ./walk.ts: a sentence
  // ends where the next one STARTS — whitespace + a capital or digit — or at
  // the end of the text. So "$5.00", "vendor.com" and "123 Main St., Suite
  // 400" no longer end a sentence, which is what used to truncate an
  // obligation's action and hand the next one an obligor of "Suite 400, and".
  //
  // An abbreviation followed by a CAPITAL is left as a boundary on purpose.
  // It is ambiguous — "5:00 p.m. Eastern Time" is one sentence, "5:00 p.m. The
  // Provider shall then execute…" is two — and an earlier version that
  // suppressed it merged the second shape, swallowing the Provider's duty into
  // the previous sentence's action and reporting the obligor as "Notice".
  // Losing a whole obligation is worse than cutting one short, so the boundary
  // stands; walk.ts documents the same call at more length for the rule
  // helpers, which reached it from the other direction.
  //
  // The check is O(1) and local, so the O(n) scan — and the ReDoS property it
  // exists for — is preserved.
  const ABBREV_RE = new RegExp(String.raw`\b(?:${ABBREV_BEFORE_NUMBER})$`);
  const isTerm = (i: number): boolean => {
    const c = text[i]!;
    if (c === "!" || c === "?") return true;
    if (c !== ".") return false;
    if (i >= 2 && /[a-z]/.test(text[i - 1]!) && text[i - 2] === ".") return false;
    let j = i + 1;
    let sawSpace = false;
    while (j < n && (text[j] === " " || text[j] === "\t" || text[j] === "\n" || text[j] === "\r")) {
      sawSpace = true;
      j += 1;
    }
    if (j >= n) return true; // trailing period closes the last sentence
    if (!sawSpace) return false; // "$5.00", "vendor.com", "p.m"
    // A cross-reference or date abbreviation before its number is not a
    // sentence end — "described in Ex. 4", "in accordance with Sec. 7", "by
    // Jan. 5". Splitting there truncated the action at "…described in Ex" and
    // dropped the rest as an unterminated remainder. Same list, and so the same
    // answer, as SENTENCE_END in ./walk.js; the two had drifted apart.
    if (text[j]! >= "0" && text[j]! <= "9") {
      return !ABBREV_RE.test(text.slice(Math.max(0, i - 6), i));
    }
    return /[A-Z]/.test(text[j]!);
  };
  let i = 0;
  while (i < n) {
    while (i < n && isTerm(i)) i += 1; // skip leading terminators
    if (i >= n) break;
    const start = i;
    while (i < n && !isTerm(i)) i += 1; // [^.!?]+
    if (i >= n) break; // no terminator follows → unterminated remainder, dropped
    while (i < n && isTerm(i)) i += 1; // [.!?]+
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
  // A compound subject naming TWO parties ("The Provider and the Customer shall
  // each …", "Acme Corp. and Globex Inc. shall jointly …") states a MUTUAL
  // obligation. The endsWith matches below key on the tail of the subject, so
  // they would attribute the whole duty to whichever party happens to sit last
  // — making OBLI-002 read a shared obligation as one-sided (a false asymmetry).
  // When the "and"-joined segments each resolve to a known party/role, the duty
  // is borne by both, so it resolves to "the parties" like "each party" does.
  const segments = lower.split(/\s+and\s+/);
  if (segments.length >= 2) {
    const resolvedCount = segments.filter((seg) => {
      const t = seg.trim();
      for (const name of partyNames) if (t.endsWith(name)) return true;
      for (const role of partyRoles) if (t.endsWith(role) || t.endsWith(`the ${role}`)) return true;
      return false;
    }).length;
    if (resolvedCount >= 2) return "the parties";
  }
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

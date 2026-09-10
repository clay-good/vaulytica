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
  // The negative of "is permitted to", and the one OBLI-005's own comment named
  // as missing: "Employee is not permitted to disclose" is the identical
  // restriction as "Employee shall not disclose". Measured 2026-09-08 by
  // rewriting `shall not` across the corpus — **66 of the 121 documents that
  // write a prohibition lost OBLI-005 entirely**, because the obligation was
  // never extracted at all. It sits before "is permitted to" so the negative
  // wins the overlap, which is what the ordering note above is for.
  "is not permitted to",
  "are not permitted to",
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
        const predicate = cl.predicate;
        // `except` has two grammars and they point at OPPOSITE parties, so
        // the subject is resolved before either is applied.
        const subject = exceptProvisoSubject(cl.subject);
        const obligorExclusion = scopeExclusion(subject);
        // A trailing `except …` always comes off before the obligor is
        // resolved, whether or not it named a party — otherwise the tail wins
        // the `endsWith` match and the obligor reads "Each party except the
        // Provider" → "Provider", or "…any statutory share, except as
        // provided in a". Stripping and RECORDING are separate questions: an
        // `except` clause is a qualifier on the duty, and only an `except`
        // PHRASE naming a party is a carve-out `scopeExclusion` reports.
        const subjectForObligor = stripExceptTail(subject);
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

        // A MODAL WITH NO VERB PHRASE AFTER IT IS NOT AN OBLIGATION. "will" is
        // also a noun, and legal documents are where it is one: "employment
        // with the Company is at will", "any trust created under this Will",
        // "by beneficiary designation, or by will". Each produced a row whose
        // obligor was a sentence fragment ("employment with the Company is at")
        // and whose ACTION WAS EMPTY — "who must do what", with the what
        // missing, printed straight into the obligations ledger a lawyer reads.
        //
        // The trigger/qualifier test is what keeps this narrow. An action can
        // also come back empty because the TRIGGER swallowed the verb phrase
        // ("you must within 10 days after recording send a copy…", where the
        // trigger pattern's tail runs to the sentence end) — that row names a
        // real duty and is kept. Only a modal with nothing after it at all is
        // dropped. 7 of the corpus's 8 empty actions are the noun; the eighth
        // is that swallowed trigger, and it survives.
        if (!action && !trigger && !qualifier) continue;

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
    // A HYPHEN IS A WORD BOUNDARY, so the `\b` in MODAL_RE opens inside a
    // hyphenated compound and "at-will" reads as the modal "will". Employment
    // documents are full of it, and the resulting row is not a near-miss but
    // nonsense: "No provision of this Agreement alters the at-will nature of
    // the employment" became obligor "of this Agreement alters the at-",
    // action "nature of the employment", and a section heading "Term; At-Will
    // Employment." became a duty to do "Employment". 22 rows across 13
    // specimens, every one false, and none reachable by the empty-action guard
    // below because the compound's SECOND half supplies a plausible action.
    //
    // The test is a hyphen with a word character before it — a genuine
    // compound. A dash that OPENS a clause ("— shall pay") is not one, and an
    // em-dash is not a hyphen at all.
    if (m.index > 0 && /\w[-\u2010\u2011]$/.test(sentence.slice(0, m.index))) continue;
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
 * `except` has two grammars, and they name OPPOSITE parties.
 *
 * As a PREPOSITION it narrows the subject — "Each party except the Provider
 * shall maintain insurance" — and the carve-out must come off before the
 * obligor is resolved, or the trailing excluded name wins the `endsWith`
 * match and the one party that does not owe the duty is reported as owing it.
 * That is `scopeExclusion` below.
 *
 * As a SUBORDINATOR (`except that`) it opens a PROVISO carrying its own
 * subject and its own duty, and stripping there is the same inversion one step
 * further on: it deletes the real obligor and leaves the `endsWith` match to
 * land on whoever the clause BEFORE happened to name. "OEM may label the
 * Products under OEM's own brand and need not identify Supplier, except that
 * OEM shall not remove any Supplier notice" reported SUPPLIER as owing a duty
 * not to remove Supplier's own notice — the duty is OEM's, and it is owed TO
 * Supplier. Eight of the corpus's eleven `except` subjects were misattributed
 * this way, and the obligations ledger is a CSV a lawyer reads.
 *
 * `splitModalClauses` already draws exactly this distinction for `provided
 * that` (PROVISO_LEAD, "which also fixes the obligor it used to corrupt").
 * This is the same repair for `except`, which never got it.
 */
const EXCEPT_THAT = /\bexcept\s+that\b/i;

function exceptProvisoSubject(subject: string): string {
  const m = EXCEPT_THAT.exec(subject);
  if (!m) return subject;
  const after = subject.slice(m.index + m[0].length).trim();
  // An `except that` with nothing after it inside this clause is a proviso
  // whose subject was elided; the sentence's own subject still governs.
  return after.length > 0 ? after : subject;
}

/**
 * Take a trailing `except …` off the subject before the obligor is resolved.
 *
 * Whether or not the clause named a party, its tail wins the `endsWith` match
 * otherwise: "Each party except the Provider" resolved to "Provider" — the one
 * party carved out — and "…to any statutory share, except as provided in a"
 * resolved to that fragment.
 *
 * A clause boundary INSIDE the tail means the `except` clause has ENDED and
 * the sentence's real subject follows it, so nothing is stripped: "Nothing in
 * this Declaration prohibits an Owner from installing a solar energy device
 * … except as permitted by Sections 202.010 and 202.007 of the Texas Property
 * Code, and the Board shall …" owes its duty to the Board, and cutting at
 * `except` would leave the obligor reading "energy device or a rain barrel".
 */
function stripExceptTail(subject: string): string {
  const i = subject.search(/\bexcept\b/i);
  if (i < 0) return subject;
  if (/,\s+and\s+|;\s+/.test(subject.slice(i))) return subject;
  return subject.slice(0, i).trim() || subject;
}

/**
 * Function words that open an `except` CLAUSE rather than name a party.
 * "except as provided in a will", "except by will or the laws of descent",
 * "EXCEPT AS THOSE MAY NOT BE EXCLUDED UNDER MANDATORY LAW" — the remaining
 * three corpus `except` subjects, each of which put a cross-reference or a
 * bare preposition into a field whose whole job is to name the party that
 * does NOT owe the duty.
 */
const EXCEPT_NOT_A_PARTY =
  /^(?:as|by|to|for|in|on|with|under|upon|pursuant|where|when|while|insofar|if|and|or|the\s*$)\b/i;

/**
 * Capture a scope-narrowing exclusion in the obligor subject:
 * "Each party except the Provider shall …" → "Provider".
 */
function scopeExclusion(subject: string): string | undefined {
  const m = /\bexcept\s+(?:for\s+)?(?:the\s+)?([A-Za-z][\w .'’-]{1,40}?)\s*$/i.exec(
    subject.replace(/[,;]\s*$/, "").trim(),
  );
  if (!m) return undefined;
  const excluded = trimEdges(m[1]!, /[\s.]/).trim();
  if (!excluded || EXCEPT_NOT_A_PARTY.test(excluded)) return undefined;
  return excluded;
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

/**
 * A sentence that opens with a fronted adverbial puts its SUBJECT after the
 * comma: "Within five (5) business days after the Effective Date, **Seller**
 * shall file the stipulation", "For three (3) years after the Closing, **each
 * Seller** shall not compete", "Until the expiration of four (4) years after
 * the furnishing of the Services, **Medical Director** shall make the records
 * available". The subject capture reaches back to the start of the clause, so
 * the whole adverbial came with it — and the last-resort branch below then
 * published "days after the Effective Date, Seller" as the party who owes the
 * duty, in the findings and in the critical-dates register.
 *
 * Keyed on the opening subordinator, so a genuinely comma-bearing subject is
 * untouched: "Seller, Buyer, and the Company shall" does not start with one.
 *
 * "to the extent" is here; "to the FULLEST extent permitted by law," was not,
 * and that is the opening of nearly every indemnity clause written in the
 * United States. An owner-architect agreement published the obligor of its
 * indemnity as "fullest extent permitted by law, Architect", which matched no
 * party, so OBLI-002 reported that only the Owner indemnified — on a document
 * where the Architect indemnifies the Owner in the very sentence being read.
 */
const FRONTED_ADVERBIAL =
  /^(?:within|for|if|upon|on|before|after|during|notwithstanding|subject\s+to|in\s+the\s+event|at|unless|when|while|except|to\s+the\s+(?:fullest\s+|maximum\s+|greatest\s+|extent\s+)?extent|following|pending|provided|in\s+connection\s+with|in\s+accordance\s+with|from|until|as\s+of|beginning|commencing|so\s+long\s+as|concurrently|promptly|immediately|thereafter|not\s+later\s+than|no\s+later\s+than|between\s+the)\b/i;

function stripFrontedAdverbial(subject: string): string {
  if (!FRONTED_ADVERBIAL.test(subject.trimStart())) return subject;
  const lastComma = subject.lastIndexOf(",");
  if (lastComma < 0) return subject;
  const tail = subject.slice(lastComma + 1).trim();
  return tail.length > 0 ? tail : subject;
}

/**
 * A subordinator is not part of the subject it introduces.
 *
 * "obtain written assurances from the recipient **that** the recipient will
 * notify …" makes the duty the recipient's; the "that" is the conjunction that
 * attaches the clause, and it printed straight into the obligations ledger's
 * obligor column ("that the recipient", "that the Work", "That the Grantor").
 * 11 rows across the corpus, every one a clean improvement.
 *
 * The determiner lookahead is what keeps this off a DEMONSTRATIVE. "that party
 * shall …" is a subject whose first word is doing real work, and stripping it
 * would lose which party. So the strip fires only when a determiner follows —
 * "that **the** recipient", never "that party".
 */
const LEADING_SUBORDINATOR =
  /^(?:that|which|whereby|whereupon)\s+(?=(?:the|a|an|its|his|her|their|our|your|each|any|no|such|all|either|both|every|this|these|those)\s+\S)/i;

function resolveObligor(subject: string, partyNames: Set<string>, partyRoles: Set<string>): string {
  return stripSubordinator(resolveObligorInner(subject, partyNames, partyRoles));
}

function stripSubordinator(obligor: string): string {
  return obligor.replace(LEADING_SUBORDINATOR, "");
}

function resolveObligorInner(
  subject: string,
  partyNames: Set<string>,
  partyRoles: Set<string>,
): string {
  const trimmed = trimEdges(stripFrontedAdverbial(subject), /[,;.\s]/);
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
  //
  // 🚨 This is the branch that makes 8.8% of obligors sentence fragments, and
  // the module header's promise (emit `obligor: ""` so the rule engine can flag
  // it, which is what OBLI-001 exists for) is the opposite of what happens
  // here. Honouring that promise makes OBLI-001 fire on 173 of 312 specimens —
  // 55% — which is either a large true-positive discovery or a large noise
  // addition, and deciding which is a judgment about the product.
  //
  // ⚠️ MEASURED 9.545.0, AND THE OBVIOUS SUB-FIX DOES NOT APPLY. 134 of the
  // corpus's 3,187 obligors end in a COORDINATOR — "SOLE SHAREHOLDER OF THE
  // BORROWER AND", "violates its published advertising policies, and", a bare
  // "AND" — which looks exactly like the seam of a chained predicate
  // ("Provider shall X, and shall Y"), where the right repair is to inherit the
  // previous clause's subject. It is not that: **124 of the 134 sit in a
  // sentence with only ONE modal**, so there is no earlier clause to inherit
  // from. Implemented and measured anyway, subject inheritance in
  // `splitModalClauses` repairs **2**. Reverted rather than shipped — two
  // repairs do not pay for a concept the data does not support. The remaining
  // 124 are subjects that begin mid-sentence, which is the general fragment
  // problem above, not a sub-shape with its own answer.
  const words = trimmed.split(/\s+/).filter(Boolean);
  if (words.length === 0) return "";
  return words.slice(Math.max(0, words.length - 6)).join(" ");
}

function findOriginalCasing(source: string, lowerNeedle: string): string {
  const idx = source.toLowerCase().lastIndexOf(lowerNeedle);
  if (idx < 0) return lowerNeedle;
  return source.slice(idx, idx + lowerNeedle.length);
}

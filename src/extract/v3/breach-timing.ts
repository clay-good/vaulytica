/**
 * v3 breach-notification timing extractor (spec-v3.md §22).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { BreachAddressee, BreachChannel, BreachTiming, BreachTrigger } from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";
import { PERIOD_COUNT, countValue } from "../counts.js";

/**
 * Sentence-scoped: any sentence (period-delimited) that pairs a breach noun with a
 * notification verb in either order. Greedy across `[^.]` lets us scoop the
 * neighborhood that carries trigger/addressee/channel.
 *
 * The breach noun is pluralized (`breach(?:es)?`, `incident(?:s)?`) — a BAA that
 * says "shall report Breaches within sixty (60) days" states its notification
 * duty in the plural, and `\bbreach\b` (boundary after "breach") never matched
 * "Breaches", so the whole clause was dropped.
 */
const BREACH_NOUN = String.raw`breach(?:es)?|security incident(?:s)?|data incident(?:s)?|incident(?:s)?|unauthor(?:i[sz]ed) (?:access|disclosure(?:s)?)`;
const BREACH_RX = new RegExp(
  String.raw`[^.\n]*?\b(?:(?:${BREACH_NOUN})\b[^.\n]*?\b(?:notify|notification|inform|report|disclose)|(?:notify|notification|inform|report|disclose)\b[^.\n]*?\b(?:${BREACH_NOUN}))\b[^.\n]*\.`,
  "i",
);

// Legal drafting states a period as "word (numeral)" — "within seventy-two
// (72) hours", "within two (2) business days" — and the authoritative value is
// the parenthesized numeral. The old `within\s+(\d)` anchored on a digit
// immediately after the connector, so every spelled-out-plus-numeral deadline
// (the dominant form in breach clauses) parsed to a null max_delay_hours. The
// optional `(?:[^.()\d]*?\()?` skips the spelled words up to the numeral's open
// paren; it is bounded by the sentence (no `.`) and by parens (no `(`/`)`), so
// it never reaches a later, unrelated parenthetical, and a plain "within 72
// hours" still matches with the group empty.
const NUMERIC_TIME_RX = new RegExp(
  String.raw`\b(?:within|no later than|no longer than|not (?:to exceed|later than))\s+(${PERIOD_COUNT})\s*(hour|hr|day|business day|calendar day)s?\b`,
  "i",
);

const VAGUE_TIME_RX =
  /\b(without unreasonable delay|without undue delay|promptly|as soon as practicable|as soon as reasonably practicable|immediately)\b/i;

const TRIGGERS: { rx: RegExp; trigger: BreachTrigger }[] = [
  {
    // "identif(y|ying|ication|ied)" (but not "identifiable", as in PII) reads
    // the "upon identifying a breach" form as a discovery trigger.
    rx: /\b(?:upon|after|of|following|on)\s+(?:its )?discovery\b|\bbecoming aware\b|\bidentif(?:y|ies|ying|ication|ied)\b/i,
    trigger: "discovery",
  },
  { rx: /\b(?:once|upon|after)\s+(?:confirm|verif)/i, trigger: "confirmation" },
  { rx: /\bsuspect|\breasonable belief\b/i, trigger: "suspicion" },
  { rx: /\bdetermin/i, trigger: "determination" },
];

const ADDRESSEES: { rx: RegExp; addressee: BreachAddressee }[] = [
  { rx: /\bsupervisory authorit/i, addressee: "regulator" },
  { rx: /\bregulator/i, addressee: "regulator" },
  { rx: /\battorney general\b/i, addressee: "regulator" },
  { rx: /\bdata subject/i, addressee: "data-subject" },
  {
    // US breach-notification statutes address the "affected individuals" —
    // the data subjects by another name (persons, consumers, residents).
    rx: /\baffected (?:individual|person|customer|consumer|party|resident|user)s?\b/i,
    addressee: "data-subject",
  },
  { rx: /\blaw enforcement\b/i, addressee: "law-enforcement" },
  { rx: /\bcontroller\b/i, addressee: "controller" },
  { rx: /\bcovered entity\b/i, addressee: "controller" },
  {
    rx: /\bcustomer(?:['’]s)? (?:named|designated) contact\b|\bdesignated contact\b/i,
    addressee: "customer-named-contact",
  },
];

const CHANNELS: { rx: RegExp; channel: BreachChannel }[] = [
  { rx: /\bemail\b|\be-mail\b/i, channel: "email" },
  { rx: /\bwritten notice\b|\bin writing\b/i, channel: "written-notice" },
  { rx: /\bdesignated contact\b/i, channel: "designated-contact" },
  { rx: /\bby (?:tele)?phone\b|\btelephone\b/i, channel: "phone" },
];

function normalizeToHours(n: number, unit: string): number {
  const u = unit.toLowerCase();
  if (u.startsWith("hour") || u === "hr") return n;
  if (u.includes("day")) return n * 24;
  return n;
}

/**
 * The NAME of a breach-notification regulation is not a breach event.
 *
 * 🚨 A BAA's definitions sentence — "Terms used but not defined here have the
 * meanings given them in the Privacy Rule, the Security Rule, the **Breach
 * Notification Rule**, and the Enforcement Rule at 45 C.F.R. Parts 160 and
 * 164" — carries a breach noun and a notification word in one sentence, which
 * is all `BREACH_RX` asks for. Both BAAs in the corpus recorded a
 * breach-timing obligation from their glossary, with every field
 * "unspecified", in exactly the document type this extractor exists for.
 *
 * Masked rather than excluded, because a sentence may legitimately do both:
 * "shall comply with the Breach Notification Rule and notify Covered Entity
 * within sixty (60) days" is a real obligation, and dropping the whole
 * sentence would lose it. Masking the rule NAME leaves any real breach-plus-
 * notify pair elsewhere in the sentence to match on its own.
 *
 * ⚠️ Equal-length masking (spaces), because `position` is computed from the
 * match index and any other replacement would shift every offset after it.
 */
const BREACH_RULE_NAME =
  /\b(?:(?:security|data|personal\s+information)\s+)?breach\s+notification\s+(?:rules?|acts?|laws?|regulations?|requirements?)\b/gi;

function maskRuleNames(text: string): string {
  return text.replace(BREACH_RULE_NAME, (name) => " ".repeat(name.length));
}

export function extractBreachTimings(tree: DocumentTree): BreachTiming[] {
  const out: BreachTiming[] = [];
  forEachParagraph(tree, (ctx) => {
    const m = BREACH_RX.exec(maskRuleNames(ctx.text));
    if (!m) return;
    const window = m[0];
    const numeric = NUMERIC_TIME_RX.exec(window);
    const vague = numeric ? null : VAGUE_TIME_RX.exec(window);

    const trigger =
      TRIGGERS.find((t) => t.rx.test(window))?.trigger ?? ("unspecified" as BreachTrigger);
    const addressee =
      ADDRESSEES.find((a) => a.rx.test(window))?.addressee ?? ("unspecified" as BreachAddressee);
    const channel =
      CHANNELS.find((c) => c.rx.test(window))?.channel ?? ("unspecified" as BreachChannel);

    out.push({
      trigger,
      addressee,
      max_delay_hours:
        numeric && numeric[1] && numeric[2]
          ? normalizeToHours(countValue(numeric[1]), numeric[2])
          : null,
      max_delay_phrase: vague && vague[1] ? vague[1].toLowerCase() : null,
      channel,
      raw_text: window,
      position: posInParagraph(ctx, m.index, m.index + window.length),
    });
  });
  out.sort((a, b) => a.position.start - b.position.start);
  return out;
}

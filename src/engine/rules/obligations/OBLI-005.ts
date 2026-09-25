import type { Rule, RuleContext, Finding } from "../../finding.js";
import { ATTACHMENT_KIND_PLURAL } from "../../../extract/attachment-kinds.js";
import { INSTRUMENT_NOUN } from "../../../extract/instrument-kinds.js";
import { emit, excerptWindow } from "../_helpers.js";

// "must not <verb>" is a covenant negation the extractor captures but this filter
// did not classify — a "Employee must not disclose" restriction was dropped.
// Bare "cannot" is deliberately NOT added: it reads too broadly, sweeping in
// savings clauses ("rights that cannot be waived") and conditionals ("if the
// importer cannot comply") that are not restrictive covenants. ("is not
// permitted to" needed BOTH halves — the extractor had to capture the form
// before this filter could classify it, which is why widening the filter alone
// would not have surfaced it. Both landed in 9.599.0.)
/**
 * A covenant is negative when THIS OBLIGATION is negative — its own modal
 * carries the negation ("may not", "cannot", "is prohibited from"), or its
 * action opens with one ("shall" + "not remove or obscure …").
 *
 * 🚨 The test used to be `NEG.test(o.raw_text)`, over the whole SENTENCE. A
 * sentence yields one obligation per modal clause, so a negation anywhere in
 * it made every clause in it a "negative covenant" — and an MSA's report
 * listed "Provider represents and warrants that the services will be
 * performed in a professional and workmanlike manner" as one. **83 of 678
 * entries across the corpus were affirmative clauses** sharing a sentence
 * with a negation.
 */
/**
 * The negation must belong to THIS obligation — its modal ("may not", "is
 * prohibited from"), or its own action, whether the action opens with the
 * negation ("shall" + "not engage a subcontractor") or carries it in a
 * coordinated second clause the splitter kept merged ("maintain in strict
 * confidence … and shall not disclose").
 *
 * 🚨 The test used to be over the whole SENTENCE. A sentence yields one
 * obligation per modal clause, so a negation anywhere in it made every clause
 * in it a "negative covenant" — an MSA's report listed "Provider represents
 * and warrants that the services will be performed in a professional and
 * workmanlike manner" as one, twice.
 *
 * 🚨 Bare `cannot` is deliberately NOT here. Every one of the 55 corpus
 * obligations it alone would add is a statement of IMPOSSIBILITY, not a
 * promise to refrain: "the template cannot be reversed", "strictly necessary
 * cookies cannot be switched off", "a missed deadline generally cannot be
 * cured", "if the parties cannot agree, JAMS appoints a neutral arbitrator".
 */
const NEG_MODAL = /\b(?:not|prohibited)\b/i;
const NEG_ACTION = /^not\b/i;
const NEG_PHRASE =
  /\b(?:shall\s+not|may\s+not|must\s+not|(?:is|are)\s+not\s+permitted\s+to|(?:is|are)\s+prohibited\s+from|will\s+not)\b/i;

/**
 * 🚨 **A negative covenant has a PARTY who must not do something.** "Sections
 * 3.2 and 3.3 shall not apply to a transfer by a Key Holder to a trust" and
 * "the Act shall not apply" are SCOPE CARVE-OUTS — the subject is a provision
 * or a statute, and nobody is promising to refrain from anything.
 *
 * `present-indicative.test.ts` named this class and declared one specimen
 * against it rather than correct it in passing; keying on the SUBJECT is what
 * settles it, and the declaration comes off with this change.
 *
 * Keyed on the subject and not the verb, deliberately: "Licensee shall not
 * **apply** to register the Licensed Marks" is a real covenant, and excluding
 * "not apply" would drop it.
 */
// A provision that names itself by what it does is a provision too: "except
// that this LIMITATION shall not apply to fraud" carves out of a cap, and with
// the cap no longer mistaken for a covenant (9.737.0), the metamorphic relation
// in `present-indicative.test.ts` exposed it as one.
const INSTRUMENT_SUBJECT = new RegExp(
  // A fronted conditional keeps its subordinator on the subject ("If the Act
  // shall not apply…"), so one is allowed before the determiner.
  //
  // 🚨 Both vocabularies come from their SINGLE OWNERS. `INSTRUMENT_NOUN`'s
  // own docstring says why — "three separate hand-written subsets of this
  // vocabulary already existed in `_helpers.ts` alone, agreeing with each
  // other only loosely" — and a narrower copy here was caught immediately:
  // written by hand it listed "agreement" and not "contract", so
  // `instrument-vocabulary.test.ts` rewrote one specimen's Agreement as a
  // Contract and the covenant count moved.
  String.raw`^(?:if\s+|when\s+|where\s+|unless\s+)?(?:this\s+|these\s+|the\s+)?(?:sections?|articles?|clauses?|paragraphs?|subsections?|provisions?|limitations?|exclusions?|waivers?|restrictions?|caps?|act\b|statute|law|${ATTACHMENT_KIND_PLURAL}|${INSTRUMENT_NOUN})\b`,
  "i",
);

// 🚨 A cap is not a covenant — and it is no longer an obligation at all. The
// filter that lived here read the OBLIGOR, which the extractor's mutual-subject
// resolution had already turned from "EACH PARTY'S TOTAL LIABILITY" into "the
// parties"; `extractObligations` now drops caps on the raw subject, so this
// rule and the obligations ledger agree.

/**
 * "Damages alone MAY NOT BE AN ADEQUATE remedy" (every injunctive-relief
 * clause) is the same kind of statement, and an English NDA listed it as its
 * one negative covenant.
 *
 * "Material generated without human authorship MAY NOT BE ELIGIBLE for
 * copyright" states a possibility, not a prohibition. Only a status adjective
 * is excluded: "may not be assigned" is still a covenant, in the passive.
 */
const STATUS_ACTION =
  /^be\s+(?:an?\s+)?(?:eligible|entitled|enforceable|protectable|valid|available|possible|adequate|sufficient)\b/i;

/**
 * An instrument that "may not be offered, sold or transferred" is restricted,
 * not describing its own scope. A SAFE's securities legend — "THIS INSTRUMENT
 * AND ANY SECURITIES ISSUABLE PURSUANT HERETO … MAY NOT BE OFFERED, SOLD, OR
 * OTHERWISE TRANSFERRED" — is the holder's transfer restriction, and once the
 * ledger named its whole subject the instrument-subject filter above dropped
 * it as though it read "this Section shall not apply".
 */
const TRANSFER_RESTRICTION =
  /^be\s+(?:offered|sold|resold|transferred|assigned|pledged|hypothecated|encumbered)\b/i;

/**
 * A provision referred to by PRONOUN is still a provision: "This Section does
 * not restrict a Settlor's power to revoke, and IT shall not apply to a
 * Settlor's own beneficial interest" states the Section's scope. The
 * instrument-subject filter reads the noun, so the pronoun passed as a party
 * and the scope statement counted as a negative covenant — found by the
 * `present-indicative` relation once the trust's only other "covenant" (a
 * statement of law, 9.781.0) left the ledger. "Licensee shall not apply to
 * REGISTER the Marks" is a covenant and keeps its verb after "to".
 */
const PRONOUN_SUBJECT = /^(?:it|they|this|these)$/i;
const SCOPE_ACTION =
  /^not\s+apply(?:\s*$|\s+to\s+(?:a|an|the|any|such|its|his|her|their|this|that|these|those|each|all|[A-Z])|\s+(?:if|where|when|unless|in|during|after|before)\b)/;

/** Up to 120 characters of a clause, cut at a word, marked when cut. */
function clauseSnippet(raw: string): string {
  const text = raw.trim();
  const window = excerptWindow(text, 0, 0, 120);
  return window.length < text.length ? `${window}…` : window;
}

/** OBLI-005 — Negative covenants list (info). */
export const rule: Rule = {
  id: "OBLI-005",
  version: "1.6.0",
  name: "Negative covenants list",
  category: "obligations",
  default_severity: "info",
  description:
    "Surfaces all 'shall not' / 'may not' / 'must not' / 'is prohibited from' obligations.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const negs = ctx.extracted.obligations.filter(
      (o) =>
        (NEG_MODAL.test(o.modal) || NEG_ACTION.test(o.action) || NEG_PHRASE.test(o.action)) &&
        (!INSTRUMENT_SUBJECT.test(o.obligor.trim()) || TRANSFER_RESTRICTION.test(o.action)) &&
        !(PRONOUN_SUBJECT.test(o.obligor.trim()) && SCOPE_ACTION.test(o.action)) &&
        !STATUS_ACTION.test(o.action),
    );
    if (negs.length === 0) return null;
    // 🚨 Distinct SNIPPETS, and say when there are more.
    //
    // Two covenants in one sentence ("… shall not solicit …, and shall not
    // disclose …") are two obligations with the same `raw_text`, so the list
    // printed the identical 120 characters twice — 41 corpus documents showed
    // a reader the same clause twice in a list of four.
    //
    // And the cap was silent: the title said "Negative covenants: 5" above a
    // list of four, with nothing to say the fifth existed. 43 documents were
    // truncated that way. A cap is a silent truncation until something says
    // the number (spec-v8; the same repair as MAX_SECONDARY_FAMILIES).
    const shown: string[] = [];
    for (const n of negs) {
      // Cut at a word and say so: a fixed slice ended clauses mid-word
      // ("… as the Upstream BAA permits Busine", "… of Milwaukee, Wis").
      const snippet = clauseSnippet(n.raw_text);
      if (!shown.includes(snippet)) shown.push(snippet);
      if (shown.length === 4) break;
    }
    const more = negs.length - shown.length;
    return emit(ctx, rule, {
      title: `Negative covenants: ${negs.length}`,
      description:
        shown.join(" | ") +
        (more > 0 ? ` | +${more} more — see the obligations ledger for the full list` : ""),
      excerpt: negs[0]!.raw_text,
      explanation:
        "Negative covenants restrict what a party may do. Surfacing them collectively makes it easier to check they are intended and consistent with the overall deal.",
      position: negs[0]!.position,
    });
  },
};

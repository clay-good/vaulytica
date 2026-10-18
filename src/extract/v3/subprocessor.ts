/**
 * v3 subprocessor inventory and onward-transfer extractor (spec-v3.md §24).
 *
 * Returns the first detected subprocessor clause as a single normalized record,
 * or null if no subprocessor language appears.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  SubprocessorConsentForm,
  SubprocessorInventory,
  SubprocessorListLocation,
  SubprocessorObjectionConsequence,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";
import { truncate } from "../../engine/text.js";

/** How much of the clause the §57 page carries as its evidence. */
const EXCERPT_LIMIT = 600;

const SUBP_RX = /\b(?:sub[- ]?processor|subcontractor)s?\b/i;

// `(?:[^.()\d\n]*?\()?` reads the "word (numeral)" form — "thirty (30) days'
// prior written notice" — whose parenthesized numeral is authoritative; a
// bare-digit anchor dropped it to null. Bounded by the sentence and by parens
// so no unrelated parenthetical is consumed; a plain "30 days" still matches.
const NOTICE_RX =
  /\b(?:no less than |at least |minimum |with )?(?:[^.()\d\n]{0,60}?\()?(\d{1,3})\)?\s+(?:business days?|calendar days?|days?)['’]?\s+(?:prior )?(?:written )?notice\b/i;

/**
 * The Art. 28(4) flow-down, however the drafter words it.
 *
 * 🚨 The old test was `same obligations` / `equivalent obligations` /
 * `flow-down`, which is the regulation's own wording and NOT how contracts are
 * drafted. `dpa-complete.txt` — a document written to be correct — says
 * "Processor shall impose on each Sub-processor, by written contract, data
 * protection obligations **no less protective than** those in this DPA", and
 * the §57 page reported "Flow-down to subprocessors required: **Not required
 * by the document**". A false "not required" is worse than silence: it is a
 * statement about the document's content, on the page devoted to
 * subprocessing, and it is flatly untrue.
 *
 * Two shapes, plus the term of art:
 *   - an obligations noun qualified as the same / equivalent / substantially
 *     similar;
 *   - a comparative of protectiveness ("no less protective", "at least as
 *     stringent"), which is the commonest drafting by some distance.
 *
 * The comparative needs no obligations noun beside it because the paragraph
 * has already been matched on sub-processor language; "no less protective" in
 * a sub-processing clause is the flow-down and nothing else.
 */
const FLOW_DOWN_RX = new RegExp(
  [
    String.raw`\b(?:the\s+)?(?:same|equivalent|identical|substantially\s+(?:similar|identical|the\s+same)|materially\s+(?:equivalent|the\s+same))\s+(?:data\s+protection\s+|privacy\s+|confidentiality\s+|security\s+|contractual\s+)?(?:obligations|terms|duties|requirements|commitments|protections|safeguards)\b`,
    String.raw`\b(?:no\s+less\s+(?:protective|onerous|stringent|restrictive|favourable|favorable)|at\s+least\s+as\s+(?:protective|onerous|stringent|restrictive))\b`,
    String.raw`\bflow[-\s]?down\b`,
  ].join("|"),
  "i",
);

export function extractSubprocessorInventory(tree: DocumentTree): SubprocessorInventory | null {
  let best: SubprocessorInventory | null = null;
  forEachParagraph(tree, (ctx) => {
    const m = SUBP_RX.exec(ctx.text);
    if (!m) return;

    const text = ctx.text;

    // "No sub-processor <verb> permitted" is a prohibition. The verb agrees
    // with singular/plural ("is"/"are") and may be modal ("shall be", "may
    // be"); the old pattern only allowed "are", so the natural singular "No
    // sub-processor IS permitted" slipped through and inverted `permitted` to
    // true — reporting a flat ban as "sub-processing allowed".
    const permitted =
      !/\bno sub[- ]?processors?\s+(?:(?:is|are|shall|may|will|can)\s+(?:be\s+)?)?permitted\b/i.test(
        text,
      );

    const consent: SubprocessorConsentForm =
      /\bspecific prior (?:written )?consent\b|\bspecific prior authori[sz]ation\b/i.test(text)
        ? "specific-prior"
        : /\bgeneral (?:written )?authori[sz]ation\b/i.test(text)
          ? "general-written"
          : "silent";

    const list: SubprocessorListLocation = /\bannex\b|\bschedule\b|\bexhibit\b/i.test(text)
      ? "annex"
      : /https?:\/\//i.test(text)
        ? "url"
        : /\bupon request\b|\bon request\b/i.test(text)
          ? "on-request"
          : "absent";

    const noticeMatch = NOTICE_RX.exec(text);
    const notice = noticeMatch ? Number(noticeMatch[1]) : null;

    const objection = /\bobject\b|\bobjection\b|\breasonable objection\b/i.test(text);

    const consequence: SubprocessorObjectionConsequence = /\bterminate for convenience\b/i.test(
      text,
    )
      ? "terminate-for-convenience"
      : /\bterminate the affected services\b|\bterminate the impacted services\b/i.test(text)
        ? "terminate-affected-services"
        : objection
          ? "unspecified"
          : "no-right";

    const flow = FLOW_DOWN_RX.test(text);

    const candidate: SubprocessorInventory = {
      permitted,
      consent_form: consent,
      list_location: list,
      notice_days: notice,
      objection_right: objection,
      objection_consequence: consequence,
      flow_down_required: flow,
      position: posInParagraph(ctx, m.index, m.index + m[0].length),
      raw_text: m[0],
      excerpt: truncate(text, EXCERPT_LIMIT),
    };

    // Pick the most-informative paragraph (highest number of distinctive fields set).
    const score = (s: SubprocessorInventory): number =>
      (s.consent_form !== "silent" ? 1 : 0) +
      (s.list_location !== "absent" ? 1 : 0) +
      (s.notice_days !== null ? 1 : 0) +
      (s.objection_right ? 1 : 0) +
      (s.flow_down_required ? 1 : 0);

    if (!best || score(candidate) > score(best)) best = candidate;
  });
  return best;
}

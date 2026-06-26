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

const SUBP_RX = /\b(?:sub[- ]?processor|subcontractor)s?\b/i;

const NOTICE_RX =
  /\b(?:no less than |at least |minimum |with )?(\d{1,3})\s+(?:business days?|calendar days?|days?)['’]?\s+(?:prior )?(?:written )?notice\b/i;

export function extractSubprocessorInventory(tree: DocumentTree): SubprocessorInventory | null {
  let best: SubprocessorInventory | null = null;
  forEachParagraph(tree, (ctx) => {
    const m = SUBP_RX.exec(ctx.text);
    if (!m) return;

    const text = ctx.text;

    const permitted = !/\bno sub[- ]?processor[s]? (?:are )?permitted\b/i.test(text);

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

    const flow =
      /\bsame (?:data protection )?obligations\b|\bequivalent (?:data protection )?obligations\b|\bflow[- ]down\b/i.test(
        text,
      );

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

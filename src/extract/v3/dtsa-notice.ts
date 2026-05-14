/**
 * v3 whistleblower / DTSA notice detector (spec-v3.md §26).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { DtsaNotice } from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

const DTSA_PRESENT_RX =
  /\b(?:18\s*U\.?S\.?C\.?\s*§?\s*1833(?:\(b\))?|Defend Trade Secrets Act|DTSA)\b|\bimmunity (?:from liability )?for (?:the )?disclosure of (?:a )?trade secret\b/i;

const GOV_DISCLOSURE_RX =
  /\b(?:federal|state|local)\s+government\s+official\b|\bin confidence\s+to\s+(?:a |an )?(?:federal|state|local)?\s*government official\b|\battorney\s+(?:solely|only)?\s*for\s+the\s+purpose\s+of\s+reporting/i;

const UNDER_SEAL_RX = /\bunder seal\b/i;

const CONTRACTOR_RX = /\bcontractors?\b|\bconsultants?\b/i;

export function extractDtsaNotice(tree: DocumentTree): DtsaNotice {
  let result: DtsaNotice = {
    present: false,
    covers_government_disclosure: false,
    covers_under_seal: false,
    covers_contractors: false,
    substantively_complete: false,
    raw_text: null,
    position: null,
  };

  forEachParagraph(tree, (ctx) => {
    if (result.present) return;
    const m = DTSA_PRESENT_RX.exec(ctx.text);
    if (!m) return;

    // Look at a wider window: this paragraph + a neighborhood
    // (the next paragraph often carries the substantive elements).
    const window = ctx.text;
    const gov = GOV_DISCLOSURE_RX.test(window);
    const seal = UNDER_SEAL_RX.test(window);
    const contractors = CONTRACTOR_RX.test(window);

    result = {
      present: true,
      covers_government_disclosure: gov,
      covers_under_seal: seal,
      covers_contractors: contractors,
      substantively_complete: gov && seal && contractors,
      raw_text: m[0],
      position: posInParagraph(ctx, m.index, m.index + m[0].length),
    };
  });

  return result;
}

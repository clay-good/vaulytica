/**
 * v3 whistleblower / DTSA notice detector (spec-v3.md §26).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { DtsaNotice } from "./types.js";
import { forEachParagraph, posInParagraph, type ParagraphContext } from "../walk.js";

const DTSA_PRESENT_RX =
  /\b(?:18\s*U\.?S\.?C\.?\s*§?\s*1833(?:\(b\))?|Defend Trade Secrets Act|DTSA)\b|\bimmunity (?:from liability )?for (?:the )?disclosure of (?:a )?trade secret\b/i;

const GOV_DISCLOSURE_RX =
  /\b(?:federal|state|local)\s+government\s+official\b|\bin confidence\s+to\s+(?:a |an )?(?:federal|state|local)?\s*government official\b|\battorney\s+(?:solely|only)?\s*for\s+the\s+purpose\s+of\s+reporting/i;

const UNDER_SEAL_RX = /\bunder seal\b/i;

const CONTRACTOR_RX = /\bcontractors?\b|\bconsultants?\b/i;

export function extractDtsaNotice(tree: DocumentTree): DtsaNotice {
  const paras: ParagraphContext[] = [];
  forEachParagraph(tree, (ctx) => paras.push(ctx));

  for (let i = 0; i < paras.length; i++) {
    const ctx = paras[i]!;
    const m = DTSA_PRESENT_RX.exec(ctx.text);
    if (!m) continue;

    // The DTSA immunity notice is commonly split across a "notice" paragraph
    // and a following "elements" paragraph (18 U.S.C. § 1833(b)(3) quoted as a
    // block). Scan this paragraph plus the next two for the substantive
    // elements — the code previously looked only at the current paragraph
    // despite the comment promising a neighborhood, under-reporting a
    // multi-paragraph notice as "incomplete".
    const window = [ctx.text, paras[i + 1]?.text, paras[i + 2]?.text]
      .filter((t): t is string => t !== undefined)
      .join(" ");
    const gov = GOV_DISCLOSURE_RX.test(window);
    const seal = UNDER_SEAL_RX.test(window);
    const contractors = CONTRACTOR_RX.test(window);

    return {
      present: true,
      covers_government_disclosure: gov,
      covers_under_seal: seal,
      covers_contractors: contractors,
      substantively_complete: gov && seal && contractors,
      raw_text: m[0],
      position: posInParagraph(ctx, m.index, m.index + m[0].length),
    };
  }

  return {
    present: false,
    covers_government_disclosure: false,
    covers_under_seal: false,
    covers_contractors: false,
    substantively_complete: false,
    raw_text: null,
    position: null,
  };
}

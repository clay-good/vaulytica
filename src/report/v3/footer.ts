/**
 * Page footer (spec-v3.md §32).
 *
 * v2's footer carried the determinism / privacy / non-advice disclaimers
 * in a closing section. v3 adds a per-page footer line carrying the
 * machine-verifiable provenance (engine version, DKB version, result
 * hash, and the citation-as-of date) so a reader of a single printed page
 * can verify the report against its source.
 */

import { Footer, Paragraph, TextRun } from "docx";
import { DEFAULT_FONT, BODY_SIZE } from "./_dx.js";

export type FooterFields = {
  engine_version: string;
  dkb_version: string;
  result_hash: string;
  dkb_build_date?: string;
};

export function buildV3Footer(fields: FooterFields): Footer {
  const parts: string[] = [
    `Engine v${fields.engine_version}`,
    `DKB ${fields.dkb_version}`,
    `Result hash ${shortHash(fields.result_hash)}`,
  ];
  if (fields.dkb_build_date) {
    parts.push(`Citations as of ${fields.dkb_build_date.slice(0, 10)}`);
  }
  return new Footer({
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: parts.join("  |  "),
            font: DEFAULT_FONT,
            size: BODY_SIZE - 4,
            color: "888888",
          }),
        ],
      }),
    ],
  });
}

function shortHash(h: string): string {
  if (h.length <= 12) return h;
  return `${h.slice(0, 8)}…${h.slice(-4)}`;
}

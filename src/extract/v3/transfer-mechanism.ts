/**
 * v3 cross-border transfer language detector (spec-v3.md §20).
 *
 * Scans for canonical phrases, classifies the asserted mechanism, locates the
 * supporting text (annex, attachment, hyperlink, by-reference, recital-only).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  TransferMechanismKind,
  TransferMechanismLocation,
  TransferMechanismReference,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";
import { truncate } from "../../engine/text.js";

/**
 * How much of the clause the §56 page carries. Long enough for a reader to see
 * the mechanism in context and for the page's TIA and supplementary-measures
 * tests to find those phrases where a drafter puts them — in the same clause.
 */
const EXCERPT_LIMIT = 300;

type MechanismPattern = { kind: TransferMechanismKind; rx: RegExp };

/**
 * The SCC instrument, however a DPA names it.
 *
 * 🚨 All four module detectors were DEAD — zero firings across 327 specimens,
 * including `scc-module-2.txt` and `scc-module-3.txt`, the two specimens named
 * for their module. Every transfer in the corpus reported "module
 * unspecified", so the §56 page told a reader the document had not said which
 * module it adopted while the document said so in its own title.
 *
 * The cause was WORD ORDER, the same defect shape as the insurance
 * certificate's labels in 9.888.0: the old patterns accepted only
 * `SCCs Module Two` (the designator second, adjacent) or `Module Two …
 * Standard Contractual Clauses` (the designator first). Real drafting puts the
 * instrument FIRST and punctuates between:
 *
 *   - "standard contractual clauses annexed to that Decision, **Module Two**"
 *   - "STANDARD CONTRACTUAL CLAUSES — **MODULE THREE** (PROCESSOR TO PROCESSOR)"
 *   - "the Standard Contractual Clauses, **Module Two**, are incorporated"
 *
 * so the designator is now read on EITHER side within a bounded window.
 */
const SCC_NAME = String.raw`(?:Standard Contractual Clauses|EU SCCs?|SCCs?)`;

/**
 * The module's official name in Decision (EU) 2021/914, which identifies it on
 * its own.
 *
 * A heading reads "MODULE TWO: TRANSFER CONTROLLER TO PROCESSOR" with the
 * instrument named nowhere near it, and that phrase IS the module — so the
 * role pair is accepted in place of the instrument's name. A BARE "Module Two"
 * is deliberately not enough: a software agreement's "Module 2" is a software
 * module, and nothing about the number says otherwise.
 */
const MODULE_ROLES: Record<1 | 2 | 3 | 4, string> = {
  1: String.raw`controller\s+to\s+controller`,
  2: String.raw`controller\s+to\s+processor`,
  3: String.raw`processor\s+to\s+processor`,
  4: String.raw`processor\s+to\s+controller`,
};

/** The designator may precede or follow what identifies it as an SCC module. */
function sccModuleRx(n: 1 | 2 | 3 | 4, word: string): RegExp {
  const designator = String.raw`Module\s+(?:${n}|${word})\b`;
  const roles = MODULE_ROLES[n];
  const sameLine = String.raw`[^\n]`;
  return new RegExp(
    [
      // instrument first:  "Standard Contractual Clauses, Module Two"
      String.raw`\b${SCC_NAME}\b${sameLine}{0,80}?${designator}`,
      // designator first:  "Module Two ... Standard Contractual Clauses"
      String.raw`\b${designator}${sameLine}{0,80}?${SCC_NAME}\b`,
      // the module's own official name, which needs no instrument beside it
      String.raw`\b${designator}${sameLine}{0,40}?${roles}`,
    ].join("|"),
    "i",
  );
}

const PATTERNS: MechanismPattern[] = [
  { kind: "scc-module-1", rx: sccModuleRx(1, "One") },
  { kind: "scc-module-2", rx: sccModuleRx(2, "Two") },
  { kind: "scc-module-3", rx: sccModuleRx(3, "Three") },
  { kind: "scc-module-4", rx: sccModuleRx(4, "Four") },
  {
    kind: "scc-unspecified",
    rx: /\bStandard Contractual Clauses\b|\bEU SCCs?\b|\bSCCs?\b(?!\s*Module)/i,
  },
  { kind: "uk-idta", rx: /\bInternational Data Transfer Agreement\b|\bIDTA\b/i },
  { kind: "uk-addendum", rx: /\bUK Addendum\b|\bInternational Data Transfer Addendum\b/i },
  { kind: "swiss-addendum", rx: /\bSwiss Addendum\b/i },
  // EU Art. 45 "adequacy decision" (a.k.a. "adequacy finding") and the UK GDPR
  // "adequacy regulations" are the same adequacy-based transfer basis.
  { kind: "adequacy-decision", rx: /\badequacy (?:decision|finding|regulations?)\b/i },
  { kind: "binding-corporate-rules", rx: /\bBinding Corporate Rules\b|\bBCRs?\b/i },
  { kind: "article-49-derogation", rx: /\bArticle\s*49\b|\bArt\.\s*49\b/i },
  { kind: "data-privacy-framework", rx: /\bData Privacy Framework\b|\bDPF\b/i },
  // Privacy Shield was invalidated by Schrems II (2020) but still appears as a
  // stated basis in older DPAs; it is a distinct (defunct) mechanism, not DPF.
  { kind: "privacy-shield", rx: /\bPrivacy Shield\b/i },
];

function inferLocation(text: string): TransferMechanismLocation {
  const t = text.toLowerCase();
  if (/\bannex\b|\bschedule\b|\bexhibit\b/.test(t)) return "annex";
  if (/\battachment\b/.test(t) || /\battached hereto\b/.test(t)) return "attachment";
  if (/https?:\/\//.test(text)) return "hyperlink";
  if (/\bincorporated by reference\b|\bby reference\b/.test(t)) return "by-reference";
  if (/\bwhereas\b|\brecital[s]?\b/.test(t)) return "recital-only";
  return "inline";
}

export function extractTransferMechanisms(tree: DocumentTree): TransferMechanismReference[] {
  const seen = new Set<string>();
  const out: TransferMechanismReference[] = [];
  forEachParagraph(tree, (ctx) => {
    for (const p of PATTERNS) {
      const m = p.rx.exec(ctx.text);
      if (!m) continue;
      const key = `${p.kind}|${ctx.paragraph.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        kind: p.kind,
        raw_text: m[0],
        excerpt: truncate(ctx.text, EXCERPT_LIMIT),
        location: inferLocation(ctx.text),
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });
  // Suppress unspecified-SCC when a module was identified ANYWHERE in the
  // document, not merely in the same paragraph.
  //
  // They are one instrument: a DPA that adopts Module Two names it once, in
  // its definitions or its transfers clause, and then says "the SCCs" a dozen
  // times after. Scoping the suppression to the paragraph meant the page
  // listed the module once and "module unspecified" for every later mention —
  // reporting the document as vague about something it had already pinned. A
  // DPA that genuinely adopts two modules still lists both, because the
  // suppression only ever removes the UNSPECIFIED row.
  const moduleIdentified = out.some((r) => r.kind.startsWith("scc-module-"));
  const filtered = out.filter((r) => r.kind !== "scc-unspecified" || !moduleIdentified);
  filtered.sort((a, b) =>
    a.position.start !== b.position.start
      ? a.position.start - b.position.start
      : a.kind < b.kind
        ? -1
        : a.kind > b.kind
          ? 1
          : 0,
  );
  return filtered;
}

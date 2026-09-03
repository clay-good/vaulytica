import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * STRUCT-002 — Effective date present and parseable (warning).
 *
 * Searches for a named-anchor `Effective Date` reference, an absolute
 * date in the first 25% of the document, or a defined term `Effective
 * Date` in the definitions map. Fires if none is present.
 */
export const rule: Rule = {
  id: "STRUCT-002",
  version: "1.2.0",
  name: "Effective date present and parseable",
  category: "structural",
  default_severity: "warning",
  description:
    "Verifies the contract has an identifiable Effective Date — by named anchor, by a top-of-document absolute date, or by defined term.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const hasAnchor = ctx.extracted.dates.some(
      (d) => d.type === "named-anchor" && /Effective Date/i.test(d.anchor ?? ""),
    );
    if (hasAnchor) return null;

    const defined = ctx.extracted.definitions.entries.find(
      (e) => e.term.toLowerCase() === "effective date",
    );
    if (defined) return null;

    const firstAbsolute = ctx.extracted.dates.find((d) => d.type === "absolute" && d.iso);
    if (firstAbsolute && firstAbsolute.position.start < documentLength(ctx) * 0.25) {
      return null;
    }

    // The EXECUTION DATE is the effective date of a signed form. A contributor
    // license agreement, a consent, an acknowledgment, and an offer letter all
    // put their only date on the "Date:" line the signer fills in — at the
    // BOTTOM of the page, which is nowhere near the first quarter — and every
    // one of them was told it states no effective date. The label is what makes
    // this a date the document adopts, rather than an incidental date in prose.
    let dateLine = false;
    forEachParagraph(ctx.tree, (p) => {
      // The date has to FOLLOW the label. An unsigned template writes
      // "Date: ____________________", and accepting any absolute date in the
      // same paragraph let a blank line borrow one from elsewhere in a joined
      // signature block — which is how the corpus's own unsigned fixtures
      // stopped reporting the effective date they genuinely lack.
      // The separator is a PIPE as often as a colon: a signature block laid out
      // as a table flattens to "Date | April 6, 2026" (`src/ingest/docx.ts`),
      // and this label already anticipated the pipe on its LEFT — as a cell
      // boundary — while requiring a colon on its right.
      const LABEL = /(?:^|[\s>|])[Dd]ated?\s*(?::|\||\s+as\s+of)\s*/g;
      LABEL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = LABEL.exec(p.text)) !== null) {
        const at = p.start + m.index + m[0].length;
        for (const d of ctx.extracted.dates) {
          if (
            d.type === "absolute" &&
            d.iso &&
            d.position.section_id === p.section.id &&
            d.position.start >= at &&
            d.position.start <= at + 2
          )
            dateLine = true;
        }
      }
      // The FORMAL EXECUTION LINE of an instrument: "SIGNED AND SEALED this
      // 2nd day of February, 2026", "EXECUTED this 6th day of February,
      // 2026", "WITNESS my hand this 14th day of March, 2026". Every bond,
      // deed, will, affidavit, and acknowledgment dates itself there and
      // nowhere else, and the branch here read only "Dated this Nth day of" —
      // so a payment and performance bond whose foot carries its own date in
      // the oldest form there is was told it states no effective date. The
      // verb list is spelled in both cases rather than flagged `i`, because
      // the month anchor beside it has to stay case-sensitive.
      if (
        /\b(?:[Dd]ated|DATED|[Ss]igned|SIGNED|[Ss]ealed|SEALED|[Ee]xecuted|EXECUTED|[Dd]elivered|DELIVERED|hand)\b[^.]{0,60}?\bthis\s+\d{1,2}(?:st|nd|rd|th)?\s+day\s+of\s+(?:[A-Z][a-z]+|[A-Z]{3,}),?\s+\d{4}/.test(
          p.text,
        )
      )
        dateLine = true;
      // The EXECUTION RECITAL at the foot of the instrument: "IN WITNESS
      // WHEREOF, the parties have EXECUTED this Assignment of Claim AS OF
      // November 12, 2026." An instrument that dates itself only where it is
      // signed has an identifiable starting point, and the first-quarter test
      // never reaches it.
      // The date must PARSE, not merely look like one. `bad-nda` is dated "as
      // of February 30, 2026" — an impossible date, which is the point of the
      // fixture — and a surface-pattern test stood the rule down on it.
      if (
        /\b(?:executed|signed|entered\s+into|made)\b[^.]{0,90}?\bas\s+of\b/.test(p.text) &&
        ctx.extracted.dates.some(
          (d) =>
            d.type === "absolute" &&
            d.iso &&
            d.position.section_id === p.section.id &&
            d.position.start >= p.start &&
            d.position.end <= p.end,
        )
      )
        dateLine = true;
    });
    if (dateLine) return null;

    const firstSectionId = ctx.tree.sections[0]?.id ?? "";
    return makeFinding({
      rule,
      title: "No Effective Date found",
      description: "No Effective Date is named, defined, or stated near the top of this Agreement.",
      excerptText: "(no Effective Date reference matched)",
      explanation:
        "Most contracts identify a starting point that other date references rely on. Without it, relative terms like 'within 30 days after the Effective Date' have no anchor.",
      recommendation:
        "Add an Effective Date — either in the preamble ('dated as of [date]'), as a defined term, or as an explicit 'Effective Date: [date]' line.",
      position: { section_id: firstSectionId, start: 0, end: 0 },
      source_citations: [],
    });
  },
};

function documentLength(ctx: RuleContext): number {
  let max = 0;
  for (const s of ctx.tree.sections) {
    for (const p of s.paragraphs) {
      const last = p.runs[p.runs.length - 1];
      if (last && last.end > max) max = last.end;
    }
  }
  return max || 1;
}

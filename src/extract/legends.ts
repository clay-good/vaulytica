import { ATTACHMENT_KIND } from "./attachment-kinds.js";
/**
 * The stamps a document carries above its own name.
 *
 * "EXECUTION VERSION", "CONFIDENTIAL", "DRAFT — FOR DISCUSSION PURPOSES ONLY",
 * "PRIVILEGED AND CONFIDENTIAL — ATTORNEY WORK PRODUCT". They are furniture:
 * the document's identity is the line BELOW them.
 *
 * This vocabulary lived inside `playbooks/matcher.ts`, which is where it was
 * first needed — and then STRUCT-006 and TEMP-007 needed the same answer to
 * the same question, and importing it from there pulled the whole playbook
 * matcher into the rules bundle (`rules-core` went past its 600 KB guard,
 * which is how this was caught). A vocabulary two layers share belongs to
 * neither of them.
 *
 * A negotiated agreement wears these above its title, and the document's own
 * name is the line below. A legend that is the WHOLE line is furniture;
 * "EXHIBIT A — FORM OF MUTUAL NDA" carries the title and is kept. No
 * playbook's title keywords begin with one of these words, so nothing loses a
 * signal.
 */
const LEGEND_TOKEN =
  /execution\s+(?:version|copy)|conformed\s+copy|final\s+(?:version|form)|drafts?|confidential(?:ity)?|privileged|proprietary|trade\s+secrets?|attorney[-\s]work[-\s]product|attorney[-\s]client\s+privileged?|work\s+product|for\s+(?:discussion|settlement|negotiation)\s+purposes\s+only|subject\s+to\s+(?:protective\s+order|review|contract|revision)|confidential\s+treatment\s+requested|do\s+not\s+(?:copy|distribute|file)|not\s+for\s+distribution/;
const LEGEND_LINE = new RegExp(
  String.raw`^[\s\-–—*|/[\]()]*(?:(?:${LEGEND_TOKEN.source})[\s\-–—*|/,;:[\]()]*(?:and[\s\-–—*|/,;:]*)?)+$`,
  "i",
);

/**
 * Longest an uppercase, sentence-punctuated line may be and still be read as a
 * title rather than a legend paragraph. Real titles run well under this even
 * when they are long ("AMENDED AND RESTATED LIMITED LIABILITY COMPANY
 * OPERATING AGREEMENT"), and they do not end in a period.
 */
const LEGEND_SENTENCE_CHARS = 120;

function isLegendSentence(line: string): boolean {
  return (
    line.length > LEGEND_SENTENCE_CHARS &&
    /[.;]$/.test(line) &&
    /[A-Z]/.test(line) &&
    line === line.toUpperCase()
  );
}

/**
 * A bare container header — "Exhibit A", "Schedule 3.7" — standing alone above
 * the attachment's own title.
 *
 * The kinds come from {@link ATTACHMENT_KIND}, and they did not always: this
 * pattern enumerated five of the six by hand and had never read "annexure".
 * It lived in `playbooks/matcher.ts`, which `attachment-kinds.test.ts` does
 * not scan, so the guard written to catch exactly this could not see it.
 * Moving the file into `src/extract` is what surfaced it.
 */
const CONTAINER_MARKER = new RegExp(
  String.raw`^(?:${ATTACHMENT_KIND})\s+[A-Za-z0-9][A-Za-z0-9.-]*[\s.:—–-]*$`,
  "i",
);

/**
 * Drop the leading legend lines so the document's own title is first.
 *
 * Exported because STRUCT-006 needs the same answer to the same question. That
 * rule excuses a term that appears in the document's TITLE — "this Written
 * Consent" is not a term an ACTION BY WRITTEN CONSENT forgot to define — and
 * it was reading the first line, so stamping "CONFIDENTIAL" or "EXECUTION
 * VERSION" above the title made the legend the title and the document's own
 * name an undefined term. Three specimens, on a legend every executed
 * agreement carries.
 */
/**
 * Is this whole line nothing but a legend?
 *
 * The single-line half of {@link dropLegends}, for a consumer that walks
 * paragraphs rather than the opening of a document. TEMP-007 audits a survival
 * list only for the categories the document actually HAS — "an obligation the
 * document does not have cannot be missing from its list" — and it decided
 * that by testing `/confidential/i` against every paragraph. A one-word
 * "CONFIDENTIAL" stamp is not a confidentiality obligation, and on six
 * specimens it turned a complete survival list into an incomplete one.
 */
export function isLegendLine(line: string): boolean {
  return LEGEND_LINE.test(line.trim());
}

export function dropLegends(lines: readonly string[]): string[] {
  let i = 0;
  while (
    i < lines.length &&
    (lines[i]!.length === 0 ||
      LEGEND_LINE.test(lines[i]!) ||
      CONTAINER_MARKER.test(lines[i]!) ||
      isLegendSentence(lines[i]!))
  )
    i += 1;
  return lines.slice(i);
}

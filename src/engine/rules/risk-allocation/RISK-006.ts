import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";
import type { DocPosition } from "../../../extract/types.js";
import { truncate } from "../../text.js";

const TYPICAL = [
  ["fraud", /fraud/i],
  ["willful misconduct", /willful\s+misconduct/i],
  // General indemnification is the single most common LoL carve-out — a clause
  // reading "except for indemnification obligations" must not read as zero
  // carve-outs. Kept distinct from the narrower "IP indemnity" category so a doc
  // that names an IP-specific indemnity still surfaces that too.
  // `indemnity` is the noun a carve-out list uses — "except for the INDEMNITY
  // OBLIGATIONS in Sections 8.1 and 8.2" — and the `indemnif` stem does not
  // match it, so a clause carving out the indemnity read as carving out
  // nothing.
  ["indemnification", /\bindemnif|\bindemnit(?:y|ies)\b/i],
  ["IP indemnity", /(?:ip|intellectual\s+property)\s+indemnit/i],
  ["confidentiality breach", /confidential/i],
  // Same shape as the `indemnity` widening above, one row down: a carve-out
  // list names the payment obligation the way a drafter says it — "Licensee's
  // OBLIGATION TO PAY amounts due", "Customer's obligation to pay fees" — and
  // the literal noun phrase "payment obligations" is the rarer of the two. A
  // complete patent licence carving out the obligation to pay was told the
  // category was missing.
  ["payment obligations", /payment\s+obligations?|obligations?\s+to\s+pay\b/i],
] as const;

/**
 * An exception clause, bounded to its own sentence. `\.(?=\d)` is the repo's
 * idiom for a decimal point inside a figure — a carve-out list cites the
 * sections it excepts ("the indemnity obligations in Sections 8.1 and 8.2"),
 * and a bare `[^.;\n]` stopped at the "8.1".
 */
const EXCEPTION_CLAUSE =
  /\b(?:except\s+for|excluding|other\s+than|(?:do|does|shall|will|must)\s+not\s+apply\s+to)\b(?:[^.;\n]|\.(?=\d)){0,400}/i;

/**
 * The section anchor, plus the first exception clause that follows it.
 *
 * "LIMITATION OF LIABILITY **OF MANAGERS**" is a corporate exculpation article
 * — a charter provision under the state's LLC or corporation act, whose
 * exceptions are the duty of loyalty and bad faith, not a commercial cap's
 * carve-outs. Reading it as one reported "0/6 typical carve-outs present" about
 * an articles of organization. The whole-office negative is the tightest thing
 * that separates them: nothing calls a commercial cap a limitation of liability
 * OF someone.
 */
const LIMITATION_WITH_EXCEPTION = new RegExp(
  `\\blimitation\\s+of\\s+liability\\b(?!\\s+of\\s+(?:the\\s+)?(?:managers?|directors?|officers?|trustees?|members?)\\b)[\\s\\S]*?${EXCEPTION_CLAUSE.source}`,
  "i",
);

/**
 * The enclosing SECTION's text, and the position of the paragraph the anchor
 * sits in.
 *
 * A limitation-of-liability article puts its heading in one paragraph and its
 * clause in the next — "11. Limitation of Liability." then "Neither party is
 * liable for indirect … These limits do not apply to a party's indemnity
 * obligations under Section 10" — so a paragraph-scoped read can never see the
 * anchor and the carve-out list at once. `format-invariance` is what says so
 * out loud: with the document's blank lines stripped the two paragraphs merge
 * and the finding appears, which is a finding that depends on the document's
 * whitespace. The section is the unit the clause actually occupies.
 */
function sectionMatch(
  ctx: RuleContext,
  re: RegExp,
): { text: string; excerpt: string; match: RegExpExecArray; position: DocPosition } | null {
  interface Part {
    readonly text: string;
    readonly at: number;
    readonly position: DocPosition;
  }
  const bySection = new Map<string, { text: string; parts: Part[] }>();
  const order: string[] = [];
  forEachParagraph(ctx.tree, (p) => {
    let entry = bySection.get(p.section.id);
    if (!entry) {
      order.push(p.section.id);
      entry = { text: p.section.heading ?? "", parts: [] };
      bySection.set(p.section.id, entry);
    }
    const at = entry.text.length === 0 ? 0 : entry.text.length + 1;
    entry.text = entry.text.length === 0 ? p.text : `${entry.text} ${p.text}`;
    entry.parts.push({
      text: p.text,
      at,
      position: {
        section_id: p.section.id,
        paragraph_id: p.paragraph.id,
        start: p.start,
        end: p.end,
      },
    });
  });
  for (const key of order) {
    const entry = bySection.get(key)!;
    const m = re.exec(entry.text);
    if (!m) continue;
    // The excerpt and the position must name a REAL paragraph: the section text
    // above is a synthetic join, and quoting it produced an excerpt the
    // document does not contain — which `format-invariance`'s quote check says
    // out loud. Report the paragraph the EXCEPTION CLAUSE sits in rather than
    // the one the anchor sits in: when they differ, the anchor's paragraph is
    // the bare heading ("11. Limitation of Liability.") and the clause is the
    // half a reader needs.
    const clauseAt = m.index + m[0].length - 1;
    const part = [...entry.parts].reverse().find((p) => p.at <= clauseAt) ?? entry.parts[0] ?? null;
    if (!part) continue;
    return {
      text: entry.text,
      excerpt: part.text,
      match: m as RegExpExecArray,
      position: part.position,
    };
  }
  return null;
}

/** RISK-006 — LoL exceptions list (info). */
export const rule: Rule = {
  id: "RISK-006",
  version: "1.5.0",
  name: "LoL exceptions list",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the list of carve-outs from the limitation-of-liability cap.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = sectionMatch(ctx, LIMITATION_WITH_EXCEPTION);
    if (!hit) return null;
    // A limitation-of-liability section states its exceptions in MORE THAN ONE
    // sentence, and the first one is usually not the cap's. The textbook layout
    // is a damages exclusion with its own narrow exception ("…OR FOR LOST
    // PROFITS, EXCEPT FOR AMOUNTS PAYABLE UNDER SECTION 11"), then the cap,
    // then the carve-out list — and the carve-out list is where the fraud, the
    // indemnity and the confidentiality breach live. Reading only the first
    // exception clause reported "0/6 typical carve-outs present. Present:
    // none." about a section that carves out four of them.
    //
    // The other half of the same defect is the vocabulary: a modern carve-out
    // list is introduced by "These limits DO NOT APPLY TO …", not by "except
    // for". Neither spelling reached this rule.
    //
    // Every exception clause in the section is read, and each is still bounded
    // to its OWN sentence, so a carve-out name in an unrelated sentence is no
    // more visible than it was before.
    const window = hit.text.slice(hit.match.index);
    const scan = new RegExp(EXCEPTION_CLAUSE.source, "gi");
    const clauses = window.match(scan) ?? [hit.match[0]];
    const exceptions = clauses.join(" ");
    const present = TYPICAL.filter(([, re]) => re.test(exceptions)).map(([name]) => name);
    const missing = TYPICAL.filter(([, re]) => !re.test(exceptions)).map(([name]) => name);
    return emit(ctx, rule, {
      title: `LoL exceptions: ${present.length}/${TYPICAL.length} typical carve-outs present`,
      description: `Present: ${present.join(", ") || "none"}. Missing: ${missing.join(", ") || "none"}.`,
      excerpt: truncate(hit.excerpt, 320),
      explanation:
        "Typical LoL carve-outs include fraud, willful misconduct, IP indemnity, confidentiality breach, and accrued payment obligations. Missing categories may be deliberate but are worth confirming.",
      position: hit.position,
    });
  },
};

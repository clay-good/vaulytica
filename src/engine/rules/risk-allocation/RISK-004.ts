import type { Rule, RuleContext, Finding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { PAGE_FURNITURE } from "../_helpers.js";
import { emit } from "../_helpers.js";

// `[^.;\n]` after the exception so the indemnity carve-out must be in the
// SAME sentence as the exception — otherwise a later, unrelated "indemnif"
// mention (e.g. a clause stating indemnity IS inside the cap) satisfied the
// pattern and produced a false "indemnity carved out of the cap". The cap is
// also called a "liability cap" / "cap on liability", and the carve-out is as
// often written "the cap SHALL/DOES NOT APPLY TO indemnification" as "except
// for indemnification" — the dominant phrasing the exception-only list missed.
const CARVE_OUT =
  /\b(?:limitation\s+of\s+liability|aggregate\s+liability|liability\s+cap|cap\s+on\s+liability)\b[\s\S]{0,400}?\b(?:except\s+for|excluding|other\s+than|(?:shall|does|do|will|would)\s+not\s+apply\s+to)\b[^.;\n]{0,200}\bindemnif/i;

/**
 * The paragraph in which the CAP itself excepts the indemnity, if any.
 *
 * Exported so RISK-015 can stand down where this rule speaks. Both rules were
 * reporting the same clause of a well-drafted consulting agreement, at
 * `warning`, in the same words — "Indemnity carved out of the liability cap"
 * and "Indemnification carved out of liability cap" — and a linter that says
 * one thing twice at its second-highest severity is spending the reader's
 * attention on its own bookkeeping. RISK-015's own subject is the indemnity
 * with NO cap anywhere, which this cannot see.
 */
export function capExceptsIndemnity(ctx: RuleContext): {
  text: string;
  position: ReturnType<typeof positionOf>;
} | null {
  const hits: Array<{ text: string; position: ReturnType<typeof positionOf> }> = [];
  let heading = "";
  forEachParagraph(ctx.tree, (p) => {
    // Page furniture is SKIPPED, not merely refused as a heading: a running
    // footer between a heading and the clause beneath it would otherwise clear
    // the heading the clause is read under, which is the same loss by another
    // route.
    if (PAGE_FURNITURE.test(p.text.trim())) return;
    const lead = p.section.heading.trim() || heading;
    heading = isHeadingLine(p.text) ? p.text.trim() : "";
    if (hits.length > 0) return;
    if (!CARVE_OUT.test(lead ? `${lead} ${p.text}` : p.text)) return;
    hits.push({ text: p.text, position: positionOf(p) });
  });
  return hits[0] ?? null;
}

/** RISK-004 — Indemnity cap vs. LoL cap interaction (warning). */
export const rule: Rule = {
  id: "RISK-004",
  version: "1.4.0",
  name: "Indemnity vs. LoL cap interaction",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Flags when an indemnity is carved out of the liability cap, creating uncapped exposure.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // The cap phrase is as often in the section HEADING as in the clause —
    // "13. Limitation of Liability." over "Neither party is liable … This
    // limitation does not apply to Seller's indemnification obligations" — and
    // a paragraph-only reading found the phrase in a heading that carries no
    // carve-out, then never saw the carve-out beneath it. A set of purchase
    // order terms and a set of SaaS terms each carve indemnity out of their
    // cap in exactly that shape, and neither was reported. The heading is
    // read together with the paragraph; the excerpt and position stay the
    // paragraph's.
    // Plain-text and pasted documents carry no styled headings at all, so the
    // "heading" a clause is read under is simply the short line before it.
    const carveOut = capExceptsIndemnity(ctx);
    if (!carveOut) return null;
    return emit(ctx, rule, {
      title: "Indemnity carved out of the liability cap",
      description:
        "The limitation-of-liability clause appears to except indemnification, potentially creating uncapped indemnity exposure.",
      excerpt: carveOut.text.slice(0, 320),
      explanation:
        "When indemnity is carved out of the LoL cap, the indemnifying party may face uncapped exposure on third-party claims. Verify a separate indemnity-specific cap exists, or that the carve-out is intended.",
      recommendation:
        "Confirm the carve-out is what you intend. An indemnity outside the cap is standard for third-party IP claims and is uncapped exposure everywhere else; if it is meant to be bounded, give it its own super-cap rather than leaving it outside the general one.",
      position: carveOut.position,
    });
  },
};

/** A short unbroken line is a heading, whether or not the file styles it as one. */
function isHeadingLine(text: string): boolean {
  if (PAGE_FURNITURE.test(text.trim())) return false;
  // The section number is part of the heading, and its own period is not a
  // sentence break: "13. Limitation of Liability." is one line, not two.
  const t = text.trim().replace(/^\d+(?:\.\d+)*\.?\s+/, "");
  return t.length > 0 && t.length <= 80 && !/[.;:!?]\s/.test(t);
}

/** The whole paragraph's position, which is what the finding points at. */
function positionOf(p: {
  section: { id: string };
  paragraph: { id: string };
  start: number;
  text: string;
}) {
  return {
    section_id: p.section.id,
    paragraph_id: p.paragraph.id,
    start: p.start,
    end: p.start + p.text.length,
  };
}

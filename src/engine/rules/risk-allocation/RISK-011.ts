import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const PROCEDURE = [
  ["notice", /prompt(?:ly)?\s+notice|written\s+notice/i],
  // "defense control" must be tied to the defense/claim — a bare "sole control"
  // matched an unrelated clause ("sole control over its own systems") and
  // wrongly reported this element as present.
  [
    "defense control",
    /(?:sole\s+|exclusive\s+)?control\s+of\s+the\s+(?:defense|claim|litigation|proceeding|action)|control\s+the\s+defense|(?:assume|conduct)\s+(?:the\s+)?defense/i,
  ],
  ["settlement consent", /settle(?:ment)?[\s\S]{0,40}consent/i],
] as const;

// An operative indemnity promise, as distinct from a passing reference. A
// SOW that incorporates "the MSA's … indemnification … provisions" by
// reference contains no indemnity clause of its own — auditing that
// cross-reference for defense-control and settlement-consent mechanics
// accused a correctly drafted document of an incomplete clause it never
// purported to contain.
const OPERATIVE_INDEMNITY =
  /\b(?:shall|will|must|agrees?\s+to|hereby)\s+(?:(?:further|also|fully|jointly\s+and\s+severally|at\s+all\s+times)\s+)?(?:defend,?\s+)?indemnif|\bindemnifies\b|\bindemnification\s+by\b/i;

/** RISK-011 — Indemnity procedure clause present (info). */
export const rule: Rule = {
  id: "RISK-011",
  version: "1.1.0",
  name: "Indemnity procedure clause",
  category: "risk-allocation",
  default_severity: "info",
  description:
    "Verifies the indemnity includes notice, defense-control, and settlement-consent procedural elements.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const indem = firstParagraphMatch(ctx, /\bindemnif/i);
    if (!indem) return null;
    // The first match is often the SECTION HEADING ("7. INDEMNIFICATION"),
    // and testing the procedure regexes against a heading declared every
    // element missing while they sat one paragraph below — with the excerpt
    // anchored to the heading (audit). Evaluate the whole containing
    // section, and anchor to its first substantive indemnity paragraph.
    const section = ctx.tree.sections.find((s) => s.id === indem.position.section_id);
    const paraText = (p: { runs: { text: string }[] }): string =>
      p.runs.map((r) => r.text).join("");
    const sectionText = section
      ? [section.heading ?? "", ...section.paragraphs.map(paraText)].join("\n")
      : indem.text;
    // No operative promise anywhere in the containing section means the match
    // was a passing reference (an incorporation of a parent agreement's
    // indemnity, a liability-cap carve-out) — there is no clause to audit.
    if (!OPERATIVE_INDEMNITY.test(sectionText)) return null;
    const missing = PROCEDURE.filter(([, re]) => !re.test(sectionText)).map(([n]) => n);
    if (missing.length === 0) return null;
    const substantive = section?.paragraphs
      .map(paraText)
      .find((t) => /\bindemnif/i.test(t) && t.length > 60);
    return emit(ctx, rule, {
      title: `Indemnity procedural elements missing: ${missing.join(", ")}`,
      description: `Indemnity clause appears to be missing: ${missing.join(", ")}.`,
      excerpt: (substantive ?? indem.text).slice(0, 280),
      explanation:
        "A complete indemnity clause specifies (a) the timeline and form for notice of a claim, (b) which party controls defense, and (c) whether settlement requires consent.",
      position: substantive
        ? { section_id: indem.position.section_id, start: 0, end: 0 }
        : indem.position,
    });
  },
};

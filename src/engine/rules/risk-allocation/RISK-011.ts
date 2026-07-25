import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { isStatutoryDandOIndemnity } from "./RISK-015.js";

const PROCEDURE = [
  ["notice", /prompt(?:ly)?\s+notice|written\s+notice/i],
  // "defense control" must be tied to the defense/claim — a bare "sole control"
  // matched an unrelated clause ("sole control over its own systems") and
  // wrongly reported this element as present.
  [
    "defense control",
    // "duty to defend" and "defend … with counsel …" articulate which party
    // conducts the defense just as much as "control of the defense" — an
    // indemnity that spells out the defense obligation and counsel selection
    // was wrongly reported as missing this element.
    /(?:sole\s+|exclusive\s+)?control\s+(?:of|over)\s+the\s+(?:defense|claim|litigation|proceeding|action)|control\s+the\s+defense|(?:assume|conduct)\s+(?:the\s+)?defense|duty\s+to\s+defend|defend[^.]{0,50}\bcounsel\b/i,
  ],
  // "shall not settle any claim in a manner that imposes liability on the
  // indemnified party without the indemnified party's prior written consent"
  // puts ~110 chars between "settle" and "consent". Bound the run to one
  // sentence ([^.]) — where a co-occurring settle/consent is always the
  // settlement-consent term — and accept either order.
  ["settlement consent", /settl\w*[^.]{0,160}consent|consent[^.]{0,120}settl/i],
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
  version: "1.4.0",
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
    // Statutory D&O indemnification (bylaws/charter) is not a commercial
    // indemnity clause; demanding defense-control and settlement-consent
    // mechanics of DGCL § 145 language audits the wrong instrument.
    if (isStatutoryDandOIndemnity(sectionText)) return null;
    // Likewise the fiduciary-protection indemnity every escrow agreement and
    // indenture gives its neutral agent ("Buyer and Seller shall jointly and
    // severally indemnify and hold harmless the Escrow Agent") — the agent's
    // protection is good-faith reliance and ministerial duties, not
    // commercial claims-procedure mechanics.
    if (
      /indemnify\s+and\s+hold\s+harmless\s+the\s+(?:escrow\s+agent|trustee|administrative\s+agent|depositary|custodian)\b/i.test(
        sectionText,
      )
    ) {
      return null;
    }
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

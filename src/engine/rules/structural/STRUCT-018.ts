import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";

/**
 * STRUCT-018 — Attachment completeness (spec-v9 Thrust B, §19–§20).
 *
 * The second classic closing gap: an agreement that refers to "Exhibit C"
 * with no Exhibit C anywhere in it. Where `STRUCT-016` flags the
 * *incorporation risk* of one missing exhibit (and fires on the first), this
 * rule is the *reconciliation view* — it sweeps every Exhibit / Schedule /
 * Annex / Appendix / Attachment **reference** against the set of those
 * attachments **present** in the document (as a section heading or a title
 * line), and reports the full set of referenced-but-absent attachments, plus
 * present-but-unreferenced ones, in one consolidated finding.
 *
 * Bundle-aware by composition: in a single document "present" means a
 * heading/title here; in folder mode the pipeline reconciles a referenced
 * exhibit that is a sibling file before surfacing this, so a legitimately
 * separate attachment file is not flagged. Internal-consistency only.
 */

const ATTACH_KINDS = "Exhibit|Schedule|Annex|Annexure|Appendix|Attachment|Addendum";
// A reference in running text: "see Exhibit C", "as set forth in Schedule 2".
const REF_RE = new RegExp(String.raw`\b(${ATTACH_KINDS})\s+([A-Z]|\d{1,2})\b`, "g");
// A heading / title line that *is* the attachment: "Exhibit C — Data Terms".
const TITLE_RE = new RegExp(String.raw`^\s*(${ATTACH_KINDS})\s+([A-Z]|\d{1,2})\b`, "i");

export const rule: Rule = {
  id: "STRUCT-018",
  version: "1.0.0",
  name: "Attachment completeness",
  category: "structural",
  default_severity: "warning",
  description:
    "Reconciles every referenced Exhibit / Schedule / Annex / Appendix / Attachment against the set present in the document and reports referenced-but-absent attachments (and present-but-unreferenced ones).",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const referenced = new Map<string, { label: string; section?: string; start: number }>();
    const present = new Set<string>();

    // Present attachments: section headings that name one.
    forEachSection(ctx.tree, (s) => {
      const m = TITLE_RE.exec(s.heading);
      if (m) present.add(key(m[1]!, m[2]!));
    });

    forEachParagraph(ctx.tree, (p) => {
      // A title line at the start of a paragraph also marks presence.
      const title = TITLE_RE.exec(p.text);
      if (title) present.add(key(title[1]!, title[2]!));
      // Collect references (skip the title-line self-reference).
      REF_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = REF_RE.exec(p.text)) !== null) {
        const k = key(m[1]!, m[2]!);
        if (!referenced.has(k)) {
          referenced.set(k, {
            label: `${nice(m[1]!)} ${m[2]!.toUpperCase()}`,
            section: p.section.id,
            start: p.start + m.index,
          });
        }
      }
    });

    if (referenced.size === 0) return null;

    const absent = [...referenced.entries()]
      .filter(([k]) => !present.has(k))
      .map(([, v]) => v)
      .sort((a, b) => a.label.localeCompare(b.label, "en"));
    if (absent.length === 0) return null;

    const unreferenced = [...present]
      .filter((k) => !referenced.has(k))
      .map((k) => labelOf(k))
      .sort((a, b) => a.localeCompare(b, "en"));

    const absentList = absent.map((a) => a.label).join(", ");
    const first = absent[0]!;
    const unrefNote =
      unreferenced.length > 0
        ? ` Also present but never referenced: ${unreferenced.join(", ")}.`
        : "";
    return makeFinding({
      rule,
      title: `Referenced attachment${absent.length === 1 ? "" : "s"} not present: ${absent.length}`,
      description: `${absentList} ${absent.length === 1 ? "is" : "are"} referenced but not attached to the document.${unrefNote}`,
      excerptText: first.label,
      explanation:
        "The agreement refers to an exhibit, schedule, annex, appendix, or attachment that is not present in the document. If the referenced material carries operative terms, those terms are missing from the contract. (In folder mode, a referenced attachment that is a sibling file is reconciled before this is reported.) This is an internal-consistency check, not an assertion that the attachment is legally required.",
      recommendation: `Attach each referenced item (${absentList}) before execution, or remove the reference if it is no longer needed. Reconcile every cross-reference to a present attachment as part of the closing checklist.`,
      position: {
        section_id: first.section ?? "",
        start: first.start,
        end: first.start + first.label.length,
      },
      source_citations: [],
    });
  },
};

function key(kind: string, id: string): string {
  return `${kind.toLowerCase()}:${id.toLowerCase()}`;
}

function labelOf(k: string): string {
  const [kind, id] = k.split(":") as [string, string];
  return `${nice(kind)} ${id.toUpperCase()}`;
}

function nice(kind: string): string {
  return kind.charAt(0).toUpperCase() + kind.slice(1).toLowerCase();
}

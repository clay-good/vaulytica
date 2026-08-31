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
// Decimal designators ("Schedule 3.7") are the disclosure-schedule norm —
// the integer-only capture truncated them to "Schedule 3" and reconciled a
// reference the document never makes.
// A hyphenated suffix belongs to the designator: "Exhibit A-1" is one
// attachment, not a reference to "Exhibit A". Capturing only the head both
// named the wrong attachment and reconciled a reference the document never
// made.
/**
 * A letter designator followed immediately by a dotted number is a VERSION, not
 * an attachment: "the template Addendum B.1.0 issued by the Information
 * Commissioner" is the ICO's own version string for the UK IDTA, and every
 * executed IDTA carries it. Read as a designator it reconciled a reference to
 * "Addendum B" that the document never makes. The digit must follow the period
 * immediately, so an ordinary sentence break — "Exhibit A. 3 copies shall be
 * delivered" — is untouched.
 */
const LETTER_DESIGNATOR = String.raw`[A-Z](?!\.\d)`;

const REF_RE = new RegExp(
  String.raw`\b(${ATTACH_KINDS})\s+(\d{1,2}(?:\.\d{1,2})*|${LETTER_DESIGNATOR})(-\d{1,2})?\b`,
  "g",
);

/**
 * IRS partnership and S-corporation forms, which every LLC, partnership, and
 * profits-interest agreement names in its tax provisions — "reporting the
 * Participant's distributive share on Schedule K-1". They are forms the IRS
 * issues, never attachments to the contract, and the head-only capture read
 * them as a referenced "Schedule K" that was missing from the document.
 */
const IRS_FORM = /^Schedule K-[123]$/i;
// A heading / title line that *is* the attachment: "Exhibit C — Data Terms".
// A title line may carry a leading clause number ("3. Schedule 3.7 —
// Litigation" in a flat-paste layout) — the attachment is present. The
// identifier may be quoted ('Exhibit "C" — Data Terms') or introduced by "No."
// ("Exhibit No. 3"); without tolerating those, the heading went unrecognized
// and a plainly attached exhibit read as referenced-but-absent.
const TITLE_RE = new RegExp(
  String.raw`^\s*(?:\d+(?:\.\d+)*\.\s+)?(${ATTACH_KINDS})\s+(?:No\.?\s+|Number\s+)?["'“”‘’]?(\d{1,2}(?:\.\d{1,2})*|${LETTER_DESIGNATOR})(-\d{1,2})?(?:["'“”‘’]|\b)`,
  "i",
);

/**
 * One entry of an attachment LIST — `Exhibit B — Depiction of the Easement
 * Area`. The em/en dash and the Title-Case name after it are what separate an
 * entry from a body reference; a plain hyphen is excluded because it is part
 * of a compound id ("Exhibit A-1").
 */
const LIST_ENTRY_RE = new RegExp(
  String.raw`\b(${ATTACH_KINDS})\s+(\d{1,2}(?:\.\d{1,2})*|[A-Z])(-\d{1,2})?\s*[\u2013\u2014]\s*[A-Z]`,
  "g",
);

export const rule: Rule = {
  id: "STRUCT-018",
  version: "1.3.0",
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
      if (m) present.add(key(m[1]!, `${m[2]!}${m[3] ?? ""}`));
    });

    forEachParagraph(ctx.tree, (p) => {
      // A title line at the start of a paragraph also marks presence.
      const title = TITLE_RE.exec(p.text);
      if (title) present.add(key(title[1]!, `${title[2]!}${title[3] ?? ""}`));
      // An attachment LIST is several entries together:
      //
      //   Exhibit A — Legal Description of the Servient Estate
      //   Exhibit B — Depiction of the Easement Area
      //
      // Whether those arrive as one paragraph or two — or joined onto the
      // signature block above them — is a fact about the file, and the
      // anchored scan above sees only whichever one happens to come first. An
      // easement that attaches both was told Exhibit B is referenced but not
      // attached, and so were six other specimens.
      //
      // The entry shape carries the discrimination on its own: an em or en
      // dash directly after the id, followed by a Title-Case name. A body
      // reference ("described on Exhibit B, being a strip twenty feet wide")
      // has a comma there, not a dash — so the scan needs no anchor and finds
      // the list wherever the ingest happens to put it.
      LIST_ENTRY_RE.lastIndex = 0;
      let e: RegExpExecArray | null;
      while ((e = LIST_ENTRY_RE.exec(p.text)) !== null) {
        present.add(key(e[1]!, `${e[2]!}${e[3] ?? ""}`));
      }
      // Collect references (skip the title-line self-reference).
      REF_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = REF_RE.exec(p.text)) !== null) {
        const id = `${m[2]!}${m[3] ?? ""}`;
        if (IRS_FORM.test(`${m[1]!} ${id}`)) continue;
        const k = key(m[1]!, id);
        if (!referenced.has(k)) {
          referenced.set(k, {
            label: `${nice(m[1]!)} ${id.toUpperCase()}`,
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

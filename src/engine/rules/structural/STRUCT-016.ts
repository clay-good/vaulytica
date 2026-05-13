import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, allMatches } from "../_helpers.js";
import { forEachSection } from "../../../extract/walk.js";

/**
 * STRUCT-016 — Incorporation by reference to an external / unattached
 * document (warning).
 *
 * Detects clauses that incorporate an Acceptable Use Policy, Privacy
 * Policy, Service Description, SLA, Documentation, Order Form, Exhibit
 * or similar by URL or by name, when that document is not attached to
 * the contract and not present elsewhere in the file. Common patterns:
 *
 *   - "subject to Vendor's Acceptable Use Policy available at
 *      https://vendor.com/aup"
 *   - "incorporated herein by reference: the Service Description
 *      attached as Exhibit B"  — but Exhibit B is empty / missing
 *   - "the SLA published on Vendor's website" — no anchor section,
 *     no link
 *
 * The legal risk: an incorporation-by-reference clause makes that
 * external document part of the contract. If it's hosted on a URL
 * the vendor controls, the vendor can change the agreement
 * unilaterally by updating the linked page (this stacks on DARK-009).
 * If it's a missing Exhibit, the operative terms are simply absent.
 *
 * Detection runs in two passes:
 *   (a) URL-based: the paragraph cites an Acceptable Use Policy,
 *       Privacy Policy, SLA, Service Description, Documentation,
 *       etc. with a URL and "incorporated" / "subject to" /
 *       "governed by" language.
 *   (b) Exhibit-based: the document refers to "Exhibit B" / "Schedule
 *       2" / "Attachment 1" as containing operative terms ("attached
 *       as", "set forth in", "described in"), and the referenced
 *       exhibit either does not exist as a section heading or is
 *       present but empty.
 */
export const rule: Rule = {
  id: "STRUCT-016",
  version: "1.0.0",
  name: "Incorporation by reference to external / unattached document",
  category: "structural",
  default_severity: "warning",
  description:
    "Flags AUP / privacy policy / SLA / documentation / exhibit incorporation-by-reference where the referenced material is hosted at a URL or is an empty / missing exhibit.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // Pass A: URL-based incorporation.
    const urlMatches = allMatches(
      ctx,
      /\b(?:incorporated\s+(?:by|herein\s+by|into\s+this\s+Agreement\s+by)\s+reference|subject\s+to|governed\s+by|in\s+accordance\s+with|comply\s+with)\b[\s\S]{0,200}\b(?:Acceptable\s+Use\s+Policy|Privacy\s+Policy|Cookie\s+Policy|SLA|Service\s+Level\s+Agreement|Documentation|Service\s+Description|Terms\s+of\s+Use|Terms\s+of\s+Service|Code\s+of\s+Conduct|Security\s+Policy|Data\s+Processing\s+Addendum|DPA)\b[\s\S]{0,200}(?:https?:\/\/[^\s,)]+|located\s+at\s+[^\s,]+|available\s+at\s+[^\s,]+|on\s+(?:Vendor|Provider|Company|Licensor)'?s?\s+website|on\s+the\s+(?:Vendor|Provider|Company)\s+(?:website|portal))/i,
    );
    if (urlMatches.length > 0) {
      const first = urlMatches[0]!;
      return emit(ctx, rule, {
        title: "Incorporation by reference to a URL-hosted document",
        description: first.match[0].slice(0, 240),
        excerpt: first.text.slice(Math.max(0, first.match.index - 30), first.match.index + 320),
        explanation:
          "A clause that incorporates an Acceptable Use Policy, Privacy Policy, SLA, Documentation, or similar by URL makes the linked page part of the binding agreement. Because the vendor controls the page, the vendor can change the contract unilaterally by updating it. This compounds the 'post-and-pray' amendment risk (see DARK-009).",
        recommendation:
          "Either attach the referenced document as an exhibit (pin the version that was negotiated), or limit the incorporation: 'as in effect on the Effective Date, attached hereto as Exhibit X.' Add a notice-and-objection right for material changes to the linked policy.",
        position: first.position,
      });
    }

    // Pass B: exhibit-based incorporation pointing at a missing /
    // empty exhibit.
    const exhibitRefs = allMatches(
      ctx,
      /\b(?:attached\s+(?:hereto\s+)?as|set\s+forth\s+in|described\s+in|specified\s+in|incorporated\s+(?:into|by\s+reference\s+(?:in|from))|provided\s+in|listed\s+in)\s+(Exhibit|Schedule|Attachment|Appendix|Annex)\s+([A-Z]|\d{1,2})\b/i,
    );
    if (exhibitRefs.length === 0) return null;

    // Build a set of exhibit anchors actually present in the document.
    const anchors = new Set<string>();
    const anchorParaCounts = new Map<string, number>();
    forEachSection(ctx.tree, (s) => {
      const m = /^\s*(Exhibit|Schedule|Attachment|Appendix|Annex)\s+([A-Z]|\d{1,2})\b/i.exec(s.heading);
      if (m) {
        const key = `${m[1]!.toLowerCase()}:${m[2]!.toLowerCase()}`;
        anchors.add(key);
        // Count substantive paragraphs (≥30 chars) to decide whether
        // the exhibit was actually filled in or left as a stub.
        const count = s.paragraphs.filter((p) => p.runs.map((r) => r.text).join("").trim().length >= 30).length;
        anchorParaCounts.set(key, count);
      }
    });

    for (const r of exhibitRefs) {
      const kind = (r.match[1] ?? "").toLowerCase();
      const id = (r.match[2] ?? "").toLowerCase();
      const key = `${kind}:${id}`;
      const present = anchors.has(key);
      const substantive = (anchorParaCounts.get(key) ?? 0) >= 1;
      if (present && substantive) continue;

      const niceKind = (r.match[1] ?? "").replace(/^./, (c) => c.toUpperCase());
      const niceId = (r.match[2] ?? "").toUpperCase();
      const status = present ? "is present but empty / placeholder" : "is not attached to the document";
      return emit(ctx, rule, {
        title: `${niceKind} ${niceId} referenced but ${present ? "empty" : "missing"}`,
        description: `${r.match[0]} — ${niceKind} ${niceId} ${status}.`,
        excerpt: r.text.slice(Math.max(0, r.match.index - 40), r.match.index + 240),
        explanation:
          "The agreement refers to an exhibit / schedule / attachment as the source of operative terms, but the referenced exhibit is missing or empty. The operative terms are therefore not in the contract. If the exhibit is meant to be supplied later, that later supplement is a new contractual document and should be governed by an amendment process.",
        recommendation:
          `Attach a substantive ${niceKind} ${niceId} before execution, or remove the reference. If the exhibit is genuinely intended to be filled in later, mark it 'to be agreed' and add a process: who proposes, by when, what happens if the parties cannot agree.`,
        position: r.position,
      });
    }
    return null;
  },
};

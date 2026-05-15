/**
 * Subprocessor inventory section (spec-v3.md §57).
 *
 * Rendered only when a subprocessor inventory is referenced in the document.
 * The page surfaces the list location, the form of authorization, the
 * notice period, the objection right, and any subprocessors actually named
 * in the document text. v3 explicitly does not fetch external subprocessor
 * lists.
 */

import type { Paragraph, Table } from "docx";
import type { SubprocessorInventory } from "../../extract/v3/types.js";
import { h1, para, pageBreak, buildTable, headerRow, bodyRow } from "./_dx.js";

const CONSENT_LABEL: Record<SubprocessorInventory["consent_form"], string> = {
  "general-written": "General written authorization (Art. 28(2) opt-in)",
  "specific-prior": "Specific prior authorization required",
  silent: "Silent — not addressed in the document",
};

const LIST_LOCATION_LABEL: Record<SubprocessorInventory["list_location"], string> = {
  annex: "Annex / Schedule inside the document",
  url: "External URL referenced by the document",
  "on-request": "Available on request (not enumerated)",
  absent: "Not located",
};

const OBJECTION_CONSEQUENCE_LABEL: Record<SubprocessorInventory["objection_consequence"], string> = {
  "terminate-for-convenience": "Right to terminate the affected agreement for convenience",
  "terminate-affected-services": "Right to terminate the affected services only",
  "no-right": "No termination right on objection",
  unspecified: "Consequence of objection not specified",
};

export function renderSubprocessorPage(inv: SubprocessorInventory | null | undefined): (Paragraph | Table)[] {
  if (!inv) return [];
  const rows = [
    headerRow(["Attribute", "Value"]),
    bodyRow(["Subprocessing permitted", inv.permitted ? "Yes" : "No"]),
    bodyRow(["Consent form", CONSENT_LABEL[inv.consent_form]]),
    bodyRow(["List location", LIST_LOCATION_LABEL[inv.list_location]]),
    bodyRow([
      "Notice of additions",
      inv.notice_days !== null ? `${inv.notice_days} days` : "Not numerically specified",
    ]),
    bodyRow([
      "Objection right",
      inv.objection_right
        ? `Yes — ${OBJECTION_CONSEQUENCE_LABEL[inv.objection_consequence]}`
        : "No",
    ]),
    bodyRow([
      "Flow-down to subprocessors required",
      inv.flow_down_required ? "Yes (Art. 28(4) compliant)" : "Not required by the document",
    ]),
  ];
  return [
    h1("Subprocessor Inventory"),
    para({
      text: "The following terms govern subprocessing under this document. Subprocessors named in external lists are not enumerated here; the v3 engine does not fetch URLs at run time.",
    }),
    buildTable(rows),
    para({ text: `Source excerpt: "${truncate(inv.raw_text, 480)}"`, italics: true }),
    pageBreak(),
  ];
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}

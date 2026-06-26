/**
 * Insurance summary section (spec-v3.md §58).
 *
 * Rendered when an insurance schedule is present in the document — either
 * because the COI playbook is active, or because an MSA carries an
 * insurance addendum. Surfaces per-line coverage amounts, required
 * endorsements, the carrier-rating requirement, and the cancellation-
 * notice clause.
 */

import type { Paragraph, Table } from "docx";
import type { InsuranceSchedule, InsuranceLine } from "../../extract/v3/types.js";
import { h1, para, pageBreak, buildTable, headerRow, bodyRow } from "./_dx.js";

const LINE_LABEL: Record<InsuranceLine, string> = {
  "commercial-general-liability": "Commercial General Liability",
  "professional-liability": "Professional Liability (E&O)",
  "cyber-liability": "Cyber Liability",
  "umbrella-excess": "Umbrella / Excess",
  "workers-compensation": "Workers' Compensation",
  "employers-liability": "Employer's Liability",
  "automobile-liability": "Automobile Liability",
  "employment-practices-liability": "Employment Practices Liability (EPLI)",
  "fiduciary-liability": "Fiduciary Liability",
  other: "Other",
};

export function renderInsurancePage(
  schedule: InsuranceSchedule | undefined,
): (Paragraph | Table)[] {
  if (!schedule) return [];
  if (
    schedule.amounts.length === 0 &&
    schedule.endorsements.length === 0 &&
    !schedule.required_am_best_rating &&
    schedule.notice_of_cancellation_days === null
  ) {
    return [];
  }
  const out: (Paragraph | Table)[] = [
    h1("Insurance Summary"),
    para({
      text: "The following insurance terms were detected in this document. Coverage amounts are compared against typical minimums in the report's findings section, not in this summary.",
    }),
  ];
  if (schedule.amounts.length > 0) {
    out.push(
      buildTable([
        headerRow(["Line", "Per-occurrence (USD)", "Aggregate (USD)"]),
        ...schedule.amounts.map((a) =>
          bodyRow([
            LINE_LABEL[a.line] ?? a.line,
            a.per_occurrence_usd !== null ? formatUsd(a.per_occurrence_usd) : "—",
            a.aggregate_usd !== null ? formatUsd(a.aggregate_usd) : "—",
          ]),
        ),
      ]),
    );
  }
  if (schedule.endorsements.length > 0) {
    out.push(
      para({
        text: `Endorsements referenced by form number: ${schedule.endorsements.map((e) => e.form_number).join(", ")}.`,
      }),
    );
  }
  if (schedule.required_am_best_rating) {
    out.push(
      para({ text: `Required carrier rating: ${schedule.required_am_best_rating} (AM Best).` }),
    );
  }
  if (schedule.notice_of_cancellation_days !== null) {
    out.push(
      para({ text: `Notice of cancellation: ${schedule.notice_of_cancellation_days} days.` }),
    );
  }
  out.push(pageBreak());
  return out;
}

function formatUsd(n: number): string {
  return "$" + n.toLocaleString("en-US");
}

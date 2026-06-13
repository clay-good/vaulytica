/**
 * The v9 "Last Look" report surfaces, bundled for the multi-format renderers.
 *
 * Thrust A (delivery / `HANDOFF-*`), Thrust B (the closing checklist), and
 * Thrust C (the critical-dates register) are all **additive, render-side**
 * artifacts that live outside the engine `result_hash` (each carries its own
 * hash, or is a pure projection of `run.findings`). The JSON report, the tab,
 * the CLI, and the Markdown/CSV/.ics exports already carry them; this bundle is
 * the single optional argument the DOCX, HTML, and SARIF builders accept so the
 * same three surfaces render everywhere the report does — without changing any
 * builder's required positional signature, so every existing caller and golden
 * is unaffected.
 */

import type { DeliveryReport } from "../delivery/types.js";
import type { CriticalDatesRegister } from "./critical-dates.js";
import type { ClosingChecklist } from "./closing-checklist.js";

export type V9Surfaces = {
  /** Pre-disclosure ("Clean to Send") scan over the original container bytes. */
  delivery?: DeliveryReport;
  /** Computed critical-dates register (Thrust C). */
  criticalDates?: CriticalDatesRegister;
  /** Consolidated execution-readiness checklist (Thrust B). */
  closingChecklist?: ClosingChecklist;
};

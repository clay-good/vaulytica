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
import type { RelatedDocument } from "./companions.js";

export type V9Surfaces = {
  /** Pre-disclosure ("Clean to Send") scan over the original container bytes. */
  delivery?: DeliveryReport;
  /** Computed critical-dates register (Thrust C). */
  criticalDates?: CriticalDatesRegister;
  /** Consolidated execution-readiness checklist (Thrust B). */
  closingChecklist?: ClosingChecklist;
  /**
   * The families the matched playbook names as its normal pairings
   * (`Playbook.companion_playbooks`), resolved to display names against the
   * full catalog — which is why it is computed by the pipeline and passed in
   * rather than derived here from `playbook`. A reference list, never a gap: a
   * single document cannot know whether the companion exists, so unlike the
   * bundle's "Companion Documents Not in This Package" it asserts nothing about
   * absence. Omitted for the 50 families that name none, so those reports are
   * byte-unchanged.
   *
   * Note this bag has outgrown its name: it is no longer only the three v9
   * "Last Look" surfaces, but the one optional argument every multi-format
   * builder accepts, which is what makes it the right place for an additive
   * render-side surface that must reach DOCX, HTML and JSON alike.
   */
  relatedDocuments?: ReadonlyArray<RelatedDocument>;
};

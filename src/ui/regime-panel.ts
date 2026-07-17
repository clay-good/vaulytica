/**
 * Privacy-regime assertion panel (add-privacy-notice-pack — the tab
 * counterpart of the CLI's `--regime`). A small affordance beside the drop
 * zone: assert which privacy-notice regimes apply, and the next single-document
 * analysis runs the PNOT content checks for them — only when the document
 * matches a privacy-notice playbook, dormant otherwise, exactly like the CLI.
 *
 * Which law applies is the reviewer's assertion, never an inference: nothing
 * is checked by default, and the asserted regimes are stamped into the run.
 *
 * The id/label list below is a hand-copied projection of `REGIME_IDS` so the
 * eager marketing-page bundle stays free of the full pattern data; a unit
 * test pins it against the real registry (drift fails the suite).
 */

// Type-only import — erased at build; keeps the regime pattern data lazy.
import type { RegimeId } from "../privacy/regime-data.js";

export type RegimeChoice = { id: RegimeId; label: string };

/** The assertable regimes, in the registry's order. Pinned to `REGIME_IDS` by test. */
export const REGIME_CHOICES: readonly RegimeChoice[] = [
  { id: "ccpa", label: "California (CCPA/CPRA)" },
  { id: "gdpr-13", label: "GDPR Art. 13" },
  { id: "gdpr-14", label: "GDPR Art. 14" },
  { id: "co", label: "Colorado (CPA)" },
  { id: "va", label: "Virginia (VCDPA)" },
  { id: "tx", label: "Texas (TDPSA)" },
  { id: "or", label: "Oregon (OCPA)" },
];

export type RegimePanelOptions = {
  /**
   * Called with the asserted regime ids (sorted) whenever the selection
   * changes. An empty array keeps the pack dormant.
   */
  onChange: (regimes: readonly RegimeId[]) => void;
};

export function bindRegimePanel(container: HTMLElement, opts: RegimePanelOptions): () => void {
  container.innerHTML = `
    <details class="regime-details" data-role="regime-details">
      <summary class="btn-link" data-role="regime-summary">Reviewing a privacy notice? Assert its regimes…</summary>
      <fieldset class="regime-fieldset" data-role="regime-fieldset">
        <legend>Asserted regimes</legend>
        ${REGIME_CHOICES.map(
          (c) =>
            `<label><input type="checkbox" value="${c.id}" data-role="regime-choice" /> ${c.label}</label>`,
        ).join("\n        ")}
        <div class="regime-hint" data-role="regime-hint">Runs the regime's notice content checks when the document is a privacy notice — presence of the required content, never a compliance conclusion. Nothing is asserted by default.</div>
      </fieldset>
    </details>
  `;

  const boxes = [...container.querySelectorAll<HTMLInputElement>('[data-role="regime-choice"]')];

  const notify = (e: Event): void => {
    e.stopPropagation();
    const asserted = boxes
      .filter((b) => b.checked)
      .map((b) => b.value as RegimeId)
      .sort((a, b) => a.localeCompare(b, "en"));
    opts.onChange(asserted);
  };

  for (const box of boxes) {
    box.addEventListener("click", (e) => e.stopPropagation());
    box.addEventListener("change", notify);
  }

  return () => {
    container.innerHTML = "";
  };
}

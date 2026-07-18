/**
 * Estate-checks assertion panel (add-estate-planning-pack — the tab
 * counterpart of the CLI's `--estate-checks` / `--state`). A small affordance
 * beside the drop zone: assert the estate deepening checks and, optionally,
 * the will's state — the next single-document analysis runs the EST recital /
 * arithmetic rules, overlay-aware when the state is in the verified
 * formalities catalog. Only when the document matches a will / trust /
 * codicil playbook; dormant otherwise, exactly like the CLI.
 *
 * Selecting a state implies the checks (mirror of `--state` implying
 * `--estate-checks`): the checkbox is auto-checked and locked while a state
 * is selected. Nothing is asserted by default.
 *
 * The state list below is a hand-copied projection of `US_STATE_CODES`
 * (src/dkb/estate-formalities.ts) so the eager marketing-page bundle stays
 * free of the formalities catalog; a unit test pins it against the real
 * registry (drift fails the suite).
 */

export type EstateAssertion = {
  /** True when the estate deepening checks are asserted. */
  checks: boolean;
  /** Normalized `us-xx` id when a state is asserted (implies `checks`). */
  state?: string;
};

export type EstateStateChoice = { id: string; label: string };

/** The 50 states + DC, in code order. Pinned to `US_STATE_CODES` by test. */
export const ESTATE_STATE_CHOICES: readonly EstateStateChoice[] = [
  { id: "us-al", label: "Alabama" },
  { id: "us-ak", label: "Alaska" },
  { id: "us-az", label: "Arizona" },
  { id: "us-ar", label: "Arkansas" },
  { id: "us-ca", label: "California" },
  { id: "us-co", label: "Colorado" },
  { id: "us-ct", label: "Connecticut" },
  { id: "us-de", label: "Delaware" },
  { id: "us-dc", label: "District of Columbia" },
  { id: "us-fl", label: "Florida" },
  { id: "us-ga", label: "Georgia" },
  { id: "us-hi", label: "Hawaii" },
  { id: "us-id", label: "Idaho" },
  { id: "us-il", label: "Illinois" },
  { id: "us-in", label: "Indiana" },
  { id: "us-ia", label: "Iowa" },
  { id: "us-ks", label: "Kansas" },
  { id: "us-ky", label: "Kentucky" },
  { id: "us-la", label: "Louisiana" },
  { id: "us-me", label: "Maine" },
  { id: "us-md", label: "Maryland" },
  { id: "us-ma", label: "Massachusetts" },
  { id: "us-mi", label: "Michigan" },
  { id: "us-mn", label: "Minnesota" },
  { id: "us-ms", label: "Mississippi" },
  { id: "us-mo", label: "Missouri" },
  { id: "us-mt", label: "Montana" },
  { id: "us-ne", label: "Nebraska" },
  { id: "us-nv", label: "Nevada" },
  { id: "us-nh", label: "New Hampshire" },
  { id: "us-nj", label: "New Jersey" },
  { id: "us-nm", label: "New Mexico" },
  { id: "us-ny", label: "New York" },
  { id: "us-nc", label: "North Carolina" },
  { id: "us-nd", label: "North Dakota" },
  { id: "us-oh", label: "Ohio" },
  { id: "us-ok", label: "Oklahoma" },
  { id: "us-or", label: "Oregon" },
  { id: "us-pa", label: "Pennsylvania" },
  { id: "us-ri", label: "Rhode Island" },
  { id: "us-sc", label: "South Carolina" },
  { id: "us-sd", label: "South Dakota" },
  { id: "us-tn", label: "Tennessee" },
  { id: "us-tx", label: "Texas" },
  { id: "us-ut", label: "Utah" },
  { id: "us-vt", label: "Vermont" },
  { id: "us-va", label: "Virginia" },
  { id: "us-wa", label: "Washington" },
  { id: "us-wv", label: "West Virginia" },
  { id: "us-wi", label: "Wisconsin" },
  { id: "us-wy", label: "Wyoming" },
];

export type EstatePanelOptions = {
  /** Called with the current assertion whenever it changes. */
  onChange: (assertion: EstateAssertion) => void;
};

export function bindEstatePanel(container: HTMLElement, opts: EstatePanelOptions): () => void {
  container.innerHTML = `
    <details class="regime-details" data-role="estate-details">
      <summary class="btn-link" data-role="estate-summary">Reviewing a will or trust? Assert the estate checks…</summary>
      <fieldset class="regime-fieldset" data-role="estate-fieldset">
        <legend>Estate deepening checks</legend>
        <label><input type="checkbox" data-role="estate-toggle" /> Run the estate recital / arithmetic checks</label>
        <label>State
          <select data-role="estate-state">
            <option value="">No state asserted</option>
            ${ESTATE_STATE_CHOICES.map((c) => `<option value="${c.id}">${c.label}</option>`).join(
              "\n            ",
            )}
          </select>
        </label>
        <div class="regime-hint" data-role="estate-hint">Runs the recital-presence, residuary-arithmetic, and fiduciary checks when the document is a will, trust, or codicil. Selecting a state implies the checks and applies its verified execution-formality posture when available. Checks recitals, never valid execution. Nothing is asserted by default.</div>
      </fieldset>
    </details>
  `;

  const toggle = container.querySelector<HTMLInputElement>('[data-role="estate-toggle"]')!;
  const state = container.querySelector<HTMLSelectElement>('[data-role="estate-state"]')!;

  const notify = (e: Event): void => {
    e.stopPropagation();
    const selected = state.value || undefined;
    // A selected state implies the checks — mirror the CLI, and show it.
    if (selected) {
      toggle.checked = true;
      toggle.disabled = true;
    } else {
      toggle.disabled = false;
    }
    opts.onChange({
      checks: toggle.checked || selected !== undefined,
      ...(selected ? { state: selected } : {}),
    });
  };

  for (const el of [toggle, state]) {
    el.addEventListener("click", (e) => e.stopPropagation());
    el.addEventListener("change", notify);
  }

  return () => {
    container.innerHTML = "";
  };
}

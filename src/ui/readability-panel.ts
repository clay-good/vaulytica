/**
 * Readability-standard assertion (add-readability-measure, task 4): the tab's
 * counterpart of `--readability`. Choosing a statute holds the next
 * single-document analysis to it; nothing is asserted by default, because
 * nothing in a document says where it was filed.
 *
 * The choices are a hand-copied projection of `READABILITY_STANDARDS`, so the
 * eager bundle stays free of the table; a unit test pins the two together.
 */
export const READABILITY_CHOICES: ReadonlyArray<{ id: string; label: string }> = [
  { id: "fl", label: "Florida, Fla. Stat. § 627.4145 (policy forms)" },
  { id: "me", label: "Maine, 24-A M.R.S. § 2441 (policy forms)" },
  { id: "mi", label: "Michigan, MCL § 500.2236(3) (personal-lines forms)" },
  { id: "mn", label: "Minnesota, Minn. Stat. ch. 72C (auto, home, life, health)" },
  { id: "nv", label: "Nevada, NRS § 687B.124 (life and health policies)" },
  { id: "oh", label: "Ohio, Ohio Rev. Code § 3902.04 (life and health forms)" },
  { id: "or", label: "Oregon, ORS § 743.106 (life and health policies)" },
  { id: "mt", label: "Montana, MCA § 33-15-325 (life and disability policies)" },
  { id: "wv", label: "West Virginia, W. Va. Code § 33-29-5 (life and health policies)" },
  { id: "nd", label: "North Dakota, N.D.C.C. §§ 26.1-33-30, 26.1-36-14 (life, health)" },
  { id: "ne", label: "Nebraska, Neb. Rev. Stat. § 44-3405 (life and health policies)" },
  { id: "dc", label: "District of Columbia, D.C. Code § 31-4725 (life insurers' forms)" },
  { id: "ok", label: "Oklahoma, 36 O.S. § 3645 (life, accident and health forms)" },
];

export function bindReadabilityPanel(
  container: HTMLElement,
  opts: { onChange: (standard: string | undefined) => void },
): void {
  container.innerHTML = `<details class="regime-details"><summary class="btn-link">Reviewing an insurance policy form? Hold it to a readability statute…</summary><fieldset class="regime-fieldset"><legend>Readability statute</legend><label>Statute <select data-role="readability-standard"><option value="">None asserted</option>${READABILITY_CHOICES.map((c) => `<option value="${c.id}">${c.label}</option>`).join("")}</select></label><div class="regime-hint">Flags a reading-ease score below the statute's minimum, and a long form with no table of contents. The score always appears in the reports; only a statute you choose produces findings.</div></fieldset></details>`;
  const select = container.querySelector<HTMLSelectElement>('[data-role="readability-standard"]')!;
  select.addEventListener("click", (e) => e.stopPropagation());
  select.addEventListener("change", (e) => {
    e.stopPropagation();
    opts.onChange(select.value || undefined);
  });
}

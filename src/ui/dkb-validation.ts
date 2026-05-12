/**
 * Footer hookup for the DKB validation status (spec-v3.md §14, Step 20).
 *
 * The build pipeline writes `/dkb/v3/validation-status.json` of the form
 * `{ dkb_last_validated_at: ISO8601, stale_citations_pending_review: N }`.
 * This module fetches that file at page load and renders into the
 * `data-role="dkb-validation"` footer node. A network failure leaves the
 * footer at its default text (the privacy posture forbids any external
 * call, so the fetch hits the same origin only).
 */

export type DkbValidationStatus = {
  dkb_last_validated_at: string;
  stale_citations_pending_review: number;
};

const formatDate = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
};

export function renderDkbValidation(
  root: ParentNode,
  status: DkbValidationStatus,
): void {
  const dateEl = root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]');
  const countEl = root.querySelector<HTMLElement>('[data-role="dkb-stale-count"]');
  if (dateEl) dateEl.textContent = formatDate(status.dkb_last_validated_at);
  if (countEl) countEl.textContent = String(status.stale_citations_pending_review);
  const wrapper = root.querySelector<HTMLElement>('[data-role="dkb-validation"]');
  if (wrapper) {
    wrapper.dataset.validatedAt = status.dkb_last_validated_at;
    wrapper.dataset.staleCount = String(status.stale_citations_pending_review);
  }
}

export async function hydrateDkbValidation(
  options: { base?: string; fetchImpl?: typeof fetch; root?: ParentNode } = {},
): Promise<DkbValidationStatus | null> {
  const base = options.base ?? "/dkb";
  const f = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const root = options.root ?? document;
  if (!f) return null;
  try {
    const res = await f(`${base}/v3/validation-status.json`, { cache: "no-cache" });
    if (!res.ok) return null;
    const json = (await res.json()) as unknown;
    if (
      typeof json !== "object" ||
      json === null ||
      typeof (json as Record<string, unknown>).dkb_last_validated_at !== "string" ||
      typeof (json as Record<string, unknown>).stale_citations_pending_review !== "number"
    ) {
      return null;
    }
    const status = json as DkbValidationStatus;
    renderDkbValidation(root, status);
    return status;
  } catch {
    return null;
  }
}

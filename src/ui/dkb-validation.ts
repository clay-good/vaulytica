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

export type DkbValidationStatus =
  | {
      /** A real attestation produced by the DKB validation pipeline. */
      attested?: true;
      dkb_last_validated_at: string;
      stale_citations_pending_review: number;
    }
  | {
      /**
       * Explicit unknown (fix-build-attestation-honesty): no validation
       * has been recorded. The build writes this instead of fabricating a
       * date + "0 stale citations" — unstated is never conflated with
       * validated.
       */
      attested: false;
      dkb_last_validated_at: null;
      stale_citations_pending_review: null;
    };

const formatDate = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
};

export function renderDkbValidation(root: ParentNode, status: DkbValidationStatus): void {
  const wrapper = root.querySelector<HTMLElement>('[data-role="dkb-validation"]');
  if (status.dkb_last_validated_at === null) {
    // No real attestation exists — say so; never render a "validated"
    // date or count that nothing performed.
    if (wrapper) {
      wrapper.textContent = "DKB validation status not recorded";
      wrapper.dataset.attested = "false";
    }
    return;
  }
  const dateEl = root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]');
  const countEl = root.querySelector<HTMLElement>('[data-role="dkb-stale-count"]');
  if (dateEl) dateEl.textContent = formatDate(status.dkb_last_validated_at);
  if (countEl) countEl.textContent = String(status.stale_citations_pending_review);
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
    if (typeof json !== "object" || json === null) return null;
    const rec = json as Record<string, unknown>;
    const attestedShape =
      typeof rec.dkb_last_validated_at === "string" &&
      typeof rec.stale_citations_pending_review === "number";
    const unknownShape =
      rec.attested === false &&
      rec.dkb_last_validated_at === null &&
      rec.stale_citations_pending_review === null;
    if (!attestedShape && !unknownShape) return null;
    const status = json as DkbValidationStatus;
    renderDkbValidation(root, status);
    return status;
  } catch {
    return null;
  }
}

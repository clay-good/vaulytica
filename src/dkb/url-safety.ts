/**
 * Shared URL-safety policy.
 *
 * A citation URL is only ever rendered as an active link (an HTML `<a href>`
 * or a DOCX `ExternalHyperlink`) when it is an absolute **http(s)** web
 * address. `z.string().url()` and `new URL()` both accept `javascript:` and
 * `data:` URLs, which — in a *shareable* report (the standalone HTML, the
 * DOCX) — would otherwise become an executable link on open. The
 * custom-playbook schema rejects non-http(s) citation URLs at the input
 * boundary (fail-fast for the one user-controlled path); the renderers apply
 * this same predicate at the output boundary, so a non-http(s) URL from *any*
 * source (a future field, a tampered DKB) is neutralized at the point of
 * danger rather than relied upon to have been caught upstream.
 *
 * Pure and deterministic. `http` is permitted alongside `https` because the
 * shipped DKB carries at least one legitimate `http://` license URL (the UK
 * Open Government Licence); only the *scheme* is constrained, never the host.
 */
export function isHttpUrl(value: string): boolean {
  try {
    const protocol = new URL(value).protocol;
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

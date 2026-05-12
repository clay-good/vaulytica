/**
 * Service-worker registration + the "Works offline" footer badge.
 *
 * The badge appears once `navigator.serviceWorker.controller` is
 * present, which happens after the SW takes control of the page (via
 * `clients.claim()` on the first install, or on subsequent loads).
 */

export type RegisterOptions = {
  /** URL of the service worker script. Default `/sw.js`. */
  url?: string;
  /** Optional badge element to toggle visibility on. */
  badge?: HTMLElement | null;
};

export async function registerServiceWorker(opts: RegisterOptions = {}): Promise<void> {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  const url = opts.url ?? "/sw.js";
  try {
    await navigator.serviceWorker.register(url, { scope: "/" });
  } catch {
    // Registration may fail in private mode or on unsupported hosts.
    // Failure is non-fatal — the app remains functional online.
    return;
  }

  if (opts.badge) {
    updateBadge(opts.badge);
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      updateBadge(opts.badge!);
    });
  }
}

function updateBadge(badge: HTMLElement): void {
  if (navigator.serviceWorker?.controller) {
    badge.hidden = false;
    badge.setAttribute("aria-hidden", "false");
  } else {
    badge.hidden = true;
    badge.setAttribute("aria-hidden", "true");
  }
}

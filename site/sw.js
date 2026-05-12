/**
 * Vaulytica service worker.
 *
 * Caching strategies (spec §26 step 13):
 *   - "/" (the HTML): network-first, fall through to cache. Keeps users
 *     on the latest build when online, offline-fallback when not.
 *   - Hashed assets under "/assets/*" (Vite output): cache-first with a
 *     background fetch that refreshes the cache for next time.
 *   - DKB manifest + DKB files under "/dkb/*": stale-while-revalidate
 *     — serve the cached copy immediately and revalidate in the
 *     background so the next page load picks up the new manifest.
 *   - Playbooks under "/playbooks/*": cache-first (immutable per
 *     version + checked into the repo, so no revalidate window
 *     matters).
 *
 * Anything not matched is left to the browser's default cache.
 */

const CACHE_VERSION = "vaulytica-v1";
const HTML_CACHE = `${CACHE_VERSION}-html`;
const ASSET_CACHE = `${CACHE_VERSION}-assets`;
const DKB_CACHE = `${CACHE_VERSION}-dkb`;
const PLAYBOOK_CACHE = `${CACHE_VERSION}-playbooks`;
const ALL_CACHES = [HTML_CACHE, ASSET_CACHE, DKB_CACHE, PLAYBOOK_CACHE];

const PRECACHE_URLS = [
  "/",
  "/manifest.webmanifest",
  "/favicon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/icon-maskable-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(HTML_CACHE);
      // Use { cache: "reload" } so the install step never reuses a
      // stale HTTP cache entry — the precache is the source of truth.
      await cache.addAll(
        PRECACHE_URLS.map((u) => new Request(u, { cache: "reload" })),
      );
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names
          .filter((n) => !ALL_CACHES.includes(n))
          .map((n) => caches.delete(n)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname === "/" || url.pathname === "/index.html") {
    event.respondWith(networkFirst(req, HTML_CACHE));
    return;
  }
  if (url.pathname.startsWith("/assets/")) {
    event.respondWith(cacheFirstWithRevalidate(req, ASSET_CACHE));
    return;
  }
  if (url.pathname.startsWith("/dkb/")) {
    event.respondWith(staleWhileRevalidate(req, DKB_CACHE));
    return;
  }
  if (url.pathname.startsWith("/playbooks/")) {
    event.respondWith(cacheFirstWithRevalidate(req, PLAYBOOK_CACHE));
    return;
  }
  if (PRECACHE_URLS.includes(url.pathname)) {
    event.respondWith(cacheFirstWithRevalidate(req, HTML_CACHE));
    return;
  }
});

async function networkFirst(req, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const res = await fetch(req);
    if (res.ok) cache.put(req, res.clone());
    return res;
  } catch (_) {
    const cached = await cache.match(req);
    if (cached) return cached;
    throw _;
  }
}

async function cacheFirstWithRevalidate(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);
  const revalidate = fetch(req)
    .then((res) => {
      if (res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(() => undefined);
  if (cached) {
    // Fire-and-forget revalidation.
    revalidate.catch(() => {});
    return cached;
  }
  const fresh = await revalidate;
  if (fresh) return fresh;
  throw new Error(`cache-first miss + offline: ${req.url}`);
}

async function staleWhileRevalidate(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);
  const network = fetch(req)
    .then((res) => {
      if (res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(() => undefined);
  if (cached) {
    network.catch(() => {});
    return cached;
  }
  const fresh = await network;
  if (fresh) return fresh;
  throw new Error(`stale-while-revalidate miss + offline: ${req.url}`);
}

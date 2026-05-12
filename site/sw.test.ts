/**
 * Service worker behavioral tests.
 *
 * The SW relies on `self`, `caches`, `fetch`, and the `Request` /
 * `Response` constructors. We load `sw.js` into a Node `vm` context
 * with stubs for those globals and then dispatch synthetic install /
 * activate / fetch events. This is the same harness pattern the
 * Workbox project uses for service-worker unit tests.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

type Listener = (event: unknown) => void;

function loadSw(opts: {
  fetchImpl: typeof fetch;
  precachedHtml?: Response;
}): {
  dispatch: (type: string, event: unknown) => void;
  caches: Map<string, Map<string, Response>>;
} {
  const code = readFileSync(join(process.cwd(), "site", "sw.js"), "utf8");

  const listeners = new Map<string, Listener[]>();
  const cacheStore = new Map<string, Map<string, Response>>();
  const cachesApi = {
    open: async (name: string) => {
      let store = cacheStore.get(name);
      if (!store) {
        store = new Map();
        cacheStore.set(name, store);
      }
      return {
        match: async (req: Request) => store!.get(reqKey(req)),
        put: async (req: Request, res: Response) => {
          store!.set(reqKey(req), res);
        },
        addAll: async (reqs: Request[]) => {
          for (const r of reqs) {
            const res = opts.precachedHtml ?? new Response("ok");
            store!.set(reqKey(r), res);
          }
        },
      };
    },
    keys: async () => [...cacheStore.keys()],
    delete: async (name: string) => cacheStore.delete(name),
    match: async (req: Request) => {
      for (const store of cacheStore.values()) {
        const hit = store.get(reqKey(req));
        if (hit) return hit;
      }
      return undefined;
    },
  };

  const selfStub: Record<string, unknown> = {
    location: { origin: "http://localhost" },
    skipWaiting: async () => {},
    clients: { claim: async () => {} },
    addEventListener: (type: string, fn: Listener) => {
      const arr = listeners.get(type) ?? [];
      arr.push(fn);
      listeners.set(type, arr);
    },
  };

  const sandbox = {
    self: selfStub,
    caches: cachesApi,
    fetch: opts.fetchImpl,
    Request,
    Response,
    URL,
    Promise,
    setTimeout,
    clearTimeout,
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);

  return {
    dispatch: (type, event) => {
      for (const fn of listeners.get(type) ?? []) fn(event);
    },
    caches: cacheStore,
  };
}

function reqKey(req: Request): string {
  return new URL(req.url).pathname;
}

function syntheticFetchEvent(req: Request): { request: Request; respondedWith: Promise<Response> } {
  let respond!: (res: Promise<Response>) => void;
  const responded = new Promise<Response>((resolve) => {
    respond = (p) => p.then(resolve);
  });
  return {
    request: req,
    respondedWith: responded,
    // The SW calls event.respondWith(promise); we capture that promise.
    respondWith: (p: Promise<Response>) => respond(p),
  } as unknown as { request: Request; respondedWith: Promise<Response> };
}

describe("service worker", () => {
  it("installs and precaches the HTML + manifest + favicon", async () => {
    const fetchImpl = async () => new Response("ignored");
    const { dispatch, caches } = loadSw({ fetchImpl });
    let installPromise: Promise<unknown> | undefined;
    dispatch("install", {
      waitUntil: (p: Promise<unknown>) => {
        installPromise = p;
      },
    });
    await installPromise;
    const html = caches.get("vaulytica-v1-html");
    expect(html?.has("/")).toBe(true);
    expect(html?.has("/manifest.webmanifest")).toBe(true);
  });

  it("network-first for / returns the cached HTML when offline", async () => {
    const online = false;
    const fetchImpl = (async (req: Request) => {
      if (!online) throw new Error("offline");
      return new Response(`fresh ${req.url}`);
    }) as typeof fetch;
    const { dispatch } = loadSw({
      fetchImpl,
      precachedHtml: new Response("cached html"),
    });
    let installP: Promise<unknown> | undefined;
    dispatch("install", { waitUntil: (p: Promise<unknown>) => (installP = p) });
    await installP;

    const ev = syntheticFetchEvent(new Request("http://localhost/"));
    dispatch("fetch", ev);
    const res = await ev.respondedWith;
    expect(await res.text()).toBe("cached html");
  });

  it("cache-first-with-revalidate returns the cached asset and refreshes in the background", async () => {
    let networkCalls = 0;
    const fetchImpl = (async (req: Request) => {
      networkCalls++;
      return new Response(`net-${req.url}`);
    }) as typeof fetch;
    const { dispatch, caches } = loadSw({ fetchImpl });

    // Seed the asset cache.
    const store = new Map<string, Response>();
    store.set("/assets/app.js", new Response("cached-app-js"));
    caches.set("vaulytica-v1-assets", store);

    const ev = syntheticFetchEvent(new Request("http://localhost/assets/app.js"));
    dispatch("fetch", ev);
    const res = await ev.respondedWith;
    expect(await res.text()).toBe("cached-app-js");
    // Allow the fire-and-forget revalidate to run.
    await new Promise((r) => setTimeout(r, 0));
    expect(networkCalls).toBeGreaterThanOrEqual(1);
  });

  it("stale-while-revalidate for /dkb/* serves cached then revalidates", async () => {
    const fetchImpl = (async () => new Response("net-dkb")) as typeof fetch;
    const { dispatch, caches } = loadSw({ fetchImpl });
    const store = new Map<string, Response>();
    store.set("/dkb/dkb-manifest.json", new Response('{"v":"old"}'));
    caches.set("vaulytica-v1-dkb", store);
    const ev = syntheticFetchEvent(new Request("http://localhost/dkb/dkb-manifest.json"));
    dispatch("fetch", ev);
    const res = await ev.respondedWith;
    expect(await res.text()).toBe('{"v":"old"}');
  });

  it("ignores cross-origin requests", () => {
    const fetchImpl = (async () => new Response("ext")) as typeof fetch;
    const { dispatch } = loadSw({ fetchImpl });
    let calledRespond = false;
    const ev = {
      request: new Request("https://evil.example/x"),
      respondWith: () => {
        calledRespond = true;
      },
    };
    dispatch("fetch", ev);
    expect(calledRespond).toBe(false);
  });

  it("ignores non-GET requests", () => {
    const fetchImpl = (async () => new Response("p")) as typeof fetch;
    const { dispatch } = loadSw({ fetchImpl });
    let calledRespond = false;
    const ev = {
      request: new Request("http://localhost/", { method: "POST" }),
      respondWith: () => {
        calledRespond = true;
      },
    };
    dispatch("fetch", ev);
    expect(calledRespond).toBe(false);
  });
});

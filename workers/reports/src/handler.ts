/**
 * The report endpoint (spec-v53 §5): `POST /api/reports`, and nothing else.
 *
 * It answers one request shape. There is no read endpoint — a maintainer
 * reads the database through authenticated `wrangler`. Missing configuration
 * fails closed: the page is told reporting is unavailable, and the app, which
 * never calls this, is unaffected.
 */

import { MAX_BODY_BYTES, parseReport, type Catalog } from "./validate.js";
import { dayOf, purgeExpired, reporterKey, storeReport, type Database } from "./store.js";

export const REPORT_PATH = "/api/reports";
/** The action name the Turnstile widget is created with; a token for any other is refused. */
export const TURNSTILE_ACTION = "report";
const TURNSTILE_VERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const VERIFY_TIMEOUT_MS = 5000;

export type Env = {
  DB?: Database;
  TURNSTILE_SECRET?: string;
  REPORTER_HMAC_SECRET?: string;
};

export type Deps = {
  catalog: Catalog;
  now: () => Date;
  /** True when Cloudflare confirms the token, for this action. */
  verifyToken: (token: string, secret: string, ip: string) => Promise<boolean>;
};

/** Ask Turnstile, server-side, with a timeout. Any failure is "not verified". */
export async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  try {
    const res = await fetch(TURNSTILE_VERIFY, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (!res.ok) return false;
    const out = (await res.json()) as { success?: boolean; action?: string };
    return out.success === true && out.action === TURNSTILE_ACTION;
  } catch {
    return false;
  }
}

function reply(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      // Nothing here is cacheable, and nothing is to be read by another origin.
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

/** Read at most the cap, and say so when there was more. */
async function readCapped(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) return null;
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > MAX_BODY_BYTES) return null;
  return new TextDecoder().decode(bytes);
}

export async function handleRequest(request: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== REPORT_PATH) return reply(404, { error: "not found" });
  if (request.method !== "POST") return reply(405, { error: "method not allowed" });
  if (!env.DB || !env.TURNSTILE_SECRET || !env.REPORTER_HMAC_SECRET) {
    return reply(503, { error: "reporting is unavailable" });
  }
  if (!(request.headers.get("content-type") ?? "").startsWith("application/json")) {
    return reply(415, { error: "send JSON" });
  }

  const text = await readCapped(request);
  if (text === null) return reply(413, { error: "body too large" });
  const parsed = parseReport(text, deps.catalog);
  if (!parsed.ok) return reply(parsed.status, { error: parsed.error });

  // The IP is used twice — to verify the token and to key today's count — and
  // is written nowhere.
  const ip = request.headers.get("cf-connecting-ip") ?? "";
  if (!(await deps.verifyToken(parsed.token, env.TURNSTILE_SECRET, ip))) {
    return reply(403, { error: "verification failed" });
  }

  const now = deps.now();
  const reporter = await reporterKey(ip, env.REPORTER_HMAC_SECRET, dayOf(now));
  const outcome = await storeReport(env.DB, parsed.report, reporter, now);
  if (outcome === "limited") return reply(429, { error: "daily limit reached" });
  // A duplicate is told the same thing as a first report: it was received.
  return reply(outcome === "stored" ? 201 : 200, { ok: true });
}

/** The daily retention sweep. */
export async function handleScheduled(env: Env, now: Date): Promise<number> {
  if (!env.DB) return 0;
  return purgeExpired(env.DB, now);
}

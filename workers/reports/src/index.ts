/**
 * vaulytica-reports — the Worker entry (spec-v53 §5).
 *
 * NOT DEPLOYED. Launch needs the owner's Cloudflare account; the checklist is
 * `docs/finding-reports.md`. Nothing in `src/` or `tools/` imports this
 * directory, and the app never calls the path it serves.
 */

import ids from "./catalog-ids.json";
import { handleRequest, handleScheduled, verifyTurnstile, type Env } from "./handler.js";

const catalog = { rules: new Set<string>(ids.rules), types: new Set<string>(ids.types) };

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env, {
      catalog,
      now: () => new Date(),
      verifyToken: verifyTurnstile,
    });
  },
  async scheduled(_event: unknown, env: Env): Promise<void> {
    await handleScheduled(env, new Date());
  },
};

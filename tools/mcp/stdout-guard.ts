/**
 * Import this FIRST in the server. stdout carries protocol frames and nothing
 * else (spec-v48 §3), and a module's imports are evaluated before its own
 * first line — so a rebinding written in `server.ts` would run only after
 * every dependency had already been loaded, and one that prints while loading
 * would have printed into the protocol stream.
 */
for (const method of ["log", "info", "debug"] as const) {
  console[method] = (...args: unknown[]) => console.error(...args);
}

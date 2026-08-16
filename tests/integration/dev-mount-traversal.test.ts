/**
 * Dev-server mount containment.
 *
 * `vite.config.ts`'s `serveExtras` middleware mounts three directories
 * that live outside the Vite root (`playbooks/`, the latest DKB build,
 * the pdf.js worker) at virtual URL prefixes. It reads those files off
 * disk itself, so Vite's `server.fs.allow` never sees the request — the
 * containment rule in `resolveMountedFile` is the only thing standing
 * between a dev server and an arbitrary file read.
 *
 * It was missing: `GET /playbooks/../../../../../../../../../../../etc/hosts`
 * against a live `npm run dev` returned the real `/etc/hosts`. These
 * tests pin the guard.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { resolveMountedFile } from "../../vite.config.js";

/** A mount root holding `inside.json`, with a secret next to it. */
function makeMount(): { mounts: Record<string, string>; base: string } {
  const base = mkdtempSync(join(tmpdir(), "vaulytica-mount-"));
  const root = join(base, "served");
  mkdirSync(root);
  writeFileSync(join(root, "inside.json"), "{}", "utf8");
  mkdirSync(join(root, "nested"));
  writeFileSync(join(root, "nested", "deep.json"), "{}", "utf8");
  writeFileSync(join(base, "secret.txt"), "top secret", "utf8");
  // A sibling whose name starts with the mount root's name — the
  // `startsWith(root)` prefix trap the `+ sep` guards against.
  mkdirSync(join(base, "served-evil"));
  writeFileSync(join(base, "served-evil", "sneak.txt"), "nope", "utf8");
  return { mounts: { "/served": root }, base };
}

describe("resolveMountedFile", () => {
  it("serves a file inside the mount", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/inside.json")).not.toBeNull();
  });

  it("serves a nested file inside the mount", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/nested/deep.json")).not.toBeNull();
  });

  it("ignores the query string", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/inside.json?v=2")).not.toBeNull();
  });

  it("refuses to escape the mount with ..", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/../secret.txt")).toBeNull();
  });

  it("refuses a deep traversal to an absolute system path", () => {
    const { mounts } = makeMount();
    const up = "../".repeat(20);
    expect(resolveMountedFile(mounts, `/served/${up}etc/hosts`)).toBeNull();
  });

  it("refuses a sibling directory sharing the mount's name prefix", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/../served-evil/sneak.txt")).toBeNull();
  });

  it("returns null for an unmounted prefix", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/elsewhere/inside.json")).toBeNull();
  });

  it("returns null for a directory rather than serving it", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served/nested")).toBeNull();
  });

  it("does not treat the bare prefix as a mounted path", () => {
    const { mounts } = makeMount();
    expect(resolveMountedFile(mounts, "/served")).toBeNull();
  });

  it("keeps the real repo mounts self-consistent", () => {
    const playbooks = resolve(process.cwd(), "playbooks");
    const mounts = { "/playbooks": playbooks };
    expect(resolveMountedFile(mounts, "/playbooks/extended.json")).toBe(
      join(playbooks, "extended.json"),
    );
    expect(resolveMountedFile(mounts, "/playbooks/../package.json")).toBeNull();
  });
});

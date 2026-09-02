/**
 * Does the workflow snippet we hand a stranger actually resolve?
 *
 * The README and the CI guide both tell a reader to paste
 * `uses: clay-good/vaulytica@v8` into their workflow. There has never been a
 * `v8` tag — the repository carried exactly one, `v6.0.0` — so every reader who
 * copied the snippet got "unable to resolve action clay-good/vaulytica, unable
 * to find version v8" before a single document was read. The engine was on
 * 9.371.0 at the time, so the number in the docs had been stale across two
 * major versions, and nothing could notice: the snippet is prose, and prose
 * does not fail a build.
 *
 * A test cannot ask GitHub whether a tag exists without a network call, and
 * this suite makes none. What it CAN do is pin the two facts that drifted: the
 * major in the snippet is the major we ship, and every snippet agrees. Cutting
 * the moving major tag stays a maintainer step, and this is the reminder that
 * the docs promise one.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const DOCS = ["README.md", join("docs", "ci-integration.md")];
const USES = /uses:\s*clay-good\/vaulytica@([^\s#]+)/g;
const major = (
  JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string }
).version.split(".")[0];

describe("the Action reference we publish", () => {
  const refs = DOCS.flatMap((doc) =>
    [...readFileSync(join(ROOT, doc), "utf8").matchAll(USES)].map((m) => ({
      doc,
      ref: m[1] as string,
    })),
  );

  it("appears in the docs a reader is told to copy from", () => {
    expect(refs.length).toBeGreaterThanOrEqual(3);
    expect([...new Set(refs.map((r) => r.doc))].sort()).toEqual([...DOCS].sort());
  });

  it("names the major version this repository ships", () => {
    const wrong = refs.filter((r) => r.ref !== `v${major}`);
    expect(
      wrong.map((r) => `${r.doc}: @${r.ref} (engine is v${major}.x)`),
      "a reader copying this gets 'unable to find version' — the tag does not exist",
    ).toEqual([]);
  });

  it("is the same ref everywhere, so no reader pins an older one by accident", () => {
    expect([...new Set(refs.map((r) => r.ref))]).toHaveLength(1);
  });
});

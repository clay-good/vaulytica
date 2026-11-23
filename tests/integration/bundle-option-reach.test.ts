/**
 * A ratchet on WHO can reach a pipeline option.
 *
 * 🚨 WHY THIS EXISTS. `add-readability-measure` added `readability` to
 * `PipelineOptions`, wired it into the single-document path, taught the tab's
 * panel to set it — and never touched `prepareBundle`. The bundle pipeline
 * accepted the option and dropped it, so a user who chose a statute and then
 * dropped a FOLDER got no `READ-*` finding and nothing on screen to say the
 * assertion had been ignored. It shipped because nothing forced the question.
 * The privacy and estate packs had been wired into both paths by hand, one
 * author remembering each time; readability was the time it was forgotten.
 *
 * So this asks the question mechanically: every option the single-document
 * path reads must be read by the bundle path too, unless it is listed below
 * with a reason. Adding an option to one path and not the other now fails
 * here, naming the option, instead of shipping as a silent no-op.
 *
 * This is a static read of the source, deliberately: the behavioural guards
 * (`bundle-readability.test.ts`, `bundle-privacy-regimes.test.ts`,
 * `bundle-estate-checks.test.ts`) prove each option actually works per member,
 * and this one proves none was skipped. A new option should get both — this
 * test failing is the prompt to write the behavioural one.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Options the single-document path reads and the bundle path is NOT expected
 * to, each with the reason it does not apply. An entry here is a decision on
 * the record, not an exemption to be added casually: it says this option
 * cannot mean anything for a folder.
 */
const NOT_IN_BUNDLE: Readonly<Record<string, string>> = {
  // add-filing-format-lint — the court profile and brief kind are CLI-only
  // (`--court`): the tab ships no filing selector, so nothing in the browser
  // can set it on either path. If a selector is ever added, the bundle path
  // has to be wired at the same time and this entry removed.
  filing: "CLI-only (--court); the tab has no filing selector on either path",
};

const SOURCE = readFileSync(join(process.cwd(), "src", "ui", "pipeline.ts"), "utf8");

/**
 * The `options.<key>` reads inside one exported function's body. Sliced to the
 * next top-level `export`, which is how every function in this module ends.
 */
function optionsReadBy(fn: string): Set<string> {
  const start = SOURCE.indexOf(`export async function ${fn}(`);
  expect(start, `no exported async function ${fn} in src/ui/pipeline.ts`).toBeGreaterThan(-1);
  const end = SOURCE.indexOf("\nexport ", start + 10);
  const body = SOURCE.slice(start, end === -1 ? undefined : end);
  return new Set([...body.matchAll(/options\.(\w+)/g)].map((m) => m[1]!));
}

describe("pipeline option reach: the bundle path reads what the single document does", () => {
  it("leaves no option wired into one path and silently dropped by the other", () => {
    const single = optionsReadBy("runReport");
    const bundle = optionsReadBy("prepareBundle");

    // Sanity: the slices found real bodies. Without this a selector typo would
    // make both sets empty and the comparison below vacuously true.
    expect(single.size).toBeGreaterThan(3);
    expect(bundle.size).toBeGreaterThan(3);

    const missing = [...single].filter((k) => !bundle.has(k) && !(k in NOT_IN_BUNDLE)).sort();
    expect(
      missing,
      `src/ui/pipeline.ts: runReport reads ${missing.join(", ")} and prepareBundle does not. ` +
        `A folder drop would accept the option and ignore it. Wire it into prepareBundle (and ` +
        `main.ts's runBundlePipeline call sites), add a per-member behavioural test like ` +
        `tests/integration/bundle-readability.test.ts — or, if it cannot apply to a bundle, add ` +
        `it to NOT_IN_BUNDLE in this file with the reason.`,
    ).toEqual([]);
  });

  it("keeps every NOT_IN_BUNDLE entry honest", () => {
    const single = optionsReadBy("runReport");
    const bundle = optionsReadBy("prepareBundle");
    for (const [key, reason] of Object.entries(NOT_IN_BUNDLE)) {
      // A stale exemption is worse than none: it suppresses the real check.
      expect(single.has(key), `NOT_IN_BUNDLE lists "${key}", which runReport no longer reads`).toBe(
        true,
      );
      expect(
        bundle.has(key),
        `NOT_IN_BUNDLE says prepareBundle does not read "${key}", but it does — drop the entry`,
      ).toBe(false);
      expect(reason.length, `NOT_IN_BUNDLE["${key}"] needs a reason`).toBeGreaterThan(20);
    }
  });
});

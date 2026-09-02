/**
 * A rule whose own fix does not satisfy its check is a broken rule.
 *
 * Every presence check ships a `recommendation`, and it is the only thing a
 * reader is given to act on. Where that recommendation QUOTES drafting —
 * "remise, release, and forever quitclaim", "Lessee's obligation to pay Rent
 * is absolute and unconditional" — the quoted clause is a promise: write this
 * and the finding goes away. A rule that would still fire on its own quoted
 * fix is telling the reader to do something that does not work.
 *
 * This is the third question in the reachability family, and it is not asked
 * by the other two. `v34-title-vacuity` and `title-vacuity` ask whether a
 * check can ever FIRE; `boilerplate-satisfaction` asks whether it can ever be
 * SATISFIED by any document at all. Neither asks whether it is satisfied by
 * the specific document the rule itself asks for.
 *
 * The probe is the quoted drafting under the rule's own name as a heading.
 * The heading matters: most of these checks are conjunctions, and a
 * recommendation usually quotes the ONE pillar a reader would get wrong while
 * leaving the other to the section it is telling them to write. Probing the
 * quote alone reported three rules, and two of the three were the probe's
 * fault rather than the rule's.
 *
 * Scope is honest and small: of the 1,385 ungated presence checks, only 16
 * recommendations quote drafting at all — the rest say "Add a 'Distributions'
 * section specifying the timing and allocation method", which is an
 * instruction rather than a clause and cannot be probed this way. The
 * invariant holds across those 16 today. It is pinned because nothing else
 * would notice if a new rule broke it, and because the number grows every
 * time someone writes a recommendation the way the best ones here are
 * written.
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import {
  V4_PRESENCE_RULE_IDS,
  V4_GATED_PRESENCE_RULE_IDS,
} from "../../src/engine/rules/v4/_helpers.js";
import { PACK_SPECS, GATED_PACK_RULE_IDS } from "../../src/engine/rules/v5/_pack.js";

/** A quoted phrase of at least this many words is drafting, not a section name. */
const DRAFTING_WORDS = 3;

describe("a presence check is satisfied by the drafting its own recommendation quotes", () => {
  it("holds across every ungated presence check", () => {
    const failed: string[] = [];
    let probed = 0;
    let presence = 0;

    for (const r of [...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES]) {
      if (!V4_PRESENCE_RULE_IDS.has(r.id) && !PACK_SPECS.has(r.id)) continue;
      // A gated check is supposed to stay silent on a document that does not
      // show the shape it looks for, so its recommendation is not a promise
      // about this probe.
      if (V4_GATED_PRESENCE_RULE_IDS.has(r.id) || GATED_PACK_RULE_IDS.has(r.id)) continue;
      presence += 1;

      const pb = { id: (r.applies_to_playbooks ?? ["generic-fallback"])[0]!, version: "1.0.0" };
      const bare = {
        ...buildContext(["Agreement", "The parties met on a Tuesday and discussed the weather."]),
        playbook: pb,
      };
      const rec = r.check(bare)?.recommendation;
      if (!rec) continue;

      const quoted = [...rec.matchAll(/["“]([^"”]{12,})["”]/g)].map((m) => m[1]!);
      const drafting = quoted.filter((q) => q.trim().split(/\s+/).length >= DRAFTING_WORDS);
      if (drafting.length === 0) continue;
      probed += 1;

      const written = {
        ...buildContext([r.name, ...drafting, "Executed as of the date first written above."]),
        playbook: pb,
      };
      if (r.check(written) !== null)
        failed.push(`${r.id}  ${r.name}\n      → ${drafting.join(" | ")}`);
    }

    expect(presence, "the sweep found no presence rules — it is broken").toBeGreaterThan(1000);
    expect(probed, "no recommendation quotes drafting — the extraction is broken").toBeGreaterThan(
      12,
    );
    expect(
      failed.sort(),
      `these rules still fire on the drafting their own recommendation quotes:\n  ${failed.sort().join("\n  ")}`,
    ).toEqual([]);
  }, 300_000);
});

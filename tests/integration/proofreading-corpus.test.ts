/**
 * The proofreading pack's corpus count, held by equality
 * (add-proofreading-pack task 5). The 363 specimens and the two clean deal
 * rooms are drafted documents; a PROOF finding on one of them is a false hit
 * until a person reads it and says otherwise, so the count is pinned at zero
 * and a change to any detector that makes one fire fails here first.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { rule as PROOF_001 } from "../../src/engine/rules/proofreading/PROOF-001.js";
import { rule as PROOF_002 } from "../../src/engine/rules/proofreading/PROOF-002.js";
import { rule as PROOF_003 } from "../../src/engine/rules/proofreading/PROOF-003.js";
import { rule as PROOF_005 } from "../../src/engine/rules/proofreading/PROOF-005.js";
import { rule as PROOF_006 } from "../../src/engine/rules/proofreading/PROOF-006.js";
import { rule as PROOF_007 } from "../../src/engine/rules/proofreading/PROOF-007.js";
import { extractAll } from "../../src/extract/index.js";
import type { RuleContext } from "../../src/engine/finding.js";

const ROOT = process.cwd();
const DIR = join(ROOT, "tests", "fixtures", "specimens");
const ROOMS = ["clean-deal-room", "clean-deal-room-phi"].map((d) =>
  join(ROOT, "tests", "golden", "v4", "bundles", d),
);
const RULES = [PROOF_001, PROOF_002, PROOF_003, PROOF_005, PROOF_006, PROOF_007];

describe("the proofreading pack over the specimen corpus", () => {
  it("fires on no specimen", async () => {
    const specimens = readdirSync(DIR).filter((f) => f.endsWith(".txt"));
    expect(specimens.length).toBeGreaterThanOrEqual(363);
    // The two clean deal rooms are documents written to agree with themselves.
    const names = [
      ...specimens.map((f) => join(DIR, f)),
      ...ROOMS.flatMap((d) =>
        readdirSync(d)
          .filter((f) => f.endsWith(".txt"))
          .map((f) => join(d, f)),
      ),
    ];
    const fired: string[] = [];
    for (const name of names) {
      const { tree } = await ingestPaste(readFileSync(name, "utf8"));
      // The rules read the tree and what the extractors read from it.
      const ctx = { tree, extracted: extractAll(tree) } as RuleContext;
      for (const rule of RULES) {
        const f = rule.check(ctx);
        if (f) fired.push(`${name} ${rule.id}: ${f.description}`);
      }
    }
    expect(fired).toEqual([]);
  });
});

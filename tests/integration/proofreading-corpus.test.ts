/**
 * The proofreading pack's corpus count, held by equality
 * (add-proofreading-pack task 5). The 363 specimens are drafted documents;
 * a PROOF finding on one of them is a false hit until a person reads it and
 * says otherwise, so the count is pinned at zero and a change to any of the
 * three detectors that makes one fire fails here first.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { rule as PROOF_001 } from "../../src/engine/rules/proofreading/PROOF-001.js";
import { rule as PROOF_002 } from "../../src/engine/rules/proofreading/PROOF-002.js";
import { rule as PROOF_003 } from "../../src/engine/rules/proofreading/PROOF-003.js";
import type { RuleContext } from "../../src/engine/finding.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

describe("the proofreading pack over the specimen corpus", () => {
  it("fires on no specimen", async () => {
    const names = readdirSync(DIR).filter((f) => f.endsWith(".txt"));
    expect(names.length).toBeGreaterThanOrEqual(363);
    const fired: string[] = [];
    for (const name of names) {
      const { tree } = await ingestPaste(readFileSync(join(DIR, name), "utf8"));
      // The three rules read only the tree.
      const ctx = { tree } as RuleContext;
      for (const rule of [PROOF_001, PROOF_002, PROOF_003]) {
        const f = rule.check(ctx);
        if (f) fired.push(`${name} ${rule.id}: ${f.description}`);
      }
    }
    expect(fired).toEqual([]);
  });
});

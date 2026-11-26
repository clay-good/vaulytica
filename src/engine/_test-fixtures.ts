import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DKB } from "../dkb/types.js";
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";
import { resolveJurisdictionId } from "../dkb/jurisdiction-ids.js";
import type { RuleContext, Playbook } from "./finding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let cachedDkb: DKB | null = null;

/** Read the starter DKB synchronously from disk. Reusable across tests. */
export function loadStarterDkbSync(): DKB {
  if (cachedDkb) return cachedDkb;
  const base = join(__dirname, "..", "..", "dkb", "dist", "v0.0.1-starter");
  const read = <T>(name: string): T => JSON.parse(readFileSync(join(base, name), "utf8")) as T;
  cachedDkb = {
    manifest: read("dkb-manifest.json"),
    clauses: read("dkb-clauses.json"),
    jurisdictions: read("dkb-jurisdictions.json"),
    definitions: read("dkb-definitions.json"),
    dark_patterns: read("dkb-dark-patterns.json"),
    statutes: read("dkb-statutes.json"),
    classifier: {
      vocab: read("dkb-classifier-vocab.json"),
      patterns: read("dkb-classifier-patterns.json"),
    },
  };
  return cachedDkb;
}

export const GENERIC_PLAYBOOK: Playbook = {
  id: "generic-fallback",
  version: "1.0.0",
};

/**
 * Build a RuleContext from the same `buildTree(...sections)` shorthand the
 * extractor tests use. The DKB is the on-disk starter; the playbook is
 * `generic-fallback` with no overrides.
 */
export function buildContext(...sections: [string, ...string[]][]): RuleContext {
  const tree = buildTree(...sections);
  const extracted = extractAll(tree, {
    // The product's own pipelines pass this (`wire-jurisdiction-id-resolution`).
    // 🚨 A harness that builds contexts differently from the product grades the
    // engine on inputs the engine never sees — s35, where the accuracy harness
    // routed 78 of 312 specimens differently from the product. Rules that read
    // `jurisdiction_id` would have been unit-tested against `undefined` forever
    // while the shipped pipeline filled it in.
    jurisdictionLookup: resolveJurisdictionId,
    classifier: {
      vocab: { vocab: {} },
      patterns: loadStarterDkbSync().classifier.patterns.map((p) => ({
        category: p.category,
        pattern: p.pattern,
        flags: p.flags,
        confidence: p.confidence,
      })),
    },
  });
  return {
    tree,
    extracted,
    dkb: loadStarterDkbSync(),
    playbook: GENERIC_PLAYBOOK,
  };
}

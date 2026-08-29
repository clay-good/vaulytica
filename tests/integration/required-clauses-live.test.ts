/**
 * A `required_clauses` entry must name a category the classifier can emit.
 *
 * `required_clause` is the LARGEST weight the matcher has — 0.4 each, capped at
 * 0.8, against 0.3 for a title keyword and 0.2 for a distinguishing phrase. An
 * entry naming a category the classifier never produces is worth zero forever,
 * and nothing said so: nine of the twelve launch playbooks carried one, and
 * seven of them named the same dead category, `payment-terms`.
 *
 * The live set is what the shipped DKB's classifier PATTERNS declare. The
 * pipeline passes an empty vocab — `{ vocab: { vocab: {} }, patterns:
 * dkb.classifier.patterns }` — so the vocab's ninety-odd categories are not
 * live and must not be relied on here.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybooks, parsePlaybook } from "../../src/playbooks/loader.js";

const DKB_DIST = join(process.cwd(), "dkb", "dist");
const LATEST = readdirSync(DKB_DIST).sort().at(-1)!;

const patterns = JSON.parse(
  readFileSync(join(DKB_DIST, LATEST, "dkb-classifier-patterns.json"), "utf8"),
) as Array<{ category?: string }>;
const LIVE = new Set(patterns.map((p) => p.category).filter((c): c is string => Boolean(c)));

const LAUNCH_DIR = join(process.cwd(), "playbooks");
const launch = readdirSync(LAUNCH_DIR)
  .filter((f) => f.endsWith(".json") && f !== "extended.json")
  .map((f) => parsePlaybook(JSON.parse(readFileSync(join(LAUNCH_DIR, f), "utf8"))));
const extended = parsePlaybooks(
  JSON.parse(readFileSync(join(LAUNCH_DIR, "extended.json"), "utf8")),
);

describe("a required clause names a category the classifier can emit", () => {
  it("the classifier declares categories to check against", () => {
    expect(LIVE.size, "the shipped classifier patterns are empty").toBeGreaterThan(10);
  });

  it.each([...launch, ...extended].filter((p) => p.match_features.required_clauses.length > 0))(
    "$id",
    (pb) => {
      const dead = pb.match_features.required_clauses.filter((c) => !LIVE.has(c));
      expect(
        dead,
        `${pb.id} requires categories the classifier never emits, so each is worth 0: ${dead.join(", ")}`,
      ).toEqual([]);
    },
  );
});

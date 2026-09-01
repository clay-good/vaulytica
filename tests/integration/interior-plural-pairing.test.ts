/**
 * "cloud SERVICE agreement" and "cloud SERVICES agreement" are the same
 * document, and the matcher can only ever match one of them.
 *
 * A feature is allowed to extend inside its own LAST word — that is how
 * "conflicts of interest" finds "Conflicts of Interest Policy" — and an
 * inflection on an INTERIOR word has no such tolerance. A lobbying policy
 * whose title is "Political CONTRIBUTIONS Policy" was invisible to a family
 * that knew "political CONTRIBUTION policy", and fell to `generic-fallback`.
 *
 * Widening the matcher is the wrong answer: sweeping every interior word finds
 * 489 variants and all but a handful are nonsense ("artificial intelligences
 * addendum", "vendor securities addendum"), and admitting them buys nothing
 * while loosening 250 families' features at once. The right answer is that
 * where a word GENUINELY varies in legal English, the catalog carries both
 * spellings — which its authors have been doing one keyword at a time.
 *
 * This guard makes that systematic for the one word with hard evidence behind
 * it. "Service" and "services" are both ordinary in a document's title, and
 * three families already paired them by hand before two were found that had
 * not.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";

const PLAYBOOKS = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);
const LAUNCH = LAUNCH_PLAYBOOK_IDS.map((id) =>
  parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
);

/**
 * Keywords whose singular is the term of art and whose plural is not a real
 * document title. Each needs its reason.
 */
const SINGULAR_ONLY: ReadonlySet<string> = new Set([
  // "Service Provider" is the CCPA's own defined term, singular by statute.
  "ccpa service provider",
  "cpra service provider",
  "ccpa service provider addendum",
]);

describe("a family that knows one spelling of service knows both", () => {
  it("every interior 'service' keyword has its 'services' sibling", () => {
    const missing: string[] = [];
    for (const pb of [...LAUNCH, ...PLAYBOOKS]) {
      const keywords = pb.match_features.title_keywords.map((k) => k.toLowerCase());
      for (const kw of keywords) {
        if (SINGULAR_ONLY.has(kw)) continue;
        const words = kw.split(" ");
        for (let i = 1; i < words.length - 1; i += 1) {
          if (words[i] !== "service") continue;
          const plural = [...words.slice(0, i), "services", ...words.slice(i + 1)].join(" ");
          if (!keywords.includes(plural)) missing.push(`${pb.id}: "${kw}" has no "${plural}"`);
        }
      }
    }
    expect(
      missing.sort(),
      `add the sibling spelling, or declare it singular-only:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });
});

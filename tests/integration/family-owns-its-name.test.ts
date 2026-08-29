/**
 * A family may not claim another family's own name as a title keyword.
 *
 * `stockholders-agreement` listed "voting agreement" — the whole name of the
 * `voting-agreement` family — among its own title keywords, so a document
 * titled "VOTING AGREEMENT" matched both at 0.3 and lost the lexicographic
 * tiebreak. It was told at `critical` that it had no tag-along, no right of
 * first refusal, and no voting-agreement clause, on a document whose Article 1
 * is one.
 *
 * The catalog-routing sweep cannot see this: it builds its probe from the
 * family's own keywords AND its distinguishing phrases, so the phrases carry
 * the family past its impostor. The collision only bites a real document,
 * which may carry none of them.
 *
 * A shared title keyword is not automatically wrong — "master services
 * agreement" belongs to both MSA perspectives, "privacy policy" to three
 * privacy regimes. What is wrong is claiming a keyword that IS another
 * family's identity. The two exceptions below are real ambiguities in the
 * language, not drafting mistakes, and each is named.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";

const DIR = join(process.cwd(), "playbooks");
const launch = readdirSync(DIR)
  .filter((f) => f.endsWith(".json") && f !== "extended.json")
  .map((f) => parsePlaybook(JSON.parse(readFileSync(join(DIR, f), "utf8"))));
const PLAYBOOKS = [
  ...launch,
  ...parsePlaybooks(JSON.parse(readFileSync(join(DIR, "extended.json"), "utf8"))),
];

/**
 * Claims that are a real ambiguity in the language rather than a mistake.
 * Each needs a reason; none may be added without one.
 */
const AMBIGUOUS = new Map<string, string>([
  [
    "director-indemnification-agreement:indemnification-agreement",
    "a D&O indemnification agreement is titled exactly 'Indemnification Agreement'; the generic family is the commercial one",
  ],
  [
    "mutual-nda-deep:mutual-nda",
    "the deep pack and its launch predecessor are the same document; which one you want is your choice, not the document's (see PERSPECTIVE_PAIRS)",
  ],
  ["unilateral-nda-deep:unilateral-nda", "the same deep-and-launch pair, for the one-way NDA"],
  [
    "saas-customer:subscription-agreement",
    '"Subscription Agreement" is the commonest title a SaaS agreement carries AND the name of the securities subscription agreement; the phrases decide which',
  ],
  ["saas-vendor:subscription-agreement", "the same ambiguity, from the vendor side"],
  [
    "family-msa:separation-agreement",
    "in family law a 'Separation Agreement' IS the marital settlement agreement; in employment law it is the release",
  ],
]);

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

describe("a family owns its own name", () => {
  it("no family claims another family's identity as a title keyword", () => {
    const ids = new Set(PLAYBOOKS.map((p) => p.id));
    const claims: string[] = [];
    for (const pb of PLAYBOOKS) {
      for (const keyword of pb.match_features.title_keywords) {
        const other = slug(keyword);
        if (other === pb.id || !ids.has(other)) continue;
        if (AMBIGUOUS.has(`${pb.id}:${other}`)) continue;
        claims.push(`${pb.id} claims "${keyword}", which is ${other}'s own name`);
      }
    }
    expect(claims.sort(), claims.join("\n  ")).toEqual([]);
  });

  it("every declared ambiguity is still claimed, so the list cannot outlive it", () => {
    const live = new Set<string>();
    for (const pb of PLAYBOOKS)
      for (const keyword of pb.match_features.title_keywords) live.add(`${pb.id}:${slug(keyword)}`);
    const stale = [...AMBIGUOUS.keys()].filter((k) => !live.has(k)).sort();
    expect(stale, `no longer claimed — take them off AMBIGUOUS:\n  ${stale.join("\n  ")}`).toEqual(
      [],
    );
  });
});

/**
 * Does a document titled exactly one of a family's DECLARED names reach it?
 *
 * `bare-title-reach` asks the same question of a family's display NAME, and
 * the display name is a catalog label, not a title anyone writes: "Mutual /
 * General Release", "MSA — Vendor-Side Deep Analysis", "Appellate Brief
 * (filing-format)", "Privacy Policy Linter". Nearly half of that file's
 * standing worklist is the slash, the em-dash, and the parenthetical rather
 * than anything about the family. The string a real document actually carries
 * is the one the playbook itself declares: `title_keywords`.
 *
 * So this asks the question of every declared name, one at a time, and it is
 * not circular — a title keyword is worth 0.3 against a 0.5 threshold, so a
 * family reaches its own declared name only if that name earns the second
 * credit or a distinguishing phrase fires alongside it.
 *
 * It found seven documents being routed by PART of their own title. Both
 * families matched, both earned the proper-name double credit, both scored
 * 0.6, and the tie went to the alphabet: "ASSIGNMENT AND ASSUMPTION OF LEASE"
 * to `assignment-and-assumption-agreement`, "RESIDENTIAL PURCHASE AND SALE
 * AGREEMENT" to `real-estate-psa`, "INTERNATIONAL DATA TRANSFER AGREEMENT" to
 * `data-sharing-agreement`, and "CONFLICT OF INTEREST WAIVER" — a waiver two
 * clients sign — to `coi-policy`, a company's own conflicts policy. See
 * `maximalKeywords` in the matcher for the rule that settles them.
 *
 * Both lists below are RATCHETS: they may shrink, never grow.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";
import { GENERIC_FALLBACK_ID } from "../../src/playbooks/types.js";
import { buildTree } from "../../src/extract/_fixtures.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

const PLAYBOOKS = parsePlaybooks(
  JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
);
const LAUNCH = LAUNCH_PLAYBOOK_IDS.map((id) =>
  parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
);
const dkb = loadStarterDkbSync();
const ALL = [...LAUNCH, ...PLAYBOOKS];

/**
 * Families no declared name of their own reaches.
 *
 * The two NDA entries are correct and permanent: both are deprecated, and the
 * matcher promotes their named `*-deep` successors. `ma-restrictive-covenant`
 * is the real one — every name it declares is a name an EMPLOYEE non-compete
 * carries too, and a seller's covenant given for the goodwill of a business is
 * measured against a different body of law entirely.
 */
const UNREACHED_BY_ANY_DECLARED_NAME: ReadonlySet<string> = new Set([
  "ma-restrictive-covenant",
  "mutual-nda",
  "unilateral-nda",
]);

/**
 * A name one family declares and a DIFFERENT family takes.
 *
 * Every entry here is a string two families both claim, or one a broader
 * family claims verbatim. Where the taker's own name is the longer one, the
 * matcher now settles it; what is left is genuine collision — "terms of use",
 * "letter of intent", "risk factors", "data processing agreement" — and each
 * has to be settled in the playbooks by giving one family the name and the
 * other a longer one, not in the matcher.
 *
 * Three came off at 9.368.0, and all three were the same mistake: a title
 * keyword that is not a title. "generative ai" is a TOPIC, claimed by both AI
 * families, each of which also declares its own name ("generative ai policy",
 * "ai addendum"). "waiver and release" is the genus a participant release is
 * called, while a lien waiver is called "waiver and release OF LIEN" and
 * declares four names of its own.
 *
 * "bylaws of" was the fourth candidate and stays: it looks like the same
 * mistake and is not. A nonprofit's bylaws really are titled "BYLAWS OF
 * PEMBERTON RIDGE LAND CONSERVANCY", with nothing in the title to say which
 * kind of corporation it is, and dropping the keyword cost that document its
 * family outright. The collision is live because the ambiguity is.
 */
const NAME_TAKEN_BY_ANOTHER_FAMILY: ReadonlySet<string> = new Set([
  "dpa-multi-state-us :: data processing addendum -> dpa-controller-processor",
  "dpa-multi-state-us :: data processing agreement -> dpa-controller-processor",
  "loi-term-sheet :: letter of intent -> letter-of-intent-lease",
  "ma-restrictive-covenant :: non-compete agreement -> employment-restrictive-covenant",
  "ma-restrictive-covenant :: non-compete and non-solicitation -> employment-restrictive-covenant",
  "ma-restrictive-covenant :: non-competition agreement -> employment-restrictive-covenant",
  "ma-restrictive-covenant :: non-competition and non-solicitation -> employment-restrictive-covenant",
  "ma-restrictive-covenant :: non-solicitation and non-competition -> employment-restrictive-covenant",
  "ma-restrictive-covenant :: restrictive covenant agreement -> employment-restrictive-covenant",
  "msa-customer-deep :: master services agreement -> msa-general",
  "msa-customer-deep :: master subscription agreement -> saas-customer",
  "msa-vendor-deep :: cloud service agreement -> msa-customer-deep",
  "msa-vendor-deep :: cloud services agreement -> msa-customer-deep",
  "msa-vendor-deep :: master services agreement -> msa-general",
  "msa-vendor-deep :: master subscription agreement -> saas-customer",
  "nonprofit-bylaws :: bylaws of -> bylaws-corporation",
  "privacy-policy-lint :: data privacy notice -> privacy-notice-gdpr",
  "s-1-risk-factors :: risk factors -> 10-k-risk-factors",
  "saas-customer :: cloud service agreement -> msa-customer-deep",
  "saas-customer :: cloud services agreement -> msa-customer-deep",
  "saas-vendor :: cloud service agreement -> msa-customer-deep",
  "saas-vendor :: cloud services agreement -> msa-customer-deep",
  "saas-vendor :: master service agreement -> msa-general",
  "saas-vendor :: master services agreement -> msa-general",
  "saas-vendor :: subscription order form -> saas-customer",
  "scc-module-3 :: commission implementing decision 2021/914 -> scc-module-2",
  "scc-module-3 :: standard contractual clauses -> scc-module-2",
  "separation-agreement :: release of claims -> mutual-release",
]);

function routeOf(title: string): string {
  const body: [string, ...string[]] = [
    "",
    title.toUpperCase(),
    "This document is made as of January 1, 2026 between Acme Inc. and Globex Inc.",
  ];
  const tree = buildTree(body);
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  return matchPlaybook(extracted, extracted.classified, ALL, {
    title: titleCorpus(tree, "d.txt"),
    body_text: body.join("\n"),
  }).playbook_id;
}

describe("a family's own declared names reach it", () => {
  const unreached: string[] = [];
  const taken: string[] = [];
  let names = 0;
  for (const pb of ALL) {
    if (pb.id === GENERIC_FALLBACK_ID) continue;
    const keywords = pb.match_features.title_keywords;
    let reached = false;
    for (const kw of keywords) {
      names += 1;
      const routed = routeOf(kw);
      if (routed === pb.id) {
        reached = true;
        continue;
      }
      // A DEPRECATED family's names routing to its named successor is the
      // promotion working, not a theft.
      if (routed !== GENERIC_FALLBACK_ID && pb.deprecated !== true) {
        taken.push(`${pb.id} :: ${kw} -> ${routed}`);
      }
    }
    if (keywords.length > 0 && !reached) unreached.push(pb.id);
  }

  it("the sweep ran over every declared name in the catalog", () => {
    expect(names).toBeGreaterThan(1000);
  });

  it("no family that a declared name reached has stopped being reachable", () => {
    const regressed = unreached.filter((id) => !UNREACHED_BY_ANY_DECLARED_NAME.has(id)).sort();
    expect(
      regressed,
      `no name these families declare routes to them any more:\n  ${regressed.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every listed family is still unreachable — fixed ones come off the list", () => {
    const live = new Set(unreached);
    const fixed = [...UNREACHED_BY_ANY_DECLARED_NAME].filter((id) => !live.has(id)).sort();
    expect(
      fixed,
      `these families now reach a declared name — remove them from UNREACHED_BY_ANY_DECLARED_NAME:\n  ${fixed.join("\n  ")}`,
    ).toEqual([]);
  });

  it("no new name is taken by a different family", () => {
    const fresh = taken.filter((t) => !NAME_TAKEN_BY_ANOTHER_FAMILY.has(t)).sort();
    expect(
      fresh,
      `these declared names now route to a different family, which runs the wrong rules over the document:\n  ${fresh.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every listed collision is still live — settled ones come off the list", () => {
    const live = new Set(taken);
    const settled = [...NAME_TAKEN_BY_ANOTHER_FAMILY].filter((t) => !live.has(t)).sort();
    expect(
      settled,
      `these collisions are settled — remove them from NAME_TAKEN_BY_ANOTHER_FAMILY:\n  ${settled.join("\n  ")}`,
    ).toEqual([]);
  });
});

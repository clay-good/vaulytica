/**
 * A playbook may not penalize its own vocabulary.
 *
 * `negative_features` are the matcher's counter-signal: −0.1 each, for text
 * that means "this is some OTHER family's document". A negative feature that
 * appears in the family's own name, its own title keywords, or its own
 * distinguishing phrases is therefore self-contradictory — it subtracts from
 * the very documents the playbook exists to win.
 *
 * Four shipped that way, and one of them is the substring bug in its purest
 * form: `irrevocable-trust` listed **"revocable"**, which is inside
 * "irrevocable". Features longer than an acronym are matched as plain
 * substrings, so every irrevocable trust took the penalty on its own name,
 * printed on every page. `loi-term-sheet` listed "definitive agreement" as
 * both a distinguishing phrase (+0.2) and a negative feature (−0.1) — the
 * sentence every term sheet ends on. `trademark-assignment` listed "patent",
 * while its own longest distinguishing phrase is "recordation with the united
 * states patent and trademark office". `deed-of-trust` listed "security
 * agreement", which is inside its own title keyword "mortgage and security
 * agreement", the ordinary title of a commercial deed of trust.
 *
 * The invariant is mechanical and needs no judgment: whatever a playbook
 * offers as evidence FOR itself cannot also be evidence against.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";
import { EXPECTED } from "./specimen-regression.test.js";

const PLAYBOOKS = [
  ...parsePlaybooks(
    JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
  ),
  ...LAUNCH_PLAYBOOK_IDS.map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
  ),
];

describe("negative features", () => {
  it("the catalog is loaded", () => {
    expect(PLAYBOOKS.length).toBeGreaterThan(200);
  });

  it.each(PLAYBOOKS.map((p) => [p.id, p] as const))(
    "%s does not list a negative feature drawn from its own vocabulary",
    (_id, playbook) => {
      const f = playbook.match_features;
      const own = [
        playbook.name ?? "",
        ...f.title_keywords,
        ...f.distinguishing_phrases,
        ...f.required_clauses,
      ]
        .map((s) => s.toLowerCase())
        .filter((s) => s.length > 0);

      const offending = f.negative_features
        .map((n) => n.toLowerCase())
        .flatMap((n) => own.filter((o) => o.includes(n)).map((o) => `"${n}" inside "${o}"`));

      expect(offending, `${playbook.id} penalizes itself: ${offending.join("; ")}`).toEqual([]);
    },
  );
});

/**
 * The second half of the same invariant, and the half the substring test
 * cannot see.
 *
 * Seven of the negative features fixed on 2026-08-28 were not substrings of
 * their own playbook's features — they were phrases from the family's own
 * BOILERPLATE, which no amount of reading the playbook can reveal:
 * `written-consent` listed "bylaws", the recital every DGCL § 141(f) consent
 * opens on; `prenuptial-agreement` listed "during the marriage", which is what
 * a premarital agreement is about (it scored 0.4 and routed to a DIVORCE
 * settlement); `security-agreement`, `escrow-agreement`, and
 * `payment-performance-bond` each listed the instrument they exist to secure
 * or serve; `patent-assignment` listed "trademark", which is inside the name
 * of the office it asks to record it.
 *
 * The specimens are what make this checkable: each is a realistic document of
 * a known family, so a negative feature appearing in one is, by definition, a
 * penalty the family charges itself.
 */
describe("negative features against the family's own specimen", () => {
  const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
  const byId = new Map(PLAYBOOKS.map((p) => [p.id, p]));

  it.each(Object.entries(EXPECTED))("%s", (file, expectation) => {
    const playbook = byId.get(expectation.playbook);
    if (!playbook) return; // a launch playbook not in the extended bundle
    const text = readFileSync(join(DIR, file), "utf8").toLowerCase();
    const offending = playbook.match_features.negative_features.filter((n) =>
      text.includes(n.toLowerCase()),
    );
    expect(
      offending,
      `${expectation.playbook} penalizes its own document for: ${offending.join(", ")}`,
    ).toEqual([]);
  });
});

/**
 * The same invariant against the GOLDEN FIXTURES, which reach forty families
 * the specimen corpus does not.
 *
 * Each golden fixture carries a `.playbook` sidecar naming the family it is
 * written for, so a negative feature appearing in one is a penalty the family
 * charges its own document — exactly the specimen check, over a corpus three
 * times the size. It found six on the day it was written, and every one of
 * them named the instrument the family exists ALONGSIDE rather than a rival
 * family's document: `revocable-living-trust` penalized "last will and
 * testament", which its own pour-over rule requires; `loan-agreement`
 * penalized "security agreement", which a secured loan names in its collateral
 * clause; `safe-yc` penalized the bare word "interest"; and two downstream
 * data-protection families penalized "Master Services Agreement", the
 * instrument they are appended to. Each was narrowed to the form the OTHER
 * document states in terms ("this security agreement", "declare this to be my
 * last will").
 */
describe("negative features against the family's own golden fixtures", () => {
  const byId = new Map(PLAYBOOKS.map((p) => [p.id, p]));
  const cases: [string, string, string][] = [];
  for (const dir of [
    join(process.cwd(), "tests", "golden", "v3", "fixtures"),
    join(process.cwd(), "tests", "golden", "v4", "fixtures"),
  ]) {
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".txt")) continue;
      const sidecar = join(dir, `${file}.playbook`);
      if (!existsSync(sidecar)) continue;
      cases.push([file, readFileSync(sidecar, "utf8").trim(), join(dir, file)]);
    }
  }

  it("the fixture corpus is loaded", () => {
    expect(cases.length).toBeGreaterThan(200);
  });

  it.each(cases)("%s", (_file, id, path) => {
    const playbook = byId.get(id);
    if (!playbook) return;
    const text = readFileSync(path, "utf8").toLowerCase();
    const offending = playbook.match_features.negative_features.filter((n) =>
      text.includes(n.toLowerCase()),
    );
    expect(offending, `${id} penalizes its own fixture for: ${offending.join(", ")}`).toEqual([]);
  });
});

/**
 * The same invariant reaching the families that have no specimen.
 *
 * Fifty-five of the two hundred sixty-six families have a hand-written
 * document; the rest do not, and the specimen guard above cannot see them. A
 * playbook still describes itself in four other places — its prose
 * description, the terms it expects the document to define, the clauses it
 * expects to find, and its compliance-matrix columns — and a negative feature
 * drawn from any of them is self-contradictory for the same reason a feature
 * drawn from its title keywords is.
 *
 * This passes today. It is a ratchet, not a discovery: it keeps the next
 * family from acquiring the defect in the place the other two guards cannot
 * look.
 */
describe("negative features against the family's own self-description", () => {
  it.each(PLAYBOOKS.map((p) => [p.id, p] as const))("%s", (_id, playbook) => {
    const own = [
      playbook.description ?? "",
      ...(playbook.expected_defined_terms ?? []).map((t) => t.term),
      ...(playbook.expected_clauses ?? []).map((c) => c.category),
      ...(playbook.compliance_matrix_columns ?? []),
    ]
      .map((s) => s.toLowerCase())
      .filter((s) => s.length > 0);

    const offending = playbook.match_features.negative_features
      .map((n) => n.toLowerCase())
      .flatMap((n) => own.filter((o) => o.includes(n)).map((o) => `"${n}" inside "${o}"`));

    expect(offending, `${playbook.id} penalizes itself: ${offending.join("; ")}`).toEqual([]);
  });
});

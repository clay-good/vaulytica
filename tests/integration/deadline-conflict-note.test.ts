/**
 * DDL-002 — two clauses implying conflicting dates for one obligation
 * (add-deadline-computation task 6).
 *
 * The defect a reader cannot see by reading either clause alone. A document
 * gives the same party's same deadline two different dates in two places; both
 * resolve, both read correctly in isolation, and the register ends up holding
 * both. Whichever a party relies on, the other is an argument against them.
 *
 * It was deferred with DDL-001 on the ground that both need the resolved
 * register, which is built after `runEngine`, and that wiring them "means
 * either building the register before the engine or a second post-run pass — a
 * pipeline reordering best done as its own change". DDL-001 then shipped as a
 * register NOTE rather than an engine rule: advisory, computed only under an
 * asserted `--deadline-profile`, and outside `critical_dates_hash`. That
 * pattern is all DDL-002 needs, so the reordering the deviation worried about
 * was never on the path.
 *
 * ⚠️ The cases below pin the CONSERVATISM as hard as the detection. This note
 * accuses a document of contradicting itself, so a false one is expensive.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EngineRun } from "../../src/engine/finding.js";
import type { IngestResult } from "../../src/ingest/types.js";
import type { Playbook } from "../../src/playbooks/types.js";
import { buildCriticalDates } from "../../src/report/critical-dates.js";
import { extractAll } from "../../src/extract/index.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { getDeadlineProfile } from "../../src/deadlines/profile.js";
import { resolveJurisdictionId } from "../../src/dkb/jurisdiction-ids.js";

const PROFILE = getDeadlineProfile("frcp-6")!;

async function register(paragraphs: [string, ...string[]], withProfile = true) {
  const { tree } = buildContext(paragraphs);
  const extracted = extractAll(tree, { jurisdictionLookup: resolveJurisdictionId });
  return buildCriticalDates(extracted, tree, withProfile ? { profile: PROFILE } : undefined);
}

const notes = (r: Awaited<ReturnType<typeof register>>) => r.deadline_notes ?? [];
const ddl002 = (r: Awaited<ReturnType<typeof register>>) =>
  notes(r).find((n) => n.code === "DDL-002");

describe("DDL-002 fires on a self-contradicting document", () => {
  it("reports one obligation given two different dates by two clauses", async () => {
    // The Supplier's cure window is 10 days in one clause and 30 in another,
    // both measured from the same anchor, so both resolve — and disagree.
    const r = await register([
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Supplier shall cure any breach within 10 days after the Notice Date.",
      "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
    ]);
    const note = ddl002(r);
    expect(
      note,
      `notes: ${JSON.stringify(notes(r))}\nregister: ${JSON.stringify(r.register.map((x) => [x.kind, x.responsible, x.computed_date]))}`,
    ).toBeDefined();
    // It must name both dates, so a reader can see which clauses disagree.
    expect(note!.detail).toContain("2026-03-12");
    expect(note!.detail).toContain("2026-04-01");
    expect(note!.detail).toContain("Supplier");
    // And it must not pretend to resolve the conflict.
    expect(note!.detail).toContain("decide which governs");
  });

  it("says nothing when the two clauses agree", async () => {
    const r = await register([
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Supplier shall cure any breach within 10 days after the Notice Date.",
      "For the avoidance of doubt, Supplier shall cure any breach within 10 days after the Notice Date.",
    ]);
    expect(ddl002(r)).toBeUndefined();
  });

  it("says nothing about two DIFFERENT parties' deadlines", async () => {
    // 🚨 The obvious false positive. Two cure windows of different lengths are
    // not a contradiction when they bind different parties — that is ordinary
    // asymmetric drafting.
    const r = await register([
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Supplier shall cure any breach within 10 days after the Notice Date.",
      "Customer shall cure any breach within 30 days after the Notice Date.",
    ]);
    expect(ddl002(r)).toBeUndefined();
  });

  it("is computed only under an asserted deadline profile", async () => {
    // Advisory and gated, like DDL-001: no assertion, no note.
    const r = await register(
      [
        "SUPPLY AGREEMENT",
        '"Notice Date" means March 2, 2026.',
        "Supplier shall cure any breach within 10 days after the Notice Date.",
        "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
      ],
      false,
    );
    expect(r.deadline_notes).toBeUndefined();
  });

  it("adds no register row, and leaves the hash a function of the register alone", async () => {
    // ⚠️ My first version of this case asserted that the profiled and
    // UNPROFILED registers hash identically. That is false, and the test
    // failing is what said so: asserting a profile adds `deadline_steps`,
    // `deadline_profile_id` and `deadline_calendar_version` to the ROWS, and
    // the rows are what the hash covers. The profile is supposed to change the
    // hash — it changes the resolved dates.
    //
    // What DDL-002 must not do is become a register row or otherwise reach the
    // hash, and that is what is pinned here: the note exists, no row carries
    // its code, and the hash is a deterministic function of the same input.
    const paragraphs: [string, ...string[]] = [
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Supplier shall cure any breach within 10 days after the Notice Date.",
      "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
    ];
    const first = await register(paragraphs);
    const again = await register(paragraphs);
    expect(ddl002(first)).toBeDefined();
    expect(first.critical_dates_hash).toBe(again.critical_dates_hash);
    // The note is advisory: it is not an entry in the register.
    expect(first.register.some((r) => r.rule_id === "DDL-002")).toBe(false);
    expect(first.register.map((r) => r.rule_id).every((id) => /^DATE-\d{3}$/.test(id))).toBe(true);
  });
});

/**
 * Where a drafting note actually appears.
 *
 * 🚨 The gap this closes. The register is rendered by four surfaces, and
 * `deadline_notes` reached three: the Word report and the register's Markdown
 * export printed a "Drafting notes" block, the JSON report carried the field
 * because it serializes the register whole — and the HTML report dropped it.
 * So one run wrote a note into three files and left it out of the fourth, with
 * no way for a reader of that fourth to know a note existed.
 *
 * ⚠️ `v9-surface-reach.test.ts` cannot catch this, and the reason is worth
 * recording: it asserts that each builder reads the TOP-LEVEL `criticalDates`
 * field of the `V9Surfaces` bundle, and `html.ts` did read it. The omission
 * was a field nested one level inside, below the ratchet's altitude. A guard's
 * scope is itself a defect surface.
 *
 * SARIF is deliberately not in this list. Its register contribution is the
 * dated rows and the register hash; a drafting note is advisory prose, not a
 * result, and adding one would change the result count every CI consumer
 * thresholds on.
 */
describe("a drafting note reaches every surface that renders the register", () => {
  /** A minimal run and ingest: these surfaces read the register, not the findings. */
  const RUN: EngineRun = {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    source_file: { name: "supply.docx", sha256: "a".repeat(64), size_bytes: 2048 },
    executed_at: "2026-06-08T00:00:00Z",
    findings: [],
    execution_log: [],
    result_hash: "d".repeat(64),
  };
  const INGEST: IngestResult = {
    tree: { type: "document", sections: [] },
    source: "docx",
    word_count: 400,
    sha256: "a".repeat(64),
    warnings: [],
  };
  const playbook = (): Playbook =>
    JSON.parse(readFileSync(join(process.cwd(), "playbooks", "mutual-nda.json"), "utf8"));

  const CONFLICT: [string, ...string[]] = [
    "SUPPLY AGREEMENT",
    '"Notice Date" means March 2, 2026.',
    "Supplier shall cure any breach within 10 days after the Notice Date.",
    "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
  ];

  it("prints the note in the Word report, the HTML report and the register export", async () => {
    const { buildHtmlReport } = await import("../../src/report/html.js");
    const { buildDocxReport } = await import("../../src/report/docx.js");
    const { criticalDatesMarkdownBlob } = await import("../../src/report/exports.js");
    const { loadStarterDkbSync } = await import("../../src/engine/_test-fixtures.js");
    const { unzipSync, strFromU8 } = await import("fflate");

    const reg = await register(CONFLICT);
    const note = ddl002(reg);
    expect(note, JSON.stringify(notes(reg))).toBeDefined();

    const v9 = { criticalDates: reg };
    const dkb = loadStarterDkbSync();

    // HTML — the surface that dropped it.
    const html = buildHtmlReport(RUN, INGEST, dkb, undefined, v9);
    expect(html, "the HTML report has no drafting-notes block").toContain("Drafting notes");
    expect(html).toContain("DDL-002");
    // The note's own text, not just its heading: a block with no body would
    // satisfy the line above and tell a reader nothing.
    expect(html).toContain("2026-03-12");
    expect(html).toContain("2026-04-01");

    // Word — unchanged, and asserted here so this test fails if either side
    // regresses rather than only the one that was broken.
    const blob = await buildDocxReport(
      RUN,
      INGEST,
      dkb,
      playbook(),
      undefined,
      undefined,
      undefined,
      v9,
    );
    const xml = strFromU8(
      unzipSync(new Uint8Array(await blob.arrayBuffer()))["word/document.xml"]!,
    );
    const docxText = (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join("");
    expect(docxText).toContain("Drafting notes");
    expect(docxText).toContain("DDL-002");

    // The register's own Markdown export.
    const md = await criticalDatesMarkdownBlob(reg).text();
    expect(md).toContain("Drafting notes");
    expect(md).toContain("DDL-002");
  }, 60_000);

  it("adds no notes block to any surface when no profile was asserted", async () => {
    // The other direction. The notes exist only under an asserted
    // `--deadline-profile`, so an ordinary run must gain no empty heading.
    const { buildHtmlReport } = await import("../../src/report/html.js");
    const { criticalDatesMarkdownBlob } = await import("../../src/report/exports.js");
    const { loadStarterDkbSync } = await import("../../src/engine/_test-fixtures.js");
    const reg = await register(CONFLICT, false);
    expect(reg.deadline_notes).toBeUndefined();
    const html = buildHtmlReport(RUN, INGEST, loadStarterDkbSync(), undefined, {
      criticalDates: reg,
    });
    expect(html).not.toContain("Drafting notes");
    expect(await criticalDatesMarkdownBlob(reg).text()).not.toContain("Drafting notes");
  }, 60_000);
});

/**
 * The conservatism guards, pinned individually (mutation-driven).
 *
 * 🚨 Why these exist. The header of this file says the cases above "pin the
 * CONSERVATISM as hard as the detection". Mutation testing of
 * `buildConflictNotes` on 2026-11-24 showed that was aspiration, not fact:
 * **55.74%** of mutants survived the suite as it stood — below the
 * repository's own break threshold of 57 — and the survivors were not
 * cosmetic. Deleting the unattributed-party skip survived. Deleting the
 * party-name normalization survived. Inverting the title's singular/plural
 * survived. Each is a guard against this note accusing a document of
 * contradicting itself when it does not, which is the expensive direction.
 *
 * Every case below was first run as a probe to see what the pipeline actually
 * produces, so none of them asserts an assumption about the register.
 */
describe("DDL-002's conservatism, guard by guard", () => {
  it("treats one party spelled two ways as one obligation, printed as written", async () => {
    // The grouping key lowercases and collapses whitespace, so "Supplier" and
    // "SUPPLIER" are the same obligation — otherwise a real conflict hides as
    // two parties with one date each. The note must still print the party the
    // way the DOCUMENT writes it, never the lowercased key.
    const r = await register([
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Supplier shall cure any breach within 10 days after the Notice Date.",
      "Notwithstanding the foregoing, SUPPLIER shall cure any breach within 30 days after the Notice Date.",
    ]);
    const note = ddl002(r);
    expect(note, JSON.stringify(notes(r))).toBeDefined();
    expect(note!.title).toContain("1 obligation");
    expect(note!.detail).toContain("for Supplier");
    // The lowercased grouping key must not reach a reader.
    expect(note!.detail).not.toContain("for supplier");
    expect(note!.detail).not.toContain("|");
  });

  it("says nothing when no party can be attributed", async () => {
    // Two clauses, two different dates, nobody named. They may bind DIFFERENT
    // parties, so calling it a contradiction would be a false accusation —
    // and deleting this guard survived the suite before this case existed.
    const r = await register([
      "SUPPLY AGREEMENT",
      '"Notice Date" means March 2, 2026.',
      "Any breach shall be cured within 10 days after the Notice Date.",
      "Notwithstanding the foregoing, any breach shall be cured within 30 days after the Notice Date.",
    ]);
    expect(
      ddl002(r),
      `two unattributed dates must not be a conflict: ${JSON.stringify(notes(r))}`,
    ).toBeUndefined();
    // The rows really are there and really are unattributed — otherwise this
    // passes because the register is empty, which proves nothing.
    const unattributed = r.register.filter((x) => x.responsible === "" && x.resolved);
    expect(unattributed.length, JSON.stringify(r.register)).toBeGreaterThan(1);
    expect(new Set(unattributed.map((x) => x.computed_date)).size).toBeGreaterThan(1);
  });

  it("counts the obligations and agrees with itself grammatically", async () => {
    // One conflict reads "1 obligation has"; two read "2 obligations have".
    // Inverting that condition survived the suite, so the note could have
    // shipped saying "1 obligations have".
    const one = ddl002(
      await register([
        "SUPPLY AGREEMENT",
        '"Notice Date" means March 2, 2026.',
        "Supplier shall cure any breach within 10 days after the Notice Date.",
        "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
      ]),
    );
    expect(one!.title).toBe("1 obligation has clauses implying different dates");

    const two = ddl002(
      await register([
        "SUPPLY AGREEMENT",
        '"Notice Date" means March 2, 2026.',
        "Supplier shall cure any breach within 10 days after the Notice Date.",
        "Notwithstanding the foregoing, Supplier shall cure any breach within 30 days after the Notice Date.",
        "Customer shall provide notice of termination within 5 days after the Notice Date.",
        "Notwithstanding the foregoing, Customer shall provide notice of termination within 20 days after the Notice Date.",
      ]),
    );
    expect(two!.title).toBe("2 obligations have clauses implying different dates");
    // Both obligations are described, each with its own party and kind.
    expect(two!.detail).toContain("for Supplier");
    expect(two!.detail).toContain("for Customer");
    expect(two!.detail).toContain("cure window");
    expect(two!.detail).toContain("notice period");
    expect(two!.severity).toBe("info");
  });

  it("lists an obligation's dates in ascending order, on any host", async () => {
    // The sort is locale-pinned to "en" so the wording cannot differ between
    // machines — the same class as the determinism guard's bare-localeCompare
    // finding. Ascending order is also what a reader expects to scan.
    const note = ddl002(
      await register([
        "SUPPLY AGREEMENT",
        '"Notice Date" means March 2, 2026.',
        "Supplier shall cure any breach within 30 days after the Notice Date.",
        "Notwithstanding the foregoing, Supplier shall cure any breach within 10 days after the Notice Date.",
      ]),
    );
    expect(note).toBeDefined();
    const dates = [...note!.detail.matchAll(/\d{4}-\d{2}-\d{2}/g)].map((m) => m[0]);
    expect(dates.length).toBeGreaterThan(1);
    expect(dates, "the later clause is written first, so this fails if unsorted").toEqual(
      [...dates].sort(),
    );
    // And each date is attributed to the clause it came from.
    expect(note!.detail).toContain('(from "within 10 days after the Notice Date")');
  });
});

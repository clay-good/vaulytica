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
import { describe, expect, it } from "vitest";
import { buildCriticalDates } from "../../src/report/critical-dates.js";
import { extractAll } from "../../src/extract/index.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { getDeadlineProfile } from "../../src/deadlines/profile.js";

const PROFILE = getDeadlineProfile("frcp-6")!;

async function register(paragraphs: [string, ...string[]], withProfile = true) {
  const { tree } = buildContext(paragraphs);
  const extracted = extractAll(tree);
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

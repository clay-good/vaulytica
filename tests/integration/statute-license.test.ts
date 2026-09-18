/**
 * The licence line under every statutory citation in the report.
 *
 * "Public domain (US government work)" is 17 U.S.C. § 105, which covers
 * federal works only. It was stamped on state statutes, on the UCC and on the
 * Restatements — the last two copyrighted works of the American Law Institute
 * and the Uniform Law Commission. An attorney reading the bibliography should
 * never find a licence claim that is wrong on its face.
 */
import { describe, expect, it } from "vitest";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { findStatuteCitation } from "../../src/engine/finding.js";

const dkb = loadStarterDkbSync();
const license = (id: string): string => findStatuteCitation(dkb, id)!.license!;

describe("statute licence labels", () => {
  it("claims the federal-works licence only for federal sources", () => {
    for (const s of dkb.statutes) {
      if (license(s.id) !== "Public domain (US government work)") continue;
      expect(s.jurisdiction, s.id).toBe("us-federal");
      expect(s.canonical_url, s.id).not.toMatch(/cornell\.edu\/(ucc|wex)\/|uniformlaws|europa/);
    }
  });

  it("labels every state statute by the doctrine that makes it public", () => {
    const state = dkb.statutes.filter((s) => /^us-(?!federal)/.test(s.jurisdiction));
    expect(state.length).toBeGreaterThanOrEqual(8);
    for (const s of state) expect(license(s.id), s.id).toMatch(/state statute/);
  });

  it("never calls the UCC or a Restatement a US government work", () => {
    expect(license("stat-ucc-2-201")).toMatch(/American Law Institute/);
    expect(license("stat-restatement-205-good-faith")).toMatch(/American Law Institute/);
    expect(license("stat-15-usc-8403")).toBe("Public domain (US government work)");
  });
});

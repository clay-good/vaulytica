/**
 * Three defects a hand-written executive employment agreement found.
 *
 * The agreement routed to `employment-at-will-us` — the launch playbook — even
 * though it matched `executive-employment`'s own name AND four of its own
 * distinguishing phrases (409A, 280G, CFO, CEO). The launch playbook wins on
 * `required_clauses`, a feature kind worth 0.4 per hit against a phrase's 0.2
 * that only the twelve launch playbooks carry: `confidentiality-obligation`,
 * `employee-ip-assignment`, and `term` are in every executive agreement ever
 * written, so it collected 0.8 for free. Fixed the way the guide recommends —
 * with negative features, not by inflating the other side's keywords: an
 * at-will offer letter does not mention Section 409A, Section 280G, Good
 * Reason, or a Change of Control.
 *
 * IPDATA-001 required the word "hereby" before the assignment verb. "Executive
 * ASSIGNS TO the Company all inventions conceived during employment" is a
 * complete assignment, and the rule reported that the agreement does not
 * allocate ownership of intellectual property.
 *
 * The arbitration seat sat behind a NAMED rule set — "under the JAMS
 * Employment Arbitration Rules in Columbus, Ohio" — and the institution-first
 * branch admitted only a bare "Rules" immediately after the provider, so
 * CHOICE-006 reported "seat not specified" on a clause that specifies one and
 * CHOICE-003 reported no forum at all.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";
import { extractJurisdictions } from "../../extract/jurisdictions.js";
import { buildTree } from "../../extract/_fixtures.js";

describe("IPDATA-001 — an assignment without 'hereby'", () => {
  it("reads a plain 'assigns to the Company all inventions'", () => {
    expect(
      IPDATA_001.check(
        buildContext([
          "Assignment of Inventions",
          "Executive assigns to the Company all inventions conceived during employment that relate to the Company's business.",
        ]),
      ),
    ).toBeNull();
  });

  it("is not satisfied by the plural noun in a successors clause", () => {
    // "successors and assigns" is a noun, and the branch requires the verb to
    // take an object with "to".
    expect(
      IPDATA_001.check(
        buildContext([
          "General",
          "This Agreement binds the Company's successors and assigns, and Executive may not delegate any duty under it.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("the arbitration seat behind a named rule set", () => {
  const seatOf = (text: string) =>
    extractJurisdictions(buildTree(["Dispute Resolution", text]))
      .filter((r) => r.clause_kind === "arbitration-seat")
      .map((r) => r.raw_text);

  it("reads the locality after a named rule set", () => {
    expect(
      seatOf(
        "Any dispute shall be resolved by binding arbitration before a single arbitrator under the JAMS Employment Arbitration Rules in Columbus, Ohio.",
      ),
    ).toEqual(["Columbus"]);
  });

  it("still reads the bare provider form", () => {
    expect(seatOf("Any dispute shall be administered by JAMS in Chicago, Illinois.")).toEqual([
      "Chicago",
    ]);
  });

  it("does not invent a seat where the clause names no place", () => {
    expect(
      seatOf(
        "Any dispute shall be resolved by binding arbitration under the JAMS Employment Arbitration Rules.",
      ),
    ).toEqual([]);
  });
});

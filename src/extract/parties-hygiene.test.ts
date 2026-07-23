/**
 * Party-extraction hygiene: the four defects that made a two-party agreement
 * extract five "parties", and the downstream rules that depended on the mess.
 *
 *  1. The entity-type group had no trailing boundary, so `inc` matched inside
 *     "including" and `ag` inside "agreement", manufacturing a party out of
 *     whatever Title-Case phrase preceded them ("Business Purpose, including
 *     …" -> party "Business Purpose").
 *  2. The `PARTY_DECL` path was the only one that skipped `cleanPartyName`, so
 *     it baked a trailing comma into the name ("Acme Corp,") and registered the
 *     same entity twice — once dirty, once cleanly from the `between` preamble.
 *  3. A natural person has no entity-type suffix, so `Alex Smith ("Employee")`
 *     only reached the `between` path, which kept the parenthetical inside the
 *     name and lost the role.
 *  4. A counterparty identified ONLY by role — `… the individual or entity
 *     accepting this EULA ("End User")` — was dropped entirely, because the
 *     descriptive phrase is not a usable name.
 *
 * These interact: fixing (2) alone is NET HARMFUL, because cleaning the names
 * makes the junk parties from (1) start matching in rules that compare a phrase
 * against the party set. They have to travel together.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../engine/_test-fixtures.js";
import { extractParties } from "./parties.js";

const parties = (...paras: [string, ...string[]]) => extractParties(buildContext(paras).tree);
const names = (...paras: [string, ...string[]]) => parties(...paras).map((p) => p.name);

describe("party extraction hygiene", () => {
  it("does not invent a party from an entity type matched inside a word", () => {
    const got = names(
      "Agreement",
      "This Agreement is entered into between Acme Corp, a Delaware corporation, and Globex LLC, a New York limited liability company. The parties shall use it for the Business Purpose, including evaluation.",
    );
    expect(got).not.toContain("Business Purpose");
    expect(got).not.toContain("Business Purpose,");
  });

  it("registers each entity once, without a trailing comma", () => {
    expect(
      names(
        "Agreement",
        "This Agreement is entered into between Acme Corp, a Delaware corporation, and Globex LLC, a New York limited liability company.",
      ),
    ).toEqual(["Acme Corp", "Globex LLC"]);
  });

  it("splits a natural person's defined role out of the name", () => {
    const got = parties(
      "Employment Agreement",
      'This Agreement is between Initech Inc., a Delaware corporation ("Company"), and Alex Smith ("Employee").',
    );
    expect(got.map((p) => p.name)).toEqual(["Initech Inc", "Alex Smith"]);
    expect(got.map((p) => p.role)).toEqual(["Company", "Employee"]);
  });

  it("keeps the entity's role through the de-duplication merge", () => {
    const got = parties(
      "Employment Agreement",
      'This Agreement is between Initech Inc., a Delaware corporation ("Company"), and Alex Smith, an individual ("Employee").',
    );
    expect(got.find((p) => p.name === "Initech Inc")?.role).toBe("Company");
  });

  it("reads the preamble of a short document", () => {
    // The scan window used to be a pure proportion of the paragraph count, so a
    // four-paragraph agreement examined only paragraph 1 — the title — and
    // reported "could not identify the parties" about a document naming them in
    // the very next line.
    expect(
      names(
        "Triple Net Lease Agreement",
        'This Triple Net Lease ("Lease") is between Landlord, REIT Holdings LLC, and Tenant, Retailer Inc.',
        "Rent. Tenant shall pay base rent monthly in advance.",
        "Insurance. Tenant shall maintain commercial general liability coverage.",
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it("does not turn a document reference into a party", () => {
    // `between` also matches ordinary prose about instruments. Taking the
    // parenthetical here would invent a party named "SOW", which then skews
    // every rule that tallies by party.
    expect(
      names(
        "Master Services Agreement",
        'This MSA is between Acme Corp, a Delaware corporation ("Vendor"), and Wayne Enterprises LLC, a Delaware limited liability company ("Customer").',
        'In the event of any conflict between this MSA and any Statement of Work ("SOW"), the terms of this MSA control.',
      ),
    ).toEqual(["Acme Corp", "Wayne Enterprises LLC"]);
  });

  it("names a counterparty identified only by its role", () => {
    const got = parties(
      "End User License Agreement",
      'This EULA is entered into between Globex Software Inc., a Delaware corporation ("Licensor"), and the individual or entity accepting this EULA ("End User").',
    );
    expect(got.map((p) => p.name)).toContain("End User");
    expect(got.find((p) => p.name === "End User")?.role).toBe("End User");
  });
});

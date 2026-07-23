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

  it("does not turn ordinary prose containing 'between' into parties", () => {
    // `between X and Y` is a preamble only when a preamble introduces it.
    // Read as one, a fee sentence sitting in the front matter manufactures
    // parties named "Gross Revenue" and "Net Revenue for the applicable
    // period" — names STRUCT-006 then treats as real (so it stops reporting
    // them as undefined terms) and RISK-002 reports indemnity counts against.
    expect(
      names(
        "Agreement",
        "The Service Fee is the difference between Gross Revenue and Net Revenue for the applicable period.",
      ),
    ).toEqual([]);
    expect(
      names(
        "Agreement",
        "Fees payable under this Agreement are the difference between Gross Revenue and Net Revenue.",
      ),
    ).toEqual([]);
    expect(
      names(
        "Agreement",
        "In the event of any conflict between this MSA and any Statement of Work, the MSA controls.",
      ),
    ).toEqual([]);
  });

  it("reads the preamble past a fee sentence in the same front matter", () => {
    // The paragraph's FIRST `between` is not always the preamble's.
    expect(
      names(
        "Agreement",
        "The Service Fee is the difference between Gross Revenue and Net Revenue. This Agreement is between Acme Corp., a Delaware corporation, and Globex LLC, a New York limited liability company.",
      ),
    ).toEqual(["Acme Corp", "Globex LLC"]);
  });

  it("reads every preamble lead-in the corpus writes", () => {
    // by and between
    expect(
      names(
        "Agreement",
        "This Master Services Agreement is made as of January 1, 2026, by and between Acme Corp. and Globex Industries.",
      ),
    ).toEqual(["Acme Corp", "Globex Industries"]);
    // instrument as the sentence's own subject
    expect(
      names("Statement of Work", "This Statement of Work is between Acme Inc. and Globex Inc."),
    ).toEqual(["Acme Inc", "Globex Inc"]);
    // a long statutory recital between the verb and the word
    expect(
      names(
        "Agreement",
        "This Business Associate Agreement is entered into pursuant to the requirements of 45 CFR § 164.504(e) between Acme Health Corp. and Globex Billing.",
      ),
    ).toEqual(["Acme Health Corp", "Globex Billing"]);
    // an SOW naming its parent contract
    expect(
      names(
        "Statement of Work",
        "Contractor shall perform the Services described in the Master Services Agreement between Acme Corp. and Globex Industries.",
      ),
    ).toEqual(["Acme Corp", "Globex Industries"]);
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
  it("reads a labeled party line", () => {
    // An SCC annex, an IDTA table or a certificate of insurance has no
    // preamble and no "between", and often a foreign entity type the
    // declaration pattern does not know — so STRUCT-001 reported "no parties
    // identified" about a document naming them under a Parties heading.
    const got = parties(
      "Standard Contractual Clauses",
      "Parties",
      "Data Exporter: Globex EU SARL, a French société à responsabilité limitée, 15 rue Lafayette, 75009 Paris, France, acting as data processor.",
      "Data Importer: Stark Cloud Ireland Ltd., an Irish private limited company, One Grand Canal Square, Dublin 2, Ireland.",
    );
    expect(got.map((p) => p.name)).toEqual(["Globex EU SARL", "Stark Cloud Ireland Ltd"]);
    expect(got.map((p) => p.role)).toEqual(["Data Exporter", "Data Importer"]);
  });

  it("does not read a labeled description as a party name", () => {
    expect(
      names(
        "Definitions",
        "Recipient: the party receiving Confidential Information under this Agreement.",
      ),
    ).toEqual([]);
  });
  it("does not keep a role label the preamble put in front of the name", () => {
    // "between Covered Entity, Acme Health LLC, …, and Business Associate,
    // Globex Services Inc." produced parties literally named "Covered Entity,
    // Acme Health LLC" — a string that appears nowhere else in the document,
    // so every rule matching a party surface against the text missed it. The
    // same preamble also registered the bare role as a third and fourth party.
    const got = parties(
      "Business Associate Agreement",
      'This Business Associate Agreement ("BAA") is entered into pursuant to the requirements of 45 CFR § 164.504(e) between Covered Entity, Acme Health LLC, a Delaware limited liability company ("Covered Entity"), and Business Associate, Globex Services Inc., a New York corporation ("Business Associate").',
    );
    expect(got.map((p) => p.name)).toEqual(["Acme Health LLC", "Globex Services Inc"]);
    expect(got.map((p) => p.role)).toEqual(["Covered Entity", "Business Associate"]);
  });

  it("leaves a company whose name starts with a role word alone", () => {
    expect(
      names(
        "Agreement",
        "This Agreement is between Trustee Services LLC, a Delaware limited liability company, and Globex Inc., a New York corporation.",
      ),
    ).toEqual(["Trustee Services LLC", "Globex Inc"]);
  });
  it("does not invent a party from an entity type matched at the END of a word", () => {
    // "corporation" sits inside "Incorporation"; without a leading boundary the
    // heading "EU SCC Incorporation" yielded a party named "EU SCC In".
    expect(
      names(
        "Addendum",
        "EU SCC Incorporation",
        "The Approved EU SCCs are incorporated by reference.",
      ),
    ).not.toContain("EU SCC In");
  });
});

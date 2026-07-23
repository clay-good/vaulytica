import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

describe("extractJurisdictions", () => {
  it("captures governing law and venue with raw text", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware. Exclusive jurisdiction shall be in the federal courts located in New York, New York.",
    ]);
    const refs = extractJurisdictions(tree);
    const gov = refs.find((r) => r.clause_kind === "governing-law");
    const venue = refs.find((r) => r.clause_kind === "venue");
    expect(gov?.raw_text).toMatch(/Delaware/);
    expect(venue?.raw_text).toMatch(/New York/);
  });

  it("normalizes via the DKB lookup when provided", () => {
    const tree = buildTree(["Body", "Governed by the laws of the State of California."]);
    const refs = extractJurisdictions(tree, (raw) =>
      /California/.test(raw) ? "us-ca" : undefined,
    );
    expect(refs[0]!.jurisdiction_id).toBe("us-ca");
  });

  it("captures an exception/fallback jurisdiction on the primary record", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware, except that any dispute concerning real property shall be governed by the laws of Texas.",
    ]);
    const refs = extractJurisdictions(tree);
    const gov = refs.find((r) => r.clause_kind === "governing-law");
    expect(gov?.raw_text).toMatch(/Delaware/);
    // The primary record carries the fallback precedence link.
    expect(gov?.fallback_jurisdiction).toBe("Texas");
  });

  it("does not report a disclaimed governing law, and captures the one actually chosen", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall not be governed by the laws of California, but rather by the laws of Delaware.",
    ]);
    const gov = extractJurisdictions(tree).filter((r) => r.clause_kind === "governing-law");
    // California is explicitly rejected — it must not be reported as the law.
    expect(gov.some((r) => /California/.test(r.raw_text))).toBe(false);
    // Delaware is the law the clause actually selects.
    expect(gov.map((r) => r.raw_text)).toEqual(["Delaware"]);
  });
  it("reports the state when the venue names a city inside it", () => {
    // A venue clause names a courthouse, and a courthouse sits in a city. The
    // capture stopped at the comma, so "courts located in Wilmington,
    // Delaware" was recorded as venue "Wilmington" — a name no governing-law
    // clause uses — and every law-vs-venue rule reported a mismatch the
    // document does not contain.
    const tree = buildTree([
      "Governing Law; Venue",
      "This Agreement shall be governed by the laws of the State of Delaware. Any dispute shall be resolved exclusively in the state or federal courts located in Wilmington, Delaware, and the parties consent to such jurisdiction.",
    ]);
    const refs = extractJurisdictions(tree);
    expect(refs.find((r) => r.clause_kind === "venue")?.raw_text).toBe("Delaware");
  });

  it("resolves a county-and-state venue to the state", () => {
    const tree = buildTree([
      "Venue",
      "Exclusive venue shall be in the state courts located in New Castle County, Delaware.",
    ]);
    expect(extractJurisdictions(tree).find((r) => r.clause_kind === "venue")?.raw_text).toBe(
      "Delaware",
    );
  });

  it("resolves a foreign venue to its country", () => {
    // Enforceability is a country's treaty position, never a city's.
    const tree = buildTree(["Venue", "Exclusive venue shall be in the courts of Paris, France."]);
    expect(extractJurisdictions(tree).find((r) => r.clause_kind === "venue")?.raw_text).toBe(
      "France",
    );
  });

  it("leaves a locality alone when the document names no jurisdiction after it", () => {
    const tree = buildTree(["Venue", "Exclusive venue shall be in the courts of Ulaanbaatar."]);
    expect(extractJurisdictions(tree).find((r) => r.clause_kind === "venue")?.raw_text).toBe(
      "Ulaanbaatar",
    );
  });

  it("finds the forum clause the corpus actually writes", () => {
    // Each of these was reported as having NO venue clause — CHOICE-003
    // asserting "The document does not state where disputes must be brought"
    // about a document with a forum-selection clause.
    const venue = (text: string) =>
      extractJurisdictions(buildTree(["Forum", text])).find((r) => r.clause_kind === "venue")
        ?.raw_text;
    // a long recital of what the clause covers, an uncommon verb, and an
    // adjective on the court
    expect(
      venue(
        "Any controversy, claim, or dispute arising out of, related to, or in connection with these Clauses, including any matter concerning their validity, interpretation, performance, breach, or termination, shall be commenced exclusively before the competent courts located in Dublin, Ireland.",
      ),
    ).toBe("Ireland");
    // "resolved BY the courts of"
    expect(
      venue("Disputes arising from these Clauses shall be resolved by the courts of France."),
    ).toBe("France");
    // "disagreement" as the dispute noun
    expect(
      venue(
        "Any disagreement concerning this Policy shall be resolved in the state or federal courts of New Castle County, Delaware.",
      ),
    ).toBe("Delaware");
  });

  it("does not read a court reference in an unrelated clause as a forum clause", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Records",
        "Processor shall not be obligated to share them with Controller except as required by a court of competent jurisdiction or supervisory authority.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue")).toEqual([]);
  });

  it("takes the jurisdiction a descriptive governing-law clause goes on to name", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "These Clauses shall be governed by the law of the European Union Member State in which the data exporter is established, namely France.",
      ]),
    );
    expect(refs.find((r) => r.clause_kind === "governing-law")?.raw_text).toBe("France");
  });
  it("finds the governing-law clause the corpus actually writes", () => {
    const gov = (text: string) =>
      extractJurisdictions(buildTree(["Governing Law", text])).find(
        (r) => r.clause_kind === "governing-law",
      )?.raw_text;
    // The commas are ordinary drafting, and they matched nothing — CHOICE-001
    // reported "no governing-law clause" on a Governing Law section. The
    // sovereign descriptor has to come off too, or "Republic of Ireland" never
    // reconciles against an "Ireland" venue.
    expect(
      gov(
        "These Clauses shall be governed by, and construed in accordance with, the laws of the Republic of Ireland, without reference to its conflict-of-laws principles.",
      ),
    ).toBe("Ireland");
    // The UK IDTA's own wording — a statement, not a command.
    expect(gov("The governing law of this Addendum is the law of England and Wales.")).toBe(
      "England and Wales",
    );
  });

  it("does not read a non-jurisdiction as the governing law", () => {
    expect(
      extractJurisdictions(
        buildTree([
          "Governing Law",
          "The governing law of this Addendum is determined by the parties' agreement.",
        ]),
      ).filter((r) => r.clause_kind === "governing-law"),
    ).toEqual([]);
  });
});

describe("consent-to-jurisdiction forum clauses", () => {
  const venue = (t: string) =>
    extractJurisdictions(buildTree(["Governing Law; Venue", t])).find(
      (r) => r.clause_kind === "venue",
    )?.raw_text;

  it("reads 'consent to the exclusive jurisdiction of the courts located in X'", () => {
    // No dispute noun, no "shall be resolved" verb — the parties simply consent
    // to a court's jurisdiction, one of the most common forum forms, and every
    // verb-driven pattern missed it, so CHOICE-003 reported no venue clause.
    expect(
      venue(
        "The parties consent to the exclusive jurisdiction of the state and federal courts located in New York County, New York.",
      ),
    ).toBe("New York");
  });

  it("reads 'submit to the jurisdiction of the courts of X'", () => {
    expect(
      venue(
        "Each party irrevocably submits to the jurisdiction of the courts of England and Wales.",
      ),
    ).toBe("England and Wales");
  });

  it("does not truncate 'England and Wales' at the connector", () => {
    expect(
      venue(
        "The parties consent to the exclusive jurisdiction of the courts of England and Wales, without prejudice to any mandatory rights.",
      ),
    ).toBe("England and Wales");
  });

  it("still stops a venue capture at a genuine clause connector", () => {
    expect(
      venue(
        "The parties consent to the exclusive jurisdiction of the courts of Delaware and waive any objection to venue.",
      ),
    ).toBe("Delaware");
  });

  it("does not read an ordinary 'jurisdiction' mention as a forum clause", () => {
    expect(
      venue("The Company operates in every jurisdiction where it does business."),
    ).toBeUndefined();
  });
});

describe("England and Wales — the compound jurisdiction name", () => {
  const gov = (t: string) =>
    extractJurisdictions(buildTree(["Governing Law", t])).find(
      (r) => r.clause_kind === "governing-law",
    )?.raw_text;

  it("reads the full name from the classic comma'd governing-law clause", () => {
    expect(
      gov(
        "This DPA is governed by, and construed in accordance with, the laws of England and Wales.",
      ),
    ).toBe("England and Wales");
  });

  it("still stops the law capture at a genuine connector", () => {
    expect(
      gov("This Agreement shall be governed by the laws of Delaware and applicable federal law."),
    ).toBe("Delaware");
  });
});

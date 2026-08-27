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

  it("resolves a 'Court of Chancery of the State of Delaware' venue to Delaware", () => {
    // The dispute-verb forum-selection form ("any action … shall be brought
    // exclusively in the Court of Chancery of the State of Delaware") left
    // "Chancery of the State of Delaware" in the capture — a name no
    // governing-law clause uses — so CHOICE-004/009/012 reported a
    // law-vs-venue mismatch on the standard VC / corporate forum.
    const tree = buildTree([
      "Governing Law; Venue",
      "This Agreement shall be governed by the laws of the State of Delaware. Any action arising out of this Agreement shall be brought exclusively in the Court of Chancery of the State of Delaware.",
    ]);
    const refs = extractJurisdictions(tree);
    expect(refs.find((r) => r.clause_kind === "venue")?.raw_text).toBe("Delaware");
  });

  it("captures a venue clause with an adverb between the verb and the court", () => {
    // "Venue … shall lie exclusively in the state courts located in Cook
    // County, Illinois" — the adverb "exclusively" after "shall lie" defeated
    // the VENUE pattern, so CHOICE-003 reported no venue clause at all.
    const tree = buildTree([
      "Governing Law; Venue",
      "This Lease shall be governed by the laws of the State of Illinois. Venue for any action arising out of this Lease shall lie exclusively in the state courts located in Cook County, Illinois.",
    ]);
    expect(extractJurisdictions(tree).find((r) => r.clause_kind === "venue")?.raw_text).toBe(
      "Illinois",
    );
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

describe("a numeric parenthetical does not break the forum run-up", () => {
  it("reads the escalation-then-forum clause construction contracts write", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Dispute Resolution; Governing Law",
        "The parties shall first attempt in good faith to resolve any dispute by negotiation between executives. Any dispute not resolved within thirty (30) days shall be resolved in the state or federal courts located in Franklin County, Ohio, and this Agreement is governed by the laws of the State of Ohio.",
      ]),
    );
    expect(refs.find((r) => r.clause_kind === "venue")?.raw_text).toBe("Ohio");
  });

  it("a list marker still does not bridge two clauses", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Miscellaneous",
        "Any dispute notice must state (a) the basis of the dispute; matters shall be handled per Section 4. Fees shall be resolved in the ordinary course of the courts of accounting practice.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue")).toEqual([]);
  });
});

describe("inverted exclusive-forum clauses (Delaware Chancery bylaws)", () => {
  it("extracts Delaware from 'Court of Chancery … shall be the sole and exclusive forum'", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Forum",
        "Unless the Corporation consents in writing to the selection of an alternative forum, the Court of Chancery of the State of Delaware shall be the sole and exclusive forum for any derivative action brought on behalf of the Corporation.",
      ]),
    );
    const venues = refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text);
    expect(venues).toContain("Delaware");
    // The old case-insensitive capture read the lowercase clause tail as the venue.
    expect(venues.some((v) => v.startsWith("the sole"))).toBe(false);
  });

  it("extracts the inverted generic form 'the courts of X shall be the exclusive forum'", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Forum",
        "The state and federal courts located in the State of New York shall be the exclusive forum for all disputes under this Agreement.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text)).toContain(
      "New York",
    );
  });
});

describe("interpretation-form governing law", () => {
  it("reads 'interpreted in accordance with the laws of the State of Vermont'", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This directive is made under and shall be interpreted in accordance with the laws of the State of Vermont.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text)).toContain(
      "Vermont",
    );
  });

  it("captures the adjectival 'governed by <State> law' form", () => {
    const gov = (t: string) =>
      extractJurisdictions(buildTree(["Governing Law", t])).find(
        (r) => r.clause_kind === "governing-law",
      )?.raw_text;
    expect(gov("This Agreement is governed by Ohio law.")).toBe("Ohio");
    expect(gov("This Agreement is governed by New York law, without regard to conflicts.")).toBe(
      "New York",
    );
    expect(gov("The Note shall be construed under Illinois law.")).toBe("Illinois");
  });

  it("does not treat 'governed by applicable law' as a jurisdiction", () => {
    const refs = extractJurisdictions(
      buildTree(["Governing Law", "This Agreement is governed by applicable law."]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law")).toHaveLength(0);
  });

  it("does not assert a disclaimed adjectival governing law", () => {
    const refs = extractJurisdictions(
      buildTree(["Governing Law", "This Agreement shall not be governed by California law."]),
    );
    expect(
      refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text),
    ).not.toContain("California");
  });

  it("captures a 'lawsuit must be brought in the courts located in <County>, <State>' venue", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Venue",
        "Any lawsuit must be brought in the state or federal courts located in Franklin County, Ohio.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text)).toContain("Ohio");
  });

  it("captures a 'venue … shall lie in <County>, <State>' clause (no 'courts' token)", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Dispute Resolution",
        "Venue for any proceeding shall lie in Franklin County, Ohio.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text)).toContain("Ohio");
  });

  it("captures a subject-first 'The laws of the State of Texas shall govern' clause", () => {
    const refs = extractJurisdictions(
      buildTree(["Governing Law", "The laws of the State of Texas shall govern this Agreement."]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text)).toContain(
      "Texas",
    );
  });

  it("does not read 'the laws of physics' as a governing-law jurisdiction", () => {
    const refs = extractJurisdictions(
      buildTree(["Preamble", "The laws of physics apply to this experiment."]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law")).toHaveLength(0);
  });

  it("captures a 'venue shall be proper in <County>, <State>' clause", () => {
    const refs = extractJurisdictions(
      buildTree(["Venue", "Venue shall be proper in Harris County, Texas."]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text)).toContain("Texas");
  });

  it("captures a courts-first 'courts located in <City>, <State> shall have jurisdiction' clause", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Jurisdiction",
        "The state and federal courts located in San Francisco, California shall have exclusive jurisdiction.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "venue").map((r) => r.raw_text)).toContain(
      "California",
    );
  });

  it("captures more governing-law lead-ins (subject to / determined under / interpreted / X law governs)", () => {
    const gov = (t: string) =>
      extractJurisdictions(buildTree(["Governing Law", t]))
        .filter((r) => r.clause_kind === "governing-law")
        .map((r) => r.raw_text);
    expect(
      gov("This Agreement shall be subject to the laws of the Commonwealth of Massachusetts."),
    ).toContain("Massachusetts");
    expect(
      gov("The rights of the parties shall be determined under the laws of Illinois."),
    ).toContain("Illinois");
    expect(gov("This Agreement shall be interpreted in accordance with California law.")).toContain(
      "California",
    );
    expect(gov("The parties agree that Georgia law governs this Agreement.")).toContain("Georgia");
  });

  it("does not read 'applicable law governs' or 'subject to the terms' as a governing law", () => {
    const gov = (t: string) =>
      extractJurisdictions(buildTree(["Governing Law", t])).filter(
        (r) => r.clause_kind === "governing-law",
      );
    expect(gov("This Agreement shall be governed by applicable law.")).toHaveLength(0);
    expect(gov("The Services are subject to the terms of the Order Form.")).toHaveLength(0);
  });

  it("captures 'personal jurisdiction in the courts of <State>' and 'agree to venue in <County>, <State>'", () => {
    const venue = (t: string) =>
      extractJurisdictions(buildTree(["Venue", t]))
        .filter((r) => r.clause_kind === "venue")
        .map((r) => r.raw_text);
    expect(
      venue("Each party consents to personal jurisdiction in the courts of the State of Texas."),
    ).toContain("Texas");
    expect(venue("The parties agree to venue in Harris County, Texas.")).toContain("Texas");
  });

  it("does not read 'agree to the terms' as a venue clause", () => {
    const venue = extractJurisdictions(
      buildTree(["Terms", "The parties agree to the terms of the Order Form."]),
    ).filter((r) => r.clause_kind === "venue");
    expect(venue).toHaveLength(0);
  });
  // Each of the three clause-tail helpers — the exception/fallback link, the
  // "namely X" concrete jurisdiction, and the alternative law after a
  // disclaimer — carried exactly one test row against a regex with four to six
  // distinct alternation branches, so most of the shipped behaviour could be
  // deleted with the suite green. The mutation run made that visible (35, 13
  // and 14 surviving mutants across the three). Every branch is pinned here.

  const GOV = "This Agreement shall be governed by the laws of the State of Delaware";

  const FALLBACKS: Array<[tail: string, want: string]> = [
    [
      ", except that disputes regarding intellectual property shall be governed by the laws of Texas.",
      "Texas",
    ],
    [", provided that the laws of Texas shall apply to any employment claim.", "Texas"],
    ["; otherwise the laws of Texas shall apply.", "Texas"],
    [", failing which the laws of Texas shall apply.", "Texas"],
    [", provided that if such courts lack jurisdiction, then New York shall apply.", "New York"],
    // "courts of X" is a fallback connector alongside "laws of X".
    [", except that the courts of Texas shall have jurisdiction over injunctive relief.", "Texas"],
    // Sovereign prefixes on the fallback itself.
    [", except the laws of the State of Texas shall govern any real property claim.", "Texas"],
    [
      ", except that the laws of the Commonwealth of Massachusetts shall apply to any tax matter.",
      "Massachusetts",
    ],
  ];

  for (const [tail, want] of FALLBACKS) {
    it(`links the fallback jurisdiction ${want} for: ${tail.slice(0, 34)}`, () => {
      const gov = extractJurisdictions(buildTree(["Governing Law", GOV + tail])).find(
        (r) => r.clause_kind === "governing-law",
      );
      expect(gov?.raw_text).toMatch(/Delaware/);
      expect(gov?.fallback_jurisdiction).toBe(want);
    });
  }

  const DESCRIPTIVE =
    "These Clauses shall be governed by the law of the Member State in which the data exporter is established";

  const NAMED: Array<[tail: string, want: string]> = [
    [", namely France.", "France"],
    [", i.e., Ireland.", "Ireland"],
    [", that is, Germany.", "Germany"],
    [", specifically the Netherlands.", "Netherlands"],
  ];

  for (const [tail, want] of NAMED) {
    it(`reads the concrete jurisdiction ${want} out of a descriptive clause: ${tail.trim()}`, () => {
      const gov = extractJurisdictions(buildTree(["Governing Law", DESCRIPTIVE + tail])).find(
        (r) => r.clause_kind === "governing-law",
      );
      // The description alone matches no venue clause ever written, so the
      // named jurisdiction — not the formula — is what must be recorded.
      expect(gov?.raw_text).toBe(want);
    });
  }

  const DISCLAIMED = "This Agreement shall not be governed by the laws of California";

  const ALTERNATIVES: Array<[tail: string, want: string]> = [
    [", but rather by the laws of Delaware.", "Delaware"],
    ["; instead governed by the laws of New York.", "New York"],
    [", but rather by the laws of the State of Delaware.", "Delaware"],
    [", but rather by the laws of the Commonwealth of Massachusetts.", "Massachusetts"],
  ];

  for (const [tail, want] of ALTERNATIVES) {
    it(`records only the selected law ${want} after a disclaimer: ${tail.slice(0, 30)}`, () => {
      const gov = extractJurisdictions(buildTree(["Governing Law", DISCLAIMED + tail])).filter(
        (r) => r.clause_kind === "governing-law",
      );
      expect(gov.map((r) => r.raw_text)).toEqual([want]);
    });
  }
  it("reads a venue clause past a day-count parenthetical", () => {
    // VENUE_SIMPLE's run-up excluded ")" outright, so the numeric parenthetical
    // ordinary drafting puts in a venue clause severed the anchor from its verb
    // and the clause went unread — CHOICE-003 then reported "no venue clause"
    // about a document that names one. Its sibling patterns already admitted a
    // digits-only parenthetical as a unit; this one did not.
    const withParenthetical = extractJurisdictions(
      buildTree([
        "Venue",
        "Venue for any dispute not resolved within thirty (30) days shall be in Franklin County, Ohio.",
      ]),
    ).filter((r) => r.clause_kind === "venue");
    const control = extractJurisdictions(
      buildTree(["Venue", "Venue for any proceeding shall lie in Franklin County, Ohio."]),
    ).filter((r) => r.clause_kind === "venue");
    expect(control.map((r) => r.raw_text)).toEqual(["Ohio"]);
    expect(withParenthetical.map((r) => r.raw_text)).toEqual(["Ohio"]);
  });
});

describe("the conjoined governing-law-and-forum sentence", () => {
  const venuesOf = (text: string) =>
    extractJurisdictions(buildTree(["Dispute Resolution", text]))
      .filter((r) => r.clause_kind === "venue")
      .map((r) => r.raw_text);

  it("reads the forum when the sentence names the law first", () => {
    // A great many clauses state the law and the forum in one sentence —
    // "will be governed by Ohio law AND resolved exclusively in the … courts".
    // The doublet slot required the two verbs to be adjacent ("filed and
    // maintained"), so the intervening "by Ohio law" broke it and CHOICE-003
    // reported "the document does not state where disputes must be brought"
    // about a document with a textbook forum-selection clause.
    expect(
      venuesOf(
        "Any other dispute arising out of or relating to this engagement will be governed by Ohio law and resolved exclusively in the state or federal courts sitting in Franklin County, Ohio, and each of us consents to the personal jurisdiction of those courts.",
      ),
    ).toEqual(["Ohio"]);
    expect(
      venuesOf(
        "Any claim shall be construed under Illinois law and brought only in the state and federal courts located in Cook County, Illinois.",
      ),
    ).toEqual(["Illinois"]);
  });

  it("does not invent a forum where the sentence names none", () => {
    // The widened lead-in still requires a real forum verb, the
    // "in/before/by … courts" scaffold, and a capitalized place after it.
    expect(
      venuesOf(
        "Any dispute shall be governed by Ohio law and resolved by binding arbitration administered by the American Arbitration Association.",
      ),
    ).toEqual([]);
    expect(
      venuesOf(
        "Any dispute shall be governed by the laws of the State of Ohio without regard to its conflict-of-laws rules.",
      ),
    ).toEqual([]);
  });
});

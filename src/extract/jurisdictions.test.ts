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

  it("reads the same clause written with 'will' instead of 'shall'", () => {
    // Plain-language house styles write "will govern"; the recognizer spelled
    // only "shall", so an entire governing-law clause was invisible. The
    // catalog's `shall-will` guard now reads the extractors too.
    const gov = (sentence: string): string[] =>
      extractJurisdictions(buildTree(["Governing Law", sentence]))
        .filter((r) => r.clause_kind === "governing-law")
        .map((r) => r.raw_text);
    expect(gov("The laws of the State of Texas will govern this Agreement.")).toContain("Texas");
    expect(gov("Delaware law will apply to this Agreement.")).toContain("Delaware");
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

describe("venue stated in a civil division", () => {
  const venuesOf = (text: string) =>
    extractJurisdictions(buildTree(["Dispute Resolution", text]))
      .filter((r) => r.clause_kind === "venue")
      .map((r) => r.raw_text);

  it("reads a venue laid in a borough, city, or county", () => {
    // The scaffold accepted only "the State/Commonwealth of", and the capture
    // requires a capital letter, so the lowercase "the" ahead of the division
    // stopped these dead. A New York credit agreement with a textbook
    // forum-selection clause was reported as not stating where disputes must
    // be brought.
    expect(
      venuesOf(
        "Any action arising out of or relating to this Agreement shall be brought exclusively in the state and federal courts sitting in the Borough of Manhattan, City of New York.",
      ),
    ).toEqual(["New York"]);
    expect(
      venuesOf(
        "Any action shall be brought in the courts located in the City of Chicago, Illinois.",
      ),
    ).toEqual(["Illinois"]);
    expect(
      venuesOf("Any action shall be brought in the courts of the County of Cook, Illinois."),
    ).toEqual(["Illinois"]);
    expect(
      venuesOf(
        "The parties consent to the exclusive jurisdiction of the courts located in the Borough of Manhattan, New York.",
      ),
    ).toEqual(["New York"]);
  });

  it("resolves the state behind a second civil-division preposition", () => {
    // Reading the locality alone left the venue as a bare city, which the
    // law-versus-venue comparisons then reported as a different jurisdiction
    // from the governing law — and CHOICE-005 as a foreign forum with no
    // enforceability treaty. One false finding became four.
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This Agreement is governed by the laws of the State of New York. Any action shall be brought exclusively in the state and federal courts sitting in the Borough of Manhattan, City of New York.",
      ]),
    );
    expect(refs.find((r) => r.clause_kind === "venue")?.raw_text).toBe("New York");
    expect(refs.find((r) => r.clause_kind === "governing-law")?.raw_text).toBe("New York");
  });

  it("leaves the governing-law patterns alone", () => {
    // The preposition was widened for VENUE only: a governing law is a state
    // or a country, and the `the <division> of` token is deliberately absent
    // from the `laws of X` patterns. Pinned by showing an ordinary
    // governing-law clause is unaffected, alongside a venue laid in a county
    // in the same document.
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This Agreement is governed by the laws of the State of Illinois. Any action shall be brought in the courts of the County of Cook, Illinois.",
      ]),
    );
    expect(refs.find((r) => r.clause_kind === "governing-law")?.raw_text).toBe("Illinois");
    expect(refs.find((r) => r.clause_kind === "venue")?.raw_text).toBe("Illinois");
  });
});

describe("a venue in a named federal court", () => {
  const venuesOf = (text: string) =>
    extractJurisdictions(buildTree(["Dispute Resolution", text]))
      .filter((r) => r.clause_kind === "venue")
      .map((r) => r.raw_text);

  it("reads a court named in full, with a district preposition", () => {
    // A federal forum names the court and its district: "brought exclusively
    // in the United States District Court for the Northern District of
    // Illinois". The court-name run did not admit the sovereign before the
    // court type, and the locality preposition set had no "for the … District
    // of" — so a settlement agreement that names its enforcement forum in the
    // ordinary way was reported as stating none.
    expect(
      venuesOf(
        "Any action to enforce this Agreement shall be brought exclusively in the United States District Court for the Northern District of Illinois.",
      ),
    ).toEqual(["Illinois"]);
  });

  it("still reads the plain locality form", () => {
    expect(
      venuesOf(
        "Any action shall be brought in the state and federal courts located in Cook County, Illinois.",
      ),
    ).toEqual(["Illinois"]);
  });

  it("does not invent a forum from a court named with no place", () => {
    expect(venuesOf("The Court shall retain jurisdiction to enforce this Agreement.")).toEqual([]);
  });
});

describe("the arbitrators as the subject of the seat", () => {
  const seatOf = (text: string) =>
    extractJurisdictions(buildTree(["Disputes", text]))
      .filter((r) => r.clause_kind === "arbitration-seat")
      .map((r) => r.raw_text);

  it("reads a seat stated in the participle form", () => {
    // An ICC clause names the arbitrators, not the arbitration, and uses no
    // modal: "finally resolved by arbitration under the Rules of Arbitration
    // of the International Chamber of Commerce by three arbitrators SEATED IN
    // London, England". The verb-first branch wants "the arbitration shall be
    // seated in", so the seat went unread and CHOICE-006 reported none.
    expect(
      seatOf(
        "Any dispute shall be finally resolved by arbitration under the Rules of Arbitration of the International Chamber of Commerce by three arbitrators seated in London, England, in the English language.",
      ),
      // The seat records as the LOCALITY; country resolution is a separate
      // concern and unchanged by this branch.
    ).toEqual(["London"]);
  });

  it("still reads the modal form", () => {
    expect(seatOf("The arbitration shall be seated in Stockholm, Sweden.")).toEqual(["Stockholm"]);
  });

  it("does not invent a seat where the clause names no place", () => {
    expect(seatOf("Any dispute shall be finally resolved by three arbitrators.")).toEqual([]);
  });
});

describe("the federal-first governing-law clause", () => {
  /**
   * Every national bank writes it this way: "governed by federal law and, to
   * the extent state law applies, by the laws of the State of Minnesota". The
   * state is named only after an intervening clause, so the "governed by … the
   * laws of X" anchor never reached it, and the compact adjectival form reads
   * "federal law" and correctly rejects it — between them, CHOICE-001 reported
   * no governing-law clause on a cardholder agreement that names one.
   */
  const govLaw = (text: string) =>
    extractJurisdictions(buildTree(["Governing Law", text]))
      .filter((j) => j.clause_kind === "governing-law")
      .map((j) => j.raw_text);

  it("names the state behind an intervening clause", () => {
    expect(
      govLaw(
        "This Agreement is governed by federal law and, to the extent state law applies, by the laws of the State of Minnesota, without regard to its conflict of laws rules.",
      ),
    ).toEqual(["Minnesota"]);
  });

  it("names the state in the compact federal-and-state form", () => {
    expect(
      govLaw("This Agreement is governed by federal law and the laws of the State of Ohio."),
    ).toEqual(["Ohio"]);
  });

  it("does not invent a jurisdiction from federal law alone", () => {
    expect(govLaw("This Agreement is governed by federal law.")).toEqual([]);
  });
});

describe("the arbitration seat in its bare locative form", () => {
  /**
   * A US employment or commercial arbitration clause puts the place right
   * after the arbitrator and BEFORE the provider — "submitted to binding
   * arbitration before a single arbitrator in Spokane County, Washington,
   * administered by the American Arbitration Association". Every branch wanted
   * either a participle ("seated in") or the provider first, so CHOICE-006
   * reported "seat not specified" on a clause that names one.
   */
  const seat = (text: string) =>
    extractJurisdictions(buildTree(["Dispute Resolution", text]))
      .filter((j) => j.clause_kind === "arbitration-seat")
      .map((j) => j.raw_text);

  it("reads the place after a bare 'arbitrator in'", () => {
    expect(
      seat(
        "A dispute not resolved that way shall be submitted to binding arbitration before a single arbitrator in Spokane County, Washington, administered by the American Arbitration Association.",
      ),
    ).toEqual(["Spokane County"]);
  });

  it("does not read a cross-reference as a seat", () => {
    expect(seat("The arbitration in Section 11 governs any dispute under this Agreement.")).toEqual(
      [],
    );
  });

  it("does not read a language as a seat", () => {
    expect(seat("The arbitration in English shall be conducted by a single arbitrator.")).toEqual(
      [],
    );
  });
});

describe("arbitration seat — the participle hung off the institution", () => {
  // "under the Commercial Arbitration Rules of the American Arbitration
  // Association, seated in New York, New York" is the ordinary institutional
  // form: the rules and the body sit between the arbitration noun and the
  // participle, so neither the participle branch (which wants
  // "arbitration/tribunal seated in") nor the institution branch (which wants
  // a bare "in" right after the provider) could reach the seat, and
  // CHOICE-006 reported "seat not specified" on a clause that states one.
  it("reads the seat after a comma following the administering body", () => {
    for (const clause of [
      "The dispute shall be submitted to expedited arbitration before a single arbitrator under the Commercial Arbitration Rules of the American Arbitration Association, seated in New York, New York.",
      "Any dispute shall be finally resolved under the JAMS Comprehensive Arbitration Rules and Procedures, seated in Chicago, Illinois.",
      "Arbitration shall be administered by the ICC, sitting in London, England.",
    ]) {
      const seats = extractJurisdictions(buildTree(["Dispute Resolution", clause])).filter(
        (j) => j.clause_kind === "arbitration-seat",
      );
      expect(seats.length, clause).toBeGreaterThan(0);
    }
  });

  it("does not read a seat from prose that names no arbitral body", () => {
    const seats = extractJurisdictions(
      buildTree([
        "Meetings",
        "The parties met in New York, New York, seated in the conference room.",
      ]),
    ).filter((j) => j.clause_kind === "arbitration-seat");
    expect(seats).toHaveLength(0);
  });
});

describe("the FALLBACK forum in a two-court clause", () => {
  // "…submits to the exclusive jurisdiction of the Bankruptcy Court in the
  // Case and, if that court lacks jurisdiction, the state and federal courts
  // located in New York County, New York." The first court named carries no
  // geography, so every trigger-anchored branch fails on it and none reaches
  // the second court — and an assignment of a bankruptcy claim that names two
  // forums was reported as naming none.
  const venues = (t: string) =>
    extractJurisdictions(buildTree(["Venue", t]))
      .filter((j) => j.clause_kind === "venue")
      .map((j) => j.raw_text);

  it("reads the second court when the first names no place", () => {
    expect(
      venues(
        "Assignor and Assignee each irrevocably submit to the exclusive jurisdiction of the Bankruptcy Court in the Case and, if that court lacks jurisdiction, the state and federal courts located in New York County, New York.",
      ),
    ).toEqual(["New York"]);
  });

  it("reads a subject-matter court named with a district", () => {
    expect(
      venues(
        "Each party irrevocably submits to the exclusive jurisdiction of the Bankruptcy Court for the District of Delaware.",
      ),
    ).toEqual(["Delaware"]);
  });

  it("does not add a second opinion where a branch already read the forum", () => {
    expect(
      venues(
        "Each party irrevocably submits to the exclusive jurisdiction of the state and federal courts located in New York County, New York.",
      ),
    ).toEqual(["New York"]);
  });

  it("does not invent a forum from a court named with no place at all", () => {
    expect(
      venues(
        "Each party irrevocably submits to the exclusive jurisdiction of the Bankruptcy Court in the Case.",
      ),
    ).toEqual([]);
  });
});

describe("governing law stated as a FEDERAL STATUTE", () => {
  // "This Agreement is governed by the Federal Arbitration Act, 9 U.S.C.
  // §§ 1–16" is the governing-law clause of every employment arbitration
  // agreement in the United States, and every other pattern wants "the laws
  // of <place>" — so CHOICE-001 reported that such an agreement states no
  // governing law at all.
  const gov = (t: string) =>
    extractJurisdictions(buildTree(["Governing Law", t]))
      .filter((j) => j.clause_kind === "governing-law")
      .map((j) => j.raw_text);

  it("names the United States as the sovereign", () => {
    expect(
      gov("This Agreement is governed by the Federal Arbitration Act, 9 U.S.C. §§ 1-16."),
    ).toEqual(["United States"]);
  });

  it("still reads a state governing-law clause in the same document", () => {
    expect(
      gov(
        "This Agreement is governed by the Federal Arbitration Act. If the Act does not apply, this Agreement is governed by the laws of the State of Ohio.",
      ),
    ).toEqual(expect.arrayContaining(["United States", "Ohio"]));
  });
});

describe("a completed FORM states its choices as labelled selections", () => {
  // Every executed EU SCC, UK IDTA, order form and cover sheet records the two
  // choices this way — "Clause 17 (Governing law): the law of Ireland" — because
  // the operative sentence lives in the incorporated form and the parties are
  // filling a blank. There is no verb for any of the other patterns to anchor
  // on, and CHOICE-001 reported no governing law on a document whose Clause 17
  // names one. Two corpus fixtures write it the same way in a plain contract:
  // "Term. This Agreement continues for two (2) years. Governing Law: Delaware."
  const kinds = (t: string) =>
    extractJurisdictions(buildTree(["Agreement", t])).map((j) => `${j.clause_kind}:${j.raw_text}`);

  it("reads a labelled governing-law selection", () => {
    expect(kinds("Clause 17 (Governing law): the law of Ireland.")).toContain(
      "governing-law:Ireland",
    );
    expect(kinds("Governing Law: Delaware.")).toContain("governing-law:Delaware");
  });

  it("reads a labelled venue selection", () => {
    expect(
      kinds("Clause 18(b) (Choice of forum and jurisdiction): the courts of Ireland."),
    ).toContain("venue:Ireland");
  });
});

/**
 * The forum is a TRIBUNAL as often as a court outside the United States.
 *
 * An English clause names both — "the parties submit to the exclusive
 * jurisdiction of the EMPLOYMENT TRIBUNALS AND COURTS of England and Wales" —
 * and the chain from "jurisdiction of" to "courts" admitted only court
 * adjectives and court names, so the tribunal noun and its "and" broke it. An
 * English contract of employment was reported as stating no forum at all.
 */
describe("a forum stated as a tribunal", () => {
  const venues = (text: string) =>
    extractJurisdictions(buildTree(["Contract of Employment", text]))
      .filter((j) => j.clause_kind === "venue")
      .map((j) => j.raw_text);

  it.each([
    [
      "tribunals and courts",
      "This Contract is governed by the law of England and Wales, and the parties submit to the exclusive jurisdiction of the employment tribunals and courts of England and Wales.",
    ],
    [
      "a tribunal alone",
      "Each party submits to the exclusive jurisdiction of the tribunals of Scotland.",
    ],
    [
      "courts alone, unchanged",
      "Each party irrevocably submits to the jurisdiction of the courts of England and Wales.",
    ],
  ])("reads %s", (_label, text) => {
    expect(venues(text).length).toBeGreaterThan(0);
  });
});

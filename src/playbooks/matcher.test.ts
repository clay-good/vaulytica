import { describe, expect, it } from "vitest";
import { matchPlaybook, titleCorpus } from "./matcher.js";
import { buildTree } from "../extract/_fixtures.js";
import { parsePlaybook } from "./loader.js";
import type { Playbook } from "./types.js";
import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";

describe("required clauses cap at ONE", () => {
  // `required_clauses` are classifier CATEGORIES, and the generic commercial
  // families list three apiece. At a two-clause cap any agreement with a
  // confidentiality section, a term and a statement of work collected 0.8 —
  // the largest single block in the score, and enough to beat a specialised
  // family that matched its own title and three phrases of its own register.
  it("gives no more than one clause's weight however many match", () => {
    const pb = (id: string, required: string[]): Playbook =>
      parsePlaybook({
        id,
        version: "1.0.0",
        name: id,
        description: id,
        match_features: {
          title_keywords: [],
          required_clauses: required,
          distinguishing_phrases: [],
          negative_features: [],
        },
        expected_clauses: [],
        expected_defined_terms: [],
        rule_overrides: {},
        balanced_defaults: [],
        sources: [],
        applicable_jurisdictions: ["US"],
      });
    const classified = [
      {
        category: "term",
        text: "",
        confidence: 1,
        position: { section_id: "s1", start: 0, end: 0 },
      },
      {
        category: "indemnification",
        text: "",
        confidence: 1,
        position: { section_id: "s1", start: 0, end: 0 },
      },
      {
        category: "confidentiality-obligation",
        text: "",
        confidence: 1,
        position: { section_id: "s1", start: 0, end: 0 },
      },
    ] as unknown as ClassifiedParagraph[];
    const extracted = { definitions: { entries: [] } } as unknown as ExtractedData;
    const three = matchPlaybook(
      extracted,
      classified,
      [pb("three", ["term", "indemnification", "confidentiality-obligation"])],
      { title: "", body_text: "" },
    );
    const one = matchPlaybook(extracted, classified, [pb("one", ["term"])], {
      title: "",
      body_text: "",
    });
    expect(three.raw_confidence).toBe(one.raw_confidence);
  });
});

describe("scores that are equal are ranked as equal", () => {
  // Two title keywords (0.3 × 2 = 0.6) and three distinguishing phrases
  // (0.2 × 3 = 0.6000000000000001) are the same score everywhere except in
  // IEEE-754. A trademark coexistence agreement lost to `mutual-nda-deep` by
  // one part in 10^16 — on "each party", "either party", "irreparable harm" —
  // and was audited as a mutual NDA, reporting nine critical omissions no
  // coexistence agreement could ever cure. Both scores were shown as 0.6.
  const pb = (id: string, title_keywords: string[], distinguishing_phrases: string[]): Playbook =>
    parsePlaybook({
      id,
      version: "1.0.0",
      name: id,
      description: id,
      match_features: {
        title_keywords,
        required_clauses: [],
        distinguishing_phrases,
        negative_features: [],
      },
      expected_clauses: [],
      expected_defined_terms: [],
      rule_overrides: {},
      balanced_defaults: [],
      sources: [],
      applicable_jurisdictions: ["US"],
    });

  const extracted = { definitions: { entries: [] } } as unknown as ExtractedData;

  it("prefers the family the title named over one matching only generic phrases", () => {
    const titled = pb("z-titled", ["coexistence agreement", "trademark coexistence"], []);
    const phrases = pb("a-phrases", [], ["each party", "either party", "irreparable harm"]);
    const match = matchPlaybook(extracted, [], [phrases, titled], {
      title: "trademark coexistence agreement",
      body_text:
        "each party acknowledges the other. either party may terminate. irreparable harm may result.",
    });
    expect(match.playbook_id).toBe("z-titled");
    expect(match.confidence).toBe(0.6);
  });

  it("still ranks a genuinely higher score first", () => {
    const titled = pb("z-titled", ["coexistence agreement", "trademark coexistence"], []);
    const phrases = pb("a-phrases", [], ["each party", "either party", "irreparable harm"]);
    const match = matchPlaybook(extracted, [], [phrases, titled], {
      title: "trademark coexistence agreement",
      body_text: "",
    });
    expect(match.playbook_id).toBe("z-titled");
  });
});

describe("a deprecated playbook does not beat its own successor", () => {
  // `docs/adding-a-playbook.md` says the deprecation metadata "lets a successor
  // playbook outrank its legacy v2 sibling", and the tiebreak was the whole of
  // that mechanism — so it fired only on an exact score tie, which never
  // happened: the legacy family carries `required_clauses` (0.4 each) and its
  // successor carries none. `mutual-nda` scored 1.0 against `mutual-nda-deep`'s
  // 0.9 on every NDA, so the 23 NDA-D rules never ran on an auto-routed
  // document.
  const make = (id: string, extra: Record<string, unknown>): Playbook =>
    parsePlaybook({
      id,
      version: "1.0.0",
      name: id,
      description: id,
      match_features: {
        title_keywords: ["widget agreement"],
        required_clauses: [],
        distinguishing_phrases: ["widget", "sprocket", "flange"],
        negative_features: [],
      },
      expected_clauses: [],
      expected_defined_terms: [],
      rule_overrides: {},
      balanced_defaults: [],
      sources: [],
      applicable_jurisdictions: ["US"],
      ...extra,
    });

  const extracted = { definitions: { entries: [] } } as unknown as ExtractedData;
  const body = "The widget, the sprocket and the flange are described here.";
  const run = (candidates: Playbook[]): string =>
    matchPlaybook(extracted, [], candidates, {
      title: "widget agreement",
      body_text: body,
    }).playbook_id;

  it("promotes the named successor when it clears the threshold", () => {
    const legacy = make("legacy", { deprecated: true, superseded_by: "legacy-deep" });
    const successor = make("legacy-deep", {});
    expect(run([legacy, successor])).toBe("legacy-deep");
  });

  it("leaves the legacy family in place when the successor does not recognise the document", () => {
    const legacy = make("legacy", { deprecated: true, superseded_by: "legacy-deep" });
    const stranger = make("legacy-deep", {
      match_features: {
        title_keywords: ["something else entirely"],
        required_clauses: [],
        distinguishing_phrases: ["nothing", "here", "at all"],
        negative_features: [],
      },
    });
    expect(run([legacy, stranger])).toBe("legacy");
  });
});

/**
 * The subject-line window is bounded BOTH ways.
 *
 * A paragraph count is a fact about the layout, not about the document: the
 * same letter arrives as six paragraphs with its blank lines and as sixteen
 * without them. A construction preliminary notice is required by statute to be
 * addressed to the owner AND the construction lender — two address blocks over
 * a letterhead, a delivery legend, and a date — so an Ohio Notice of
 * Furnishing reached its "Re:" line at paragraph sixteen when double-spaced,
 * and lost the title it had routed on in its original layout.
 */
describe("titleCorpus — a letter with two address blocks", () => {
  const LETTERHEAD = [
    "TALLOW RIDGE COMPONENTS, LLC",
    "1180 Foundry Road",
    "Grand Rapids, Michigan 49503",
    "(616) 555-0177",
    "CERTIFIED MAIL, RETURN RECEIPT REQUESTED",
    "AND FIRST-CLASS MAIL",
    "April 14, 2026",
    "Kestrel Development Partners, LLC",
    "Attn: Marisol Trent, Manager",
    "1400 Foundry Road",
    "Akron, Ohio 44305",
    "Northbridge Savings Bank, as Construction Lender",
    "Attn: Loan Administration",
    "88 Superior Avenue",
    "Cleveland, Ohio 44114",
  ];

  it("reaches the subject line past two address blocks", () => {
    const tree = buildTree([
      "",
      ...LETTERHEAD,
      "Re: Notice of Furnishing — Kestrel Plant 3 Expansion",
      "To the Owner and the Lender:",
    ] as [string, ...string[]]);
    expect(titleCorpus(tree, "letter.txt")).toContain("Notice of Furnishing");
  });

  // The character bound is what keeps the window off the body however the
  // lines were laid out: a "Re:" that only appears after a page of prose is a
  // quoted piece of correspondence, not this document's own subject.
  it("does not reach a subject line buried under a page of body prose", () => {
    const body = Array.from(
      { length: 12 },
      (_, i) =>
        `${i + 1}. The parties acknowledge that the foregoing recitals are incorporated by reference and made a part of this Agreement for all purposes, and that each of them has had the opportunity to consult counsel.`,
    );
    const tree = buildTree([
      "",
      ...body,
      "Re: Notice of Furnishing — Kestrel Plant 3 Expansion",
    ] as [string, ...string[]]);
    expect(titleCorpus(tree, "letter.txt")).not.toContain("Notice of Furnishing");
  });
});

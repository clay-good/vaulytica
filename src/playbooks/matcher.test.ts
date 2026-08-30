import { describe, expect, it } from "vitest";
import { matchPlaybook } from "./matcher.js";
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

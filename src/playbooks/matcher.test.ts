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

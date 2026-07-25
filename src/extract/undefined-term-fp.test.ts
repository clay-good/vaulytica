import { describe, expect, it } from "vitest";
import { extractDefinitions } from "./definitions.js";
import { buildTree } from "./_fixtures.js";

// STRUCT-006 flags a Title-Case phrase used >= 2x that is never defined. Proper
// nouns, government bodies, and terms of art need no definition — flagging them
// tells the drafter to define the SEC. Each phrase is used twice here.
const SHOULD_NOT_FLAG: Array<[phrase: string, sentence: string]> = [
  [
    "Securities and Exchange Commission",
    "The Company files with the Securities and Exchange Commission. The Securities and Exchange Commission reviews it.",
  ],
  [
    "Internal Revenue Service",
    "Notice goes to the Internal Revenue Service. The Internal Revenue Service responds.",
  ],
  [
    "Board of Directors",
    "The Board of Directors approves. The Board of Directors meets quarterly.",
  ],
  ["Force Majeure", "A Force Majeure excuses performance. Each Force Majeure is notified."],
  ["Federal Reserve", "The Federal Reserve sets rates. The Federal Reserve publishes them."],
  [
    "New York Stock Exchange",
    "Shares list on the New York Stock Exchange. The New York Stock Exchange approves listings.",
  ],
  [
    "Generally Accepted Accounting Principles",
    "Statements follow Generally Accepted Accounting Principles. Generally Accepted Accounting Principles apply.",
  ],
  ["Court of Chancery", "Heard in the Court of Chancery. The Court of Chancery rules."],
  [
    "Department of Justice",
    "Referred to the Department of Justice. The Department of Justice investigates.",
  ],
  ["European Union", "Data stays in the European Union. The European Union oversees it."],
  [
    "Standard Contractual Clauses",
    "The Standard Contractual Clauses apply. These Standard Contractual Clauses bind the parties.",
  ],
  [
    "National Labor Relations Board",
    "The National Labor Relations Board ruled. A National Labor Relations Board order issued.",
  ],
  ["United Nations", "The United Nations convened. The United Nations resolved it."],
  ["Supreme Court", "The Supreme Court held so. The Supreme Court affirmed."],
  ["Great Britain", "Operations moved to Great Britain. Great Britain regulates them."],
];

describe("STRUCT-006 undefined-term FP guard", () => {
  for (const [phrase, sentence] of SHOULD_NOT_FLAG) {
    it(`does not flag: ${phrase}`, () => {
      const flagged = extractDefinitions(buildTree(["Body", sentence])).undefined_capitalized.map(
        (e) => e.term,
      );
      expect(flagged, `FALSE UNDEFINED: ${phrase}; got ${JSON.stringify(flagged)}`).not.toContain(
        phrase,
      );
    });
  }

  it("positive control: an invented Title-Case term used twice IS flagged", () => {
    const flagged = extractDefinitions(
      buildTree([
        "Body",
        "The Frobnicator Widget ships today. Each Frobnicator Widget is inspected.",
      ]),
    ).undefined_capitalized.map((e) => e.term);
    expect(flagged).toContain("Frobnicator Widget");
  });
});

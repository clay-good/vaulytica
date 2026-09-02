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

/**
 * A Title-Case phrase HEADED BY AN ACRONYM is one phrase. `TITLE_CASE_PHRASE`
 * cannot cross an all-caps word, so the capture starts one word in and names
 * something the document never wrote: an AI policy that maintains an "AI Tool
 * Register" was told it uses "Tool Register" without defining it.
 */
const ACRONYM_HEADED: Array<[string, string]> = [
  [
    "Tool Register",
    "Only a tool on the AI Tool Register may be used. The AI Tool Register is kept current.",
  ],
  ["Service Desk", "Requests go to the IT Service Desk. The IT Service Desk triages them."],
  ["Business Partner", "Ask the HR Business Partner. The HR Business Partner responds."],
  ["Advisory Committee", "The FDA Advisory Committee met. The FDA Advisory Committee voted."],
  [
    "Information Security",
    "Signed by the CISO Information Security lead. The CISO Information Security lead reviews it.",
  ],
];

describe("a phrase headed by an acronym is not a term the document forgot to define", () => {
  for (const [truncation, sentence] of ACRONYM_HEADED) {
    it(`does not flag: ${truncation}`, () => {
      const flagged = extractDefinitions(buildTree(["Body", sentence])).undefined_capitalized.map(
        (e) => e.term,
      );
      expect(
        flagged,
        `FALSE UNDEFINED: "${truncation}" is the tail of a longer acronym-headed phrase; got ${JSON.stringify(flagged)}`,
      ).not.toContain(truncation);
    });
  }

  /**
   * The guard must not swallow a phrase that merely FOLLOWS an all-caps
   * drafting connective — those precede unrelated Title-Case phrases.
   */
  it("still flags a term that follows an all-caps drafting connective", () => {
    const flagged = extractDefinitions(
      buildTree([
        "Body",
        "WHEREAS Frobnicator Widget is scarce; and WHEREAS Frobnicator Widget is needed.",
      ]),
    ).undefined_capitalized.map((e) => e.term);
    expect(flagged).toContain("Frobnicator Widget");
  });
});

/**
 * A sentence-initial participle or conjunction followed by a defined term is
 * a clause ABOUT that term, not a two-word term of its own. An owner-architect
 * agreement paces its phases with "Following Owner's written approval ..." and
 * was told it uses an undefined "Following Owner".
 */
describe("a sentence-initial connective does not head a defined term", () => {
  const CASES: Array<[string, string]> = [
    [
      "Following Owner",
      "Following Owner's approval, Architect proceeds. Following Owner's approval, work starts.",
    ],
    ["Unless Buyer", "Unless Buyer objects, the goods ship. Unless Buyer objects, title passes."],
    ["Prior Landlord", "Prior Landlord consent is needed. Prior Landlord consent was given."],
    [
      "Effective Tenant",
      "Effective Tenant occupancy begins in May. Effective Tenant occupancy ends in June.",
    ],
  ];
  for (const [phrase, sentence] of CASES) {
    it(`does not flag: ${phrase}`, () => {
      const flagged = extractDefinitions(buildTree(["Body", sentence])).undefined_capitalized.map(
        (e) => e.term,
      );
      expect(flagged, `FALSE UNDEFINED: ${phrase}; got ${JSON.stringify(flagged)}`).not.toContain(
        phrase,
      );
    });
  }
});

/**
 * A spelled-out amount is a number, not a term the drafter forgot to define.
 *
 * "Fifty Thousand Dollars ($50,000)" writes the figure twice so the words and
 * the digits check each other, and the words are Title Case for exactly the
 * reason a defined term is. The fixture corpus writes its amounts in digits,
 * so this was invisible until the corpus was rewritten in the convention every
 * real contract uses — and a golden fixture was already carrying the finding
 * for "Two Million Dollars", unread.
 */
describe("a spelled-out amount", () => {
  const flagged = (...paras: string[]) =>
    extractDefinitions(buildTree(["Agreement", ...paras])).undefined_capitalized.map((e) => e.term);

  it.each([
    [
      "Fifty Thousand Dollars",
      "Client shall pay Fifty Thousand Dollars ($50,000) on the Effective Date.",
    ],
    [
      "Two Million Dollars",
      "Vendor shall carry liability insurance of Two Million Dollars ($2,000,000) per occurrence.",
    ],
    ["Twenty-Five Percent", "The holdback is Twenty-Five Percent (25%) of the Purchase Price."],
  ])("is not reported as an undefined term: %s", (term, sentence) => {
    expect(flagged(sentence, sentence)).not.toContain(term);
  });

  // Load-bearing: a real term that merely OPENS with a number word still reports.
  it("still reports a term that only begins with a number word", () => {
    expect(
      flagged(
        "The Second Closing occurs on the Milestone Date.",
        "Buyer shall fund the Second Closing in full.",
      ),
    ).toContain("Second Closing");
  });
});

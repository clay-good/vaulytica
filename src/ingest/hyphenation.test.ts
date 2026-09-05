import { describe, expect, it } from "vitest";
import { documentVocabulary, joinWrappedLines } from "./hyphenation.js";

describe("documentVocabulary", () => {
  it("splits a hyphenated compound into its halves, never the joined form", () => {
    // The joined form can only be evidence when the document really writes it
    // as one word somewhere — otherwise "non-disclosure" would vouch for
    // "nondisclosure" and every compound would be de-hyphenated.
    const v = documentVocabulary("This non-disclosure agreement is Confidential.");
    expect(v.has("non")).toBe(true);
    expect(v.has("disclosure")).toBe(true);
    expect(v.has("nondisclosure")).toBe(false);
    expect(v.has("confidential")).toBe(true);
  });
});

describe("joinWrappedLines", () => {
  const vocab = documentVocabulary(
    "The Confidential Information of the Disclosing Party. A month-to-month term. Non-disclosure applies.",
  );

  it("drops the hyphen when the document uses the joined word elsewhere", () => {
    expect(joinWrappedLines(["The Confiden-", "tial Information"], vocab)).toBe(
      "The Confidential Information",
    );
  });

  it("keeps the hyphen of a compound the document does not write as one word", () => {
    // "nondisclosure" appears nowhere, so the hyphen was the drafter's.
    expect(joinWrappedLines(["A non-", "disclosure duty"], vocab)).toBe("A non-disclosure duty");
    expect(joinWrappedLines(["a month-to-", "month term"], vocab)).toBe("a month-to-month term");
  });

  it("keeps the hyphen when there is no evidence either way", () => {
    // The conservative default, and the behaviour that shipped before this
    // module existed: nothing joins on a guess about English.
    expect(
      joinWrappedLines(["An obliga-", "tion arises"], documentVocabulary("nothing here")),
    ).toBe("An obliga-tion arises");
  });

  it("joins ordinary lines with a single space", () => {
    expect(joinWrappedLines(["the parties", "agree that"], vocab)).toBe("the parties agree that");
  });

  it("does not join across a line starting with a capital", () => {
    // A hyphen before a capitalized word is a compound ("Third-Party" split by
    // the wrapper keeps its shape), never a syllable break.
    expect(joinWrappedLines(["a Third-", "Party claim"], vocab)).toBe("a Third-Party claim");
  });

  it("returns a single line unchanged", () => {
    expect(joinWrappedLines(["one line only"], vocab)).toBe("one line only");
    expect(joinWrappedLines([], vocab)).toBe("");
  });
});

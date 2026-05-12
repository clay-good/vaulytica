import { describe, expect, it } from "vitest";
import { tokenize, parseStopwordList, loadStopwords } from "./tokenize.js";

describe("tokenize", () => {
  const stops = new Set(["the", "shall", "of"]);

  it("lowercases, splits on punctuation, drops stopwords and short tokens", () => {
    const out = tokenize("The Parties shall comply with the Terms of Service.", stops);
    expect(out).toEqual(["parties", "comply", "with", "terms", "service"]);
  });

  it("drops pure digit tokens but keeps alphanumerics", () => {
    expect(tokenize("Section 4.2 v2 of the agreement", stops)).toEqual([
      "section",
      "v2",
      "agreement",
    ]);
  });

  it("returns [] for empty input", () => {
    expect(tokenize("", stops)).toEqual([]);
  });
});

describe("parseStopwordList", () => {
  it("ignores comments and blank lines", () => {
    const s = parseStopwordList("# header\n\nshall\nparty\n  # indented\n");
    expect(s.has("shall")).toBe(true);
    expect(s.has("party")).toBe(true);
    expect(s.size).toBe(2);
  });
});

describe("loadStopwords", () => {
  it("reads the committed stopwords.txt and includes contract-specific entries", async () => {
    const s = await loadStopwords();
    expect(s.has("shall")).toBe(true);
    expect(s.has("hereof")).toBe(true);
    expect(s.has("the")).toBe(true);
  });
});

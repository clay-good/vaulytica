import { describe, expect, it } from "vitest";
import { classify, cosineScore, trainTfIdf } from "./tfidf.js";

const stops = new Set(["the", "shall", "of", "and", "is", "a", "to", "by", "in"]);

describe("trainTfIdf", () => {
  const examples = [
    { category: "governing-law", text: "This agreement is governed by the laws of Delaware." },
    { category: "governing-law", text: "Governed by the laws of the State of New York." },
    { category: "term", text: "The term of this agreement is two years." },
    { category: "term", text: "The initial term is one year, renewing annually." },
    { category: "indemnification", text: "Each party shall indemnify and hold the other harmless." },
  ];

  it("returns one entry per category, alphabetically sorted", () => {
    const out = trainTfIdf(examples, { stopwords: stops });
    expect(out.map((c) => c.category)).toEqual(["governing-law", "indemnification", "term"]);
  });

  it("the governing-law vocab includes signature tokens like 'laws' and 'governed'", () => {
    const out = trainTfIdf(examples, { stopwords: stops });
    const gl = out.find((c) => c.category === "governing-law")!;
    expect(Object.keys(gl.terms)).toEqual(expect.arrayContaining(["laws", "governed"]));
  });

  it("is byte-stable: identical inputs produce identical vocab JSON", () => {
    const a = JSON.stringify(trainTfIdf(examples, { stopwords: stops }));
    const b = JSON.stringify(trainTfIdf(examples, { stopwords: stops }));
    expect(a).toBe(b);
  });

  it("respects top_k cap", () => {
    const out = trainTfIdf(examples, { stopwords: stops, top_k: 2 });
    for (const v of out) expect(Object.keys(v.terms).length).toBeLessThanOrEqual(2);
  });
});

describe("classify (cosine score)", () => {
  const examples = [
    { category: "governing-law", text: "Governed by the laws of Delaware Delaware laws Delaware." },
    { category: "term", text: "The term is two years two years." },
  ];

  it("picks the right category for clearly-signal text", () => {
    const vocab = trainTfIdf(examples, { stopwords: stops });
    const r = classify("This agreement is governed by Delaware laws.", vocab, stops);
    expect(r?.category).toBe("governing-law");
    expect(r?.confidence).toBeGreaterThan(0);
  });

  it("returns undefined for empty token streams", () => {
    const vocab = trainTfIdf(examples, { stopwords: stops });
    expect(classify("", vocab, stops)).toBeUndefined();
  });

  it("breaks ties alphabetically by category name", () => {
    const v1 = { category: "alpha", terms: { foo: 1 } };
    const v2 = { category: "beta", terms: { foo: 1 } };
    const r = classify("foo foo", [v1, v2], new Set());
    expect(r?.category).toBe("alpha");
  });

  it("cosineScore is 0 when no terms overlap", () => {
    expect(cosineScore(["bar"], { category: "x", terms: { foo: 1 } })).toBe(0);
  });
});

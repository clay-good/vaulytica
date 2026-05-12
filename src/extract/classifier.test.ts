import { describe, expect, it } from "vitest";
import { classifyClauses, type ClassifierData } from "./classifier.js";
import { buildTree } from "./_fixtures.js";

describe("classifyClauses", () => {
  it("labels every paragraph 'unclassified' when no DKB data is supplied", () => {
    const tree = buildTree(["H", "Some clause text.", "Another paragraph."]);
    const labels = classifyClauses(tree);
    expect(labels).toHaveLength(2);
    expect(labels.every((l) => l.category === "unclassified")).toBe(true);
  });

  it("applies regex pattern overlay with case-insensitive match", () => {
    const data: ClassifierData = {
      patterns: [
        {
          category: "governing-law",
          pattern: "governing\\s+law",
          confidence: 0.99,
        },
      ],
    };
    const tree = buildTree(["H", "Governing Law. This is the governing law section."]);
    const labels = classifyClauses(tree, data);
    expect(labels[0]!.category).toBe("governing-law");
    expect(labels[0]!.method).toBe("pattern");
    expect(labels[0]!.confidence).toBeCloseTo(0.99);
  });

  it("falls back to TF-IDF cosine similarity above threshold", () => {
    const data: ClassifierData = {
      vocab: {
        threshold: 0.05,
        vocab: {
          indemnification: { indemnify: 0.6, harmless: 0.5, claims: 0.3 },
          confidentiality: { confidential: 0.7, secret: 0.4 },
        },
      },
    };
    const tree = buildTree([
      "H",
      "The provider shall indemnify and hold the customer harmless against claims.",
    ]);
    const labels = classifyClauses(tree, data);
    expect(labels[0]!.category).toBe("indemnification");
    expect(labels[0]!.method).toBe("tfidf");
  });

  it("breaks ties alphabetically by category name", () => {
    const data: ClassifierData = {
      vocab: {
        threshold: 0,
        vocab: {
          zebra: { word: 1 },
          alpha: { word: 1 },
        },
      },
    };
    const tree = buildTree(["H", "word word word"]);
    const labels = classifyClauses(tree, data);
    // Cosines are equal → alphabetical tiebreaker → "alpha"
    expect(labels[0]!.category).toBe("alpha");
  });
});

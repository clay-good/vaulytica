import { describe, expect, it } from "vitest";
import { loadCorpus } from "./corpus.js";

describe("corpus loader (spec-v5 §4, §7)", () => {
  it("loads the committed seed corpus without throwing", async () => {
    const corpus = await loadCorpus();
    expect(corpus.version).toBe("v0.0.0-seed");
    // Seed state: scaffolding only, zero real documents.
    expect(corpus.documents).toEqual([]);
    expect(corpus.manifest?.corpus_version).toBe("v0.0.0-seed");
  });
});

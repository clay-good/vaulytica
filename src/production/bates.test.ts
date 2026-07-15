import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { parseBates, extractBatesSet } from "./bates.js";

describe("parseBates", () => {
  it("parses prefix + underscore + zero-padded number", () => {
    expect(parseBates("ACME_000123.pdf")).toEqual({
      raw: "ACME_000123",
      prefix: "ACME",
      number: 123,
      padding: 6,
      filename: "ACME_000123.pdf",
    });
  });

  it("parses prefix + hyphen separator", () => {
    expect(parseBates("SMITH-00042.docx")).toEqual({
      raw: "SMITH-00042",
      prefix: "SMITH",
      number: 42,
      padding: 5,
      filename: "SMITH-00042.docx",
    });
  });

  it("parses with no separator between prefix and number", () => {
    expect(parseBates("ACME000123.pdf")).toEqual({
      raw: "ACME000123",
      prefix: "ACME",
      number: 123,
      padding: 6,
      filename: "ACME000123.pdf",
    });
  });

  it("parses filenames with no extension", () => {
    const parsed = parseBates("ACME_000005");
    expect(parsed?.prefix).toBe("ACME");
    expect(parsed?.number).toBe(5);
    expect(parsed?.padding).toBe(6);
  });

  it("returns null for a filename without a Bates-shaped number", () => {
    expect(parseBates("cover-letter.pdf")).toBeNull();
    expect(parseBates("notes.txt")).toBeNull();
  });

  it("requires at least 2 digits", () => {
    expect(parseBates("ACME_1.pdf")).toBeNull();
  });

  it("never throws on arbitrary input", () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(() => parseBates(s)).not.toThrow();
      }),
    );
  });
});

describe("extractBatesSet", () => {
  it("drops non-Bates filenames and sorts by prefix then number", () => {
    const result = extractBatesSet([
      "ACME_000003.pdf",
      "readme.txt",
      "ACME_000001.pdf",
      "ZETA_000001.pdf",
      "ACME_000002.pdf",
    ]);
    expect(result.map((b) => b.filename)).toEqual([
      "ACME_000001.pdf",
      "ACME_000002.pdf",
      "ACME_000003.pdf",
      "ZETA_000001.pdf",
    ]);
  });

  it("returns [] for an empty or all-non-Bates input", () => {
    expect(extractBatesSet([])).toEqual([]);
    expect(extractBatesSet(["a.pdf", "b.pdf"])).toEqual([]);
  });

  it("never throws on arbitrary input arrays", () => {
    fc.assert(
      fc.property(fc.array(fc.string()), (arr) => {
        expect(() => extractBatesSet(arr)).not.toThrow();
      }),
    );
  });
});

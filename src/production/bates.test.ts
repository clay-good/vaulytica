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

describe("parseBates — range filenames", () => {
  it("reads a prefix + start-end range as one member spanning the range", () => {
    expect(parseBates("ACME_000123-000145.pdf")).toEqual({
      raw: "ACME_000123-000145",
      prefix: "ACME",
      number: 123,
      end_number: 145,
      padding: 6,
      filename: "ACME_000123-000145.pdf",
    });
  });

  it("keeps the prefix clean so ranged members still group together", () => {
    // The whole point: the old parse produced prefix "ACME_000123" for the
    // first file and "ACME_000146" for the second, so each landed in its own
    // singleton group and no cross-member sequence check could ever run.
    const set = extractBatesSet(["ACME_000123-000145.pdf", "ACME_000146-000167.pdf"]);
    expect(set.map((b) => b.prefix)).toEqual(["ACME", "ACME"]);
    expect(set.map((b) => b.number)).toEqual([123, 146]);
    expect(set.map((b) => b.end_number)).toEqual([145, 167]);
  });

  it("accepts an en-dash separator and a single-page range", () => {
    expect(parseBates("ACME_000123–000145.pdf")?.end_number).toBe(145);
    expect(parseBates("ACME_000123-000123.pdf")?.end_number).toBe(123);
  });

  it("does not read an ordinary hyphenated Bates id as a range", () => {
    expect(parseBates("SMITH-00042.docx")?.end_number).toBeUndefined();
  });

  it("does not read a descending pair as a range", () => {
    // "INV-2024-0001" is invoice numbering, not Bates 2024 through 1. Reading
    // it as a range would credit the member with covering 2,024 numbers and
    // hide every real gap underneath.
    const parsed = parseBates("INV-2024-0001.pdf");
    expect(parsed?.end_number).toBeUndefined();
    expect(parsed?.prefix).toBe("INV-2024");
  });

  it("does not read a mismatched-width pair as a range", () => {
    // Both halves of a real range are padded to the same width; unequal
    // widths mean the hyphen is part of the identifier, not a separator.
    expect(parseBates("ACME_000123-45.pdf")?.end_number).toBeUndefined();
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

import { describe, expect, it } from "vitest";
import { dropLegends } from "./legends.js";

describe("dropLegends — EDGAR's document header", () => {
  it("drops the type, sequence and file name, one to a line", () => {
    expect(
      dropLegends(["EX-10.1", "2", "acme_ex10-1.htm", "EXECUTION VERSION", "CREDIT AGREEMENT"]),
    ).toEqual(["CREDIT AGREEMENT"]);
  });

  it("drops a description that only repeats the type code", () => {
    expect(
      dropLegends(["EX-10.1", "2", "acme_ex10-1.htm", "EX-10.1", "Exhibit 10.1", "WARRANT"]),
    ).toEqual(["WARRANT"]);
  });

  it("keeps a description that names the document", () => {
    expect(
      dropLegends(["EX-10.2", "3", "acme_ex10-2.htm", "FORM OF NEW WARRANT", "Exhibit 10.2"]),
    ).toEqual(["FORM OF NEW WARRANT", "Exhibit 10.2"]);
  });

  it("reads the header copied from a browser, on one line", () => {
    expect(dropLegends(["EX-10.1 2 acme_ex10-1.htm EXHIBIT 10.1", "CREDIT AGREEMENT"])).toEqual([
      "CREDIT AGREEMENT",
    ]);
    expect(dropLegends(["EX-10.3A 4 acme.htm FORM OF WARRANT", "Body."])).toEqual([
      "FORM OF WARRANT",
      "Body.",
    ]);
  });

  it("leaves a document that merely opens on a number alone", () => {
    expect(dropLegends(["2", "CREDIT AGREEMENT"])).toEqual(["2", "CREDIT AGREEMENT"]);
    expect(dropLegends(["notes.txt", "CREDIT AGREEMENT"])).toEqual([
      "notes.txt",
      "CREDIT AGREEMENT",
    ]);
  });
});

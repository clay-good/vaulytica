import { describe, expect, it } from "vitest";
import { rule as IPDATA_004 } from "./IPDATA-004.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-004 — the standard ownership formulation", () => {
  // "Customer owns all right, title, and interest in and to Customer Data" is
  // the single most common way a contract allocates data ownership, and the
  // "owns … data" branch could not read it: after "owns all" comes "right".
  it("reads 'owns all right, title, and interest in and to Customer Data'", () => {
    expect(
      IPDATA_004.check(
        buildContext([
          "Ownership",
          "As between the parties, Customer owns all right, title, and interest in and to Customer Data and any Output generated from it.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when the contract names Customer Data and allocates nothing", () => {
    expect(
      IPDATA_004.check(
        buildContext([
          "Services",
          "Vendor shall process Customer Data solely to provide the Services.",
        ]),
      ),
    ).not.toBeNull();
  });
  // v1.4.0 — a section HEADED "Customer Data" allocates it in the words
  // "Customer retains all right, title and interest in data Customer submits",
  // and requiring the qualifier again in the allocating sentence reported a
  // cloud services agreement's own ownership clause as unaddressed.
  it("reads the right-title-and-interest form over the bare noun 'data'", () => {
    expect(
      IPDATA_004.check(
        buildContext([
          "Customer Data",
          "Customer retains all right, title and interest in data Customer submits to the Service.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires where nothing allocates ownership of the Customer Data", () => {
    expect(
      IPDATA_004.check(
        buildContext([
          "Customer Data",
          "Provider will process Customer Data in accordance with its documentation.",
        ]),
      ),
    ).not.toBeNull();
  });
});

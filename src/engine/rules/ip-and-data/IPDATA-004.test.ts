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
});

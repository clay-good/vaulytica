import { describe, expect, it } from "vitest";
import { rule as IPDATA_002 } from "./IPDATA-002.js";
import { buildContext } from "../../_test-fixtures.js";

const ASSIGN =
  "Employee hereby assigns to the Company all intellectual property created during employment.";
const doc = (carveout = "") => buildContext(["IP Assignment", `${ASSIGN} ${carveout}`.trim()]);

describe("IPDATA-002 — pre-existing IP carve-out", () => {
  it("warns when an IP assignment states no carve-out", () => {
    expect(IPDATA_002.check(doc())).not.toBeNull();
  });

  it("recognizes the common carve-out vocabularies, not only 'pre-existing IP' (v1.1.0)", () => {
    for (const carveout of [
      "Pre-existing IP is excluded from this assignment.",
      "Background IP of each party is carved out.",
      "This assignment does not apply to Prior Inventions listed on Exhibit A.",
      "Background Technology and Background Materials are excluded.",
      "Each party's Retained IP remains its own.",
      "Existing Intellectual Property of the Employee is not assigned.",
    ]) {
      expect(IPDATA_002.check(doc(carveout)), carveout).toBeNull();
    }
  });

  it("does not treat a temporal 'prior to the date' as a carve-out", () => {
    // "created prior to the date" is not a carve-out — the rule still warns.
    expect(
      IPDATA_002.check(doc("All inventions created prior to the date are also covered.")),
    ).not.toBeNull();
  });
});

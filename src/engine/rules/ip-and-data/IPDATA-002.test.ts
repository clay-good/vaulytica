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

  // The carve-out is almost always its OWN SECTION — "Limited Exclusion",
  // "Prior Inventions" — sitting after the assignment it qualifies, and the
  // paragraph-scoped test could never see it.
  it("reads a carve-out that sits in a later section (v1.2.0)", () => {
    const ctx = buildContext([
      "4. Assignment of Inventions",
      "I assign to the Company every invention and item of intellectual property that I conceive during my employment.",
      "6. Prior Inventions",
      "Attached as Exhibit A is a list of prior inventions I made before my employment that I wish to exclude from section 4.",
    ]);
    expect(IPDATA_002.check(ctx)).toBeNull();
  });
});

/**
 * The carve-out names what the assignor keeps, and it keeps TOOLS. A clean
 * contractor agreement — "Contractor retains ownership of its pre-existing
 * tools and know-how and grants Company a non-exclusive … license" — was told
 * it states no carve-out, because "tools" was not a noun the rule knew and
 * "know-how" sat after "tools and" rather than directly after "pre-existing".
 */
describe("IPDATA-002 — a coordinated carve-out", () => {
  const assign =
    "To the extent any Deliverable is not a work made for hire, Contractor assigns to Company all right, title, and interest in it, including all intellectual property rights.";

  it.each([
    "Contractor retains ownership of its pre-existing tools and know-how and grants Company a non-exclusive license to use any of them incorporated into a Deliverable.",
    "Consultant keeps its pre-existing software, templates, and components.",
  ])("is silent on %s", (carveOut) => {
    expect(IPDATA_002.check(buildContext(["Intellectual Property", assign, carveOut]))).toBeNull();
  });

  it("still fires on an assignment that keeps nothing back", () => {
    expect(
      IPDATA_002.check(
        buildContext(["Intellectual Property", assign, "Contractor shall use its own tools."]),
      ),
    ).not.toBeNull();
  });
});

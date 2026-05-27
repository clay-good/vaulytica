import { describe, expect, it } from "vitest";
import { V3_FAMILY_LABELS, familyDisplayLabel } from "./v3-labels.js";
import { FAMILY_TO_PLAYBOOK } from "./v3/auto-detect.js";

describe("V3_FAMILY_LABELS", () => {
  it("covers every non-unknown family id exported from detectV3Family", () => {
    // Drive the expected set from the auto-detect FAMILY_TO_PLAYBOOK
    // map directly rather than a hand-maintained list. If a new family
    // is added to V3Family without a corresponding entry in
    // V3_FAMILY_LABELS, this test now fails immediately rather than
    // silently passing (which it would have done against the prior
    // copy-pasted expected list).
    const expected = Object.keys(FAMILY_TO_PLAYBOOK).filter((k) => k !== "unknown");
    expect(expected.length).toBeGreaterThan(0);
    for (const f of expected) {
      expect(V3_FAMILY_LABELS[f], `missing label for v3 family "${f}"`).toBeTruthy();
    }
  });
});

describe("familyDisplayLabel", () => {
  it("returns the human label when family is known", () => {
    expect(familyDisplayLabel("baa", "BAA-playbook")).toMatch(/Business Associate/);
  });

  it("falls back to the playbook name when family is unknown", () => {
    expect(familyDisplayLabel("unknown", "Mutual NDA")).toBe("Mutual NDA");
  });

  it("falls back to the playbook name when family id is not in the table", () => {
    expect(familyDisplayLabel("brand-new-family-id", "Default")).toBe("Default");
  });
});

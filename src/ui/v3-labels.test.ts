import { describe, expect, it } from "vitest";
import { V3_FAMILY_LABELS, familyDisplayLabel } from "./v3-labels.js";

describe("V3_FAMILY_LABELS", () => {
  it("covers every non-unknown family id exported from detectV3Family", () => {
    // Every key in the auto-detect FAMILY_TO_PLAYBOOK except "unknown"
    // should have a human-readable label. If a new family is added to
    // the detector without a label, the chip would render the raw id.
    const expected = [
      "baa",
      "dpa-eu",
      "dpa-us-state",
      "scc-module-2",
      "scc-module-3",
      "uk-idta",
      "nda-deep",
      "msa-deep",
      "coi",
      "vendor-security",
      "ai-addendum",
    ];
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

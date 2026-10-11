import { describe, expect, it } from "vitest";
import {
  STATE_OVERLAYS,
  STATE_OVERLAY_COVERAGE,
  StateOverlaySchema,
  overlayFamilyForPlaybook,
  selectStateOverlays,
} from "./state-overlays.js";
import type { JurisdictionReference } from "../extract/types.js";

const gov = (raw: string, jurisdiction_id?: string): JurisdictionReference => ({
  clause_kind: "governing-law",
  raw_text: raw,
  jurisdiction_id,
  position: { section_id: "s1", start: 0, end: raw.length },
});

describe("state-overlay catalog (spec-v6 Part VI §21, Step 101)", () => {
  it("every entry validates against the schema", () => {
    for (const o of STATE_OVERLAYS) {
      expect(() => StateOverlaySchema.parse(o), o.id).not.toThrow();
    }
  });

  it("overlay ids are unique", () => {
    const ids = STATE_OVERLAYS.map((o) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("at most one overlay per (family, state)", () => {
    const seen = new Set<string>();
    for (const o of STATE_OVERLAYS) {
      const key = `${o.family}:${o.jurisdiction}`;
      expect(seen.has(key), key).toBe(false);
      seen.add(key);
    }
  });

  it("coverage count is honest (matches distinct states per family)", () => {
    for (const [family, count] of STATE_OVERLAY_COVERAGE) {
      const distinct = new Set(
        STATE_OVERLAYS.filter((o) => o.family === family).map((o) => o.jurisdiction),
      );
      expect(count).toBe(distinct.size);
    }
    // The catalog ships all three §21 families and broadens beyond CA/NY/TX/FL/IL.
    expect(STATE_OVERLAY_COVERAGE.get("employment")).toBeGreaterThanOrEqual(10);
    expect(STATE_OVERLAY_COVERAGE.get("residential-lease")).toBeGreaterThanOrEqual(10);
    expect(STATE_OVERLAY_COVERAGE.get("lending")).toBeGreaterThanOrEqual(10);
  });

  it("the catalog is a frozen, deterministic projection (two reads identical)", () => {
    expect(JSON.stringify(STATE_OVERLAYS)).toBe(JSON.stringify(STATE_OVERLAYS));
  });
});

describe("overlayFamilyForPlaybook", () => {
  it("maps employment, residential-lease, and lending playbooks", () => {
    expect(overlayFamilyForPlaybook("employment-at-will-us")).toBe("employment");
    expect(overlayFamilyForPlaybook("executive-employment")).toBe("employment");
    expect(overlayFamilyForPlaybook("employment-restrictive-covenant")).toBe("employment");
    expect(overlayFamilyForPlaybook("lease-residential-us")).toBe("residential-lease");
    expect(overlayFamilyForPlaybook("promissory-note")).toBe("lending");
    expect(overlayFamilyForPlaybook("loan-agreement")).toBe("lending");
  });

  it("selects the Texas sales-based financing node only under Texas law", () => {
    // spec-v49 §6: state law reaches a merchant cash advance through the
    // overlay, never as a check on every document of the family.
    expect(overlayFamilyForPlaybook("merchant-cash-advance")).toBe("sales-based-financing");
    const law = (raw_text: string) =>
      [{ clause_kind: "governing-law", raw_text }] as unknown as Parameters<
        typeof selectStateOverlays
      >[1];
    const tx = selectStateOverlays("merchant-cash-advance", law("State of Texas"));
    expect(tx?.matched.map((o) => o.id)).toEqual(["sbf-contract-terms-us-tx"]);
    expect(tx?.matched[0]?.citation.source).toContain("398.055");
    const ny = selectStateOverlays("merchant-cash-advance", law("State of New York"));
    expect(ny?.matched).toEqual([]);
    expect(ny?.uncovered_states).toEqual(["us-ny"]);
    // A loan under Texas law gets the usury node, not this one.
    const loan = selectStateOverlays("loan-agreement", law("State of Texas"));
    expect(loan?.matched.map((o) => o.id)).not.toContain("sbf-contract-terms-us-tx");
  });

  it("selects the California training-repayment node only under California law", () => {
    expect(overlayFamilyForPlaybook("training-repayment-agreement")).toBe("training-repayment");
    const law = (raw_text: string) =>
      [{ clause_kind: "governing-law", raw_text }] as unknown as Parameters<
        typeof selectStateOverlays
      >[1];
    const ca = selectStateOverlays("training-repayment-agreement", law("State of California"));
    expect(ca?.matched.map((o) => o.id)).toEqual(["trn-repayment-us-ca"]);
    // The statute as first enacted is inoperative for 2026; the node must say
    // which contracts it reaches.
    expect(ca?.matched[0]?.headline).toContain("January 1, 2027");
    const oh = selectStateOverlays("training-repayment-agreement", law("State of Ohio"));
    expect(oh?.matched).toEqual([]);
    // An employment agreement under California law gets the non-compete node.
    const emp = selectStateOverlays("employment-at-will-us", law("State of California"));
    expect(emp?.matched.map((o) => o.id)).toEqual(["emp-noncompete-us-ca"]);
  });

  it("selects the Texas buyer-agreement node only under Texas law", () => {
    expect(overlayFamilyForPlaybook("buyer-representation-agreement")).toBe("buyer-representation");
    const law = (raw_text: string) =>
      [{ clause_kind: "governing-law", raw_text }] as unknown as Parameters<
        typeof selectStateOverlays
      >[1];
    const tx = selectStateOverlays("buyer-representation-agreement", law("State of Texas"));
    expect(tx?.matched.map((o) => o.id)).toEqual(["buyer-rep-us-tx"]);
    expect(tx?.matched[0]?.citation.source).toContain("1101.563");
    expect(
      selectStateOverlays("buyer-representation-agreement", law("State of Georgia"))?.matched,
    ).toEqual([]);
    // The seller's listing agreement is a different document and gets nothing.
    expect(selectStateOverlays("listing-agreement", law("State of Texas"))).toBeUndefined();
  });

  it("selects the California pupil-records node only under California law", () => {
    expect(overlayFamilyForPlaybook("student-data-privacy-agreement")).toBe("student-data");
    const law = (raw_text: string) =>
      [{ clause_kind: "governing-law", raw_text }] as unknown as Parameters<
        typeof selectStateOverlays
      >[1];
    const ca = selectStateOverlays("student-data-privacy-agreement", law("State of California"));
    expect(ca?.matched.map((o) => o.id)).toEqual(["student-data-us-ca"]);
    expect(ca?.matched[0]?.citation.source).toContain("49073.1");
    expect(
      selectStateOverlays("student-data-privacy-agreement", law("State of Arizona"))?.matched,
    ).toEqual([]);
  });

  it("returns undefined for non-state-sensitive families", () => {
    expect(overlayFamilyForPlaybook("mutual-nda")).toBeUndefined();
    expect(overlayFamilyForPlaybook("ucc-1-financing-statement")).toBeUndefined();
  });

  it("does not apply residential deposit overlays to a commercial lease", () => {
    expect(overlayFamilyForPlaybook("lease-commercial-multitenant")).toBeUndefined();
  });
});

describe("selectStateOverlays", () => {
  it("returns undefined when the family has no overlays", () => {
    expect(selectStateOverlays("mutual-nda", [gov("California")])).toBeUndefined();
  });

  it("matches a covered employment governing-law state from raw text", () => {
    const r = selectStateOverlays("executive-employment", [gov("State of California")]);
    expect(r?.family).toBe("employment");
    expect(r?.matched.map((o) => o.id)).toEqual(["emp-noncompete-us-ca"]);
    expect(r?.matched[0]?.posture).toBe("prohibited");
    expect(r?.detected_states).toEqual(["us-ca"]);
    expect(r?.uncovered_states).toEqual([]);
  });

  it("normalizes 'Commonwealth of Massachusetts' and lending families", () => {
    const r = selectStateOverlays("loan-agreement", [gov("Commonwealth of Massachusetts")]);
    expect(r?.matched.map((o) => o.id)).toEqual(["lend-usury-us-ma"]);
  });

  it("matches a residential-lease deposit overlay", () => {
    const r = selectStateOverlays("lease-residential-us", [gov("New York")]);
    expect(r?.family).toBe("residential-lease");
    expect(r?.matched.map((o) => o.id)).toEqual(["lease-deposit-us-ny"]);
    expect(r?.matched[0]?.headline).toContain("1 month");
  });

  it("prefers a pre-normalized jurisdiction_id when present", () => {
    const r = selectStateOverlays("promissory-note", [gov("the laws of New York", "us-ny")]);
    expect(r?.matched.map((o) => o.id)).toEqual(["lend-usury-us-ny"]);
  });

  it("reports an uncovered state honestly rather than guessing", () => {
    // Montana has no non-compete overlay node → uncovered, never a wrong answer.
    const r = selectStateOverlays("executive-employment", [gov("Montana")]);
    expect(r?.matched).toEqual([]);
    expect(r?.detected_states).toEqual(["us-mt"]);
    expect(r?.uncovered_states).toEqual(["us-mt"]);
  });

  it("covers the 2025 statutory wave (Wyoming SF 107, Arkansas Act 232)", () => {
    const wy = selectStateOverlays("executive-employment", [gov("Wyoming")]);
    expect(wy?.matched.map((o) => o.id)).toEqual(["emp-noncompete-us-wy"]);
    expect(wy?.matched[0]?.summary).toContain("SF 107");
    const ar = selectStateOverlays("executive-employment", [gov("Arkansas")]);
    expect(ar?.matched.map((o) => o.id)).toEqual(["emp-noncompete-us-ar"]);
    expect(ar?.matched[0]?.summary).toContain("physician");
  });

  it("ignores venue / arbitration-seat clauses (governing law controls)", () => {
    const r = selectStateOverlays("executive-employment", [
      {
        clause_kind: "venue",
        raw_text: "California",
        position: { section_id: "s", start: 0, end: 1 },
      },
    ]);
    expect(r?.matched).toEqual([]);
    expect(r?.detected_states).toEqual([]);
  });

  it("deduplicates and sorts multiple governing-law references deterministically", () => {
    const r = selectStateOverlays("executive-employment", [
      gov("Texas"),
      gov("California"),
      gov("California"),
    ]);
    expect(r?.detected_states).toEqual(["us-ca", "us-tx"]);
    expect(r?.matched.map((o) => o.id)).toEqual(["emp-noncompete-us-ca", "emp-noncompete-us-tx"]);
  });

  it("is a pure function — two calls byte-identical", () => {
    const a = JSON.stringify(selectStateOverlays("loan-agreement", [gov("New York")]));
    const b = JSON.stringify(selectStateOverlays("loan-agreement", [gov("New York")]));
    expect(a).toBe(b);
  });
});

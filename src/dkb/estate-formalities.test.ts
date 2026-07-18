import { describe, expect, it } from "vitest";
import {
  ESTATE_FORMALITIES,
  ESTATE_FORMALITIES_STATE_COUNT,
  EstateFormalityOverlaySchema,
  US_STATE_CODES,
  estateFormalitiesForState,
  normalizeUsStateId,
} from "./estate-formalities.js";

describe("estate formalities catalog", () => {
  it("every node validates against the schema", () => {
    for (const node of ESTATE_FORMALITIES) {
      const parsed = EstateFormalityOverlaySchema.safeParse(node);
      expect(
        parsed.success,
        `${node.id}: ${JSON.stringify(parsed.success ? "" : parsed.error.issues)}`,
      ).toBe(true);
    }
  });

  it("ids are unique, sorted, and match their jurisdiction", () => {
    const ids = ESTATE_FORMALITIES.map((n) => n.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(ids);
    for (const node of ESTATE_FORMALITIES) {
      expect(node.id).toBe(`est-formalities-${node.jurisdiction}`);
    }
  });

  it("pins the verified seed facts (the anti-folk-wisdom corrections)", () => {
    // PA: no attesting witnesses for an ordinary signed will (20 Pa. C.S. § 2502).
    const pa = estateFormalitiesForState("us-pa")!;
    expect(pa.witnesses_expected).toBe(0);
    expect(pa.notarization_alternative).toBe(false);
    expect(pa.citation.source).toContain("2502");

    // LA: notarial testament — notary + 2 witnesses + per-page signatures.
    const la = estateFormalitiesForState("us-la")!;
    expect(la.notarial_testament).toBe(true);
    expect(la.witnesses_expected).toBe(2);
    expect(la.summary).toContain("each other separate page");
    expect(la.citation.source).toMatch(/157[67]/);

    // CO + ND: the only notarization-alternative adopters (UPC § 2-502(a)(3)(B) pattern).
    const adopters = ESTATE_FORMALITIES.filter((n) => n.notarization_alternative).map(
      (n) => n.jurisdiction,
    );
    expect(adopters).toEqual(["us-co", "us-nd"]);
    for (const j of adopters) {
      expect(estateFormalitiesForState(j)!.reasonable_time_phrasing).toBe(true);
    }

    // VT: reduced 3 → 2 witnesses; the resolved session-law citation is
    // 2005, No. 106 (Adj. Sess.) per the official annotated statute.
    const vt = estateFormalitiesForState("us-vt")!;
    expect(vt.witnesses_expected).toBe(2);
    expect(vt.citation.source).toContain("2005, No. 106 (Adj. Sess.)");
  });

  it("no state expects more than two attesting witnesses", () => {
    for (const node of ESTATE_FORMALITIES) {
      expect(node.witnesses_expected, node.id).toBeLessThanOrEqual(2);
    }
  });

  it("unverified holographic/e-will flags are omitted, never false-guessed", () => {
    // PA's holographic posture and every e-will flag were not primary-source
    // verified — honest N/A means the key is absent, not false.
    const pa = estateFormalitiesForState("us-pa")!;
    expect("holographic_recognized" in pa).toBe(false);
    for (const node of ESTATE_FORMALITIES) {
      expect("e_will_regime" in node, node.id).toBe(false);
    }
  });

  it("pins the high-traffic-state facts (CA, TX, NY, FL)", () => {
    // CA: 2 witnesses present at the same time; holographic per § 6111.
    const ca = estateFormalitiesForState("us-ca")!;
    expect(ca.witnesses_expected).toBe(2);
    expect(ca.holographic_recognized).toBe(true);
    expect(ca.citation.source).toContain("6110");

    // TX: 2+ credible witnesses age 14+; holographic per § 251.052.
    const tx = estateFormalitiesForState("us-tx")!;
    expect(tx.holographic_recognized).toBe(true);
    expect(tx.citation.source).toContain("251.051");

    // NY: 30-day window recital; holographic only for armed forces/mariners.
    const ny = estateFormalitiesForState("us-ny")!;
    expect(ny.holographic_recognized).toBe(false);
    expect(ny.summary).toContain("thirty-day");

    // FL: mutual-presence attestation; holographic NOT recognized.
    const fl = estateFormalitiesForState("us-fl")!;
    expect(fl.holographic_recognized).toBe(false);
    expect(fl.citation.source).toContain("732.502");
  });

  it("pins the second-wave facts (IL, MI, NJ, NC)", () => {
    // IL: 2+ credible witnesses in the testator's presence; NO holographic.
    const il = estateFormalitiesForState("us-il")!;
    expect(il.holographic_recognized).toBe(false);
    expect(il.reasonable_time_phrasing).toBe(false);
    expect(il.citation.source).toContain("4-3");

    // MI: UPC reasonable-time; holographic requires DATING (the MI addition).
    const mi = estateFormalitiesForState("us-mi")!;
    expect(mi.reasonable_time_phrasing).toBe(true);
    expect(mi.holographic_recognized).toBe(true);
    expect(mi.summary).toContain("DATED");

    // NJ: UPC reasonable-time; writing-intended-as-will holographic equivalent.
    const nj = estateFormalitiesForState("us-nj")!;
    expect(nj.reasonable_time_phrasing).toBe(true);
    expect(nj.holographic_recognized).toBe(true);

    // NC: attested in testator's presence; holographic per § 31-3.4.
    const nc = estateFormalitiesForState("us-nc")!;
    expect(nc.holographic_recognized).toBe(true);
    expect(nc.citation.source).toContain("31-3.3");
  });

  it("pins the third-wave facts (OH, AZ, WA)", () => {
    // OH: conscious-presence attestation; NO unwitnessed holographic.
    const oh = estateFormalitiesForState("us-oh")!;
    expect(oh.holographic_recognized).toBe(false);
    expect(oh.citation.source).toContain("2107.03");

    // AZ: UPC reasonable-time (verified verbatim); holographic per § 14-2503.
    const az = estateFormalitiesForState("us-az")!;
    expect(az.reasonable_time_phrasing).toBe(true);
    expect(az.holographic_recognized).toBe(true);

    // WA: attested by 2+ competent witnesses; holographic NOT recognized.
    const wa = estateFormalitiesForState("us-wa")!;
    expect(wa.holographic_recognized).toBe(false);
    expect(wa.citation.source).toContain("11.12.020");
  });

  it("returns undefined for unseeded states (honest N/A) and publishes the denominator", () => {
    expect(estateFormalitiesForState("us-wy")).toBeUndefined();
    expect(estateFormalitiesForState("us-ga")).toBeUndefined();
    expect(ESTATE_FORMALITIES_STATE_COUNT).toBe(ESTATE_FORMALITIES.length);
  });
});

describe("normalizeUsStateId", () => {
  it("accepts two-letter codes, any case, and the us- prefix", () => {
    expect(normalizeUsStateId("pa")).toBe("us-pa");
    expect(normalizeUsStateId("PA")).toBe("us-pa");
    expect(normalizeUsStateId(" us-La ")).toBe("us-la");
    expect(normalizeUsStateId("dc")).toBe("us-dc");
  });

  it("rejects unknown or malformed input", () => {
    expect(normalizeUsStateId("zz")).toBeUndefined();
    expect(normalizeUsStateId("pennsylvania")).toBeUndefined();
    expect(normalizeUsStateId("")).toBeUndefined();
  });

  it("covers the 50 states + DC exactly once", () => {
    expect(US_STATE_CODES.length).toBe(51);
    expect(new Set(US_STATE_CODES).size).toBe(51);
  });
});

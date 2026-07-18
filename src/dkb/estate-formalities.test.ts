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
    // PA's holographic posture and the e-will flags were not primary-source
    // verified — honest N/A means the key is absent, not false. Three
    // exceptions carry a verified flag: MD (2021 § 4-102(c)-(f) certified
    // wills), IN (IC 29-1-21, P.L. 40-2018), NV (NRS 133.085, added 2001,
    // amended 2017), and UT (Uniform Electronic Wills Act, §§ 75-2-1401 to
    // -1411, effective 2020-08-31).
    const pa = estateFormalitiesForState("us-pa")!;
    expect("holographic_recognized" in pa).toBe(false);
    const E_WILL_VERIFIED = new Set(["us-md", "us-in", "us-nv", "us-ut"]);
    for (const node of ESTATE_FORMALITIES) {
      if (E_WILL_VERIFIED.has(node.jurisdiction)) continue;
      expect("e_will_regime" in node, node.id).toBe(false);
    }
    for (const j of E_WILL_VERIFIED) {
      expect(estateFormalitiesForState(j)!.e_will_regime, j).toBe(true);
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

  it("pins the fourth-wave facts (GA, VA, MA, MD)", () => {
    // GA: 2+ competent witnesses (age 14+ per § 53-4-22); NO holographic.
    const ga = estateFormalitiesForState("us-ga")!;
    expect(ga.holographic_recognized).toBe(false);
    expect(ga.reasonable_time_phrasing).toBe(false);
    expect(ga.summary).toContain("14");
    expect(ga.citation.source).toContain("53-4-20");

    // VA: 2 witnesses present at the same time; holographic proved by
    // 2 disinterested witnesses at probate (§ 64.2-403(B)).
    const va = estateFormalitiesForState("us-va")!;
    expect(va.holographic_recognized).toBe(true);
    expect(va.reasonable_time_phrasing).toBe(false);
    expect(va.summary).toContain("disinterested");
    expect(va.citation.source).toContain("64.2-403");

    // MA: UPC with the flexibility stripped — no reasonable-time clause,
    // no holographic subsection, § 2-503 harmless error left "Reserved".
    const ma = estateFormalitiesForState("us-ma")!;
    expect(ma.holographic_recognized).toBe(false);
    expect(ma.reasonable_time_phrasing).toBe(false);
    expect(ma.summary).toContain("Reserved");
    expect(ma.citation.source).toContain("2-502");

    // MD: 2+ credible witnesses; holographic only for armed-services
    // testators signing abroad (§ 4-103); verified 2021 e-will regime.
    const md = estateFormalitiesForState("us-md")!;
    expect(md.holographic_recognized).toBe(false);
    expect(md.e_will_regime).toBe(true);
    expect(md.summary).toContain("armed services");
    expect(md.citation.source).toContain("4-102");
  });

  it("pins the fifth-wave facts (TN, MO, IN, WI)", () => {
    // TN: mutual presence + publication; holographic OK, handwriting
    // proved by 2 witnesses (§ 32-1-105).
    const tn = estateFormalitiesForState("us-tn")!;
    expect(tn.holographic_recognized).toBe(true);
    expect(tn.reasonable_time_phrasing).toBe(false);
    expect(tn.citation.source).toContain("32-1-104");

    // MO: pre-UPC strict presence; NO holographic.
    const mo = estateFormalitiesForState("us-mo")!;
    expect(mo.holographic_recognized).toBe(false);
    expect(mo.reasonable_time_phrasing).toBe(false);
    expect(mo.citation.source).toContain("474.320");

    // IN: mutual presence + publication; NO holographic; verified 2018
    // electronic-wills chapter (IC 29-1-21).
    const in_ = estateFormalitiesForState("us-in")!;
    expect(in_.holographic_recognized).toBe(false);
    expect(in_.e_will_regime).toBe(true);
    expect(in_.citation.source).toContain("29-1-5-3");

    // WI: the only fifth-wave UPC reasonable-time state; conscious-presence
    // witnessing; NO domestic holographic.
    const wi = estateFormalitiesForState("us-wi")!;
    expect(wi.reasonable_time_phrasing).toBe(true);
    expect(wi.holographic_recognized).toBe(false);
    expect(wi.citation.source).toContain("853.03");
  });

  it("pins the sixth-wave facts (MN, SC, AL, KY)", () => {
    // MN: pre-2008 UPC — reasonable time, no notary alternative, NO
    // holographic subsection; non-uniform conservator-signing option.
    const mn = estateFormalitiesForState("us-mn")!;
    expect(mn.reasonable_time_phrasing).toBe(true);
    expect(mn.holographic_recognized).toBe(false);
    expect(mn.summary).toContain("conservator");
    expect(mn.citation.source).toContain("524.2-502");

    // SC: UPC two-witness with the timing clause stripped; NO holographic.
    const sc = estateFormalitiesForState("us-sc")!;
    expect(sc.reasonable_time_phrasing).toBe(false);
    expect(sc.holographic_recognized).toBe(false);
    expect(sc.citation.source).toContain("62-2-502");

    // AL: pre-1990 UPC; holographic non-recognition verified. No Alabama
    // e-wills act could be evidenced, so e_will_regime stays omitted.
    const al = estateFormalitiesForState("us-al")!;
    expect(al.holographic_recognized).toBe(false);
    expect("e_will_regime" in al).toBe(false);
    expect(al.citation.source).toContain("43-8-131");

    // KY: wholly-handwritten wills need NO witnesses; otherwise 2 credible
    // witnesses in the presence of the testator AND each other.
    const ky = estateFormalitiesForState("us-ky")!;
    expect(ky.holographic_recognized).toBe(true);
    expect(ky.summary).toContain("each other");
    expect(ky.citation.source).toContain("394.040");
  });

  it("pins the seventh-wave facts (OK, CT, OR, NV)", () => {
    // OK: 1910 formalism — end placement + publication; holographic must
    // be DATED (84 O.S. § 54, the minority rule shared with NV).
    const ok = estateFormalitiesForState("us-ok")!;
    expect(ok.holographic_recognized).toBe(true);
    expect(ok.summary).toContain("DATED");
    expect(ok.citation.source).toContain("§§ 54, 55");

    // CT: single-sentence statute, two witnesses since 1971 (was three);
    // NO domestic holographic; same-sentence borrowing clause.
    const ct = estateFormalitiesForState("us-ct")!;
    expect(ct.holographic_recognized).toBe(false);
    expect(ct.summary).toContain("1971");
    expect(ct.citation.source).toContain("45a-251");

    // OR: reasonable time runs BEFORE death (2015 amendment), not the
    // UPC's after-witnessing window; e-wills expressly banned.
    const or_ = estateFormalitiesForState("us-or")!;
    expect(or_.reasonable_time_phrasing).toBe(true);
    expect(or_.holographic_recognized).toBe(false);
    expect(or_.summary).toContain("BEFORE the testator's death");
    expect(or_.citation.source).toContain("112.235");

    // NV: dated holographic (NRS 133.090) + the third verified e-will
    // regime (NRS 133.085, added 2001, amended 2017).
    const nv = estateFormalitiesForState("us-nv")!;
    expect(nv.holographic_recognized).toBe(true);
    expect(nv.e_will_regime).toBe(true);
    expect(nv.summary).toContain("DATE");
    expect(nv.citation.source).toContain("133.040");
  });

  it("pins the eighth-wave facts (UT, IA, AR, KS)", () => {
    // UT: 1990 UPC — reasonable time, holographic OK; NO notarization
    // alternative (the 1998 re-enactment predates the 2008 UPC option —
    // listings calling Utah a notarization state are wrong); fourth
    // verified e-will node (UEWA, effective 2020-08-31).
    const ut = estateFormalitiesForState("us-ut")!;
    expect(ut.reasonable_time_phrasing).toBe(true);
    expect(ut.holographic_recognized).toBe(true);
    expect(ut.notarization_alternative).toBe(false);
    expect(ut.e_will_regime).toBe(true);
    expect(ut.citation.source).toContain("75-2-502");

    // IA: mutual presence + publication; witnesses may be 16; NO
    // holographic; electronic real-time presence since 2023.
    const ia = estateFormalitiesForState("us-ia")!;
    expect(ia.holographic_recognized).toBe(false);
    expect(ia.summary).toContain("16");
    expect(ia.citation.source).toContain("633.279");

    // AR: publication + signature at the end; holographic proved by
    // THREE disinterested handwriting witnesses (§ 28-25-104).
    const ar = estateFormalitiesForState("us-ar")!;
    expect(ar.holographic_recognized).toBe(true);
    expect(ar.summary).toContain("three");
    expect(ar.citation.source).toContain("28-25-103");

    // KS: signed at the end, witnesses saw-or-heard; NO holographic;
    // oral deathbed wills for personalty survive (§ 59-608).
    const ks = estateFormalitiesForState("us-ks")!;
    expect(ks.holographic_recognized).toBe(false);
    expect(ks.summary).toContain("oral");
    expect(ks.citation.source).toContain("59-606");
  });

  it("pins the ninth-wave facts (NE, NM, WV, ID)", () => {
    // NE: pre-1990 UPC; holographic needs a handwritten DATE indication,
    // softened by the 1980 savings clause (§ 30-2328).
    const ne = estateFormalitiesForState("us-ne")!;
    expect(ne.holographic_recognized).toBe(true);
    expect(ne.summary).toContain("DATE OF SIGNING");
    expect(ne.citation.source).toContain("30-2327");

    // NM: strictest wave-9 posture — mutual presence, witnesses must see
    // the actual signing; "will" definitionally excludes holographs.
    const nm = estateFormalitiesForState("us-nm")!;
    expect(nm.holographic_recognized).toBe(false);
    expect(nm.reasonable_time_phrasing).toBe(false);
    expect(nm.summary).toContain("Reserved");
    expect(nm.citation.source).toContain("45-2-502");

    // WV: witnesses simultaneously present AND subscribing before each
    // other — the Virginia-derived pattern VA itself relaxed; wholly
    // handwritten wills fully excused.
    const wv = estateFormalitiesForState("us-wv")!;
    expect(wv.holographic_recognized).toBe(true);
    expect(wv.summary).toContain("PRESENT AT THE SAME TIME");
    expect(wv.citation.source).toContain("41-1-3");

    // ID: pre-1990 UPC, most permissive two-witness statute; § 51-109 is
    // a notarial proxy-signature, NOT a notarization alternative.
    const id_ = estateFormalitiesForState("us-id")!;
    expect(id_.holographic_recognized).toBe(true);
    expect(id_.notarization_alternative).toBe(false);
    expect(id_.citation.source).toContain("15-2-502");
  });

  it("returns undefined for unseeded states (honest N/A) and publishes the denominator", () => {
    expect(estateFormalitiesForState("us-wy")).toBeUndefined();
    expect(estateFormalitiesForState("us-ms")).toBeUndefined();
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

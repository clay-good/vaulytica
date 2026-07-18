/**
 * Per-state will-execution formalities overlay (add-estate-planning-pack
 * deferred task 3). Seeds the states the proposal names as the verified
 * corrections to the "two witnesses everywhere" folk rule:
 *
 *   - **PA** — no attesting witnesses for an ordinary signed will
 *     (20 Pa. C.S. § 2502: writing + testator's signature at the end;
 *     witnesses are required only for a signature by mark or by another
 *     person at the testator's direction).
 *   - **LA** — the notarial testament requires a notary AND two competent
 *     witnesses, with the testator signing at the end and on each other
 *     separate page, plus a prescribed attestation declaration
 *     (La. Civ. Code arts. 1576–1577); the olographic testament
 *     (art. 1575) is the handwritten alternative.
 *   - **CO / ND** — the UPC § 2-502(a) pattern as enacted: two witnesses
 *     signing "within a reasonable time", OR the will acknowledged by the
 *     testator before a notary public (the notarization alternative only
 *     these two states adopted); holographic wills recognized.
 *   - **VT** — two or more credible witnesses attesting in the presence
 *     of the testator and each other (14 V.S.A. § 5; the three-witness
 *     requirement was reduced to two by 2005, No. 106 (Adj. Sess.), § 1 —
 *     the session-law citation verified against the official annotated
 *     statute).
 *
 * Plus the four highest-traffic states, verified the same way: **CA**
 * (§§ 6110–6111: two witnesses present at the same time; holographic OK),
 * **TX** (§§ 251.051–.052: 2+ credible witnesses age 14+; holographic OK),
 * **NY** (EPTL §§ 3-2.1–3-2.2: two witnesses within one 30-day period,
 * signed at the end; holographic only for armed forces/mariners), and
 * **FL** (§ 732.502: mutual-presence attestation; holographic NOT
 * recognized, even for nonresident-executed wills).
 *
 * Honest-N/A discipline (same as `state-overlays.ts`): a state with no
 * node yields `undefined` — never a guessed answer — and the optional
 * `holographic_recognized` / `e_will_regime` flags are OMITTED (not
 * `false`) when they were not verified against a primary source.
 *
 * Every node was verified against the cited primary source on the
 * `retrieved_at` date. This catalog is malpractice-bait if wrong — do not
 * extend it with folk wisdom; verify against the official statute first.
 */

import { z } from "zod";
import type { SourceCitation } from "./types.js";

/** ISO 8601 date the statutes below were checked against primary sources.
 * A fixed constant (never wall-clock) so the catalog stays byte-identical
 * across machines and runs. */
const CURATED_AT = "2026-07-17";

export type EstateFormalityOverlay = {
  /** Stable id, e.g. `est-formalities-us-pa`. */
  id: string;
  /** Normalized jurisdiction id, e.g. `us-pa`. */
  jurisdiction: string;
  state_name: string;
  /**
   * Attesting witnesses the state's ordinary (non-holographic) attested-will
   * path expects. 0 for Pennsylvania — the verified outlier.
   */
  witnesses_expected: number;
  /** Notarized acknowledgment accepted in lieu of witnesses (CO / ND). */
  notarization_alternative: boolean;
  /** The state's standard typed will is the civil-law notarial testament (LA). */
  notarial_testament: boolean;
  /** Witnesses may sign "within a reasonable time" (UPC § 2-502(a) phrasing). */
  reasonable_time_phrasing: boolean;
  /** Holographic wills recognized. OMITTED when not primary-source verified. */
  holographic_recognized?: boolean;
  /** Electronic-will regime enacted. OMITTED when not primary-source verified. */
  e_will_regime?: boolean;
  /** Short status line, e.g. `No witnesses required (signed will)`. */
  headline: string;
  /** Plain-language description of the state's execution-formality posture. */
  summary: string;
  citation: SourceCitation;
};

export const EstateFormalityOverlaySchema = z.object({
  id: z.string().min(1),
  jurisdiction: z.string().regex(/^us-[a-z]{2}$/, "jurisdiction must be us-XX"),
  state_name: z.string().min(1),
  witnesses_expected: z.number().int().min(0).max(2),
  notarization_alternative: z.boolean(),
  notarial_testament: z.boolean(),
  reasonable_time_phrasing: z.boolean(),
  holographic_recognized: z.boolean().optional(),
  e_will_regime: z.boolean().optional(),
  headline: z.string().min(1),
  summary: z.string().min(1),
  citation: z.object({
    id: z.string().min(1),
    source: z.string().min(1),
    source_url: z.string().url(),
    retrieved_at: z.string().min(1),
    source_published_at: z.string().optional(),
    license: z.string().min(1),
    license_url: z.string().url(),
    attribution: z.string().optional(),
  }),
});

const PUBLIC_LAW_LICENSE = {
  license: "Public domain (US state government work)",
  license_url: "https://www.usa.gov/government-works",
} as const;

const cite = (id: string, source: string, source_url: string): SourceCitation => ({
  id,
  source,
  source_url,
  retrieved_at: CURATED_AT,
  ...PUBLIC_LAW_LICENSE,
});

/** The seed catalog — only primary-source-verified states, ordered by id. */
export const ESTATE_FORMALITIES: readonly EstateFormalityOverlay[] = [
  {
    id: "est-formalities-us-ak",
    jurisdiction: "us-ak",
    state_name: "Alaska",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK (material portions)",
    summary:
      "Alaska follows the 1990 UPC pattern: the will must be in writing, signed by the testator (or by another in the testator's conscious presence and at the testator's direction), and signed by at least two individuals each signing within a reasonable time after witnessing the signing or the testator's acknowledgment — witnesses need not sign in the testator's presence (Alaska Stat. § 13.12.502(a)). A non-complying document is valid as a holographic will, witnessed or not, when the signature and material portions are in the testator's handwriting (§ 13.12.502(b)). No notarization alternative was adopted, and both the formalities and the holographic rule are expressly subject to the AS 13.06.068 choice-of-law provision.",
    citation: cite(
      "ak-stat-13-12-502",
      "Alaska Stat. § 13.12.502 (execution; witnessed wills; holographic wills)",
      "https://codes.findlaw.com/ak/title-13-decedents-estates-guardianships-transfers-trusts-and-health-care-decisions/ak-st-sect-13-12-502/",
    ),
  },
  {
    id: "est-formalities-us-al",
    jurisdiction: "us-al",
    state_name: "Alabama",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses (pre-1990 UPC, no timing clause); holographic NOT recognized in-state",
    summary:
      "Alabama enacted the pre-1990 UPC § 2-502 formula: every will must be in writing, signed by the testator (or by proxy in the testator's presence and at the testator's direction), and signed by at least two persons who each witnessed the signing or the testator's acknowledgment (Ala. Code § 43-8-131) — no notarization alternative, no 'reasonable time' clause, and no requirement that the witnesses sign in the testator's presence. Interested witnesses do not invalidate the will (§ 43-8-134(b)). Unwitnessed holographic wills executed in Alabama are invalid; the § 43-8-135 choice-of-law rule admits wills valid where executed or where the testator was domiciled.",
    citation: cite(
      "al-code-43-8-131",
      "Ala. Code §§ 43-8-131, 43-8-134, 43-8-135 (execution; witnesses; choice of law)",
      "https://law.onecle.com/alabama/title-43/43-8-131.html",
    ),
  },
  {
    id: "est-formalities-us-ar",
    jurisdiction: "us-ar",
    state_name: "Arkansas",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses, publication + signature at the end; holographic OK (proved by 3 disinterested witnesses)",
    summary:
      "Arkansas requires an attested will to be signed AT THE END by the testator (or by mark or proxy with extra writing formalities) after declaring to the witnesses that the instrument is his or her will (publication), all in the presence of at least two attesting witnesses, who must sign at the testator's request and in the testator's presence (Ark. Code Ann. § 28-25-103) — no notarization alternative, no 'reasonable time' window, and no requirement that witnesses sign in each other's presence. A will whose ENTIRE body and signature are in the testator's handwriting needs no attesting witnesses, but establishing it requires at least three credible disinterested witnesses to the handwriting and signature (§ 28-25-104) — a heavier proof burden than the two witnesses typical elsewhere.",
    citation: cite(
      "ar-code-28-25-103",
      "Ark. Code Ann. §§ 28-25-103, 28-25-104 (execution generally; holographic wills)",
      "https://codes.findlaw.com/ar/title-28-wills-estates-and-fiduciary-relationships/ar-code-sect-28-25-103.html",
    ),
  },
  {
    id: "est-formalities-us-az",
    jurisdiction: "us-az",
    state_name: "Arizona",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK",
    summary:
      "Arizona follows the UPC witnessing pattern for paper wills: signed by at least two people, each signing within a reasonable time after witnessing the signing or the testator's acknowledgment (A.R.S. § 14-2502(A)(3)). A holographic will is valid, whether or not witnessed, if the signature and the material provisions are in the testator's handwriting (§ 14-2503); testamentary intent may be shown by extrinsic evidence, including non-handwritten portions (§ 14-2502(B)).",
    citation: cite(
      "az-ars-14-2502",
      "Ariz. Rev. Stat. §§ 14-2502, 14-2503 (execution of paper wills; holographic wills)",
      "https://www.azleg.gov/ars/14/02502.htm",
    ),
  },
  {
    id: "est-formalities-us-ca",
    jurisdiction: "us-ca",
    state_name: "California",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses, present at the same time; holographic OK",
    summary:
      "California requires the will to be signed during the testator's lifetime by at least two persons who, being present at the same time, witnessed the signing or the testator's acknowledgment of the signature or of the will, and who understand the instrument is the testator's will (Prob. Code § 6110). A non-complying will is valid as a holographic will, whether or not witnessed, if the signature and the material provisions are in the testator's handwriting (§ 6111).",
    citation: cite(
      "ca-prob-code-6110",
      "Cal. Prob. Code §§ 6110–6111 (execution; holographic wills)",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=6110.&lawCode=PROB",
    ),
  },
  {
    id: "est-formalities-us-co",
    jurisdiction: "us-co",
    state_name: "Colorado",
    witnesses_expected: 2,
    notarization_alternative: true,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time) OR notarized acknowledgment",
    summary:
      "Colorado enacted the UPC § 2-502(a) pattern: the will must be signed by at least two individuals, each signing within a reasonable time after witnessing the signing or the testator's acknowledgment (C.R.S. § 15-11-502(1)(c)(I)) — OR acknowledged by the testator before a notary public (§ 15-11-502(1)(c)(II), the notarization alternative). A non-complying will is valid as a holographic will if the signature and material portions are in the testator's handwriting (§ 15-11-502(2)).",
    citation: cite(
      "co-rev-stat-15-11-502",
      "Colo. Rev. Stat. § 15-11-502 (execution — witnessed or notarized wills — holographic wills)",
      "https://colorado.public.law/statutes/crs_15-11-502",
    ),
  },
  {
    id: "est-formalities-us-ct",
    jurisdiction: "us-ct",
    state_name: "Connecticut",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses, each subscribing in the testator's presence; holographic NOT recognized in-state",
    summary:
      "Connecticut makes a will invalid to pass property unless it is in writing, subscribed by the testator, and attested by two witnesses each subscribing in the testator's presence (Conn. Gen. Stat. § 45a-251) — the statute's only presence requirement, with no reciprocal requirement that the testator sign before the witnesses, no notarization alternative, and no 'reasonable time' language. Two witnesses only since a 1971 act reduced the former three-witness requirement. Unwitnessed holographic wills are not recognized domestically; the same sentence's borrowing clause admits any will executed according to the laws of the state or country where it was executed.",
    citation: cite(
      "ct-gen-stat-45a-251",
      "Conn. Gen. Stat. § 45a-251 (making and execution of wills; wills executed outside the state)",
      "https://www.cga.ct.gov/current/pub/chap_802a.htm",
    ),
  },
  {
    id: "est-formalities-us-de",
    jurisdiction: "us-de",
    state_name: "Delaware",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ credible witnesses, attesting in the testator's presence; noncompliance = VOID",
    summary:
      "Delaware requires every will to be in writing, signed by the testator (or by proxy in the testator's presence at express direction), and attested and subscribed in the testator's presence by 2 or more credible witnesses (12 Del. C. § 202(a)) — presence runs one direction only (the statute never requires the testator to sign or acknowledge before the witnesses), with no notarization alternative and no 'reasonable time' window. The statute is unusually blunt: any will not complying 'shall be void' (§ 202(b)). No holographic provision exists; § 1306's choice-of-law rule saves wills validly executed under the law of the place of execution or the testator's domicile, abode, or nationality. Interested witnesses do not invalidate (§ 203(b)).",
    citation: cite(
      "de-12-del-c-202",
      "12 Del. C. §§ 202, 203, 1306 (execution; interested witnesses; choice of law)",
      "https://delcode.delaware.gov/title12/c002/sc01/index.html",
    ),
  },
  {
    id: "est-formalities-us-fl",
    jurisdiction: "us-fl",
    state_name: "Florida",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses, mutual presence; holographic NOT recognized",
    summary:
      "Florida requires the testator to sign (or acknowledge) in the presence of at least two attesting witnesses, and the witnesses to sign in the presence of the testator and of each other (Fla. Stat. § 732.502(1)). Holographic wills are not recognized: an unwitnessed handwritten will is invalid, and even a nonresident's will valid where executed is excluded from Florida recognition if holographic (§ 732.502(2)). A handwritten will executed with the full formalities is simply a valid will, not a 'holographic' one.",
    citation: cite(
      "fl-stat-732-502",
      "Fla. Stat. § 732.502 (execution of wills)",
      "https://www.flsenate.gov/Laws/Statutes/2025/0732.502",
    ),
  },
  {
    id: "est-formalities-us-ga",
    jurisdiction: "us-ga",
    state_name: "Georgia",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ competent witnesses (age 14+), in the testator's presence; holographic NOT recognized",
    summary:
      "Georgia requires the will to be in writing, signed by the testator (or by another in the testator's presence and at the testator's express direction), and attested and subscribed in the presence of the testator by two or more competent witnesses, who may be as young as 14 (O.C.G.A. §§ 53-4-20, 53-4-22) — with no mutual-presence requirement and no notarization substitute. Holographic wills are not recognized: a handwritten will is valid only with the same two-witness attestation. A gift to a subscribing witness is void unless two other non-beneficiary witnesses subscribed (§ 53-4-23(a)); the § 53-4-24 self-proving affidavit affects only proof at probate, not validity.",
    citation: cite(
      "ga-ocga-53-4-20",
      "O.C.G.A. §§ 53-4-20, 53-4-22, 53-4-23 (execution and attestation; witness competency; interested witnesses)",
      "https://law.onecle.com/georgia/title-53/53-4-20.html",
    ),
  },
  {
    id: "est-formalities-us-hi",
    jurisdiction: "us-hi",
    state_name: "Hawaii",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK; harmless error available",
    summary:
      "Hawaii enacted the 1990 UPC in 1996: the will must be in writing, signed by the testator (or by proxy in the testator's conscious presence and at direction), and signed by at least two individuals each signing within a reasonable time after witnessing the signing or the testator's acknowledgment — witnesses need not sign in anyone's presence (Haw. Rev. Stat. § 560:2-502(a)). A non-complying will is valid as a holographic will if the signature and material portions are in the testator's handwriting (§ 560:2-502(b)), with intent provable by extrinsic evidence including non-handwritten portions (pre-printed form blanks filled in by hand can qualify). No 2008 notarization alternative was adopted; UPC harmless error is available on clear and convincing evidence (§ 560:2-503).",
    citation: cite(
      "hi-hrs-560-2-502",
      "Haw. Rev. Stat. §§ 560:2-502, 560:2-503 (execution; witnessed wills; holographic wills; writings intended as wills)",
      "https://codes.findlaw.com/hi/division-3-property-family/hi-rev-st-sect-560-2-502/",
    ),
  },
  {
    id: "est-formalities-us-ia",
    jurisdiction: "us-ia",
    state_name: "Iowa",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses, mutual presence + publication; holographic NOT recognized in-state",
    summary:
      "Iowa makes every domestic will valid only if written, signed by the testator (or proxy in the testator's presence at express direction), DECLARED by the testator to be the testator's will (publication), and witnessed at the testator's request by two competent persons who signed in the presence of the testator AND of each other (Iowa Code § 633.279(1)) — no notarization alternative and no 'reasonable time' allowance. Witnesses may be as young as 16 (§ 633.280). Since 2023, 'presence' is statutorily defined to include electronic real-time see-and-hear presence, with counterpart execution permitted (§ 633.279(3), (5)). Unwitnessed holographs are not recognized domestically; § 633.283 imports only foreign-execution law.",
    citation: cite(
      "ia-code-633-279",
      "Iowa Code §§ 633.279, 633.280, 633.283 (signed and witnessed; witness age; foreign execution)",
      "https://www.legis.iowa.gov/docs/code/633.279.pdf",
    ),
  },
  {
    id: "est-formalities-us-id",
    jurisdiction: "us-id",
    state_name: "Idaho",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses (pre-1990 UPC, no timing or presence constraint); holographic OK",
    summary:
      "Idaho keeps the classic pre-1990 UPC pattern: the will must be in writing, signed by the testator (or by another in the testator's presence and at direction), and signed by at least two persons who each witnessed the signing or the testator's acknowledgment (Idaho Code § 15-2-502) — no 'reasonable time' clause and no presence, location, or timing constraint on the witnesses' own signatures, among the most permissive two-witness statutes. A holographic will is valid unwitnessed when the signature and material provisions are in the testator's handwriting (§ 15-2-503, unchanged since 1971). The 2017 cross-reference to § 51-109 is a notarial proxy-signature for testators physically unable to sign — NOT a notarization substitute for the two witnesses.",
    citation: cite(
      "id-code-15-2-502",
      "Idaho Code §§ 15-2-502, 15-2-503 (execution; holographic will)",
      "https://legislature.idaho.gov/statutesrules/idstat/Title15/T15CH2/SECT15-2-502/",
    ),
  },
  {
    id: "est-formalities-us-il",
    jurisdiction: "us-il",
    state_name: "Illinois",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ credible witnesses, in the testator's presence; holographic NOT recognized",
    summary:
      "Illinois requires every will to be in writing, signed by the testator (or by another in the testator's presence and by the testator's direction), and attested in the presence of the testator by two or more credible witnesses (755 ILCS 5/4-3). Holographic (unwitnessed handwritten) wills are not valid under Illinois's own law; an out-of-state will is recognized only if it complied with the law where executed or of the testator's domicile (755 ILCS 5/7-1).",
    citation: cite(
      "il-755-ilcs-5-4-3",
      "755 ILCS 5/4-3 (signing and attestation)",
      "https://www.ilga.gov/documents/legislation/ilcs/documents/075500050K4-3.htm",
    ),
  },
  {
    id: "est-formalities-us-in",
    jurisdiction: "us-in",
    state_name: "Indiana",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    e_will_regime: true,
    headline: "2+ witnesses, mutual presence + publication; holographic NOT recognized; e-wills (2018)",
    summary:
      "Indiana requires the testator to signify to two or more attesting witnesses that the instrument is the testator's will and to sign, acknowledge, or direct a proxy signature in their presence, and the witnesses must sign in the presence of the testator AND each other (Ind. Code § 29-1-5-3(b)) — stricter mutual presence than the UPC, with no notarization alternative and no 'reasonable time' softening. Unwitnessed holographic wills are not valid under Indiana's own law; only nuncupative wills are excepted. Indiana separately enacted IC 29-1-21 (P.L. 40-2018), one of the first US electronic-wills statutes: two electronic witness signatures in mutual presence, with audiovisual presence only under attorney or directed-paralegal supervision (§ 29-1-21-4).",
    citation: cite(
      "in-code-29-1-5-3",
      "Ind. Code §§ 29-1-5-3, 29-1-21-4 (execution; electronic wills)",
      "https://codes.findlaw.com/in/title-29-probate/in-code-sect-29-1-5-3/",
    ),
  },
  {
    id: "est-formalities-us-ks",
    jurisdiction: "us-ks",
    state_name: "Kansas",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ witnesses, testator's presence, signed at the end; holographic NOT recognized in-state",
    summary:
      "Kansas requires every will (except a § 59-608 oral will) to be in writing, signed AT THE END by the testator (or by another in the testator's presence and at express direction), and attested and subscribed in the testator's presence by two or more competent witnesses who saw the testator subscribe or heard the testator acknowledge the will (Kan. Stat. Ann. § 59-606) — no notarization alternative and no 'reasonable time' window; a self-proving affidavit executed at signing can substitute for the attestation clause but never for the witnesses. No domestic holographic wills; § 59-609 saves out-of-state wills valid where executed, provided they are written and subscribed. Kansas is one of the few states still recognizing oral deathbed wills for personal property (§ 59-608).",
    citation: cite(
      "ks-ksa-59-606",
      "Kan. Stat. Ann. §§ 59-606, 59-608, 59-609 (execution and attestation; oral wills; wills executed without the state)",
      "https://ksrevisor.gov/statutes/chapters/ch59/059_006_0006.html",
    ),
  },
  {
    id: "est-formalities-us-ky",
    jurisdiction: "us-ky",
    state_name: "Kentucky",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 credible witnesses, mutual presence — unless wholly in the testator's handwriting",
    summary:
      "Kentucky requires every will to be in writing with the testator's name subscribed by the testator (or by a proxy in the testator's presence and at the testator's direction). If the will is not wholly written by the testator, the testator must subscribe or acknowledge it in the presence of at least two credible witnesses, who must subscribe their names in the presence of the testator AND of each other (KRS § 394.040) — an express mutual-presence requirement rare among the states, with no notarization alternative and no 'reasonable time' window. A will wholly written by the testator is valid without any witnesses — Kentucky's holographic path, with no date requirement and no 'material provisions' test.",
    citation: cite(
      "ky-krs-394-040",
      "Ky. Rev. Stat. § 394.040 (requisites of a valid will)",
      "https://apps.legislature.ky.gov/law/statutes/statute.aspx?id=36237",
    ),
  },
  {
    id: "est-formalities-us-la",
    jurisdiction: "us-la",
    state_name: "Louisiana",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: true,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "Notarial testament: notary + 2 witnesses; per-page signatures",
    summary:
      "Louisiana's notarial testament requires the testator, in the presence of a notary and two competent witnesses, to declare the instrument is his testament and to sign at the end AND on each other separate page; the notary and witnesses then sign the prescribed attestation declaration in the presence of the testator and each other (La. Civ. Code arts. 1576–1577). The olographic testament — entirely written, dated, and signed in the testator's handwriting — is the alternative form (art. 1575).",
    citation: cite(
      "la-civ-code-1577",
      "La. Civ. Code arts. 1576–1577 (notarial testament; requirements of form)",
      "https://codes.findlaw.com/la/civil-code/la-civ-code-tit-ii-art-1577",
    ),
  },
  {
    id: "est-formalities-us-ma",
    jurisdiction: "us-ma",
    state_name: "Massachusetts",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses (no timing clause); holographic NOT recognized; strict compliance",
    summary:
      "Massachusetts enacted UPC § 2-502 with the flexibility stripped out: the will must be in writing, signed by the testator (or by proxy in the testator's conscious presence and at the testator's direction), and signed by at least 2 individuals who each witnessed the signing or the testator's acknowledgment of the signature or of the will (G.L. c. 190B, § 2-502(a)) — with NO 'within a reasonable time' clause, no notarization alternative, and no holographic-will subsection. UPC § 2-503 (harmless error) was left unenacted ('Reserved'), so strict compliance governs, though § 2-506 recognizes out-of-state wills valid where executed. A devise to an interested witness is void absent 2 disinterested witnesses or proof of no fraud/undue influence (§ 2-505(b)).",
    citation: cite(
      "ma-gl-190b-2-502",
      "Mass. Gen. Laws ch. 190B, §§ 2-502, 2-503 (Reserved), 2-505, 2-506 (execution; interested witnesses; choice of law)",
      "https://malegislature.gov/Laws/GeneralLaws/PartII/TitleII/Chapter190B/Section2-502",
    ),
  },
  {
    id: "est-formalities-us-md",
    jurisdiction: "us-md",
    state_name: "Maryland",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    e_will_regime: true,
    headline: "2+ credible witnesses, testator's presence; e-will/remote witnessing regime (2021)",
    summary:
      "Maryland requires every will to be in writing, signed by the testator (or by another in the testator's physical presence and by the testator's express direction), and attested and signed by two or more credible witnesses in the testator's physical presence — or in the testator's ELECTRONIC presence when the § 4-102(c)/(d) certified-will requirements are met (testator in Maryland, witnesses in the U.S., paper certification; the attorney-supervised path per (c)) — the electronic-will regime enacted in 2021 (Md. Code, Est. & Trusts § 4-102). Notarization never substitutes for the witnesses. Holographic wills are recognized only for a testator serving in the U.S. armed services who signs outside any U.S. state, D.C., or territory, and become void one year after discharge unless the testator died within the year or then lacks capacity (§ 4-103).",
    citation: cite(
      "md-est-trusts-4-102",
      "Md. Code, Est. & Trusts §§ 4-102, 4-103 (execution; electronic wills; armed-services holographic wills)",
      "https://mgaleg.maryland.gov/mgawebsite/Laws/StatuteText?article=get&section=4-102",
    ),
  },
  {
    id: "est-formalities-us-me",
    jurisdiction: "us-me",
    state_name: "Maine",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK; NO harmless error despite the modern-UPC base",
    summary:
      "Maine's 2019 Probate Code (tit. 18-C, effective 2019-09-01) requires the will to be in writing, signed by the testator (or by proxy in the testator's conscious presence and at direction), and signed by at least 2 individuals within a reasonable time after witnessing the signing or an acknowledgment — witnesses need not sign in anyone's presence (18-C § 2-502(1)). Holographic wills are valid when the signature and material portions are handwritten (§ 2-502(2)). Though modeled on the modern UPC, Maine omitted BOTH the 2008 notarized-will alternative AND harmless error — numbering trap: Maine's § 2-503 is the self-proved-will section, not harmless error. Maine also ships a statutory will form (§ 2-517), unusual among UPC states.",
    citation: cite(
      "me-18c-2-502",
      "Me. Rev. Stat. tit. 18-C, §§ 2-502, 2-503, 2-517 (execution; holographic wills; self-proved will; statutory will form)",
      "https://legislature.maine.gov/statutes/18-C/title18-Csec2-502.html",
    ),
  },
  {
    id: "est-formalities-us-mi",
    jurisdiction: "us-mi",
    state_name: "Michigan",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK if DATED",
    summary:
      "Michigan follows the UPC witnessing pattern: the will must be signed by at least two individuals, each signing within a reasonable time after witnessing the signing or the testator's acknowledgment (MCL § 700.2502(1)(c)). A non-complying will is valid as a holographic will, whether or not witnessed, if it is DATED and the signature and material portions are in the testator's handwriting (§ 700.2502(2)) — the dating requirement is a Michigan addition most UPC states omit.",
    citation: cite(
      "mi-mcl-700-2502",
      "Mich. Comp. Laws § 700.2502 (execution; witnessed wills; holographic wills)",
      "https://www.legislature.mi.gov/mileg.aspx?page=getobject&objectname=mcl-700-2502",
    ),
  },
  {
    id: "est-formalities-us-mn",
    jurisdiction: "us-mn",
    state_name: "Minnesota",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: false,
    headline: "2 witnesses (reasonable time); holographic NOT recognized in-state",
    summary:
      "Minnesota retains the pre-2008 UPC form: the will must be in writing, signed by the testator (or by proxy in the testator's conscious presence and at the testator's direction, or by a court-authorized conservator under § 524.5-411 — a non-uniform Minnesota addition), and signed by at least two individuals within a reasonable time after witnessing the signing or the testator's acknowledgment (Minn. Stat. § 524.2-502). Neither the notarized-acknowledgment alternative nor the holographic-will subsection was enacted, so an unwitnessed holograph executed in Minnesota is invalid; out-of-state holographs may be admitted via the § 524.2-506 choice-of-law rule.",
    citation: cite(
      "mn-stat-524-2-502",
      "Minn. Stat. §§ 524.2-502, 524.2-506 (execution; witnessed wills; choice of law)",
      "https://www.revisor.mn.gov/statutes/cite/524.2-502",
    ),
  },
  {
    id: "est-formalities-us-mo",
    jurisdiction: "us-mo",
    state_name: "Missouri",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ competent witnesses, subscribing in the testator's presence; holographic NOT recognized",
    summary:
      "Missouri requires every will to be in writing, signed by the testator (or by a proxy at the testator's direction and in the testator's presence), and attested by two or more competent witnesses subscribing their names in the presence of the testator (Mo. Rev. Stat. § 474.320) — pre-UPC strict presence, with no notarization alternative and no 'reasonable time' softening. There is no holographic exception: an unwitnessed holograph executed in Missouri fails, though § 474.360 admits wills validly executed under the law of the place of execution or the testator's domicile. An interested witness does not invalidate the will but forfeits any benefit exceeding the intestate share unless two disinterested witnesses also attested (§ 474.330).",
    citation: cite(
      "mo-rev-stat-474-320",
      "Mo. Rev. Stat. §§ 474.320, 474.330, 474.360 (execution; interested witnesses; foreign execution)",
      "https://revisor.mo.gov/main/OneSection.aspx?section=474.320",
    ),
  },
  {
    id: "est-formalities-us-mt",
    jurisdiction: "us-mt",
    state_name: "Montana",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); holographic OK; full harmless error",
    summary:
      "Montana enacted the 1990 UPC: the will must be in writing, signed by the testator (or by another in the testator's conscious presence and at direction), and signed by at least two individuals within a reasonable time after witnessing the signing or the testator's acknowledgment — witnesses need not sign in the testator's presence (Mont. Code Ann. § 72-2-522(1)). Montana did NOT adopt the 2008 notarized-acknowledgment alternative — (1)(c) remains the witnesses-only clause. Holographic wills are valid when the signature and material portions are handwritten (§ 72-2-522(2)), and § 72-2-523 supplies the full clear-and-convincing harmless-error cure covering wills, revocations, alterations, and revivals.",
    citation: cite(
      "mt-mca-72-2-522",
      "Mont. Code Ann. §§ 72-2-522, 72-2-523 (execution; witnessed wills; holographic wills; writings intended as wills)",
      "https://mca.legmt.gov/bills/mca/title_0720/chapter_0020/part_0050/section_0220/0720-0020-0050-0220.html",
    ),
  },
  {
    id: "est-formalities-us-nc",
    jurisdiction: "us-nc",
    state_name: "North Carolina",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 competent witnesses, in the testator's presence; holographic OK",
    summary:
      "North Carolina requires an attested written will to be signed by the testator (or by another at the testator's direction and in the testator's presence) and attested by at least two competent witnesses, each of whom witnessed the signing or the testator's acknowledgment of the signature (N.C.G.S. § 31-3.3). A holographic will — written entirely in the testator's handwriting and signed — is valid with no attesting witness (§ 31-3.4); extraneous printed matter not in the testator's hand does not defeat it.",
    citation: cite(
      "nc-gs-31-3-3",
      "N.C. Gen. Stat. §§ 31-3.3, 31-3.4 (attested written will; holographic will)",
      "https://www.ncleg.net/enactedlegislation/statutes/html/bysection/chapter_31/gs_31-3.4.html",
    ),
  },
  {
    id: "est-formalities-us-nd",
    jurisdiction: "us-nd",
    state_name: "North Dakota",
    witnesses_expected: 2,
    notarization_alternative: true,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time) OR notarized acknowledgment",
    summary:
      "North Dakota enacted the UPC § 2-502 pattern: the will must be signed by at least two individuals, each signing within a reasonable time after witnessing the signing or the testator's acknowledgment — OR acknowledged by the testator before a notary public or other individual authorized to take acknowledgments (N.D.C.C. § 30.1-08-02, the other state besides Colorado to adopt the notarization alternative). Holographic wills are recognized when the signature and material portions are in the testator's handwriting.",
    citation: cite(
      "nd-cent-code-30-1-08-02",
      "N.D. Cent. Code § 30.1-08-02 (2-502) (execution; witnessed wills; holographic wills)",
      "https://ndlegis.gov/cencode/t30-1c08.pdf",
    ),
  },
  {
    id: "est-formalities-us-ne",
    jurisdiction: "us-ne",
    state_name: "Nebraska",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses (pre-1990 UPC); holographic OK with handwritten date indication (curable)",
    summary:
      "Nebraska enacted the pre-1990 UPC § 2-502: the will must be in writing, signed by the testator (or by proxy in the testator's presence and at direction), and signed by at least two individuals who each witnessed the signing or the testator's acknowledgment (Neb. Rev. Stat. § 30-2327) — no notarization alternative, no 'reasonable time' clause, and no presence requirement on the witnesses' own signatures. A holographic will is valid unwitnessed if the signature, material provisions, and an indication of the DATE OF SIGNING are in the testator's handwriting (§ 30-2328) — but a 1980 savings clause forgives a missing date when the instrument is the only one, is consistent with any like instrument, or the date is determinable from contents, extrinsic circumstances, or any other evidence.",
    citation: cite(
      "ne-rev-stat-30-2327",
      "Neb. Rev. Stat. §§ 30-2327, 30-2328 (execution; holographic will)",
      "https://nebraskalegislature.gov/laws/statutes.php?statute=30-2327",
    ),
  },
  {
    id: "est-formalities-us-nh",
    jurisdiction: "us-nh",
    state_name: "New Hampshire",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ credible witnesses, testator's request + presence; holographic NOT recognized",
    summary:
      "New Hampshire requires the will to be in writing, signed by the testator (or by proxy at express direction in the testator's presence), and signed by 2 or more credible witnesses who attest to the testator's signature at the testator's request and in the testator's presence (RSA 551:2) — no seal, no notarization substitute, no 'reasonable time' language, and no holographic exception anywhere in chapter 551. Since 2020, remote witnesses are deemed 'present' only via simultaneous sight-and-sound communication supervised by an NH-licensed attorney or supervised paralegal — and the same paragraph expressly disallows electronic wills. Nuncupative wills survive for soldiers in service and mariners at sea (RSA 551:15-16).",
    citation: cite(
      "nh-rsa-551-2",
      "N.H. Rev. Stat. Ann. §§ 551:2, 551:2-a (requisites of a will; self-proved wills)",
      "https://gc.nh.gov/rsa/html/LVI/551/551-2.htm",
    ),
  },
  {
    id: "est-formalities-us-nj",
    jurisdiction: "us-nj",
    state_name: "New Jersey",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    headline: "2 witnesses (reasonable time); handwritten 'writing intended as will' OK",
    summary:
      "New Jersey follows the UPC witnessing pattern: the will must be signed by at least two individuals, each signing within a reasonable time after witnessing the signing or the testator's acknowledgment (N.J.S.A. § 3B:3-2(a)(3)). A non-complying document is valid as a writing intended as a will, whether or not witnessed, if the signature and material portions are in the testator's handwriting (§ 3B:3-2(b)) — New Jersey's holographic-equivalent; testamentary intent may be shown by extrinsic evidence (§ 3B:3-2(c)).",
    citation: cite(
      "nj-3b-3-2",
      "N.J.S.A. § 3B:3-2 (execution; witnessed wills; writings intended as wills)",
      "https://law.justia.com/codes/new-jersey/title-3b/section-3b-3-2/",
    ),
  },
  {
    id: "est-formalities-us-nm",
    jurisdiction: "us-nm",
    state_name: "New Mexico",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses, mutual presence, must witness the actual signing; holographic NOT recognized",
    summary:
      "New Mexico stripped the UPC's flexibility in the strict direction: the will must be in writing, signed by the testator (or by proxy in the testator's conscious presence and at direction), and signed by at least two individuals each of whom signed in the presence of the testator AND of each other AFTER each witnessed the signing of the will itself (N.M. Stat. Ann. § 45-2-502) — no 'reasonable time' window, no acknowledgment alternative (witnesses must see the actual signing), and no notarization option. Neither the holographic subsection nor harmless error was adopted (§ 45-2-503 is Reserved), and § 45-1-201 states outright that 'will' does not include a holographic will; § 45-2-506 choice of law may still admit out-of-state wills.",
    citation: cite(
      "nm-stat-45-2-502",
      "N.M. Stat. Ann. §§ 45-2-502, 45-1-201, 45-2-506 (execution; definitions; choice of law)",
      "https://codes.findlaw.com/nm/chapter-45-uniform-probate-code/nm-st-sect-45-2-502.html",
    ),
  },
  {
    id: "est-formalities-us-nv",
    jurisdiction: "us-nv",
    state_name: "Nevada",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    e_will_regime: true,
    headline: "2 witnesses, in the testator's presence; holographic OK if DATED; e-wills (2001)",
    summary:
      "Nevada requires a written will signed by the testator (or by an attending person at the testator's express direction) and attested by at least two competent witnesses who subscribe their names in the presence of the testator (NRS 133.040) — no notarization alternative for paper wills and no 'reasonable time' language. A holographic will is valid whether or not witnessed when the signature, DATE, and material provisions are in the testator's handwriting (NRS 133.090) — the handwritten date is statutorily required, unlike UPC-pattern states. NRS 133.085 (added 2001, amended 2017) validates electronic wills carrying the testator's date and e-signature plus an authentication characteristic, an e-notary's signature and seal, or two witnesses' e-signatures.",
    citation: cite(
      "nv-nrs-133-040",
      "Nev. Rev. Stat. §§ 133.040, 133.085, 133.090 (valid wills; electronic wills; holographic wills)",
      "https://www.leg.state.nv.us/NRS/NRS-133.html",
    ),
  },
  {
    id: "est-formalities-us-ny",
    jurisdiction: "us-ny",
    state_name: "New York",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses within one 30-day period; signed at the end",
    summary:
      "New York requires the will to be signed at the end by the testator and attested by at least two witnesses who, within one thirty-day period, attest the testator's signature as affixed or acknowledged in their presence and sign their names with residence addresses at the end of the will (EPTL § 3-2.1; the 30-day requirement carries a rebuttable presumption of fulfillment). Holographic and nuncupative wills are valid only for members of the armed forces during armed conflict, persons serving with them, and mariners at sea (EPTL § 3-2.2) — not for ordinary testators.",
    citation: cite(
      "ny-eptl-3-2-1",
      "N.Y. EPTL §§ 3-2.1, 3-2.2 (execution and attestation; nuncupative and holographic wills)",
      "https://www.nysenate.gov/legislation/laws/EPT/3-2.1",
    ),
  },
  {
    id: "est-formalities-us-oh",
    jurisdiction: "us-oh",
    state_name: "Ohio",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ competent witnesses, conscious presence; no unwitnessed holographic",
    summary:
      "Ohio requires every will to be in writing (handwritten or typewritten), signed at the end by the testator (or by another in the testator's conscious presence and at the testator's express direction), and attested and subscribed in the conscious presence of the testator by two or more competent witnesses who saw the testator subscribe or heard the acknowledgment (R.C. § 2107.03; 'conscious presence' excludes telephonic/electronic sensing). A handwritten will is valid ONLY with that attestation — Ohio has no unwitnessed holographic doctrine.",
    citation: cite(
      "oh-rc-2107-03",
      "Ohio Rev. Code § 2107.03 (method of making will)",
      "https://codes.ohio.gov/ohio-revised-code/section-2107.03",
    ),
  },
  {
    id: "est-formalities-us-ok",
    jurisdiction: "us-ok",
    state_name: "Oklahoma",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses signing at the end, testator's presence + publication; holographic OK if DATED",
    summary:
      "Oklahoma keeps 1910-vintage formalism: the will must be subscribed at the end by the testator (or by proxy in the testator's presence and at direction), the subscription made or acknowledged in the presence of two attesting witnesses, the testator must declare to them that the instrument is his will (publication), and each witness must sign at the end at the testator's request and in the testator's presence (84 O.S. § 55) — though witnesses need not sign in each other's presence, and there is no notarization alternative. A holographic will must be ENTIRELY written, DATED, and signed by the testator's hand (§ 54) — the date is an element of validity, a minority rule shared with Nevada.",
    citation: cite(
      "ok-84-os-55",
      "84 O.S. §§ 54, 55 (holographic wills; execution and attestation)",
      "https://www.oscn.net/applications/oscn/DeliverDocument.asp?CiteID=72959",
    ),
  },
  {
    id: "est-formalities-us-or",
    jurisdiction: "us-or",
    state_name: "Oregon",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: false,
    headline: "2 witnesses (reasonable time BEFORE death); holographic NOT recognized; e-wills banned",
    summary:
      "Oregon requires a written — expressly non-electronic — will that the testator signs, directs signed, or acknowledges in the presence of each of at least two witnesses, who must each see, hear, or observe the act and attest by signing within a reasonable time BEFORE the testator's death (ORS 112.235, the 2015 amendment's outer deadline — not the UPC's 'after witnessing' formulation; witnesses who sign after death fail the statute). No notarization alternative and no presence requirement on the witnesses' own signatures. Unwitnessed holographs are not a valid domestic execution method, though ORS 112.238 harmless error can excuse defects on clear and convincing evidence of intent, and ORS 112.255 honors wills valid where executed.",
    citation: cite(
      "or-ors-112-235",
      "Or. Rev. Stat. §§ 112.235, 112.238, 112.255 (execution; harmless error; choice of law)",
      "https://www.oregonlegislature.gov/bills_laws/ors/ors112.html",
    ),
  },
  {
    id: "est-formalities-us-pa",
    jurisdiction: "us-pa",
    state_name: "Pennsylvania",
    witnesses_expected: 0,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    headline: "No attesting witnesses required (ordinary signed will)",
    summary:
      "Pennsylvania requires only that a will be in writing and signed by the testator at the end (20 Pa. C.S. § 2502) — no attesting witnesses are required for an ordinary signed will. Two witnesses are required only when the testator signs by mark or another person signs at the testator's direction. (Proving the will at probate still involves witnesses to the signature, but attestation at execution is not an execution requirement.)",
    citation: cite(
      "pa-20-pacs-2502",
      "20 Pa. C.S. § 2502 (form and execution of a will)",
      "https://www.legis.state.pa.us/WU01/LI/LI/CT/HTM/20/00.025.002.000..HTM",
    ),
  },
  {
    id: "est-formalities-us-ri",
    jurisdiction: "us-ri",
    state_name: "Rhode Island",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses, simultaneously present at signing; holographic NOT recognized in-state",
    summary:
      "Rhode Island keeps the near-verbatim English Wills Act 1837 pattern: the will must be signed by the testator (or by proxy in the testator's presence at express direction), with the signature made or acknowledged in the presence of two or more witnesses PRESENT AT THE SAME TIME, who then attest and subscribe in the testator's presence — though no attestation form or publication is necessary (R.I. Gen. Laws § 33-5-5). No notarization alternative, no 'reasonable time' softening, and no domestic holographic wills; the only exceptions are § 33-5-6 (soldiers in actual military service and mariners at sea, personal estate only) and the § 33-5-7 foreign-execution conformity clause.",
    citation: cite(
      "ri-gen-laws-33-5-5",
      "R.I. Gen. Laws §§ 33-5-5, 33-5-6, 33-5-7 (execution; military service; foreign execution)",
      "http://webserver.rilegislature.gov/Statutes/TITLE33/33-5/33-5-5.htm",
    ),
  },
  {
    id: "est-formalities-us-sc",
    jurisdiction: "us-sc",
    state_name: "South Carolina",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2 witnesses (no timing clause); holographic NOT recognized in-state",
    summary:
      "South Carolina follows the UPC two-witness pattern with the timing language stripped: the will must be in writing, signed by the testator (or by proxy in the testator's presence and at the testator's direction), and signed by at least two individuals who each witnessed the signing or the testator's acknowledgment (S.C. Code Ann. § 62-2-502) — no 'reasonable time' clause, no notarization alternative, and no presence requirement for the witnesses' own signatures. Unwitnessed holographic wills are not valid under SC law, though § 62-2-505 admits wills valid where executed or where the testator was domiciled. Numbering trap: § 62-2-503 is the self-proving-affidavit section, not UPC harmless error, which SC has not adopted.",
    citation: cite(
      "sc-code-62-2-502",
      "S.C. Code Ann. §§ 62-2-502, 62-2-505 (execution; choice of law)",
      "https://www.scstatehouse.gov/code/t62c002.php",
    ),
  },
  {
    id: "est-formalities-us-sd",
    jurisdiction: "us-sd",
    state_name: "South Dakota",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2+ witnesses, conscious presence (no reasonable-time grace); holographic OK",
    summary:
      "South Dakota tightened the 1990 UPC: a non-holographic will must be in writing, signed by the testator (or by proxy in the testator's conscious presence and at direction), and signed by two or more individuals IN THE TESTATOR'S CONSCIOUS PRESENCE who also witnessed the signing or the acknowledgment of the signature in that same conscious presence (S.D. Codified Laws § 29A-2-502(b)) — the 'within a reasonable time' clause was deleted, the 'acknowledgment of the will' alternative omitted, and no notarization option adopted. Holographic wills are valid when the signature and material portions are handwritten — at subsection (a), not (b): South Dakota inverted the UPC's subsection order, a citation trap for UPC-keyed references.",
    citation: cite(
      "sd-scl-29a-2-502",
      "S.D. Codified Laws § 29A-2-502 (holographic will; validity of non-holographic will; establishing intent)",
      "https://sdlegislature.gov/api/Statutes/29A-2-502.html",
    ),
  },
  {
    id: "est-formalities-us-tn",
    jurisdiction: "us-tn",
    state_name: "Tennessee",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses, mutual presence + publication; holographic OK (handwriting proved by 2)",
    summary:
      "Tennessee requires the testator to signify to the attesting witnesses that the instrument is the testator's will (publication) and to sign, acknowledge, or direct a proxy signature in the presence of at least two attesting witnesses, who must then sign in the presence of the testator AND of each other (Tenn. Code Ann. § 32-1-104(a)) — stricter than the UPC, with no notarization alternative and no 'reasonable time' flexibility. A holographic will needs no witnesses to execution, but the signature and all material provisions must be in the testator's handwriting, proved by two witnesses to the handwriting (§ 32-1-105). For wills executed before July 1, 2016, § 32-1-104(b) retroactively counts witness signatures on a § 32-2-110 affidavit as will signatures when made simultaneously with the testator's signing.",
    citation: cite(
      "tn-tca-32-1-104",
      "Tenn. Code Ann. §§ 32-1-104, 32-1-105 (execution; holographic wills)",
      "https://codes.findlaw.com/tn/title-32-wills/tn-code-sect-32-1-104/",
    ),
  },
  {
    id: "est-formalities-us-tx",
    jurisdiction: "us-tx",
    state_name: "Texas",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2+ credible witnesses (age 14+); holographic OK",
    summary:
      "Texas requires an attested will to be signed by the testator (or another at the testator's direction and in the testator's presence) and attested by two or more credible witnesses at least 14 years of age who subscribe their names in their own handwriting in the testator's presence (Est. Code § 251.051). A will written wholly in the testator's handwriting is exempt from the attestation requirement (§ 251.052 — the holographic exception).",
    citation: cite(
      "tx-est-code-251-051",
      "Tex. Est. Code §§ 251.051–251.052 (written, signed, and attested; holographic exception)",
      "https://law.justia.com/codes/texas/estates-code/title-2/subtitle-f/chapter-251/subchapter-b/section-251-051/",
    ),
  },
  {
    id: "est-formalities-us-ut",
    jurisdiction: "us-ut",
    state_name: "Utah",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: true,
    e_will_regime: true,
    headline: "2 witnesses (reasonable time); holographic OK; Uniform Electronic Wills Act (2020)",
    summary:
      "Utah follows the 1990 UPC pattern: writing, testator signature (or conscious-presence proxy), and at least two individuals signing within a reasonable time after witnessing the signing or the testator's acknowledgment, with no requirement they sign in the testator's presence (Utah Code § 75-2-502(1)). Utah did NOT enact the 2008 UPC notarized-acknowledgment alternative — a paper will cannot substitute notarization for the two witnesses (§ 75-2-502 was re-enacted in 1998 and never updated; listings calling Utah a notarization-alternative state are wrong). A non-complying will is valid as a holographic will if the signature and material portions are handwritten (§ 75-2-502(2)). Utah separately enacted the Uniform Electronic Wills Act (§§ 75-2-1401 to -1411, effective 2020-08-31): text-readable e-wills witnessed by two individuals in the testator's physical or ELECTRONIC presence.",
    citation: cite(
      "ut-code-75-2-502",
      "Utah Code §§ 75-2-502, 75-2-1401 to 75-2-1411 (execution; holographic wills; Uniform Electronic Wills Act)",
      "https://le.utah.gov/xcode/Title75/Chapter2/C75-2-S502_1800010118000101.pdf",
    ),
  },
  {
    id: "est-formalities-us-va",
    jurisdiction: "us-va",
    state_name: "Virginia",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses, present at the same time; holographic OK (proved by 2 disinterested witnesses)",
    summary:
      "Virginia requires the testator to sign the will — or acknowledge it — in the presence of at least two competent witnesses who are present at the same time and who subscribe the will in the testator's presence; no form of attestation clause is necessary (Va. Code § 64.2-403(C)). A will wholly in the testator's handwriting and signed is valid with no witnesses at execution, provided the handwriting and signature are proved at probate by at least two disinterested witnesses (§ 64.2-403(B)). § 64.2-404 adds a harmless-error remedy on clear and convincing evidence (filed within one year of death), which cannot excuse the testator's signature except in swapped-wills or self-proving-certificate mix-ups.",
    citation: cite(
      "va-code-64-2-403",
      "Va. Code §§ 64.2-403, 64.2-404 (execution of wills; writings intended as wills)",
      "https://law.lis.virginia.gov/vacode/title64.2/section64.2-403/",
    ),
  },
  {
    id: "est-formalities-us-vt",
    jurisdiction: "us-vt",
    state_name: "Vermont",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    headline: "2+ credible witnesses, in mutual presence",
    summary:
      "Vermont requires the will to be in writing, signed in the presence of two or more credible witnesses by the testator (or in the testator's name by another at the testator's express direction), and attested and subscribed by the witnesses in the presence of the testator and each other (14 V.S.A. § 5). The former three-witness requirement was reduced to two by 2005, No. 106 (Adj. Sess.), § 1 — the session-law citation per the official annotated statute.",
    citation: cite(
      "vt-14-vsa-5",
      "14 V.S.A. § 5 (execution of will; requisites; amended 2005, No. 106 (Adj. Sess.), § 1)",
      "https://legislature.vermont.gov/statutes/section/14/001/00005",
    ),
  },
  {
    id: "est-formalities-us-wa",
    jurisdiction: "us-wa",
    state_name: "Washington",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: false,
    headline: "2+ competent witnesses; holographic NOT recognized in-state",
    summary:
      "Washington requires every will to be in writing, signed by the testator (or by another at the testator's direction and in the testator's presence), and attested by two or more competent witnesses by subscribing their names or signing an affidavit while in the presence (including electronic presence) of and at the direction or request of the testator (RCW § 11.12.020). An unattested holographic will made in Washington is not valid, though a holographic will validly executed in a state that permits them is recognized as a foreign will.",
    citation: cite(
      "wa-rcw-11-12-020",
      "Wash. Rev. Code § 11.12.020 (requisites of wills — foreign wills)",
      "https://app.leg.wa.gov/rcw/default.aspx?cite=11.12.020",
    ),
  },
  {
    id: "est-formalities-us-wi",
    jurisdiction: "us-wi",
    state_name: "Wisconsin",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: true,
    holographic_recognized: false,
    headline: "2 witnesses (reasonable time), conscious presence; holographic NOT recognized in-state",
    summary:
      "Wisconsin requires the will to be signed by the testator (or with assistance, or by proxy in the testator's conscious presence) and signed by at least 2 witnesses within a reasonable time after witnessing the signing or the testator's implicit or explicit acknowledgment, each in the witness's conscious presence — and the two witnesses may observe at different times (Wis. Stat. § 853.03(2)(am)-(bm)). 'Conscious presence' statutorily includes attorney-supervised 2-way real-time audiovisual appearance with in-state location attestations (§ 853.03(2)(c)). No notarization alternative and no domestic holographic wills; a holograph valid under the law of the place of execution or the testator's domicile is recognized via § 853.05.",
    citation: cite(
      "wi-stat-853-03",
      "Wis. Stat. §§ 853.03, 853.05 (execution of wills; wills validly executed elsewhere)",
      "https://docs.legis.wisconsin.gov/statutes/statutes/853/i/03",
    ),
  },
  {
    id: "est-formalities-us-wv",
    jurisdiction: "us-wv",
    state_name: "West Virginia",
    witnesses_expected: 2,
    notarization_alternative: false,
    notarial_testament: false,
    reasonable_time_phrasing: false,
    holographic_recognized: true,
    headline: "2 witnesses, simultaneously present, subscribing before testator AND each other; holographic OK",
    summary:
      "West Virginia requires the will to be signed by the testator (or by proxy in the testator's presence and at direction) in such manner as to make it manifest that the name is intended as a signature, with the signature made or acknowledged in the presence of at least two competent witnesses PRESENT AT THE SAME TIME, who must subscribe in the presence of the testator AND of each other — no attestation clause necessary (W. Va. Code § 41-1-3). The mutual-presence subscription requirement is a Virginia-derived pattern WV retained after Virginia relaxed it — a common out-of-state execution trap. A will WHOLLY in the testator's handwriting is exempt from all witnessing (the carve-out is embedded mid-sentence in § 41-1-3 itself); no notarization alternative and no harmless-error provision exist in the article.",
    citation: cite(
      "wv-code-41-1-3",
      "W. Va. Code § 41-1-3 (must be in writing; witnesses)",
      "https://code.wvlegislature.gov/41-1-3/",
    ),
  },
];

/** Number of states the formalities catalog covers (the honest denominator). */
export const ESTATE_FORMALITIES_STATE_COUNT = ESTATE_FORMALITIES.length;

const BY_JURISDICTION: ReadonlyMap<string, EstateFormalityOverlay> = new Map(
  ESTATE_FORMALITIES.map((o) => [o.jurisdiction, o]),
);

/** The 50 states + DC — the values `--state` accepts (two-letter codes). */
export const US_STATE_CODES: readonly string[] = [
  "al",
  "ak",
  "az",
  "ar",
  "ca",
  "co",
  "ct",
  "de",
  "dc",
  "fl",
  "ga",
  "hi",
  "id",
  "il",
  "in",
  "ia",
  "ks",
  "ky",
  "la",
  "me",
  "md",
  "ma",
  "mi",
  "mn",
  "ms",
  "mo",
  "mt",
  "ne",
  "nv",
  "nh",
  "nj",
  "nm",
  "ny",
  "nc",
  "nd",
  "oh",
  "ok",
  "or",
  "pa",
  "ri",
  "sc",
  "sd",
  "tn",
  "tx",
  "ut",
  "vt",
  "va",
  "wa",
  "wv",
  "wi",
  "wy",
];

const CODE_SET = new Set(US_STATE_CODES);

/**
 * Normalize a user-supplied state ("PA", "pa", "us-pa") to a `us-xx`
 * jurisdiction id. Unknown or malformed input returns `undefined` so the
 * caller can reject it with the valid list.
 */
export function normalizeUsStateId(input: string): string | undefined {
  const lower = input.trim().toLowerCase();
  const code = lower.startsWith("us-") ? lower.slice(3) : lower;
  return CODE_SET.has(code) ? `us-${code}` : undefined;
}

/**
 * Look up the formalities overlay for a normalized `us-xx` id. A state with
 * no node returns `undefined` — the honest-N/A path: the estate-checks pack
 * then runs with its jurisdiction-neutral wording, never a guessed overlay.
 */
export function estateFormalitiesForState(
  jurisdiction: string,
): EstateFormalityOverlay | undefined {
  return BY_JURISDICTION.get(jurisdiction);
}

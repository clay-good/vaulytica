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

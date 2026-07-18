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

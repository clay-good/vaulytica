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

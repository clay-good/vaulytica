/**
 * v3 fetchers — barrel export (spec-v3.md §VI / Steps 21–22).
 */

import type { V3Fetcher } from "./_common.js";
import { hipaaTitle45Fetcher } from "./hipaa-ecfr-title-45.js";
import { hhsSampleBaaFetcher } from "./hhs-sample-baa.js";
import { hhsOcrResolutionsFetcher } from "./hhs-ocr-resolutions.js";
import { STATE_PRIVACY_FETCHERS, STATE_PRIVACY_SOURCES } from "./state-privacy.js";
import { gdprFetcher, GDPR_URL } from "./gdpr.js";
import { euSccFetcher, EU_SCC_URL } from "./eu-scc.js";
import {
  ukGdprFetcher,
  ukIdtaFetcher,
  ukAddendumFetcher,
  UK_GDPR_URL,
  UK_IDTA_URL,
  UK_ADDENDUM_URL,
} from "./uk.js";
import {
  swissFadpFetcher,
  swissAddendumFetcher,
  edpbGuidelinesFetcher,
  SWISS_FADP_URL,
  SWISS_ADDENDUM_URL,
  EDPB_GUIDELINES_URL,
} from "./swiss-edpb.js";
import { INTL_FETCHERS, INTL_SOURCES } from "./international.js";

export * from "./_common.js";
export {
  hipaaTitle45Fetcher,
  HIPAA_TITLE_45_URL,
  parseHipaaSnapshot,
} from "./hipaa-ecfr-title-45.js";
export {
  hhsSampleBaaFetcher,
  HHS_SAMPLE_BAA_URL,
  parseHhsSampleBaa,
} from "./hhs-sample-baa.js";
export {
  hhsOcrResolutionsFetcher,
  HHS_OCR_INDEX_URL,
  parseOcrIndex,
} from "./hhs-ocr-resolutions.js";
export {
  STATE_PRIVACY_FETCHERS,
  STATE_PRIVACY_SOURCES,
  makeStatePrivacyFetcher,
  parseStatePrivacy,
} from "./state-privacy.js";
export { gdprFetcher, GDPR_URL, parseGdpr } from "./gdpr.js";
export { euSccFetcher, EU_SCC_URL, parseEuScc } from "./eu-scc.js";
export {
  ukGdprFetcher,
  ukIdtaFetcher,
  ukAddendumFetcher,
  UK_GDPR_URL,
  UK_IDTA_URL,
  UK_ADDENDUM_URL,
  parseUkGdpr,
  parseUkIdta,
  parseUkAddendum,
} from "./uk.js";
export {
  swissFadpFetcher,
  swissAddendumFetcher,
  edpbGuidelinesFetcher,
  SWISS_FADP_URL,
  SWISS_ADDENDUM_URL,
  EDPB_GUIDELINES_URL,
  parseSwissFadp,
  parseSwissAddendum,
  parseEdpbGuidelines,
} from "./swiss-edpb.js";
export {
  INTL_FETCHERS,
  INTL_SOURCES,
  makeIntlFetcher,
  parseIntl,
} from "./international.js";

export const V3_FETCHERS: Record<string, V3Fetcher> = {
  "hipaa-ecfr-title-45": hipaaTitle45Fetcher,
  "hhs-sample-baa": hhsSampleBaaFetcher,
  "hhs-ocr-resolutions": hhsOcrResolutionsFetcher,
  ...STATE_PRIVACY_FETCHERS,
  gdpr: gdprFetcher,
  "eu-scc-2021-914": euSccFetcher,
  "uk-gdpr": ukGdprFetcher,
  "uk-idta": ukIdtaFetcher,
  "uk-addendum": ukAddendumFetcher,
  "swiss-fadp": swissFadpFetcher,
  "swiss-addendum": swissAddendumFetcher,
  "edpb-guidelines": edpbGuidelinesFetcher,
  ...INTL_FETCHERS,
};

export const V3_FETCHER_IDS = Object.keys(V3_FETCHERS).sort();

export const V3_SOURCE_URLS: Record<string, string> = {
  "hipaa-ecfr-title-45":
    "https://www.ecfr.gov/api/versioner/v1/full/2026-05-12/title-45.xml?part=164",
  "hhs-sample-baa":
    "https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html",
  "hhs-ocr-resolutions":
    "https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html",
  ...Object.fromEntries(
    Object.values(STATE_PRIVACY_SOURCES).map((s) => [s.source_id, s.source_url]),
  ),
  gdpr: GDPR_URL,
  "eu-scc-2021-914": EU_SCC_URL,
  "uk-gdpr": UK_GDPR_URL,
  "uk-idta": UK_IDTA_URL,
  "uk-addendum": UK_ADDENDUM_URL,
  "swiss-fadp": SWISS_FADP_URL,
  "swiss-addendum": SWISS_ADDENDUM_URL,
  "edpb-guidelines": EDPB_GUIDELINES_URL,
  ...Object.fromEntries(Object.values(INTL_SOURCES).map((s) => [s.source_id, s.source_url])),
};

/**
 * v4 fetchers — barrel export (spec-v4.md §13 / Step 60).
 *
 * Eight new sources (the spec table lists each):
 *   - NVCA model legal documents     → C.* equity, D.* M&A
 *   - DGCL Title 8                   → B.* governance, D.* M&A
 *   - MBCA (vendored excerpts)       → B.*
 *   - UCC Articles 2, 3, 9           → A.* commercial, L.* lending
 *   - AIA contract documents catalog → M.* construction
 *   - FRCP + FRE                     → G.* settlement
 *   - State landlord-tenant statutes → E.* real estate
 *   - State trust + will codes       → N.* trust / estate / family
 *
 * v4 fetchers emit v3 DKB nodes (`statutory_clause_requirement` and
 * `regulator_model_form` per spec §12) so the existing Step-20
 * staleness gate covers them without modification.
 */

import type { V4Fetcher } from "./_common.js";
import { nvcaFetcher, NVCA_MODEL_DOCS_URL } from "./nvca.js";
import { dgclFetcher, DGCL_URL } from "./dgcl.js";
import { mbcaFetcher, MBCA_URL } from "./mbca.js";
import { UCC_FETCHERS, UCC_SOURCES } from "./ucc.js";
import { aiaFetcher, AIA_CONTRACTS_URL } from "./aia.js";
import { PROCEDURAL_FETCHERS, PROCEDURAL_SOURCES, FRCP_URL, FRE_URL } from "./frcp-fre.js";
import {
  STATE_LANDLORD_TENANT_FETCHERS,
  STATE_LANDLORD_TENANT_SOURCES,
} from "./state-landlord-tenant.js";
import {
  STATE_TRUST_WILL_FETCHERS,
  STATE_TRUST_WILL_SOURCES,
} from "./state-trust-will.js";

export * from "./_common.js";
export { nvcaFetcher, NVCA_MODEL_DOCS_URL, parseNvcaIndex } from "./nvca.js";
export { dgclFetcher, DGCL_URL, parseDgcl } from "./dgcl.js";
export { mbcaFetcher, MBCA_URL, parseMbca } from "./mbca.js";
export {
  UCC_FETCHERS,
  UCC_SOURCES,
  UCC_ARTICLE_2_URL,
  UCC_ARTICLE_3_URL,
  UCC_ARTICLE_9_URL,
  parseUccArticle,
} from "./ucc.js";
export { aiaFetcher, AIA_CONTRACTS_URL, parseAiaCatalog } from "./aia.js";
export {
  PROCEDURAL_FETCHERS,
  PROCEDURAL_SOURCES,
  FRCP_URL,
  FRE_URL,
  parseProceduralRule,
} from "./frcp-fre.js";
export {
  STATE_LANDLORD_TENANT_FETCHERS,
  STATE_LANDLORD_TENANT_SOURCES,
  makeStateLandlordTenantFetcher,
  parseStateLandlordTenant,
} from "./state-landlord-tenant.js";
export {
  STATE_TRUST_WILL_FETCHERS,
  STATE_TRUST_WILL_SOURCES,
  makeStateTrustWillFetcher,
  parseStateTrustWill,
} from "./state-trust-will.js";

export const V4_FETCHERS: Record<string, V4Fetcher> = {
  nvca: nvcaFetcher,
  dgcl: dgclFetcher,
  mbca: mbcaFetcher,
  ...UCC_FETCHERS,
  aia: aiaFetcher,
  ...PROCEDURAL_FETCHERS,
  ...STATE_LANDLORD_TENANT_FETCHERS,
  ...STATE_TRUST_WILL_FETCHERS,
};

export const V4_FETCHER_IDS: string[] = Object.keys(V4_FETCHERS).sort();

export const V4_SOURCE_URLS: Record<string, string> = {
  nvca: NVCA_MODEL_DOCS_URL,
  dgcl: DGCL_URL,
  mbca: MBCA_URL,
  ...Object.fromEntries(Object.values(UCC_SOURCES).map((s) => [s.source_id, s.source_url])),
  aia: AIA_CONTRACTS_URL,
  frcp: FRCP_URL,
  fre: FRE_URL,
  ...Object.fromEntries(
    Object.values(STATE_LANDLORD_TENANT_SOURCES).map((s) => [s.source_id, s.source_url]),
  ),
  ...Object.fromEntries(
    Object.values(STATE_TRUST_WILL_SOURCES).map((s) => [s.source_id, s.source_url]),
  ),
};

void PROCEDURAL_SOURCES; // re-exported above; referenced here for tree-shake stability

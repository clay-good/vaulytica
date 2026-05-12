/**
 * International privacy-statute fetchers — PIPEDA (Canada), LGPD
 * (Brazil), APPI (Japan), PIPL (China). Spec-v3.md §9.
 *
 * Same pattern as `state-privacy.ts`: each source is a snapshot of the
 * processor / service-provider contract requirement section of the
 * statute, and the parser emits one `statutory_clause_requirement`
 * node per matched requirement.
 *
 * PIPL note: the spec calls for vendoring a single reputable English
 * translation from a named source and recording the translation
 * provenance. The cite list does that — `authority` names the
 * translator and the citation field carries the translation date.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export type IntlSource = {
  source_id: string;
  jurisdiction: string;
  regulator: string;
  source_url: string;
  effective_date: string;
  /** Provenance note copied into the authority field — translation source for PIPL etc. */
  authority_label: string;
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

export const INTL_SOURCES: Record<string, IntlSource> = {
  pipeda: {
    source_id: "pipeda",
    jurisdiction: "ca",
    regulator: "Office of the Privacy Commissioner of Canada",
    source_url: "https://laws-lois.justice.gc.ca/eng/acts/p-8.6/page-1.html",
    effective_date: "2004-01-01",
    authority_label: "Personal Information Protection and Electronic Documents Act, S.C. 2000, c. 5",
    requirements: [
      {
        id: "pipeda-principle-4.1.3-third-party-processing",
        citation: "PIPEDA Schedule 1, Principle 4.1.3",
        requirement:
          "Organization is responsible for personal information transferred to a third party for processing, and must use contractual or other means to provide a comparable level of protection.",
        minimum_compliant_text:
          "Organization shall, by contractual or other means, ensure that personal information transferred to a third party for processing receives a comparable level of protection to that required by PIPEDA.",
        detect: /(accountab(le|ility)|comparable level of protection|third party.*processing)/i,
      },
    ],
  },
  lgpd: {
    source_id: "lgpd",
    jurisdiction: "br",
    regulator: "ANPD (Autoridade Nacional de Proteção de Dados)",
    source_url:
      "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
    effective_date: "2020-09-18",
    authority_label: "Lei Geral de Proteção de Dados Pessoais (Lei nº 13.709/2018)",
    requirements: [
      {
        id: "lgpd-art-39-operator-contract",
        citation: "LGPD (Lei 13.709/2018), Art. 39",
        requirement:
          "Operator must process personal data following the controller's instructions and the standards established by ANPD.",
        minimum_compliant_text:
          "Operator (processor) shall process personal data strictly according to the instructions provided by the Controller and shall maintain the security and confidentiality of the data.",
        detect: /(operador|operator|art.*39|instructions.*controller)/i,
      },
    ],
  },
  appi: {
    source_id: "appi",
    jurisdiction: "jp",
    regulator: "Personal Information Protection Commission (PPC) Japan",
    source_url: "https://www.ppc.go.jp/en/legal/",
    effective_date: "2022-04-01",
    authority_label: "Act on the Protection of Personal Information (APPI), Law No. 57 of 2003 as amended",
    requirements: [
      {
        id: "appi-art-25-supervision-of-trustee",
        citation: "APPI Art. 25 (Supervision of Trustees)",
        requirement:
          "Where a business operator entrusts handling of personal data to a third party, it must exercise necessary and appropriate supervision over the trustee.",
        minimum_compliant_text:
          "Business Operator shall exercise necessary and appropriate supervision over the trustee to ensure secure handling of personal data, including written supervisory measures.",
        detect: /(trustee|entrust|supervis(ion|e)|article\s*25)/i,
      },
    ],
  },
  pipl: {
    source_id: "pipl",
    jurisdiction: "cn",
    regulator: "Cyberspace Administration of China",
    source_url:
      "https://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml",
    effective_date: "2021-11-01",
    authority_label:
      "Personal Information Protection Law of the People's Republic of China — National People's Congress official English translation, 2021",
    requirements: [
      {
        id: "pipl-art-21-entrusted-processing-contract",
        citation: "PIPL Art. 21 (Entrusted Processing)",
        requirement:
          "Personal information handler entrusting processing must conclude a contract with the entrusted party specifying purpose, time limit, processing method, types of personal information, protective measures, and the rights and duties of both sides; the handler is responsible for supervising the entrusted party's handling activities.",
        minimum_compliant_text:
          "Personal Information Handler shall conclude an agreement with the Entrusted Party setting forth the purpose of processing, the period of processing, the method of processing, the types of personal information handled, the protective measures applied, and the rights and duties of both sides; the Handler shall supervise the Entrusted Party's processing activities.",
        detect: /(entrusted|article\s*21|personal information handler)/i,
      },
      {
        id: "pipl-art-38-cross-border-conditions",
        citation: "PIPL Art. 38 (Cross-Border Transfer)",
        requirement:
          "Outbound transfer of personal information requires one of: a CAC security assessment, certification by a specialized institution, a standard contract approved by the CAC, or other conditions provided by law.",
        minimum_compliant_text:
          "Parties shall comply with one of the cross-border transfer mechanisms under PIPL Art. 38, including the CAC standard contract or a CAC security assessment for important categories.",
        detect: /(cross[- ]border|outbound|article\s*38|security assessment)/i,
      },
    ],
  },
};

export function parseIntl(
  source: IntlSource,
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return source.requirements
    .filter((r) => r.detect.test(normalized))
    .map((r) => ({
      id: r.id,
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: source.regulator,
      jurisdiction: source.jurisdiction,
      authority: source.authority_label,
      citation: r.citation,
      effective_date: source.effective_date,
      requirement: r.requirement,
      minimum_compliant_text: r.minimum_compliant_text,
      applies_to_document_types: ["DPA"],
      cites: [
        pin({
          authority: source.authority_label,
          citation: r.citation,
          source_url: source.source_url,
          fetched_at: nowIso,
          text,
        }),
      ],
    }));
}

export function makeIntlFetcher(source: IntlSource): V3Fetcher {
  return async (ctx): Promise<V3FetcherResult> => {
    const text = ctx.reader.read(source.source_url);
    if (!text) {
      throw new Error(`${source.source_id}: missing snapshot for ${source.source_url}`);
    }
    return { source_id: ctx.source_id, nodes: parseIntl(source, text, ctx.nowIso) };
  };
}

export const INTL_FETCHERS: Record<string, V3Fetcher> = Object.fromEntries(
  Object.values(INTL_SOURCES).map((s) => [s.source_id, makeIntlFetcher(s)]),
);

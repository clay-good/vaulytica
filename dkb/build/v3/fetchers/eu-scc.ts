/**
 * EU Standard Contractual Clauses fetcher — Commission Implementing
 * Decision (EU) 2021/914 of 4 June 2021. Source at EUR-Lex.
 *
 * Emits four `regulator_model_form` nodes — one per module — plus a
 * `transfer_mechanism` node for each module so the Step 26 transfer
 * ruleset can match against them.
 */

import type {
  RegulatorModelForm,
  TransferMechanism,
  TransferMechanismKind,
  V3DkbNode,
} from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const EU_SCC_URL = "https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj";

type ModuleSpec = {
  kind: TransferMechanismKind;
  number: 1 | 2 | 3 | 4;
  label: string;
  scope: string;
  detect: RegExp;
};

const MODULES: ModuleSpec[] = [
  {
    kind: "scc_module_1",
    number: 1,
    label: "Controller to Controller",
    scope: "Transfers from an EEA controller to a non-EEA controller.",
    detect: /Module\s*1|Controller\s+to\s+Controller/i,
  },
  {
    kind: "scc_module_2",
    number: 2,
    label: "Controller to Processor",
    scope: "Transfers from an EEA controller to a non-EEA processor.",
    detect: /Module\s*2|Controller\s+to\s+Processor/i,
  },
  {
    kind: "scc_module_3",
    number: 3,
    label: "Processor to Processor",
    scope: "Transfers from an EEA processor to a non-EEA sub-processor.",
    detect: /Module\s*3|Processor\s+to\s+Processor/i,
  },
  {
    kind: "scc_module_4",
    number: 4,
    label: "Processor to Controller",
    scope: "Transfers from an EEA processor to a non-EEA controller.",
    detect: /Module\s*4|Processor\s+to\s+Controller/i,
  },
];

const ANNEX_CLAUSES = [
  { id: "annex-i-list-of-parties", heading: "Annex I — List of Parties / Description of Transfer / Competent Supervisory Authority" },
  { id: "annex-ii-tom", heading: "Annex II — Technical and Organisational Measures" },
  { id: "annex-iii-sub-processors", heading: "Annex III — List of Sub-processors (Modules 2 & 3)" },
];

export function parseEuScc(text: string, nowIso: string): V3DkbNode[] {
  const normalized = normalizeForHash(text);
  const fullHash = sha256Hex(text);
  const out: V3DkbNode[] = [];

  for (const m of MODULES) {
    if (!m.detect.test(normalized)) continue;

    const form: RegulatorModelForm = {
      id: `eu-scc-2021-914-module-${m.number}`,
      node_type: "regulator_model_form",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      name: `EU SCC Module ${m.number} (${m.label})`,
      regulator: "European Commission",
      jurisdiction: "eu",
      authoritative_url: EU_SCC_URL,
      vendored_path: `dkb/fixtures/v3/eu-scc-2021-914-module-${m.number}.docx`,
      vendored_content_hash: fullHash,
      clauses: ANNEX_CLAUSES.map((c) => ({
        clause_id: `${c.id}-module-${m.number}`,
        heading: c.heading,
        required_by_citation: "Commission Implementing Decision (EU) 2021/914, Annex",
        normalized_text: c.heading,
      })),
      cites: [
        pin({
          authority: "Commission Implementing Decision (EU) 2021/914",
          citation: `Commission Implementing Decision (EU) 2021/914 (Module ${m.number})`,
          source_url: EU_SCC_URL,
          fetched_at: nowIso,
          text,
        }),
      ],
    };

    const mechanism: TransferMechanism = {
      id: `transfer-scc-module-${m.number}`,
      node_type: "transfer_mechanism",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      kind: m.kind,
      name: `EU SCC Module ${m.number} (${m.label})`,
      scope: m.scope,
      required_ancillary_documents: [
        "Transfer Impact Assessment (TIA)",
        "Annex I (List of Parties / Description of Transfer / Competent Supervisory Authority)",
        "Annex II (Technical and Organisational Measures)",
        ...(m.number === 2 || m.number === 3 ? ["Annex III (List of Sub-processors)"] : []),
      ],
      cites: [
        pin({
          authority: "Commission Implementing Decision (EU) 2021/914",
          citation: `Commission Implementing Decision (EU) 2021/914 (Module ${m.number})`,
          source_url: EU_SCC_URL,
          fetched_at: nowIso,
          text,
        }),
      ],
    };

    out.push(form, mechanism);
  }

  return out;
}

export const euSccFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(EU_SCC_URL);
  if (!text) throw new Error(`eu-scc: missing snapshot for ${EU_SCC_URL}`);
  return { source_id: ctx.source_id, nodes: parseEuScc(text, ctx.nowIso) };
};

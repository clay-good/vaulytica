/**
 * Filing-format-lint activation — the single place both pipelines (CLI
 * `runIngested` and the browser `runReport`) decide whether the FILE pack
 * fires and how it is wired into the engine call. Keeping it here guarantees
 * the CLI and browser produce identical runs (the cross-surface parity
 * contract).
 *
 * The pack fires only when BOTH a court profile was selected AND the matched
 * playbook is a filing playbook. In every other case the base rule set is
 * returned untouched — so a document analyzed without `--court`, or a
 * non-filing document analyzed with `--court`, has a byte-identical hash to
 * before this feature existed.
 */

import type { FilingProfileStamp, Rule } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";
import { FILING_RULES, FILING_PLAYBOOK_IDS, CITE_RULES } from "../engine/rules/filing/index.js";
import type { CourtProfile } from "./court-profile.js";
import { FILING_OPTIONS_KEY, type BriefKind, type FilingRunOptions } from "./run-options.js";

export type FilingActivation = { profile: CourtProfile; brief_kind: BriefKind };

export type FilingWiring = {
  rules: readonly Rule[];
  options?: Record<string, unknown>;
  filing_profile?: FilingProfileStamp;
};

const FILING_IDS: readonly string[] = FILING_PLAYBOOK_IDS;

export function activateFiling(
  filing: FilingActivation | undefined,
  playbookId: string,
  ingest: IngestResult,
  baseRules: readonly Rule[],
): FilingWiring {
  // Nothing to do unless the document matched a filing playbook. Non-filing
  // documents never match one, so their rule set (and hash) is untouched.
  if (!FILING_IDS.includes(playbookId)) return { rules: baseRules };

  // The citation-lint pack (CITE-###) runs on any filing brief — it checks
  // citation format/consistency and needs no court profile. The format pack
  // (FILE-###) additionally requires a selected court profile.
  let rules: readonly Rule[] = [...baseRules, ...CITE_RULES];
  if (!filing) return { rules };

  rules = [...rules, ...FILING_RULES];
  const filingOpts: FilingRunOptions = {
    profile: filing.profile,
    brief_kind: filing.brief_kind,
    word_count: ingest.word_count,
    page_count: ingest.page_count,
    source: ingest.source,
  };
  return {
    rules,
    options: { [FILING_OPTIONS_KEY]: filingOpts },
    filing_profile: {
      id: filing.profile.id,
      version: filing.profile.version,
      court_name: filing.profile.court_name,
      brief_kind: filing.brief_kind,
      authority: filing.profile.authority.map((a) => a.cite),
    },
  };
}

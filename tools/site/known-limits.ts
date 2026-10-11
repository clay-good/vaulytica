/**
 * The data behind `/known-limits` (spec-v53 §1–§2).
 *
 * Built from what the tests enforce and what the engine's own constants say,
 * and committed as `tools/site/known-limits.json`. The site build reads only
 * that file — it must not import a test module — and
 * `site-known-limits.test.ts` fails when the file differs from this
 * generator's output, so a ledger entry cannot change without the page.
 *
 * The rule (spec-v53 §2): a number about the engine's behavior appears on the
 * page only if a test asserts it by equality, or it is read from the constant
 * that enforces it.
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  V5_RULES,
  V6_RULES,
  V7_RULES,
} from "../../src/engine/index.js";
import { MAX_DOCUMENT_BYTES, MAX_OCR_PAGES } from "../../src/ingest/limits.js";
import { MATCH_THRESHOLD } from "../../src/playbooks/types.js";
import { MAX_SECONDARY_FAMILIES } from "../../src/ui/playbook-candidates.js";
import { KNOWN_DEBT, debtCount, debtSentence } from "../../tests/integration/_known-debt.js";
import { loadLegalBasisLedger } from "../accuracy/legal-basis.js";
import { buildDocTypes } from "./doc-types.js";
import type { KnownLimitsData } from "./seo-pages.js";

export async function buildKnownLimits(root: string = process.cwd()): Promise<KnownLimitsData> {
  const debts = Object.entries(KNOWN_DEBT).map(([id, d]) => ({
    id,
    count: debtCount(d),
    sentence: debtSentence(d),
  }));
  return {
    reads: {
      max_document_mb: MAX_DOCUMENT_BYTES / 1024 / 1024,
      max_ocr_pages: MAX_OCR_PAGES,
      max_secondary_families: MAX_SECONDARY_FAMILIES,
      match_threshold: MATCH_THRESHOLD,
    },
    self_measured: {
      specimens: readdirSync(join(root, "tests", "fixtures", "specimens")).length,
      document_types: buildDocTypes(root).types.length,
      rules: [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES, ...V7_RULES]
        .length,
      attorney_signed_rules: (await loadLegalBasisLedger()).length,
    },
    // Largest first; a debt held at zero is a relation that holds, and is
    // listed apart from the ones that do not.
    open: debts
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count || (a.id < b.id ? -1 : 1)),
    held_at_zero: debts
      .filter((d) => d.count === 0)
      .map((d) => d.id)
      .sort(),
  };
}

export const serializeKnownLimits = (d: KnownLimitsData): string =>
  JSON.stringify(d, null, 1) + "\n";

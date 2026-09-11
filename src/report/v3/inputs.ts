/**
 * The producer the v3 report layer never had.
 *
 * `src/report/v3/` has shipped six conditional renderers since spec-v3, with
 * tests behind each, and `buildDocxReport` has accepted them as an optional
 * fifth argument the whole time. **Nothing constructed that argument** — the
 * type, its re-exports and the `docx.ts` parameter were its only mentions in
 * the tree — so the cross-border transfers summary (§56), the subprocessor
 * inventory page (§57) and the insurance schedule page (§58) were code that
 * shipped, was tested, was specified, and could not be obtained from any
 * surface. This function is what was missing.
 *
 * 🚨 **It deliberately does NOT build the §54 compliance matrix.** A
 * `MatrixCell` carries a status of Pass / Partial / Fail / N/A per column, and
 * nothing in the tree maps a column to the rules that decide it: playbooks
 * declare `compliance_matrix_columns` as human-readable LABELS ("AM Best
 * rating ≥ A-", "General liability ≥ $1M / $2M") and a single-string
 * `regulator_frame`. Deriving a status from a label would make this tool
 * render a **legal conclusion** — the one thing its posture forbids, and the
 * highest-consequence version of the confidently-wrong failure the rest of the
 * engine spends its test suite preventing. That mapping is a legal judgment
 * and belongs beside the attorney sign-offs; `v3-report-reach.test.ts` watches
 * for it appearing. See BUILD_PROGRESS step 32.
 *
 * The three pages this DOES produce need no judgment at all. Each renderer
 * already returns `[]` for an absent or empty input, so a document with none
 * of this language renders the byte-identical report it did before — the same
 * gated-on-presence discipline every opt-in pack in the tree follows.
 */

import { extractAllV3 } from "../../extract/v3/index.js";
import type { DocumentTree } from "../../ingest/types.js";
import type { Party } from "../../extract/types.js";
import type { V3ReportInputs } from "./types.js";
import type { ConsistencyRun } from "../../engine/consistency/types.js";

/**
 * Build the v3 report sections a document actually supports.
 *
 * Cheap enough to run unconditionally: the nine v3 extractors together take
 * ~7.6ms per document, measured across the 327-specimen corpus (2.5s total).
 * Over that corpus 37 documents carry a subprocessor inventory, 10 carry
 * transfer mechanisms and 3 carry an insurance schedule — so this is not a
 * theoretical surface, it is roughly one document in seven.
 */
export function buildV3ReportInputs(
  tree: DocumentTree,
  options: {
    parties?: readonly Party[];
    dkb_build_date?: string;
    /**
     * 🚨 The cross-document consistency run, when this document was analysed
     * as part of a bundle.
     *
     * `docx.ts` renders the §59 appendix from `V3ReportInputs.consistency` —
     * and nothing ever set it, so the section was unreachable. Meanwhile the
     * CLI passes the same `ConsistencyRun` straight to `buildHtmlReport`, and
     * `html.ts`'s own comment describes the resulting state exactly, for the
     * mirror image of it: "a bundle's conflicts reached one human-readable
     * surface and not the other". It was repaired in that direction only.
     */
    consistency?: ConsistencyRun;
  } = {},
): V3ReportInputs {
  const v3 = extractAllV3(tree, { parties: [...(options.parties ?? [])] });

  // Each field is omitted rather than passed empty, so the renderers' own
  // "absent → []" branches decide, and a run that carries none of this
  // produces exactly the artifact it produced before this function existed.
  const insurance = v3.insurance;
  const hasInsurance =
    insurance !== undefined &&
    insurance !== null &&
    (insurance.amounts.length > 0 ||
      insurance.endorsements.length > 0 ||
      insurance.required_am_best_rating !== null ||
      insurance.notice_of_cancellation_days !== null);

  return {
    ...(v3.transfer_mechanisms.length > 0 ? { transfers: v3.transfer_mechanisms } : {}),
    ...(v3.subprocessor ? { subprocessor: v3.subprocessor } : {}),
    ...(hasInsurance ? { insurance } : {}),
    ...(options.dkb_build_date ? { dkb_build_date: options.dkb_build_date } : {}),
    ...(options.consistency ? { consistency: options.consistency } : {}),
    extracted_v3: v3,
  };
}

/**
 * Whether the inputs would render any section at all.
 *
 * The caller uses this to decide whether to pass them, so a document with no
 * v3 language keeps a `v3` argument of `undefined` — which is what every
 * golden in the tree was recorded against.
 */
export function hasV3Sections(inputs: V3ReportInputs): boolean {
  // `consistency` counts: the §59 appendix is a section, and a bundle whose
  // documents conflict must reach the DOCX as well as the HTML.
  return Boolean(
    inputs.transfers?.length || inputs.subprocessor || inputs.insurance || inputs.consistency,
  );
}

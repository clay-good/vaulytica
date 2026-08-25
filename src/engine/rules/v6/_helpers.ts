/**
 * Shared helpers for the v6 law-practice packs (spec-v46.md).
 *
 * v5 and everything before it review documents a lawyer's *client* is a
 * party to. v6 reviews the documents the practice itself produces: the
 * engagement letter, the discovery request, the pleading. Their governing
 * text is not the UCC or a regulator's rulebook — it is the rules of
 * professional conduct the lawyer is personally bound by, and the rules of
 * procedure the court enforces.
 *
 * That difference drives two things this module exists to keep honest:
 *
 *  - **The Model Rules are not law anywhere.** Every state adopts its own
 *    version, and several differ materially on the exact points these
 *    packs check (fee-agreement writing requirements, business-transaction
 *    consent, file-return duties). `modelRule()` renders that caveat into
 *    the citation itself, so no finding can be read as "your state
 *    requires this."
 *  - **Local rules and standing orders outrank the national rule.**
 *    Discovery response formats, privilege-log contents, and pleading
 *    formalities are all commonly modified by local rule or by the judge's
 *    own standing order. `localRule()` says so.
 */

import { v4Cite } from "../v4/_helpers.js";
import type { SourceCitation } from "../../../dkb/types.js";

export { pack, GATED_PACK_RULE_IDS, type ColumnSpec } from "../v5/_pack.js";
export {
  frcp,
  fre,
  usc,
  cfr,
  modelRule,
  practice,
  stateLaw,
  standardForm,
} from "../v5/_helpers.js";

function slug(text: string): string {
  return text
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

/**
 * A local rule or a judge's standing order — cited as a *class*, because
 * which one applies is a fact about the forum that this tool cannot know.
 */
export function localRule(topic: string, label: string): SourceCitation {
  return v4Cite({
    id: `local-rule-${slug(topic)}`,
    source: `Local rules and standing orders — ${label} (varies by district, division, and judge; the assigned court's own rules govern)`,
    source_url: "https://www.uscourts.gov/rules-policies/current-rules-practice-procedure",
    license: "Court rules (public domain)",
    license_url: "https://www.uscourts.gov/",
  });
}

/**
 * An ABA formal ethics opinion. Advisory everywhere, and frequently the
 * clearest published statement of what a duty means in practice.
 */
export function ethicsOpinion(number: string, label: string): SourceCitation {
  return v4Cite({
    id: `aba-formal-op-${slug(number)}`,
    source: `ABA Formal Opinion ${number} — ${label} (advisory; not binding in any jurisdiction)`,
    source_url:
      "https://www.americanbar.org/groups/professional_responsibility/publications/ethics_opinions/",
    license: "ABA ethics opinion (citation only — copying restricted)",
    license_url: "https://www.americanbar.org/",
  });
}

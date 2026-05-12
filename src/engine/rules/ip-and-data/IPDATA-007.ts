import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * IPDATA-007 — Data retention period unspecified (warning).
 *
 * When a contract references customer data, personal data, or data
 * processing — typically via a DPA reference, an inline data clause,
 * or a "Customer Data" defined term — and *no clause* in the
 * document specifies how long that data is retained, the silence is
 * itself a problem. Under GDPR Art. 5(1)(e), CCPA, and most modern
 * data-protection regimes, retention has to be defined (or at minimum
 * tied to a defined purpose). A contract that ducks the question
 * leaves the data subject without a clear ceiling.
 *
 * The rule is conservative: it fires only when data-handling
 * language is present AND no retention/deletion language appears
 * anywhere in the document. A DPA-by-reference clause that
 * incorporates retention terms from a separate document still
 * fires (the in-document text is what gets audited).
 */
export const rule: Rule = {
  id: "IPDATA-007",
  version: "1.0.0",
  name: "Data retention period unspecified",
  category: "ip-and-data",
  default_severity: "warning",
  description:
    "Fires when the contract handles data but no clause specifies how long the data is retained or when it must be deleted.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Hit = { sectionId: string; start: number; end: number; raw: string };
    let dataHit: Hit | null = null;
    let hasRetention = false;

    const DATA_HANDLING =
      /\b(?:customer\s+data|personal\s+data|personally\s+identifiable\s+information|PII|data\s+processing|process(?:es|ing)?\s+personal\s+data|data\s+processing\s+addendum|DPA\b)/i;
    const RETENTION =
      /\b(?:retain(?:ed|ing|s)?|retention|delete(?:d|s)?|deletion|destroy(?:ed|ing|s)?|purge(?:d)?|erase(?:d|s)?|return(?:ed|s)?\s+(?:or\s+destroy|and\s+destroy|or\s+delete)|for\s+(?:no\s+more\s+than|a\s+period\s+of)\s+\w+\s+(?:days?|months?|years?))\b/i;

    forEachParagraph(ctx.tree, (p) => {
      if (!dataHit) {
        const m = DATA_HANDLING.exec(p.text);
        if (m) {
          dataHit = {
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
            raw: m[0],
          };
        }
      }
      if (RETENTION.test(p.text)) hasRetention = true;
    });

    if (!dataHit) return null;
    if (hasRetention) return null;

    const hit: Hit = dataHit;
    return emit(ctx, rule, {
      title: "Data retention period unspecified",
      description: `The contract references data handling (\`${hit.raw}\`) but no clause specifies retention duration or deletion obligations.`,
      excerpt: hit.raw,
      explanation:
        "Under GDPR Article 5(1)(e), CCPA, and most modern data-protection regimes, the duration for which data is retained must be defined or tied to a defined purpose. A contract that handles data but says nothing about retention leaves the data subject without a contractual ceiling on how long their information can be held — and leaves the data controller without a clear obligation to delete.",
      recommendation:
        "Add an explicit retention clause: how long data is kept (or the trigger that ends retention), what happens at the end of retention (return / deletion / certification of destruction), and the cooperation timeline.",
      position: { section_id: hit.sectionId, start: hit.start, end: hit.end },
    });
  },
};

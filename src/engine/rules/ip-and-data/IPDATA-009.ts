import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * IPDATA-009 — AI / ML training rights over Customer Data (critical,
 * ip-and-data).
 *
 * Modern SaaS dark pattern: vendor grants itself a license to use
 * Customer Data — including personal data — to "operate, improve,
 * train, and develop" its services and machine-learning models.
 * Galkin Law, Morgan Lewis (Sourcing@MorganLewis), and ContractNerds
 * all flag that this conflicts with GDPR (no lawful basis once data
 * is in a trained model; right-to-erasure becomes impossible since
 * a model cannot easily unlearn), with sector laws (HIPAA, GLBA),
 * and with the EU AI Act. Litigation around training data
 * (*Andersen v. Stability AI*, *Getty Images v. Stability AI*)
 * shows how downstream IP exposure flows back to customers.
 */
export const rule: Rule = {
  id: "IPDATA-009",
  version: "1.0.0",
  name: "AI / model-training rights over Customer Data",
  category: "ip-and-data",
  default_severity: "critical",
  description:
    "Fires when the vendor grants itself a license to use Customer Data for AI / ML training or model improvement.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:license\s+to\s+(?:use|reproduce)|right\s+to\s+(?:use|process|reproduce))[^.]{0,200}\bCustomer\s+Data[^.]{0,200}\b(?:train(?:ing)?\s+(?:Vendor's\s+)?(?:services|models|AI|machine[-\s]?learning|ML)|model[-\s]?training|machine[-\s]?learning|AI\s+models?|develop(?:ing)?\s+(?:our\s+|Vendor's\s+|Provider's\s+)?(?:AI|ML|machine[-\s]?learning))|use\s+(?:Customer\s+Data|your\s+content|your\s+data)[^.]{0,200}\b(?:train(?:ing)?|improve\s+our\s+models|develop\s+our\s+models|machine[-\s]?learning)/i,
    );
    if (!hit) return null;
    // "Vendor shall NOT use Customer Data to train …" disclaims the training
    // grant — a critical false accusation if flagged. The trigger's "use …
    // train" alternative starts at "use", so the negator straddles the match
    // boundary; check the text immediately before the match for a trailing
    // "shall/will/may/does not" in addition to the sentence-scoped guard.
    const before = hit.text.slice(0, hit.match.index);
    if (
      isPresenceDisclaimed(hit.text, hit.match.index) ||
      /\b(?:shall|will|may|must|do(?:es)?|is|are)\s+not\s+$/i.test(before)
    )
      return null;
    return emit(ctx, rule, {
      title: "AI / model-training rights over Customer Data",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 280),
      explanation:
        "Granting the vendor a license to train ML / AI models on Customer Data creates several distinct problems: (1) under GDPR, training is processing that requires a lawful basis the customer typically cannot grant on behalf of the data subjects; (2) the right-to-erasure under Art. 17 is practically impossible because a trained model cannot unlearn specific training examples; (3) under HIPAA, GLBA, FERPA the training-license breaches the customer's downstream regulatory obligations; (4) downstream IP exposure from training-data litigation (*Andersen v. Stability AI*, *Getty Images*) flows back via indemnity.",
      recommendation:
        "Strike the training license entirely, or narrow it dramatically: (a) only de-identified / aggregated data, (b) only for operating the Service for that customer (not 'developing' the vendor's other services), (c) explicit opt-in rather than buried-in-TOS license, (d) carve-out for regulated data categories (PII, PHI, financial data, education records).",
      position: hit.position,
    });
  },
};

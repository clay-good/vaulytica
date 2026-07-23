/**
 * MSA deep ruleset — 30 rules (spec-v3.md §33 / Step 28).
 *
 * Covers indemnification, limitation of liability (including
 * California § 1668 and NY § 5-322.1 overlays), IP allocation,
 * warranties, SLA, term + termination + wind-down, data return,
 * force majeure, assignment / change-of-control, governing-law-
 * vs-venue alignment, boilerplate (amendment / no-waiver /
 * severability / entire agreement / notices / survival),
 * order-of-precedence (with cross-document consistency probe),
 * and AI-usage clause flagging.
 *
 * Scoped to msa-vendor-deep + msa-customer-deep.
 *
 * Earlier drafts of this header planned to deprecate v2's
 * `msa-general`, `saas-customer`, and `saas-vendor` to `*-legacy`
 * alongside the v3 deep variants — that follow-up was reconsidered
 * and NOT pursued. The v2 NDA playbooks have a clean 1:1 successor
 * (`mutual-nda` → `mutual-nda-deep`) so the v2-NDA-deprecation
 * commit (2026-05-28) added the `deprecated` + `superseded_by`
 * metadata path on those two ids. The v2 MSA + SaaS playbooks
 * have no analogous 1:1 successor: `msa-general` is a fallback
 * parent for B2B services contracts that are not specifically
 * SaaS or consulting (the deep variants are narrower vendor- and
 * customer-side specializations, not a strict successor); v3
 * `saas-tos` lints SaaS Terms of Service which is a different
 * document shape from the v2 enterprise SaaS Subscription
 * Agreement playbooks. None of the three v2 ids carry
 * `deprecated: true` today, by design.
 */

import type { Finding, Rule, RuleContext } from "../../../finding.js";
import { makeFinding } from "../../../finding.js";
import { forEachParagraph } from "../../../../extract/walk.js";
import type { DocPosition } from "../../../../extract/types.js";
import type { SourceCitation } from "../../../../dkb/types.js";
import {
  buildLanguageRule,
  buildPresenceRule,
  docTop,
  fullText,
  type LanguageSpec,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../_regulated-rule.js";

const MSA_PLAYBOOKS = ["msa-vendor-deep", "msa-customer-deep"];

const CONFIG: RegulatedRuleConfig = {
  category: "msa-deep",
  applies_to_playbooks: MSA_PLAYBOOKS,
  cite_for(citation: string) {
    const lower = citation.toLowerCase();
    let url = "https://www.law.cornell.edu/ucc";
    if (
      lower.includes("§ 1668") ||
      lower.includes("section 1668") ||
      lower.includes("california civ")
    ) {
      url =
        "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1668";
    } else if (
      lower.includes("5-322.1") ||
      lower.includes("ny gen") ||
      lower.includes("new york general obligations")
    ) {
      url = "https://www.nysenate.gov/legislation/laws/GOB/5-322.1";
    } else if (lower.includes("texas") || lower.includes("tex. bus")) {
      url = "https://statutes.capitol.texas.gov/Docs/BC/htm/BC.151.htm";
    } else if (lower.includes("ucc § 2-316") || lower.includes("u.c.c. § 2-316")) {
      url = "https://www.law.cornell.edu/ucc/2/2-316";
    } else if (lower.includes("ucc § 2-719") || lower.includes("u.c.c. § 2-719")) {
      url = "https://www.law.cornell.edu/ucc/2/2-719";
    } else if (lower.includes("u.s. bankruptcy code") || lower.includes("11 u.s.c. § 365")) {
      url = "https://www.law.cornell.edu/uscode/text/11/365";
    } else if (lower.includes("nist ai rmf")) {
      url = "https://www.nist.gov/itl/ai-risk-management-framework";
    }
    return {
      id: `msa-deep-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
      source_url: url,
    };
  },
};

const presence = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG);
const language = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG);

function cite(citation: string): SourceCitation {
  const { id, source_url } = CONFIG.cite_for(citation);
  return {
    id,
    source: citation,
    source_url,
    retrieved_at: "2026-05-13T00:00:00Z",
    license: "Public domain or regulator re-use",
    license_url: "https://www.usa.gov/government-works",
  };
}

/**
 * MSA-027 — Order-of-precedence consistency check.
 *
 * If the MSA states a precedence order (e.g., "in the event of
 * conflict, this MSA controls over any SOW") AND the document also
 * embeds language that operative SOW-typical terms (indemnity,
 * liability cap) live in a separate SOW/Order Form, the rule
 * surfaces the structural risk: the stated precedence may bury the
 * very terms that should govern. Custom check rather than a
 * presence/language pattern because it needs both signals.
 */
function buildPrecedenceConsistencyRule(): Rule {
  const { id: dkb_id } = CONFIG.cite_for("Order-of-precedence consistency");
  return {
    id: "MSA-027",
    version: "1.0.0",
    name: "Order-of-precedence may bury operative terms",
    category: CONFIG.category,
    default_severity: "warning",
    description:
      "Flags when an MSA's stated order of precedence places the MSA above its SOWs or Order Forms while operative terms (indemnity, liability, IP) appear to live in those subordinate documents.",
    dkb_citations: [dkb_id],
    applies_to_playbooks: [...MSA_PLAYBOOKS],
    check(ctx: RuleContext): Finding | null {
      const text = fullText(ctx);
      const declaresPrecedence =
        /(?:in\s+the\s+event\s+of\s+(?:any\s+)?(?:conflict|inconsistency)|order\s+of\s+precedence|takes?\s+precedence\s+over|controls?\s+over)/i.test(
          text,
        );
      if (!declaresPrecedence) return null;
      const msaOverSow =
        /(?:this\s+(?:Agreement|MSA)|the\s+MSA)\s+(?:shall\s+|will\s+)?(?:control|prevail|govern|take\s+precedence)[^.]{0,160}(?:SOW|Statement\s+of\s+Work|Order\s+Form|Schedule)/is.test(
          text,
        );
      if (!msaOverSow) return null;
      const operativeInSow =
        /(?:SOW|Statement\s+of\s+Work|Order\s+Form|Schedule|Exhibit)[^.]{0,200}(?:indemn|liability\s+cap|aggregate\s+liability|intellectual\s+property|IP\s+ownership|warrant)/is.test(
          text,
        ) ||
        /(?:indemn\w+|liability\s+cap|aggregate\s+liability|intellectual\s+property|IP\s+ownership|warrant\w+)[^.]{0,200}(?:set\s+out\s+in|set\s+forth\s+in|contained\s+in|provided\s+in|appears\s+in)\s+(?:the\s+)?(?:SOW|Statement\s+of\s+Work|Order\s+Form|Schedule|Exhibit)/is.test(
          text,
        );
      if (!operativeInSow) return null;
      let position: DocPosition = docTop(ctx);
      let excerpt = "(see Order-of-Precedence clause)";
      forEachParagraph(ctx.tree, (p) => {
        if (excerpt !== "(see Order-of-Precedence clause)") return;
        if (/order\s+of\s+precedence|takes?\s+precedence|controls?\s+over/i.test(p.text)) {
          excerpt = p.text.slice(0, 280);
          position = {
            section_id: p.section.id,
            paragraph_id: p.paragraph.id,
            start: p.start,
            end: p.start + Math.min(p.text.length, 280),
          };
        }
      });
      return makeFinding({
        rule: this as Rule,
        title: "Order-of-precedence may bury operative terms",
        description:
          "The MSA's stated precedence places it above the SOW/Order Form, but operative terms (indemnity, liability, IP, warranty) appear in those subordinate documents.",
        excerptText: excerpt,
        explanation:
          "When precedence puts the MSA on top of its SOWs, terms that actually live in a SOW may be overridden by silent MSA defaults at the moment of conflict. The order is internally inconsistent with where the operative terms sit.",
        recommendation:
          "Either relocate the operative term to the MSA, carve out the term from the precedence rule (e.g., 'except for the limitation of liability set out in the SOW'), or invert the precedence for that subject.",
        position,
        source_citations: [cite("Order-of-precedence consistency")],
      });
    },
  };
}

export const MSA_DEEP_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // Indemnification (MSA-001..005)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-001",
    name: "Third-party IP infringement indemnity",
    description: "MSA must address third-party IP infringement indemnification.",
    citation: "Commercial drafting baseline — indemnification scope",
    missing_title: "IP infringement indemnity missing",
    missing_description: "No third-party IP infringement indemnification clause was found.",
    explanation:
      "A vendor-supplied product that infringes a third party's IP exposes the customer to suit. The standard allocation is that the vendor indemnifies for IP claims.",
    recommendation:
      "Add a third-party IP infringement indemnity (defense, settlement, damages) with the usual customer-cooperation conditions.",
    present_patterns: [
      /(?:indemnif\w+).{0,200}(?:intellectual\s+property|infring\w+|IP\s+claim)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-002",
    name: "Indemnification procedure (notice / defense / settlement)",
    description:
      "Indemnification clause must include procedural mechanics (prompt notice, control of defense, settlement consent).",
    citation: "Commercial drafting baseline — indemnification procedure",
    missing_title: "Indemnification procedure unspecified",
    missing_description:
      "No prompt-notice / control-of-defense / settlement-consent language found alongside the indemnity.",
    explanation:
      "Without procedural mechanics the indemnity is ambiguous: who controls defense, who consents to settlement, what notice is required.",
    recommendation:
      "Add: prompt written notice, indemnitor controls defense with reputable counsel, settlement requires indemnitee consent for non-monetary terms.",
    present_patterns: [
      /(prompt(?:ly)?\s+(?:notify|notice)|control\s+of\s+(?:the\s+)?defense|settlement.{0,40}consent)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-003",
    name: "Indemnity for breach of confidentiality",
    description: "MSA should indemnify for breach of confidentiality obligations.",
    citation: "Commercial drafting baseline — confidentiality indemnity",
    missing_title: "Confidentiality breach indemnity missing",
    missing_description: "No indemnification covering breach of confidentiality was found.",
    explanation:
      "Confidentiality breaches often produce damages that are difficult to quantify; indemnification anchors the remedy.",
    recommendation:
      "Add an indemnity for damages arising from breach of confidentiality obligations.",
    present_patterns: [
      /(?:indemnif\w+).{0,200}(?:confidential\w+|confidentiality\s+(?:breach|obligation))/is,
    ],
    default_severity: "info",
  }),
  presence({
    id: "MSA-004",
    name: "Indemnity for breach of data protection / gross negligence / wilful misconduct",
    description:
      "Indemnification must cover breach of data-protection obligations, gross negligence, or wilful misconduct.",
    citation: "Commercial drafting baseline — DP/gross-negligence indemnity",
    missing_title: "Indemnity for data-protection / gross-negligence missing",
    missing_description:
      "No indemnification covering breach of data protection, gross negligence, or wilful misconduct was found.",
    explanation: "These categories are unusually high-impact and routinely indemnified.",
    recommendation:
      "Add an indemnity for damages arising from gross negligence, wilful misconduct, or breach of data-protection obligations.",
    present_patterns: [
      /(?:indemnif\w+).{0,200}(?:gross\s+negligence|wil[l]?ful\s+misconduct|data\s+protection|personal\s+data|breach\s+of\s+(?:DPA|data\s+protection))/is,
    ],
    default_severity: "warning",
  }),
  language({
    id: "MSA-005",
    name: "Indemnification carved out of liability cap",
    description: "Detects when indemnification is excluded from the aggregate liability cap.",
    citation: "Commercial drafting baseline — indemnity / cap interaction",
    bad_title: "Indemnification excluded from liability cap",
    bad_description: "Indemnification appears to be excluded from the aggregate liability cap.",
    explanation:
      "Whether indemnification falls inside or outside the cap is the most contested cap-carve-out term. The report surfaces it for explicit review.",
    recommendation:
      "Confirm intent: keep indemnity inside the cap (lower vendor exposure), put it outside (higher customer protection), or place it under a supercap (compromise).",
    bad_patterns: [
      /(?:liability|cap)\s+(?:shall|will)\s+not\s+apply\s+to.{0,80}indemn/is,
      /except(?:\s+for)?\s+indemnif\w+.{0,80}(?:cap|limitation\s+of\s+liability)/is,
      /indemnif\w+\s+(?:are|is)\s+excluded\s+from\s+(?:the\s+)?(?:cap|limitation)/is,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Limitation of liability (MSA-006..010)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-006",
    name: "Aggregate liability cap present",
    description: "MSA must specify an aggregate liability cap.",
    citation: "Commercial drafting baseline — aggregate cap",
    missing_title: "Aggregate liability cap missing",
    missing_description: "No aggregate cap on liability was found.",
    explanation: "Absent a cap, liability is unbounded — an unusual posture for a commercial MSA.",
    recommendation: "Add an aggregate cap (commonly 12 months' fees) with explicit carve-outs.",
    present_patterns: [
      /(aggregate\s+liability|total\s+liability).{0,80}(?:not\s+exceed|capped\s+at|limited\s+to)/i,
      /(twelve\s+months\s+(?:of\s+)?fees|12\s*months\s+(?:of\s+)?fees)/i,
    ],
  }),
  presence({
    id: "MSA-007",
    name: "Liability cap carve-outs (fraud / wilful misconduct / IP indemnity)",
    description:
      "Liability cap must carve out fraud, wilful misconduct, IP indemnity, and breach of confidentiality.",
    citation: "Commercial drafting baseline — cap carve-outs",
    missing_title: "Cap carve-outs missing",
    missing_description:
      "No carve-outs from the liability cap (fraud / wilful misconduct / IP indemnity / confidentiality / DP) were found.",
    explanation:
      "A cap that absorbs fraud and wilful misconduct is unconscionable in many jurisdictions and commercially abnormal.",
    recommendation:
      "Carve fraud, wilful misconduct, IP indemnification, confidentiality breach, and data-protection breach out of the cap.",
    present_patterns: [
      /(cap|limitation).{0,200}(?:shall\s+not\s+apply|excluded|carved\s+out).{0,200}(fraud|wil[l]?ful\s+misconduct|IP\s+indemn|confidentiality|data\s+protection)/is,
      /supercap\b/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-008",
    name: "Consequential-damages waiver is mutual",
    description: "Consequential-damages waiver should apply to both parties symmetrically.",
    citation: "Commercial drafting baseline — mutual consequential waiver",
    missing_title: "Consequential-damages waiver may be one-sided",
    missing_description:
      "Consequential-damages language was found but no mutual / either-party scoping was detected.",
    explanation:
      "An asymmetric waiver lets one side recover lost-profit damages and bars the other; the mutual form is the commercial baseline.",
    recommendation:
      "Phrase the waiver as 'neither party shall be liable to the other for any indirect, incidental, special, consequential, or punitive damages.'",
    present_patterns: [
      /(?:neither\s+party|each\s+party|in\s+no\s+event\s+shall\s+either\s+party).{0,160}(?:consequential|indirect|special|punitive|lost\s+profits)/is,
    ],
    default_severity: "info",
  }),
  language({
    id: "MSA-009",
    name: "California Civil Code § 1668 problem flag",
    description:
      "Flags a liability cap or exculpation that purports to limit liability for fraud, wilful injury, or violation of law where California law may govern — void per Cal. Civ. Code § 1668.",
    citation: "California Civil Code § 1668",
    bad_title: "Cap may run afoul of Cal. Civ. Code § 1668",
    bad_description:
      "Liability limitation purports to limit fraud / wilful injury / violation of law and California law may govern.",
    explanation:
      "California Civil Code § 1668 voids contracts that exempt anyone from responsibility for their own fraud, wilful injury, or violation of law. A cap that absorbs these categories is unenforceable in California.",
    recommendation:
      "Carve fraud, wilful injury, and violations of law out of any liability cap; verify governing law.",
    bad_patterns: [
      /(?:no\s+(?:liability|limitation|exclusion)\s+(?:shall|will)\s+apply\s+to|shall\s+not\s+be\s+liable\s+for).{0,160}(?:fraud|wil[l]?ful\s+(?:injury|misconduct)|violation\s+of\s+(?:any\s+)?law)/is,
      /limitation\s+of\s+liability\s+(?:includes|applies\s+to|covers).{0,80}(fraud|wil[l]?ful\s+(?:injury|misconduct))/is,
    ],
    default_severity: "warning",
  }),
  language({
    id: "MSA-010",
    name: "New York Gen. Oblig. § 5-322.1 anti-indemnity flag",
    description:
      "Flags a broad indemnification for negligence in a construction-related MSA governed by New York law — void per N.Y. Gen. Oblig. § 5-322.1.",
    citation: "N.Y. Gen. Oblig. Law § 5-322.1",
    bad_title: "Indemnity for own negligence under NY § 5-322.1",
    bad_description:
      "Indemnification appears to require one party to indemnify the other for the indemnitee's own negligence in a construction context.",
    explanation:
      "N.Y. Gen. Oblig. § 5-322.1 voids construction-contract indemnities that require the indemnitor to indemnify the indemnitee for the indemnitee's own negligence.",
    recommendation:
      "Narrow the indemnity to the indemnitor's own negligence (or its share under comparative-negligence apportionment).",
    bad_patterns: [
      /(?:indemnif\w+\s+(?:and\s+hold\s+harmless\s+)?).{0,200}(?:against\s+all\s+claims|for\s+any\s+and\s+all\s+(?:claims|losses))[^.]{0,200}(?:including|even\s+(?:if|though)|regardless\s+of)[^.]{0,80}(?:negligence|fault)\s+of\s+(?:the\s+)?indemnitee/is,
      /indemnif\w+.{0,160}(?:contractor|subcontractor|construction).{0,160}negligence\s+of\s+(?:the\s+)?(?:owner|indemnitee)/is,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // IP allocation (MSA-011..012)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-011",
    name: "Background / foreground IP allocation",
    description:
      "MSA must allocate ownership of background IP (pre-existing) and foreground IP (created during the engagement).",
    citation: "Commercial drafting baseline — IP allocation",
    missing_title: "Background / foreground IP allocation missing",
    missing_description: "No background / foreground IP ownership clause was found.",
    explanation:
      "Without allocation, default copyright / patent rules govern, which rarely matches the parties' intent.",
    recommendation:
      "Add explicit allocation: each party retains its background IP; foreground IP ownership rule (usually customer for deliverables, vendor for tooling).",
    present_patterns: [
      /(background\s+(?:IP|intellectual\s+property)|pre[- ]existing\s+IP)/i,
      /(foreground\s+(?:IP|intellectual\s+property)|developed\s+(?:hereunder|under\s+this\s+Agreement))/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "MSA-012",
    name: "Feedback license may be unbounded",
    description:
      "Flags a feedback license that conveys unrestricted, perpetual, irrevocable rights in customer feedback without scope limits.",
    citation: "Commercial drafting baseline — feedback license scope",
    bad_title: "Feedback license unbounded",
    bad_description:
      "Feedback license appears to grant unlimited, perpetual, irrevocable rights without scope limits.",
    explanation:
      "A broad feedback grant can sweep in customer ideas the customer may want to commercialize separately.",
    recommendation:
      "Limit the feedback license to the vendor's product improvement and add 'non-confidential feedback' as the trigger; consider a scope cap.",
    bad_patterns: [
      /feedback.{0,80}(?:perpetual|irrevocable|royalty[- ]free|worldwide).{0,80}(?:any\s+purpose|without\s+(?:any\s+)?restriction)/is,
      /(?:assign|transfer|grant).{0,40}all\s+right.{0,40}feedback/is,
    ],
    // The finding claims the grant carries no scope limits, but the second
    // pattern only proves that rights in Feedback were granted. A grant reading
    // "solely for the limited purpose of improving the Services, and for no
    // other purpose" is scope-limited — it is the fix this rule recommends.
    exclude_if: [/\bsolely\s+for\b/i, /\blimited\s+purpose\b/i, /\bfor\s+no\s+other\s+purpose\b/i],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Warranties (MSA-013..015)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-013",
    name: "Workmanlike + conformance + no-malicious-code warranties",
    description:
      "MSA must include workmanlike-services / conformance-to-documentation / no-malicious-code warranties.",
    citation: "Commercial drafting baseline — service warranties",
    missing_title: "Service warranties incomplete",
    missing_description:
      "Standard service warranties (workmanlike, conformance to documentation, no malicious code) were not found.",
    explanation: "These are the commercial baseline warranties for a services MSA.",
    recommendation:
      "Add: services performed in a workmanlike manner, conforming to the documentation, free of malicious code.",
    present_patterns: [
      /(workmanlike|professional\s+manner)/i,
      /(conform\w*\s+(?:with|to)\s+the\s+(?:documentation|specifications))/i,
      /(no\s+(?:malicious\s+code|virus|worm|trojan|disabling\s+device))/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-014",
    name: "Compliance-with-laws + non-infringement warranties",
    description: "MSA must include compliance-with-laws and non-infringement warranties.",
    citation: "Commercial drafting baseline — compliance/non-infringement",
    missing_title: "Compliance-with-laws / non-infringement warranty missing",
    missing_description: "No compliance-with-laws or non-infringement warranty was found.",
    explanation: "Customers expect a vendor to warrant lawful operation and non-infringement.",
    recommendation:
      "Add: services and deliverables (a) comply with applicable laws and (b) do not infringe any third-party IP rights.",
    present_patterns: [
      /(?:comply|compliance).{0,40}(?:applicable\s+laws|laws\s+and\s+regulations)/i,
      /(?:do\s+not\s+(?:infringe|violate)|non[- ]infring\w+)/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "MSA-015",
    name: "Implied-warranty disclaimer overreach (UCC alignment)",
    description:
      "Flags an implied-warranty disclaimer that may overreach the UCC's conspicuous-disclaimer requirement.",
    citation: "U.C.C. § 2-316",
    bad_title: "Implied-warranty disclaimer may overreach UCC § 2-316",
    bad_description:
      "Implied-warranty disclaimer is present but may not satisfy UCC § 2-316's conspicuous-disclaimer requirement (or may include warranties UCC § 2-316 reserves).",
    explanation:
      "UCC § 2-316 requires merchantability disclaimers to mention 'merchantability' and to be conspicuous; many MSAs default to a generic 'AS IS' that fails the test.",
    recommendation:
      "Use the UCC-safe disclaimer: '[ALL-CAPS] VENDOR DISCLAIMS ALL IMPLIED WARRANTIES, INCLUDING MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.' Confirm conspicuousness.",
    bad_patterns: [
      /(?:as\s+is|with\s+all\s+faults)(?![A-Z]).{0,160}without\s+(?:any\s+)?(?:other\s+)?warrant/is,
      /disclaims?\s+all\s+(?:other\s+)?warranties(?![^.]*merchantability)/is,
    ],
    // The lookahead scans only FORWARD, so the UCC-safe form that names the
    // implied warranties first ("THE IMPLIED WARRANTIES OF MERCHANTABILITY …
    // ARE EXCLUDED, AND VENDOR DISCLAIMS ALL OTHER WARRANTIES") was flagged for
    // failing to mention merchantability — which it does. § 2-316 cares that
    // the word appears, not where.
    exclude_if: [/\bmerchantability\b/i],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // SLA (MSA-016..017)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-016",
    name: "SLA referenced or attached",
    description: "MSA must reference or attach an SLA where the service is hosted.",
    citation: "Commercial drafting baseline — SLA reference",
    missing_title: "SLA reference missing",
    missing_description: "No SLA / service level agreement / uptime commitment was found.",
    explanation:
      "An MSA for hosted services without an SLA leaves availability promises unenforceable.",
    recommendation:
      "Reference an SLA (attached or linked) with uptime, support response, and remedy schedules.",
    present_patterns: [/(service\s+level\s+agreement|\bSLA\b|uptime|availability\s+commitment)/i],
    default_severity: "warning",
  }),
  language({
    id: "MSA-017",
    name: "SLA credit as sole-and-exclusive remedy",
    description: "Flags when service-level credit is stated as the sole and exclusive remedy.",
    citation: "Commercial drafting baseline — SLA exclusivity",
    bad_title: "SLA credit is sole and exclusive remedy",
    bad_description:
      "Service-level credit appears to be the sole and exclusive remedy for downtime.",
    explanation:
      "An exclusive-remedy SLA bars the customer from terminating or seeking damages for extended outages.",
    recommendation:
      "Add a 'chronic failure' termination right after N consecutive months of breach, and preserve material-breach termination.",
    bad_patterns: [
      /(service\s+credit|SLA\s+credit).{0,40}sole\s+and\s+exclusive\s+remedy/is,
      /sole\s+and\s+exclusive\s+remedy.{0,40}(?:service\s+level|SLA|downtime)/is,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Term and termination (MSA-018..020)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-018",
    name: "Termination for material breach",
    description: "MSA must include termination for material breach with cure period.",
    citation: "Commercial drafting baseline — material-breach termination",
    missing_title: "Termination for material breach missing",
    missing_description: "No termination-for-material-breach clause with a cure window was found.",
    explanation:
      "Without an explicit material-breach termination right the customer is forced into a common-law theory.",
    recommendation:
      "Add: either party may terminate on N (e.g., 30) days' written notice of an uncured material breach.",
    present_patterns: [
      /(material\s+breach|materially\s+breach\w*).{0,160}(?:cure|notice|terminate)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-019",
    name: "Termination for bankruptcy / insolvency",
    description: "MSA must include termination on bankruptcy or insolvency.",
    citation: "11 U.S.C. § 365 — Bankruptcy considerations",
    missing_title: "Termination for bankruptcy / insolvency missing",
    missing_description: "No termination-on-insolvency clause was found.",
    explanation:
      "11 U.S.C. § 365 makes pure ipso-facto clauses unenforceable in some scenarios, but the contract should still anchor the parties' intent.",
    recommendation:
      "Add: termination on filing for bankruptcy, appointment of receiver, or assignment for the benefit of creditors.",
    present_patterns: [
      /(bankruptc\w+|insolven\w+|receiver|assignment\s+for\s+the\s+benefit\s+of\s+creditors)/i,
    ],
    default_severity: "info",
  }),
  presence({
    id: "MSA-020",
    name: "Wind-down period for hosted services",
    description: "Hosted-services MSA must include a transition / wind-down period on termination.",
    citation: "Commercial drafting baseline — transition assistance",
    missing_title: "Wind-down / transition assistance missing",
    missing_description:
      "No transition / wind-down / hosted-service continuation period was found.",
    explanation: "Without a wind-down, the customer can be cut off mid-migration.",
    recommendation:
      "Add: vendor will continue providing the service for up to N (e.g., 90) days post-termination at then-current rates to facilitate transition.",
    present_patterns: [
      /(wind[- ]down|transition\s+(?:assistance|services|period)|continued\s+access|post[- ]termination\s+(?:access|services))/i,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Data return on termination (MSA-021)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-021",
    name: "Data return / portability on termination",
    description: "MSA must address data return or portability on termination.",
    citation: "Commercial drafting baseline — data return",
    missing_title: "Data return / portability missing",
    missing_description: "No data-return / data-portability / export-format clause was found.",
    explanation:
      "Without an explicit return obligation the customer can be locked out of its own data.",
    recommendation:
      "Add: on termination, vendor shall return all customer data in a machine-readable format and then delete its copies within N days.",
    present_patterns: [
      /(return\s+(?:all\s+)?(?:customer\s+)?data|data\s+portability|export\s+(?:in\s+)?(?:a\s+)?machine[- ]readable)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Force majeure (MSA-022)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-022",
    name: "Force majeure is balanced (both parties)",
    description:
      "Force-majeure clause should apply to both parties symmetrically; payment obligations should be excluded.",
    citation: "Commercial drafting baseline — balanced force majeure",
    missing_title: "Balanced force majeure missing",
    missing_description: "No bilateral force-majeure language was found.",
    explanation:
      "A one-sided force-majeure clause (vendor-only) is commercially abnormal; payment obligations are conventionally excluded.",
    recommendation:
      "Add: 'neither party shall be liable for delay or failure due to force majeure', with a payment-obligation carve-out.",
    present_patterns: [
      /(neither\s+party|either\s+party).{0,80}force\s+majeure/is,
      /force\s+majeure.{0,160}(?:neither|both|each\s+party)/is,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Assignment / change-of-control (MSA-023)
  // ────────────────────────────────────────────────────────────────
  language({
    id: "MSA-023",
    name: "Assignment silent on change-of-control",
    description: "Flags an assignment clause silent on change-of-control / merger.",
    citation: "Commercial drafting baseline — change-of-control",
    bad_title: "Assignment silent on change-of-control",
    bad_description:
      "An assignment clause is present but does not address change-of-control or merger.",
    explanation:
      "Without a change-of-control hook, an acquirer can effectively step into the contract without the counterparty's consent.",
    recommendation:
      "Add: 'a change of control of either party shall be deemed an assignment requiring consent (or notice)' with an affiliate carve-out as desired.",
    bad_patterns: [/(?:neither\s+party\s+may\s+assign|no\s+assignment)/i],
    // Was a forward-only negative lookahead, so a change-of-control hook stated
    // BEFORE the assignment sentence ("a change of control ... shall be deemed
    // an assignment requiring consent. Except as set forth above, neither party
    // may assign ...") was reported as absent.
    exclude_if: [/(?:change\s+of\s+control|merger|acquisition)/i],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Governing-law / venue alignment (MSA-024)
  // ────────────────────────────────────────────────────────────────
  language({
    id: "MSA-024",
    name: "Governing-law / venue jurisdiction mismatch",
    description: "Flags when the governing-law jurisdiction differs from the venue jurisdiction.",
    citation: "Commercial drafting baseline — choice-of-law / venue alignment",
    bad_title: "Governing-law and venue may be misaligned",
    bad_description: "Governing-law and venue clauses appear to point to different jurisdictions.",
    explanation:
      "Choosing one state's law but another state's forum forces the forum court to apply foreign law — adds cost and uncertainty.",
    recommendation:
      "Either align the two or document the rationale (e.g., NY law / Delaware courts for incorporated entities).",
    bad_patterns: [
      /governed\s+by\s+the\s+laws?\s+of\s+(?:the\s+state\s+of\s+)?(California|New\s+York|Delaware|Texas|Washington|Massachusetts|Illinois|Florida)[^.]{0,400}(?:courts?|venue|jurisdiction|forum)[^.]{0,80}(?!(?:\1))(California|New\s+York|Delaware|Texas|Washington|Massachusetts|Illinois|Florida)/is,
    ],
    // The `(?!\1)` guard only blocks a repeat of the governing-law state at the
    // one position tested, so the engine backtracks until it finds ANY other
    // state in the window — including one the clause expressly EXCLUDES
    // ("venue shall be in Delaware only, and not in California"). A stated
    // exclusion is alignment, not a mismatch.
    exclude_if: [
      /\bnot\s+in\s+(?:the\s+state\s+of\s+)?(?:California|New\s+York|Delaware|Texas|Washington|Massachusetts|Illinois|Florida)/i,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Boilerplate (MSA-025..026)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-025",
    name: "Amendment-in-writing and no-waiver",
    description: "MSA must include amendment-in-writing and no-waiver clauses.",
    citation: "Commercial drafting baseline — amendment / waiver",
    missing_title: "Amendment-in-writing / no-waiver missing",
    missing_description: "No amendment-in-writing or no-waiver boilerplate found.",
    explanation:
      "Without these, oral modifications and unintentional waivers become litigation risks.",
    recommendation:
      "Add: 'no amendment is effective unless in writing signed by both parties' and 'no failure to enforce shall be deemed a waiver.'",
    present_patterns: [
      /amend\w+.{0,40}(?:in\s+writing|written\s+(?:and\s+)?signed)/is,
      /(?:no\s+(?:waiver|failure)|shall\s+not\s+be\s+deemed\s+a\s+waiver)/i,
    ],
    default_severity: "info",
  }),
  presence({
    id: "MSA-026",
    name: "Survival clause + entire agreement",
    description: "MSA must include a survival clause and an entire-agreement / integration clause.",
    citation: "Commercial drafting baseline — survival / entire agreement",
    missing_title: "Survival / entire-agreement clause missing",
    missing_description: "No survival or entire-agreement / integration clause was found.",
    explanation:
      "Without survival, sticky obligations (confidentiality, IP, indemnity) may not outlive termination. Without integration, prior negotiations may be admissible.",
    recommendation:
      "Add: a survival clause enumerating sticky obligations and an entire-agreement clause superseding prior negotiations.",
    present_patterns: [
      /(surviv\w+).{0,40}termination/is,
      /entire\s+agreement|integration\s+clause|supersed\w+\s+(?:all\s+)?prior/i,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // Order-of-precedence (MSA-027)
  // ────────────────────────────────────────────────────────────────
  buildPrecedenceConsistencyRule(),

  // ────────────────────────────────────────────────────────────────
  // AI usage clause (MSA-028)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "MSA-028",
    name: "AI usage clause presence",
    description:
      "MSA should address whether the vendor uses AI / generative AI in providing the service.",
    citation: "NIST AI RMF — transparency baseline",
    missing_title: "AI usage clause missing",
    missing_description:
      "No clause was found addressing AI / generative AI usage by the vendor in service delivery.",
    explanation:
      "Increasingly the contract should disclose AI use, training data, and IP ownership of outputs (see the §49 AI Addendum playbook for the deep check).",
    recommendation:
      "Add a clause disclosing whether AI is used, naming material AI subprocessors, and addressing IP in outputs.",
    present_patterns: [
      /(artificial\s+intelligence|generative\s+AI|foundation\s+model|large\s+language\s+model|\bLLM\b)/i,
    ],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // State-law overlays (MSA-029..030)
  // Consults state-commercial-overlays DKB node (dkb/fixtures/v3/nodes/state-commercial-overlays.json).
  // ────────────────────────────────────────────────────────────────
  language({
    id: "MSA-029",
    name: "Texas anti-indemnity (Tex. Bus. & Com. Code Ch. 151) flag",
    description:
      "Flags an indemnity for the indemnitee's own negligence in a Texas-governed construction MSA — void per Tex. Bus. & Com. Code § 151.102.",
    citation: "Tex. Bus. & Com. Code § 151.102",
    bad_title: "Indemnity may violate Texas anti-indemnity statute",
    bad_description:
      "Indemnification appears to require one party to indemnify the other for the indemnitee's negligence in a construction-related MSA governed by Texas law.",
    explanation:
      "Texas Bus. & Com. Code Ch. 151 voids construction-contract indemnities that cover the indemnitee's own negligence (with limited insurance-policy exceptions).",
    recommendation:
      "Narrow to the indemnitor's own negligence; verify governing law and project-state nexus.",
    bad_patterns: [
      /(?:Texas|tex\.|governed\s+by\s+the\s+laws\s+of\s+(?:the\s+state\s+of\s+)?Texas)[^.]{0,400}indemnif\w+[^.]{0,160}(?:negligence|fault)\s+of\s+(?:the\s+)?indemnitee/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MSA-030",
    name: "UCC § 2-719 limited-remedy fail-of-essential-purpose carve-out",
    description:
      "When a limited remedy is the exclusive remedy, the MSA should anchor the UCC § 2-719(2) escape if the remedy fails of its essential purpose.",
    citation: "U.C.C. § 2-719(2)",
    missing_title: "UCC § 2-719 limited-remedy escape missing",
    missing_description:
      "Exclusive / limited remedy language is present but no UCC § 2-719(2) fail-of-essential-purpose escape was found.",
    explanation:
      "UCC § 2-719(2) preserves alternative remedies when a limited remedy fails of its essential purpose — anchoring this protects the customer from a remedy gap.",
    recommendation:
      "Add: 'if the limited remedy is found to fail of its essential purpose, the customer's other remedies under this Agreement and applicable law remain available.'",
    present_patterns: [
      /(fail\w*\s+of\s+(?:its\s+)?essential\s+purpose|essential\s+purpose|U\.?C\.?C\.?\s*§\s*2-719)/i,
    ],
    default_severity: "info",
  }),
];

if (MSA_DEEP_RULES.length !== 30) {
  throw new Error(`MSA-deep ruleset must export exactly 30 rules; got ${MSA_DEEP_RULES.length}`);
}

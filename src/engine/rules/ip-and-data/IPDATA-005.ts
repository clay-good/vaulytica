import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-005 — GDPR / CCPA / HIPAA reference (info). */
export const rule: Rule = {
  id: "IPDATA-005",
  version: "1.7.0",
  // The regime is as often cited by its NUMBER as by its acronym — a European
  // distribution agreement writes "shall comply with EU Regulation 2016/679"
  // and never says "GDPR" — so a contract that names the governing regime
  // precisely was reported as citing none.
  name: "Data regime reference (GDPR / CCPA / HIPAA)",
  category: "ip-and-data",
  default_severity: "info",
  description:
    "Flags data-heavy contracts that lack references to the applicable data-protection regime.",
  dkb_citations: ["stat-gdpr-art-28", "stat-ccpa-1798-140", "stat-45-cfr-164-504"],
  check(ctx: RuleContext): Finding | null {
    const personalData = firstParagraphMatch(
      ctx,
      /\bpersonal\s+(?:data|information)\b|\bprotected\s+health\s+information\b|\bPHI\b/i,
    );
    if (!personalData) return null;
    if (
      firstParagraphMatch(
        ctx,
        // The regime list must track the current landscape: CPRA is now the
        // operative California law, and a Data Processing Agreement / the
        // Standard Contractual Clauses are themselves the governing instrument
        // (as a BAA is for HIPAA). LGPD / PIPEDA / PIPL cover non-US personal
        // data. "SCCs" (plural / spelled) is used, not the bare "SCC", which
        // also abbreviates the Stockholm Chamber of Commerce. Because this is an
        // ABSENCE detector, a regime it does not recognize is a FALSE POSITIVE
        // ("regime missing" over a contract that names one) — so the US sector
        // laws (GLBA, FERPA, COPPA), the leading state comprehensive laws
        // (VCDPA, Colorado Privacy Act), and the current EU→US transfer
        // instruments (Data Privacy Framework, Privacy Shield) are recognized.
        // All are unambiguous data-protection references (unlike a bare "CPA").
        // HIPAA is the one regime a document routinely names in FULL — an
        // estate instrument authorizing a successor trustee to receive medical
        // records writes "the Health Insurance Portability and Accountability
        // Act of 1996 and 45 C.F.R. Parts 160 and 164" and never the acronym.
        // The regulation citation is written the same way: as a Part range,
        // not as a bare "45 C.F.R. 164".
        //
        // A NOTICE OF PRIVACY PRACTICES names neither. It is the instrument
        // 45 C.F.R. § 164.520 requires, written for patients, and it speaks
        // HIPAA's regulatory vocabulary throughout — "designated record set",
        // "unsecured protected health information", "psychotherapy notes" —
        // without ever using the acronym or the Act's name. Each of those is a
        // term of art with no other home, so each names the regime. So is the
        // redisclosure warning 45 C.F.R. § 164.508(c)(2)(iii) requires an
        // authorization to carry: "may then no longer be protected by the
        // federal privacy regulations".
        /\b(?:GDPR|General\s+Data\s+Protection\s+Regulation|CCPA|California\s+Consumer\s+Privacy\s+Act|CPRA|California\s+Privacy\s+Rights\s+Act|HIPAA|Health\s+Insurance\s+Portability\s+and\s+Accountability\s+Act|Business\s+Associate\s+Agreement|BAA|Covered\s+Entit(?:y|ies)|45\s*C\.?\s*F\.?\s*R\.?(?:\s|§|\.|,|\d|Parts?|and|to|–|-){0,30}16[04]\b|GLBA|Gramm[- ]Leach[- ]Bliley|FERPA|COPPA|Children['’]?s?\s+Online\s+Privacy\s+Protection\s+Act|VCDPA|Virginia\s+Consumer\s+Data\s+Protection\s+Act|Colorado\s+Privacy\s+Act|Data\s+Privacy\s+Framework|Privacy\s+Shield|LGPD|PIPEDA|PIPL|Data\s+Processing\s+(?:Agreement|Addendum)|Standard\s+Contractual\s+Clauses|SCCs|Regulation\s*\(?:EU\s*\)?\s*2016\/679|EU\s+Regulation\s+2016\/679|Directive\s+2002\/58|e[- ]?Privacy\s+Directive|UK\s+GDPR|Data\s+Protection\s+Act\s+2018|Notice\s+of\s+Privacy\s+Practices|designated\s+record\s+set|unsecured\s+protected\s+health\s+information|psychotherapy\s+notes|federal\s+privacy\s+(?:regulations?|rules?))\b/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "Data-regime references missing",
      description: "Contract references personal data but does not cite GDPR / CCPA / HIPAA.",
      excerpt: personalData.text.slice(0, 240),
      explanation:
        "When a contract touches personal data, citing the governing regime (GDPR Art. 28, CCPA, HIPAA 45 CFR 164.504) makes obligations explicit and discoverable.",
      position: personalData.position ?? topPosition(ctx),
    });
  },
};

/**
 * Addenda ruleset — 20 rules (spec-v3.md §34 / Step 29).
 *
 * Spans six playbook surfaces, each scoping its slice of the
 * catalog via `applies_to_playbooks`:
 *
 *   vendor-security-addendum (ADDENDA-001..009)
 *   ai-addendum              (ADDENDA-010..016)
 *   eula                     (ADDENDA-017..018)
 *   saas-tos                 (ADDENDA-019)
 *   privacy-policy-lint      (ADDENDA-020)
 *
 * Where there is no controlling regulator (the AI-addendum group)
 * citations are explicit "consensus practice, not statute"
 * (NIST AI RMF / EU AI Act / FTC enforcement actions).
 */

import type { Rule } from "../../../finding.js";
import {
  buildLanguageRule,
  buildPresenceRule,
  type LanguageSpec,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../_regulated-rule.js";

const SECURITY_PLAYBOOKS = ["vendor-security-addendum"];
const AI_PLAYBOOKS = ["ai-addendum"];
const EULA_PLAYBOOKS = ["eula"];
const TOS_PLAYBOOKS = ["saas-tos"];
const PRIVACY_PLAYBOOKS = ["privacy-policy-lint"];

const URL_BY_CITATION: Record<string, string> = {
  "NIST SP 800-53": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
  "NIST AI RMF": "https://www.nist.gov/itl/ai-risk-management-framework",
  "FIPS 140-3": "https://csrc.nist.gov/publications/detail/fips/140/3/final",
  "EU AI Act": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
  "FTC Click-to-Cancel Rule": "https://www.ftc.gov/legal-library/browse/rules/negative-option-rule",
  "FTC enforcement actions on AI claims": "https://www.ftc.gov/business-guidance/blog/2023/02/keep-your-ai-claims-check",
  "CCPA § 1798.130": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.130",
  "GDPR Article 13": "https://eur-lex.europa.eu/eli/reg/2016/679/oj#d1e2208-1-1",
  "GDPR Article 14": "https://eur-lex.europa.eu/eli/reg/2016/679/oj#d1e2255-1-1",
  "COPPA 16 C.F.R. § 312.4": "https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312/section-312.4",
  "EU Digital Content Directive 2019/770": "https://eur-lex.europa.eu/eli/dir/2019/770/oj",
  "EU Consumer Rights Directive 2011/83": "https://eur-lex.europa.eu/eli/dir/2011/83/oj",
  "ROSCA 15 U.S.C. § 8403": "https://www.law.cornell.edu/uscode/text/15/8403",
};

function urlForCitation(citation: string): string {
  for (const key of Object.keys(URL_BY_CITATION)) {
    if (citation.startsWith(key)) return URL_BY_CITATION[key] ?? "";
  }
  return "https://www.nist.gov/";
}

function makeConfig(applies_to_playbooks: string[]): RegulatedRuleConfig {
  return {
    category: "addenda",
    applies_to_playbooks,
    cite_for(citation: string) {
      return {
        id: `addenda-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
        source_url: urlForCitation(citation),
      };
    },
  };
}

const CONFIG_SECURITY = makeConfig(SECURITY_PLAYBOOKS);
const CONFIG_AI = makeConfig(AI_PLAYBOOKS);
const CONFIG_EULA = makeConfig(EULA_PLAYBOOKS);
const CONFIG_TOS = makeConfig(TOS_PLAYBOOKS);
const CONFIG_PRIVACY = makeConfig(PRIVACY_PLAYBOOKS);

const presenceSec = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_SECURITY);
const presenceAi = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_AI);
const presenceEula = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_EULA);
const presenceTos = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_TOS);
const presencePrivacy = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_PRIVACY);
const languageAi = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG_AI);

export const ADDENDA_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // Vendor Security Addendum (ADDENDA-001..009)
  // ────────────────────────────────────────────────────────────────
  presenceSec({
    id: "ADDENDA-001",
    name: "Specific security measures listed",
    description: "Vendor Security Addendum must enumerate specific security measures rather than a generic 'industry-standard' hand-wave.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Specific security measures missing",
    missing_description: "No enumeration of specific security controls (access control, encryption, vulnerability management, etc.) was found.",
    explanation: "A pure 'industry-standard' commitment is unenforceable. Customers need an enumerated list to verify and audit against.",
    recommendation: "Enumerate specific controls (e.g., access control / MFA, encryption-at-rest, encryption-in-transit, vulnerability management, logging, incident response).",
    present_patterns: [
      /(access\s+control|multi[- ]factor|MFA)/i,
      /(encryption\s+(?:at\s+rest|in\s+transit)|TLS\s+1\.[23])/i,
      /(vulnerability\s+management|patching|configuration\s+management|logging\s+and\s+monitoring)/i,
    ],
    default_severity: "warning",
  }),
  presenceSec({
    id: "ADDENDA-002",
    name: "Security-review cadence stated",
    description: "Vendor Security Addendum must state the cadence for security reviews / audits / certifications.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Security-review cadence missing",
    missing_description: "No cadence (annual / quarterly / etc.) for security reviews / SOC 2 audits / ISO 27001 reviews was found.",
    explanation: "Without cadence the addendum carries no operational commitment.",
    recommendation: "State the cadence: e.g., 'Vendor shall maintain a current SOC 2 Type II report renewed annually.'",
    present_patterns: [/(annual\w*|annually|quarterly|every\s+\d+\s+(?:months?|years?))\b[^.]{0,80}(?:audit|review|assessment|certification|attestation|SOC\s*2|ISO\s*27001)/i],
    default_severity: "warning",
  }),
  presenceSec({
    id: "ADDENDA-003",
    name: "Right-to-audit or SOC 2 substitution",
    description: "Vendor Security Addendum must provide a right-to-audit (customer-initiated) or a SOC 2 / ISO 27001 substitution clause.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Right-to-audit / SOC 2 substitution missing",
    missing_description: "Neither a customer right-to-audit nor a SOC 2 / ISO 27001 substitution was found.",
    explanation: "Customers must be able to verify the vendor's security posture either directly (audit) or via an independent attestation.",
    recommendation: "Add: 'Customer may audit Vendor's security controls annually with reasonable notice, or in lieu of an audit Vendor will deliver a current SOC 2 Type II report.'",
    present_patterns: [/(right\s+to\s+audit|customer.{0,40}audit|SOC\s*2|ISO\s*27001|ISO\s*\/IEC\s*27001|in\s+lieu\s+of\s+(?:an\s+)?audit)/i],
    default_severity: "warning",
  }),
  presenceSec({
    id: "ADDENDA-004",
    name: "Incident-response notification window",
    description: "Vendor Security Addendum must specify a notification window for security incidents.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Incident-response notification window missing",
    missing_description: "No notification window for security incidents (e.g., 48 hours, 72 hours) was found.",
    explanation: "Vague 'prompt' / 'without undue delay' language is unenforceable; regulated parties (HIPAA, GDPR) require specific windows.",
    recommendation: "Specify a window: e.g., 'Vendor shall notify Customer within 48 hours of confirming a security incident affecting Customer Data.'",
    present_patterns: [/(within\s+\d+\s+(?:hours?|days?)|no\s+later\s+than\s+\d+\s+(?:hours?|days?))\b[^.]{0,160}(?:incident|breach|notif)/i],
    default_severity: "warning",
  }),
  presenceSec({
    id: "ADDENDA-005",
    name: "Vulnerability-disclosure handling",
    description: "Vendor Security Addendum should state how it handles externally-reported vulnerabilities.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Vulnerability-disclosure handling missing",
    missing_description: "No vulnerability-disclosure / coordinated-disclosure / bug-bounty policy reference was found.",
    explanation: "A documented disclosure pathway materially reduces the time-to-fix for vulnerabilities reported by researchers.",
    recommendation: "Reference a vulnerability-disclosure policy (e.g., 'Vendor maintains a coordinated vulnerability disclosure policy and acknowledges reports within 5 business days.').",
    present_patterns: [/(vulnerability\s+disclosure|coordinated\s+disclosure|bug\s+bounty|responsible\s+disclosure|VDP\b)/i],
    default_severity: "info",
  }),
  presenceSec({
    id: "ADDENDA-006",
    name: "Secure-development-lifecycle reference",
    description: "Vendor Security Addendum should reference a secure-development-lifecycle (SDLC) program.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "SDLC reference missing",
    missing_description: "No reference to a secure-development-lifecycle (SDLC), SAST/DAST, or code-review program was found.",
    explanation: "An SDLC program is the practitioner-accepted way to ensure vulnerabilities are caught before code reaches production.",
    recommendation: "Reference: e.g., 'Vendor maintains a secure-development-lifecycle program including SAST, DAST, and peer code review prior to production deployment.'",
    present_patterns: [/(secure[- ]development\s+lifecycle|\bSDLC\b|SAST|DAST|secure\s+coding\s+(?:standards|practices)|code\s+review)/i],
    default_severity: "info",
  }),
  presenceSec({
    id: "ADDENDA-007",
    name: "Data-classification mapping",
    description: "Vendor Security Addendum should state how Customer Data is classified and the controls that follow.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Data-classification mapping missing",
    missing_description: "No data-classification / tiering / sensitivity-labeling scheme was found.",
    explanation: "Without classification, all Customer Data is implicitly treated at the same (often lower) tier.",
    recommendation: "Add: e.g., 'Customer Data containing personal data is classified as Confidential and receives the controls in Schedule X.'",
    present_patterns: [/(data\s+classification|sensitivity\s+(?:label|tier)|confidential\s+tier|classify\s+(?:customer\s+data|data\s+as))/i],
    default_severity: "info",
  }),
  presenceSec({
    id: "ADDENDA-008",
    name: "Encryption standards named (FIPS 140-3 / AES-256)",
    description: "Vendor Security Addendum should name encryption standards (FIPS 140-3 / AES-256 / TLS 1.2+).",
    citation: "FIPS 140-3",
    missing_title: "Named encryption standards missing",
    missing_description: "No named encryption standard (FIPS 140-3 / AES-256 / TLS 1.2 or 1.3) was found.",
    explanation: "Generic 'encryption' is unauditable; named standards are the practitioner-accepted contract anchor.",
    recommendation: "Name the standards: e.g., 'AES-256 at rest, TLS 1.2 or 1.3 in transit, FIPS 140-3 validated modules where applicable.'",
    present_patterns: [/(FIPS\s*140[- ]?[23]|AES[- ]?256|TLS\s*1\.[23])/i],
    default_severity: "warning",
  }),
  presenceSec({
    id: "ADDENDA-009",
    name: "Penetration-test cadence stated",
    description: "Vendor Security Addendum should state pen-test cadence.",
    citation: "NIST SP 800-53 (consensus practice)",
    missing_title: "Penetration-test cadence missing",
    missing_description: "No penetration-testing cadence was found.",
    explanation: "Annual third-party pen tests are the practitioner-accepted baseline for SaaS.",
    recommendation: "State the cadence: e.g., 'Vendor commissions an independent penetration test at least annually and remediates critical findings within 30 days.'",
    present_patterns: [/(penetration\s+test\w*|pen[- ]test\w*)[^.]{0,80}(?:annual\w*|annually|quarter\w+|every\s+\d+\s+(?:months?|years?))/i, /(annual\w*|annually|quarter\w+)[^.]{0,40}(?:penetration\s+test|pen[- ]test)/i],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // AI Addendum (ADDENDA-010..016)
  // ────────────────────────────────────────────────────────────────
  presenceAi({
    id: "ADDENDA-010",
    name: "AI definitions present",
    description: "AI Addendum must define the core terms (Generative AI, Foundation Model, Output, Training Data).",
    citation: "NIST AI RMF (consensus practice, not statute)",
    missing_title: "AI definitions missing",
    missing_description: "Core AI terms (Generative AI, Foundation Model, Output, Training Data) were not all defined.",
    explanation: "Definitions anchor every other AI-addendum obligation; without them, key terms are ambiguous.",
    recommendation: "Define: Generative AI, Foundation Model (or Large Language Model), Output, and Training Data.",
    present_patterns: [/(generative\s+AI|foundation\s+model|large\s+language\s+model|\bLLM\b)/i, /(\b)(Output|Outputs)\b.{0,40}(?:means|shall\s+mean)/i, /training\s+data/i],
    default_severity: "warning",
  }),
  languageAi({
    id: "ADDENDA-011",
    name: "Prohibited use: training on customer data without opt-in",
    description: "Flags an AI Addendum that permits training on customer data without an explicit opt-in.",
    citation: "FTC enforcement actions on AI claims (consensus practice, not statute)",
    bad_title: "Training on customer data without opt-in",
    bad_description: "AI Addendum appears to allow vendor to train its models on Customer Data without an explicit opt-in.",
    explanation: "FTC enforcement has repeatedly targeted vendors that train models on customer data without clear, affirmative consent.",
    recommendation: "Require an explicit, affirmative opt-in for training on Customer Data; opt-out-by-default is insufficient under FTC posture.",
    bad_patterns: [
      /(?:may\s+use|will\s+use|reserves?\s+the\s+right\s+to\s+use)\s+(?:Customer\s+Data|your\s+data|content).{0,160}(?:to\s+train|for\s+training|to\s+improve\s+(?:our\s+)?(?:models?|AI))/is,
      /(?:opt[- ]out\s+(?:basis|default)|unless\s+(?:you\s+)?opt\s+out)[^.]{0,160}(?:train|training|AI\s+model)/is,
    ],
    default_severity: "critical",
  }),
  presenceAi({
    id: "ADDENDA-012",
    name: "AI transparency: features + default state + hosting",
    description: "AI Addendum should disclose which features use AI, whether on by default or opt-in, and whether the model is on-prem or third-party-hosted.",
    citation: "EU AI Act (Art. 50 transparency)",
    missing_title: "AI transparency disclosures missing",
    missing_description: "AI feature inventory + on-by-default-vs-opt-in + on-prem-vs-third-party-model disclosures not all present.",
    explanation: "EU AI Act Article 50 + FTC consumer-protection posture both require clear disclosure of AI use.",
    recommendation: "List the AI features, their default-on / opt-in status, and the model host (on-prem vs OpenAI / Anthropic / Google / etc.).",
    present_patterns: [/(AI\s+features?|AI\s+functions?|generative\s+features?)/i, /(on\s+by\s+default|opt[- ]in|opt[- ]out|enabled\s+by\s+default)/i, /(third[- ]party\s+(?:provider|model|host)|on[- ]prem|on[- ]premises|self[- ]hosted)/i],
    default_severity: "warning",
  }),
  presenceAi({
    id: "ADDENDA-013",
    name: "IP ownership of AI outputs",
    description: "AI Addendum must allocate IP ownership of Outputs.",
    citation: "NIST AI RMF (consensus practice, not statute)",
    missing_title: "IP ownership of AI Outputs unallocated",
    missing_description: "No clause allocates IP ownership of Outputs as between Customer and Vendor.",
    explanation: "Output ownership is a frequent dispute and varies materially across vendors; allocation must be explicit.",
    recommendation: "Allocate explicitly: e.g., 'As between the parties, Customer owns Outputs to the extent permitted by law; Vendor retains its models and tooling.'",
    present_patterns: [/(Output\w*).{0,40}(?:owns?|own|owned\s+by|title\s+to)/i, /(?:owns?|own|owned\s+by).{0,40}Output\w*/i],
    default_severity: "warning",
  }),
  presenceAi({
    id: "ADDENDA-014",
    name: "AI output warranty disclaimer + human-review obligation",
    description: "AI Addendum should disclaim warranties on AI outputs (hallucination risk) and obligate human review for high-stakes uses.",
    citation: "NIST AI RMF (consensus practice, not statute)",
    missing_title: "AI hallucination disclaimer / human-review obligation missing",
    missing_description: "No hallucination-risk acknowledgment or human-review obligation for high-stakes outputs was found.",
    explanation: "Practitioner posture is: AI outputs are not fit for legal / medical / financial advice without human review.",
    recommendation: "Add: 'Outputs are provided as-is and may contain inaccuracies; Customer is responsible for human review prior to use for legal, medical, or financial decisions.'",
    present_patterns: [/(hallucinat\w+|inaccurate\s+output|not\s+fit\s+for|not\s+(?:professional|legal|medical|financial)\s+advice)/i, /human\s+(?:review|oversight|in\s+the\s+loop)/i],
    default_severity: "info",
  }),
  presenceAi({
    id: "ADDENDA-015",
    name: "AI subprocessor disclosure",
    description: "AI Addendum should disclose AI subprocessors (OpenAI, Anthropic, Google, etc.).",
    citation: "GDPR Article 28(2) (subprocessor authorisation)",
    missing_title: "AI subprocessor disclosure missing",
    missing_description: "No AI-subprocessor list (named or by URL) was found.",
    explanation: "When AI features are powered by a third-party model provider, GDPR Art. 28(2) requires authorisation and disclosure.",
    recommendation: "List AI subprocessors by name (e.g., OpenAI, Anthropic, Google, Cohere) or reference a maintained URL.",
    present_patterns: [/(OpenAI|Anthropic|Google\s+(?:Gemini|Vertex)|Cohere|Mistral|Hugging\s*Face|Azure\s+OpenAI|AWS\s+Bedrock)/i, /(AI\s+sub[- ]?processors?|model\s+sub[- ]?processors?|AI\s+vendors?)/i],
    default_severity: "warning",
  }),
  presenceAi({
    id: "ADDENDA-016",
    name: "Deletion of fine-tuning data on termination",
    description: "AI Addendum should obligate deletion of fine-tuning / training data on termination.",
    citation: "GDPR Art. 17 (right to erasure)",
    missing_title: "Fine-tuning data deletion-on-termination missing",
    missing_description: "No obligation to delete fine-tuning / training data on termination was found.",
    explanation: "Without deletion, Customer Data can persist in vendor model weights indefinitely.",
    recommendation: "Add: 'On termination, Vendor shall delete all fine-tuning datasets derived from Customer Data within 30 days; trained model weights derived from Customer Data shall be deleted within 90 days.'",
    present_patterns: [/(delete\s+(?:fine[- ]tun\w+|training)\s+data|fine[- ]tun\w+\s+(?:data|datasets?)[^.]{0,80}(?:delet|destroy)|model\s+weights?[^.]{0,80}(?:delet|destroy))/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // EULA (ADDENDA-017..018)
  // ────────────────────────────────────────────────────────────────
  presenceEula({
    id: "ADDENDA-017",
    name: "License grant scope + prohibited uses",
    description: "EULA must include an explicit license grant scope and prohibited-uses clause.",
    citation: "EU Digital Content Directive 2019/770",
    missing_title: "License grant scope / prohibited uses missing",
    missing_description: "No license grant or prohibited-uses enumeration was found.",
    explanation: "An EULA without an explicit grant defaults to copyright law's narrow defaults; without prohibited uses, abuse vectors are unaddressed.",
    recommendation: "State the grant ('non-exclusive, non-transferable, revocable license to use the Software'); enumerate prohibited uses (reverse engineer, sublicense, competitive benchmarking).",
    present_patterns: [/(non[- ]exclusive|non[- ]transferable|revocable)\s+license/i, /(?:may\s+not|shall\s+not|prohibited\s+from)\s+(?:reverse\s+engineer|decompile|disassemble|sublicense)/i],
    default_severity: "warning",
  }),
  presenceEula({
    id: "ADDENDA-018",
    name: "EU consumer-law minimums (Digital Content Directive)",
    description: "EULAs distributed in the EU should reference Digital Content Directive 2019/770 minimums (conformity, defects, remedies).",
    citation: "EU Digital Content Directive 2019/770",
    missing_title: "EU consumer-law minimums missing",
    missing_description: "No reference to EU consumer-law minimums (Digital Content Directive 2019/770 or CRD 2011/83) was found.",
    explanation: "EU consumer law cannot be contracted around for consumer-facing EULAs.",
    recommendation: "Add: 'Nothing in this EULA limits the consumer rights conferred by Directive (EU) 2019/770 on digital content or Directive 2011/83/EU on consumer rights.'",
    present_patterns: [/(Digital\s+Content\s+Directive|Directive\s+\(?EU\)?\s*2019\/770|Consumer\s+Rights\s+Directive|Directive\s+2011\/83)/i, /(consumer\s+rights\s+(?:cannot\s+be|are\s+not)\s+(?:limited|waived))/i],
    default_severity: "info",
  }),

  // ────────────────────────────────────────────────────────────────
  // SaaS Terms of Service (ADDENDA-019)
  // ────────────────────────────────────────────────────────────────
  presenceTos({
    id: "ADDENDA-019",
    name: "FTC Click-to-Cancel alignment",
    description: "Consumer SaaS Terms of Service should align with the FTC Click-to-Cancel rule (cancellation as easy as signup).",
    citation: "FTC Click-to-Cancel Rule",
    missing_title: "FTC Click-to-Cancel alignment missing",
    missing_description: "No clause aligns cancellation difficulty with signup ease (FTC Click-to-Cancel / ROSCA).",
    explanation: "The FTC's Click-to-Cancel rule and ROSCA both require that cancellation be at least as easy as signup; phone-only cancellation for online-signed subscriptions is non-compliant.",
    recommendation: "Add: 'You may cancel your subscription using the same method you used to subscribe (e.g., online via your account).'",
    present_patterns: [/(click[- ]to[- ]cancel|cancel\s+(?:online|at\s+any\s+time)|cancel\w+\s+(?:through|via)\s+(?:your\s+account|the\s+website)|easy\s+cancellation)/i, /(ROSCA|Restore\s+Online\s+Shoppers)/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Privacy Policy Lint (ADDENDA-020)
  // ────────────────────────────────────────────────────────────────
  presencePrivacy({
    id: "ADDENDA-020",
    name: "Required privacy disclosures (CCPA + GDPR + COPPA)",
    description: "Privacy policy should contain CCPA § 1798.130 / GDPR Art. 13–14 / COPPA disclosures where applicable.",
    citation: "CCPA § 1798.130",
    missing_title: "Required privacy disclosures missing",
    missing_description: "Required privacy-policy disclosures (CCPA categories of personal information / GDPR Art. 13–14 lawful basis / COPPA child-data disclosures) were not all detected.",
    explanation: "Privacy-Policy-Lint does not opine on goodness; it verifies the regulator-required disclosures are present so a reviewer can audit alignment.",
    recommendation: "Include: categories of personal information collected, sources, purposes, third-party sharing, retention, lawful basis (GDPR), data-subject rights, COPPA child-data provisions where applicable.",
    present_patterns: [
      /(categor\w+\s+of\s+personal\s+information|categories\s+of\s+sources|personal\s+information\s+(?:we\s+collect|categories))/i,
      /(lawful\s+basis|legitimate\s+interest|consent|legal\s+obligation)/i,
      /(right\s+to\s+(?:access|delete|portability|opt[- ]out|object)|data[- ]subject\s+rights)/i,
    ],
    default_severity: "warning",
  }),
];

if (ADDENDA_RULES.length !== 20) {
  throw new Error(`Addenda ruleset must export exactly 20 rules; got ${ADDENDA_RULES.length}`);
}

/**
 * DPA US state-privacy ruleset — 25 rules (spec-v3.md §30 / Step 25).
 *
 * Covers CCPA service-provider terms (§ 1798.140(ag)) plus
 * processor-contract requirements under VCDPA, CPA, CTDPA, UCPA,
 * TDPSA, OCPA, DPDPA. Includes a rule that flags claimed-CCPA-
 * Service-Provider status without all required elements, and a
 * rule that flags multi-state contracts that fail to meet the
 * strictest applicable requirement.
 *
 * Scoped via `applies_to_playbooks` to the CCPA + multi-state
 * playbooks so v2 launch suite is untouched.
 */

import type { Rule } from "../../../finding.js";
import {
  buildLanguageRule,
  buildPresenceRule,
  type LanguageSpec,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../_regulated-rule.js";

const US_STATE_PLAYBOOKS = [
  "dpa-ccpa-service-provider",
  "dpa-multi-state-us",
  "dpa-controller-processor",
];

const CONFIG: RegulatedRuleConfig = {
  category: "dpa-us-state",
  applies_to_playbooks: US_STATE_PLAYBOOKS,
  cite_for(citation: string) {
    const lower = citation.toLowerCase();
    let url = "https://oag.ca.gov/privacy/ccpa";
    if (lower.includes("va")) url = "https://law.lis.virginia.gov/vacodefull/title59.1/chapter53/";
    else if (lower.includes("colo")) url = "https://leg.colorado.gov/sites/default/files/2021a_190_signed.pdf";
    else if (lower.includes("conn")) url = "https://www.cga.ct.gov/2022/ACT/PA/PDF/2022PA-00015-R00SB-00006-PA.PDF";
    else if (lower.includes("utah")) url = "https://le.utah.gov/xcode/Title13/Chapter61/13-61.html";
    else if (lower.includes("tex")) url = "https://capitol.texas.gov/tlodocs/88R/billtext/html/HB00004F.HTM";
    else if (lower.includes("ors")) url = "https://olis.oregonlegislature.gov/liz/2023R1/Downloads/MeasureDocument/SB0619";
    else if (lower.includes("del")) url = "https://delcode.delaware.gov/title6/c012D/";
    return { id: `us-state-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, source_url: url };
  },
};

const presence = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG);
const language = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG);

export const DPA_US_STATE_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // CCPA service-provider terms — Cal. Civ. Code § 1798.140(ag)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "USDPA-001",
    name: "CCPA: purpose-limitation clause",
    description: "CCPA service-provider contract must prohibit use of personal information outside the specific business purpose.",
    citation: "Cal. Civ. Code § 1798.140(ag)(1)(B)",
    missing_title: "CCPA purpose-limitation clause missing",
    missing_description: "No clause was found prohibiting use of personal information outside the specific business purpose.",
    explanation: "§ 1798.140(ag)(1)(B) requires the contract to prohibit the service provider from retaining, using, or disclosing personal information for any purpose other than the specific business purpose enumerated.",
    recommendation: "Add: 'Service Provider shall not retain, use, or disclose personal information for any purpose other than the specific business purpose enumerated in this Agreement.'",
    present_patterns: [/(?:specific\s+business\s+purpose|enumerated\s+(?:in\s+this\s+)?(?:contract|agreement)|business\s+purpose\s+enumerated)/i],
  }),
  presence({
    id: "USDPA-002",
    name: "CCPA: no-sale prohibition",
    description: "CCPA service-provider contract must prohibit selling personal information.",
    citation: "Cal. Civ. Code § 1798.140(ag)(1)(A)",
    missing_title: "CCPA no-sale prohibition missing",
    missing_description: "No clause was found prohibiting sale of personal information.",
    explanation: "§ 1798.140(ag)(1)(A) requires a no-sale prohibition.",
    recommendation: "Add: 'Service Provider is prohibited from selling personal information.'",
    present_patterns: [/(prohibited\s+from\s+selling|no\s+sale\s+of\s+personal\s+information|shall\s+not\s+sell\s+personal\s+information)/i],
  }),
  presence({
    id: "USDPA-003",
    name: "CCPA: no-cross-context-advertising prohibition",
    description: "CCPA service-provider contract must prohibit cross-context behavioral advertising.",
    citation: "Cal. Civ. Code § 1798.140(ag)(1)(A)",
    missing_title: "CCPA cross-context-advertising prohibition missing",
    missing_description: "No clause was found prohibiting cross-context behavioral advertising.",
    explanation: "§ 1798.140(ag)(1)(A) requires the contract to prohibit sharing including for cross-context behavioral advertising.",
    recommendation: "Add: 'Service Provider is prohibited from sharing personal information, including for cross-context behavioral advertising.'",
    present_patterns: [/cross[- ]context\s+behavioral\s+advertising/i],
  }),
  presence({
    id: "USDPA-004",
    name: "CCPA: no-combining-with-other-data restriction",
    description: "CCPA service-provider contract must prohibit combining personal information with data from other sources.",
    citation: "Cal. Civ. Code § 1798.140(ag)(1)(D)",
    missing_title: "CCPA no-combining restriction missing",
    missing_description: "No clause was found prohibiting combining personal information with other data sources.",
    explanation: "§ 1798.140(ag)(1)(D) restricts combining the personal information with data from other sources.",
    recommendation: "Add: 'Service Provider shall not combine personal information received from Business with personal information received from any other source, except as permitted by 11 CCR § 7050(c).'",
    present_patterns: [/(combin\w+\s+(personal\s+information|the\s+personal\s+data)|7050\(c\)|other\s+sources)/i],
    default_severity: "warning",
  }),
  presence({
    id: "USDPA-005",
    name: "CCPA: same-level-of-privacy-protection",
    description: "CCPA contract must require the service provider to comply with applicable CCPA obligations and provide the same level of privacy protection.",
    citation: "Cal. Civ. Code § 1798.100(d)",
    missing_title: "CCPA same-level-of-protection clause missing",
    missing_description: "No clause was found requiring the same level of privacy protection.",
    explanation: "§ 1798.100(d) requires the contract to obligate the third party / service provider to comply with applicable obligations and provide the same level of privacy protection as required by the CCPA.",
    recommendation: "Add: 'Service Provider shall comply with all applicable obligations under the CCPA and provide the same level of privacy protection as required by the CCPA.'",
    present_patterns: [/same\s+level\s+of\s+privacy\s+protection|comply\s+with\s+all\s+applicable\s+(?:obligations|ccpa)/i],
  }),
  presence({
    id: "USDPA-006",
    name: "CCPA: certification of understanding",
    description: "CCPA service-provider contract should require service-provider certification of CCPA understanding.",
    citation: "Cal. Code Regs. tit. 11, § 7051(a)(7)",
    missing_title: "CCPA certification of understanding missing",
    missing_description: "No service-provider certification of CCPA understanding was found.",
    explanation: "§ 7051(a)(7) expects the contract to require service-provider certification that it understands the restrictions and will comply.",
    recommendation: "Add: 'Service Provider certifies that it understands the restrictions in this Agreement and the CCPA and will comply with them.'",
    present_patterns: [/(certifies?|certification).{0,80}(understand|restrictions|ccpa|comply)/is],
    default_severity: "warning",
  }),
  presence({
    id: "USDPA-007",
    name: "CCPA: monitoring / oversight right",
    description: "CCPA contract must grant the business the right to take reasonable steps to ensure consistent use.",
    citation: "Cal. Civ. Code § 1798.140(ag)(1)(C)",
    missing_title: "CCPA monitoring right missing",
    missing_description: "No clause was found granting the business reasonable monitoring / oversight rights.",
    explanation: "§ 1798.140(ag)(1)(C) requires the contract to grant the business the right to take reasonable and appropriate steps to ensure that the service provider uses the personal information in a manner consistent with the business's obligations under the CCPA.",
    recommendation: "Add: 'Business may take reasonable and appropriate steps to ensure that Service Provider uses personal information in a manner consistent with Business's obligations under the CCPA.'",
    present_patterns: [/(reasonable\s+and\s+appropriate\s+steps|monitor|oversight\s+right|right\s+to\s+(?:audit|monitor|inspect))/i],
  }),
  presence({
    id: "USDPA-008",
    name: "CCPA: assistance with consumer requests",
    description: "CCPA service-provider contract must require assistance with consumer rights requests.",
    citation: "Cal. Code Regs. tit. 11, § 7051(a)(8)",
    missing_title: "CCPA consumer-request assistance missing",
    missing_description: "No clause was found requiring assistance with verifiable consumer requests.",
    explanation: "§ 7051(a)(8) requires the contract to require the service provider to enable the business to comply with verifiable consumer requests.",
    recommendation: "Add: 'Service Provider shall assist Business in responding to verifiable consumer requests under the CCPA.'",
    present_patterns: [/(verifiable\s+consumer\s+requests?|consumer\s+rights?\s+(request|assist)|assist.{0,80}consumer)/is],
  }),
  presence({
    id: "USDPA-009",
    name: "CCPA: notification of inability to comply",
    description: "CCPA service-provider must notify business if it can no longer meet its obligations under CCPA.",
    citation: "Cal. Code Regs. tit. 11, § 7051(a)(6)",
    missing_title: "CCPA inability-to-comply notification missing",
    missing_description: "No clause was found requiring notification if service provider can no longer meet CCPA obligations.",
    explanation: "§ 7051(a)(6) requires the service provider to notify the business if it makes a determination that it can no longer meet its obligations under the CCPA.",
    recommendation: "Add: 'Service Provider shall notify Business if it makes a determination that it can no longer meet its obligations under the CCPA.'",
    present_patterns: [/(no\s+longer\s+(meet|able\s+to\s+meet)|notify.{0,80}(can\s+no\s+longer|unable\s+to\s+meet|inability))/is],
  }),
  presence({
    id: "USDPA-010",
    name: "CCPA: subcontractor flow-down",
    description: "CCPA service-provider must require subcontractors to meet the same CCPA obligations.",
    citation: "Cal. Code Regs. tit. 11, § 7051(b)",
    missing_title: "CCPA subcontractor flow-down missing",
    missing_description: "No clause was found requiring subcontractors to meet the same CCPA obligations.",
    explanation: "§ 7051(b) requires the contract with subcontractors to include the same provisions.",
    recommendation: "Add a subcontractor flow-down requiring the same restrictions as in this Agreement.",
    present_patterns: [/(subcontractor|sub[- ]processor).{0,200}(same\s+(restrictions|obligations|provisions)|equivalent)/is],
  }),

  // ────────────────────────────────────────────────────────────────
  // Multi-state common requirements (VCDPA / CPA / CTDPA / UCPA /
  // TDPSA / OCPA / DPDPA) — purpose-limitation, duration, data type,
  // deletion/return, confidentiality, audit cooperation, subcontractor
  // flow-down
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "USDPA-011",
    name: "Multi-state: processing instructions clear",
    description: "Processor contract must set out the processing instructions binding on the processor.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / Conn. Gen. Stat. § 42-520 / similar",
    missing_title: "Processing-instructions clause missing",
    missing_description: "No clause was found setting out the processing instructions.",
    explanation: "Every state privacy statute requires the contract to clearly set out processing instructions.",
    recommendation: "Add a clause stating: 'Processor shall process personal data only pursuant to Controller's documented instructions, as set forth in this Agreement and any Annex.'",
    present_patterns: [/(processing\s+instructions|instructions\s+for\s+processing|documented\s+instructions)/i],
  }),
  presence({
    id: "USDPA-012",
    name: "Multi-state: nature and purpose of processing",
    description: "Processor contract must specify the nature and purpose of the processing.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Nature-and-purpose clause missing",
    missing_description: "No clause was found stating the nature and purpose of processing.",
    explanation: "VCDPA, CPA, CTDPA, UCPA, TDPSA, OCPA, DPDPA all require the contract to state the nature and purpose of processing.",
    recommendation: "Add a 'Nature and Purpose of Processing' clause.",
    present_patterns: [/nature\s+and\s+purpose\s+of\s+(?:the\s+)?processing/i],
  }),
  presence({
    id: "USDPA-013",
    name: "Multi-state: type of personal data identified",
    description: "Processor contract must identify the type of personal data processed.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Type-of-data clause missing",
    missing_description: "No clause was found identifying the type of personal data.",
    explanation: "Each state requires the contract to specify the categories of personal data.",
    recommendation: "Add an Annex listing the categories of personal data processed.",
    present_patterns: [/(type|categor(?:y|ies))\s+of\s+(personal\s+)?(?:data|information)/i],
  }),
  presence({
    id: "USDPA-014",
    name: "Multi-state: duration of processing",
    description: "Processor contract must specify the duration of processing.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Duration-of-processing clause missing",
    missing_description: "No clause was found stating the duration of processing.",
    explanation: "Every state's processor-contract statute requires the duration to be set out.",
    recommendation: "State that processing continues for the term of the agreement.",
    present_patterns: [/duration\s+of\s+(?:the\s+)?processing|processing\s+(?:shall|will)\s+continue/i],
  }),
  presence({
    id: "USDPA-015",
    name: "Multi-state: deletion or return",
    description: "Processor must delete or return personal data at end of services at controller's direction.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Deletion-or-return clause missing",
    missing_description: "No clause was found requiring deletion or return of personal data at end of services.",
    explanation: "VCDPA, CPA, CTDPA all require deletion or return at end of services.",
    recommendation: "Add: 'At Controller's direction, Processor shall delete or return all Personal Data at the end of the provision of services.'",
    present_patterns: [/(delete\s+or\s+return|return\s+or\s+delete).{0,80}(personal\s+(data|information)|end\s+of\s+(?:the\s+)?(?:provision\s+of\s+)?services)/is],
  }),
  presence({
    id: "USDPA-016",
    name: "Multi-state: confidentiality duty",
    description: "Processor must ensure persons processing personal data are subject to a duty of confidentiality.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Confidentiality duty clause missing",
    missing_description: "No clause was found requiring confidentiality of authorized persons.",
    explanation: "Every state requires the processor to subject authorized personnel to a duty of confidentiality.",
    recommendation: "Add: 'Processor shall ensure that each person processing Personal Data is subject to a duty of confidentiality.'",
    present_patterns: [/(duty\s+of\s+confidentiality|committed\s+to\s+confidentiality|bound\s+by\s+confidentiality)/i],
  }),
  presence({
    id: "USDPA-017",
    name: "Multi-state: audit cooperation",
    description: "Processor must cooperate with reasonable assessments / audits by the controller.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Audit cooperation clause missing",
    missing_description: "No clause was found obligating the processor to cooperate with reasonable assessments.",
    explanation: "VCDPA and several state statutes require the processor to allow and cooperate with reasonable assessments by the controller.",
    recommendation: "Add: 'Processor shall allow and cooperate with reasonable assessments by Controller or Controller's designated assessor.'",
    present_patterns: [/(reasonable\s+assessments|allow\s+(?:and\s+)?(?:cooperate\s+with|contribute\s+to)\s+(?:audits|assessments)|right\s+to\s+(?:audit|assess))/i],
  }),
  presence({
    id: "USDPA-018",
    name: "Multi-state: subcontractor written contract",
    description: "Processor must engage subcontractors only pursuant to a written contract.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Subcontractor written-contract clause missing",
    missing_description: "No clause was found requiring written contracts with subcontractors.",
    explanation: "Every state's processor-contract statute requires subcontractor engagement to be by written contract imposing equivalent obligations.",
    recommendation: "Add: 'Processor shall engage any subcontractor only pursuant to a written contract requiring the subcontractor to meet the obligations of Processor under this Agreement.'",
    present_patterns: [/(subcontractor|sub[- ]processor).{0,200}(written\s+contract|written\s+agreement|same\s+obligations)/is],
  }),
  presence({
    id: "USDPA-019",
    name: "Multi-state: information for compliance demonstration",
    description: "Processor must make information available to demonstrate compliance.",
    citation: "Va. Code § 59.1-579 / Colo. Rev. Stat. § 6-1-1305 / similar",
    missing_title: "Compliance-demonstration clause missing",
    missing_description: "No clause was found requiring the processor to provide information demonstrating compliance.",
    explanation: "Most state privacy statutes require the processor to make information available demonstrating compliance.",
    recommendation: "Add: 'Processor shall make available to Controller information necessary to demonstrate compliance with this Agreement and applicable state privacy law.'",
    present_patterns: [/(demonstrate\s+compliance|information\s+necessary\s+to\s+demonstrate)/i],
  }),

  // ────────────────────────────────────────────────────────────────
  // Cross-cutting risk rules
  // ────────────────────────────────────────────────────────────────
  language({
    id: "USDPA-020",
    name: "Service Provider status claimed but not earned",
    description: "Flags a document that claims CCPA 'Service Provider' status but does not contain the §7051 required elements.",
    citation: "Cal. Civ. Code § 1798.140(ag); 11 CCR § 7051",
    bad_title: "Claimed 'Service Provider' status without required elements",
    bad_description: "Document claims CCPA 'Service Provider' status but is missing one or more § 7051 required elements.",
    explanation: "Claiming Service Provider status without meeting the § 7051 contract requirements means the recipient may be reclassified as a 'third party' — triggering sale / share consequences for the disclosing party.",
    recommendation: "Add the missing § 7051(a)(1)–(8) elements, or remove the Service Provider claim and treat the recipient as a third party.",
    bad_patterns: [
      /(service\s+provider\s+(?:status|under\s+the\s+ccpa))(?!.{0,500}(?:specific\s+business\s+purpose|same\s+level\s+of\s+privacy\s+protection))/is,
    ],
    default_severity: "critical",
  }),
  language({
    id: "USDPA-021",
    name: "Multi-state contract does not meet strictest applicable requirement",
    description: "Flags multi-jurisdiction DPAs that explicitly contemplate multiple states but use weaker (e.g., Utah-style) language.",
    citation: "Multi-state DPA compliance",
    bad_title: "Multi-state contract may not meet strictest applicable requirement",
    bad_description: "Detected a multi-state DPA using minimum 'Utah-style' contract terms where stricter state law (CCPA, CPA, CTDPA) may apply.",
    explanation: "When a contract spans multiple states, the strictest applicable requirement should govern. Using minimum-common-denominator language risks non-compliance with the stricter states.",
    recommendation: "Adopt the strictest applicable state's required elements (typically CCPA / CPA / CTDPA) and document the multi-state coverage explicitly.",
    bad_patterns: [
      /multi[- ]state|several\s+(?:US\s+)?states|applicable\s+US\s+state\s+(?:privacy\s+)?law/i,
    ],
    default_severity: "info",
  }),
  presence({
    id: "USDPA-022",
    name: "Sensitive personal information separately addressed",
    description: "DPAs should specifically address sensitive personal information (SPI) handling.",
    citation: "Cal. Civ. Code § 1798.121",
    missing_title: "Sensitive personal information handling not addressed",
    missing_description: "No clause was found specifically addressing sensitive personal information.",
    explanation: "CCPA / CPRA, CPA, CTDPA define sensitive personal information / sensitive data and impose heightened obligations.",
    recommendation: "Add a 'Sensitive Personal Information' clause describing categories handled and SPI-specific safeguards.",
    present_patterns: [/sensitive\s+(personal\s+)?(?:information|data)/i],
    default_severity: "warning",
  }),
  presence({
    id: "USDPA-023",
    name: "Consumer rights process documented",
    description: "DPA should document the process for handling consumer rights requests.",
    citation: "Multi-state consumer-rights obligations",
    missing_title: "Consumer-rights process not documented",
    missing_description: "No clause was found documenting the process for consumer rights requests (access, deletion, opt-out).",
    explanation: "All US state privacy statutes provide consumer rights; the DPA should describe the operational handoff.",
    recommendation: "Add a 'Consumer Rights Requests' clause describing intake, verification, fulfillment, and timeline.",
    present_patterns: [/(consumer\s+rights?\s+(?:request|process)|access\s+request|deletion\s+request|opt[- ]out|right\s+to\s+(?:access|delete|opt-out|correct))/i],
    default_severity: "warning",
  }),
  presence({
    id: "USDPA-024",
    name: "Data minimization principle referenced",
    description: "DPA should reference the data-minimization principle.",
    citation: "Cal. Civ. Code § 1798.100(c) / Multi-state minimization",
    missing_title: "Data-minimization principle not referenced",
    missing_description: "No reference to data minimization was found.",
    explanation: "Several state privacy statutes incorporate a data-minimization principle requiring collection of only what is reasonably necessary.",
    recommendation: "Add: 'Personal data collected and processed shall be limited to what is reasonably necessary and proportionate to the disclosed purpose.'",
    present_patterns: [/(data\s+minim(?:ization|isation)|reasonably\s+necessary|necessary\s+and\s+proportionate)/i],
    default_severity: "warning",
  }),
  presence({
    id: "USDPA-025",
    name: "Personal information / data referenced",
    description: "Document should reference 'personal information' or 'personal data'; absence likely means the wrong template.",
    citation: "Multi-state US privacy statutes",
    missing_title: "Document does not reference personal information / data",
    missing_description: "No references to personal information or personal data were detected.",
    explanation: "A US DPA template that never mentions 'personal information' or 'personal data' is highly likely to be the wrong template.",
    recommendation: "Use a DPA template that explicitly references personal information / personal data throughout.",
    present_patterns: [/personal\s+(information|data)/i],
  }),
];

if (DPA_US_STATE_RULES.length !== 25) {
  throw new Error(`DPA-US-state ruleset must export exactly 25 rules; got ${DPA_US_STATE_RULES.length}`);
}

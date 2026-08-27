/**
 * v5 sub-domain K′ — US insurance policy and coverage-position review
 * (spec-v45.md §6.K). Rule ids continue the INS namespace at 101.
 *
 * These rules read a policy or a carrier letter the way coverage counsel
 * reads it: they check that the provisions the coverage fight will turn
 * on are present and locatable. They never opine on whether a claim is
 * covered — that is the attorney's judgment on the facts.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { stateLaw, practice } from "./_helpers.js";

const C = "insurance";

const DO = pack("do-policy", C, [
  {
    id: "INS-101",
    name: "Side A / B / C structure and limits",
    cite: practice("do-sides", "Side A, B, and C coverage structure in D&O policies"),
    pat: [
      /(side\s+[abc]\b|insuring\s+(agreement|clause)\s+[abc])/i,
      /(limit\s+of\s+liability|aggregate\s+limit|separate\s+(limit|excess)|dedicated)/i,
    ],
    why: "Side A protects individuals where the company cannot indemnify — the coverage that matters in insolvency or a derivative settlement. Whether it shares the aggregate limit with Side B and C decides whether directors are protected when the company has exhausted it.",
    fix: "Identify each insuring agreement, its limit, and whether Side A has a dedicated or additional limit outside the shared aggregate.",
    sev: "critical",
  },
  {
    id: "INS-102",
    name: "Claims-made-and-reported trigger and notice",
    cite: practice("claims-made", "claims-made-and-reported triggers and notice conditions"),
    pat: [
      /claims?[- ]made/i,
      /(reported\s+(to\s+the\s+insurer\s+)?during|notice\s+(of\s+(a\s+)?claim)|as\s+soon\s+as\s+practicable|within\s+\d+\s+days\s+of)/i,
    ],
    why: "A claims-made-and-reported policy covers only claims both made and reported during the period. Late notice is the most common ground for denial, and in most states no prejudice to the insurer need be shown.",
    fix: "State the trigger, the notice deadline and recipient, and the notice-of-circumstances provision that locks coverage into the current period.",
    sev: "critical",
  },
  {
    id: "INS-103",
    name: "Insured-versus-insured exclusion and carve-backs",
    cite: practice(
      "ivi-exclusion",
      "the insured versus insured exclusion and its standard carve-backs",
    ),
    pat: [
      /insured\s+(v(ersus|\.)?|vs\.?)\s+insured/i,
      /(carve-?back|shall\s+not\s+apply\s+to|derivative\s+(action|demand)|bankruptcy\s+trustee|whistleblower|former\s+(director|officer))/i,
    ],
    why: "Without carve-backs, the IvI exclusion defeats derivative suits, trustee claims in bankruptcy, and whistleblower retaliation claims — exactly the claims D&O is bought for.",
    fix: "Confirm carve-backs for derivative actions brought without insured assistance, claims by a bankruptcy trustee or examiner, whistleblower claims, and claims by former directors and officers.",
    sev: "critical",
  },
  {
    id: "INS-104",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Conduct exclusions with final-adjudication wording",
    cite: practice(
      "conduct-exclusion",
      "fraud and personal-profit exclusions and the final adjudication standard",
    ),
    pat: [
      /(fraud|dishonest|personal\s+profit|deliberate\s+criminal)/i,
      /(final[-\s]+(and\s+non-?appealable\s+)?adjudication|non-?appealable|in\s+the\s+underlying\s+(action|proceeding))/i,
    ],
    why: "A conduct exclusion triggered by allegation, or by a finding in any proceeding including a coverage action, lets the carrier cut off defense costs mid-case. Final, non-appealable adjudication in the underlying action is the policyholder standard.",
    fix: "Confirm the conduct exclusions apply only on a final, non-appealable adjudication in the underlying action, and that defense costs are advanced until then.",
    sev: "critical",
  },
  {
    id: "INS-105",
    name: "Severability of the application and of exclusions",
    cite: practice(
      "severability",
      "severability of the application and non-imputation in D&O policies",
    ),
    pat: [
      /severab/i,
      /(application|rescission|imput|knowledge\s+of\s+one\s+insured|shall\s+not\s+be\s+imputed)/i,
    ],
    why: "Without severability, one officer's misstatement in the application can void coverage for every innocent director. Full severability with a narrow imputation group is the market standard.",
    fix: "Confirm the application is severable, that no knowledge is imputed among insured persons, and identify the narrow group whose knowledge is imputed to the company.",
  },
  {
    id: "INS-106",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Defense-cost treatment",
    cite: practice("defense-costs", "duty to defend versus duty to advance in D&O policies"),
    pat: [
      /defen(se|ce)[-\s]+costs?/i,
      /(duty\s+to\s+defend|advance|within\s+\d+\s+days|allocation|reimburse)/i,
    ],
    why: "Most D&O is non-duty-to-defend with an advancement obligation. Whether costs are advanced as incurred or reimbursed later, and how mixed covered/uncovered matters are allocated, determines whether the policy funds the defense in real time.",
    fix: "State whether the insurer has a duty to defend or to advance, the advancement deadline, the consent-to-counsel process, and the allocation standard for mixed claims.",
  },
  {
    id: "INS-107",
    name: "Run-off or tail on change of control",
    cite: practice("do-runoff", "change of control and run-off coverage in D&O policies"),
    pat: [
      /(change\s+(in|of)\s+control|transaction|merger)/i,
      /(run-?off|tail|extended\s+reporting\s+period|discovery\s+period|\d+\s+years)/i,
    ],
    why: "On a change of control the policy typically converts to run-off for claims arising from pre-closing acts. Negotiating the run-off length and premium after signing is far more expensive than before.",
    fix: "Confirm the change-of-control provision, the run-off period available, and the premium formula, and negotiate a six-year tail option at a pre-agreed rate.",
  },
]);

const CYBER = pack("cyber-insurance-policy", C, [
  {
    id: "INS-108",
    name: "First-party and third-party coverage grants",
    cite: practice(
      "cyber-grants",
      "first-party and third-party insuring agreements in cyber policies",
    ),
    pat: [
      /(first[- ]party|third[- ]party)/i,
      /(insuring\s+agreement|breach\s+response|privacy\s+liability|network\s+security\s+liability|business[-\s]+interruption|extortion)/i,
    ],
    why: "Cyber policies are a bundle of narrow grants, not one broad promise. A loss that falls between two grants — say, a vendor's outage with no security failure — is uncovered even though the policy is titled cyber.",
    fix: "Enumerate each insuring agreement with its sublimit: breach response, business interruption, extortion, data restoration, privacy liability, network security liability, and media liability.",
    sev: "critical",
  },
  {
    id: "INS-109",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Business-interruption waiting period and measurement",
    cite: practice(
      "cyber-bi",
      "waiting periods and loss measurement in cyber business interruption coverage",
    ),
    pat: [
      /(business[-\s]+interruption|income\s+loss|period\s+of\s+(restoration|indemnity))/i,
      /(waiting\s+period|\d+\s+hours|hourly|actual\s+loss\s+sustained|contingent)/i,
    ],
    why: "The waiting period — commonly 8 to 12 hours — is a deductible measured in time, and most outages resolve inside it. How the income loss is measured and whether dependent business interruption is included decide whether the grant pays anything.",
    fix: "State the waiting period, the period of restoration, the measurement basis for income loss, and whether contingent/dependent business interruption is covered.",
    sev: "critical",
  },
  {
    id: "INS-110",
    name: "Ransomware sublimit and consent requirement",
    cite: practice("cyber-ransom", "extortion sublimits and consent conditions in cyber policies"),
    pat: [
      /(ransom|extortion|cyber\s+extortion)/i,
      /(sublimit|prior\s+(written\s+)?consent|co-?insurance|ofac)/i,
    ],
    why: "Extortion coverage typically carries a sublimit and co-insurance, and payment without the insurer's prior consent voids it. OFAC sanctions screening is a separate legal condition on any payment.",
    fix: "State the extortion sublimit, any co-insurance, the prior-consent requirement, and the sanctions-screening condition on payment.",
  },
  {
    id: "INS-111",
    name: "Panel-provider and pre-approval constraints",
    cite: practice("cyber-panel", "panel counsel and vendor pre-approval in cyber policies"),
    pat: [
      /panel/i,
      /(breach\s+coach|approved\s+(vendor|counsel|forensic)|prior\s+(written\s+)?(approval|consent)|pre-?approved)/i,
    ],
    why: "Costs incurred before the insurer is notified, or with a non-panel vendor, are commonly excluded. The first hour of an incident is exactly when a company reaches for the firm it already knows.",
    fix: "Identify the panel and the process for pre-approving preferred counsel and forensic vendors, and confirm the notification step required before incurring costs.",
    sev: "critical",
  },
  {
    id: "INS-112",
    name: "War, infrastructure, and nation-state exclusions",
    cite: practice("cyber-war", "war and cyber-operation exclusions in cyber policies"),
    pat: [
      /(war\s+exclusion|act\s+of\s+war|hostile|warlike)/i,
      /(nation-?state|cyber\s+operation|critical\s+infrastructure|state-?sponsored|attribut)/i,
    ],
    why: "After Merck and Mondelez, Lloyd's mandated state-backed cyber exclusions. How attribution is determined — and by whom — now decides whether a major attack is covered at all.",
    fix: "Read the war and cyber-operation exclusions, identify the attribution mechanism and who makes the determination, and negotiate carve-backs for unattributed or collateral impacts.",
    sev: "critical",
  },
  {
    id: "INS-113",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Retroactive date and prior-knowledge exclusion",
    cite: practice("cyber-retro", "retroactive dates and prior knowledge conditions"),
    pat: [
      /(retroactive\s+date|prior\s+acts)/i,
      /(prior[-\s]+knowledge|known\s+(to|by)|before\s+the\s+inception|continuity\s+date)/i,
    ],
    why: "Dwell time in an intrusion is routinely measured in months. A retroactive date at the current policy inception excludes the compromise that has already happened but has not been found.",
    fix: "Confirm the retroactive date reaches back to first placement, and read the prior-knowledge condition to see whose knowledge and what level of awareness triggers it.",
  },
]);

const ROR = pack("reservation-of-rights-letter", C, [
  {
    id: "INS-114",
    name: "Specific policy provisions cited",
    cite: stateLaw(
      "reservation-specificity",
      "the requirement that a reservation of rights identify the provisions relied on",
      "https://www.law.cornell.edu/wex/insurance_law",
    ),
    pat: [
      /(policy\s+(provision|section|exclusion)|exclusion\s+[a-z0-9]|endorsement)/i,
      /(provides|states|quoted|reserves?\s+(its|all)\s+rights\s+under)/i,
    ],
    why: "A general reservation that cites no provision is ineffective in many states and can waive the defense entirely. The letter must tell the insured what the carrier might later rely on and why.",
    fix: "Quote each policy provision, exclusion, and condition relied on, and connect each to the facts that make it potentially applicable.",
    sev: "critical",
  },
  {
    id: "INS-115",
    name: "Facts giving rise to each reservation",
    cite: practice("ror-facts", "factual specificity in reservation of rights letters"),
    pat: [
      /(the\s+complaint\s+alleges|based\s+on\s+the\s+(information|facts)|our\s+investigation)/i,
      /(if\s+(it\s+is\s+)?(determined|established)|to\s+the\s+extent\s+that|may\s+(not\s+)?be\s+covered)/i,
    ],
    why: "The insured needs to know which allegations threaten coverage so it can direct its defense accordingly — the conflict that gives rise to independent counsel rights in the first place.",
    fix: "Tie each reserved defense to the specific allegations or facts that could trigger it, and state what determination would resolve it.",
  },
  {
    id: "INS-116",
    name: "Defense provided or denied",
    cite: practice("ror-defense", "defense position statements in coverage letters"),
    pat: [
      /defen(d|se|ce)/i,
      /(will\s+(provide|defend|fund)|agrees?\s+to\s+defend|declines?\s+to\s+defend|subject\s+to\s+(this|a\s+full)\s+reservation)/i,
    ],
    why: "An insured reading a reservation letter needs one answer before all others: is the carrier defending? Ambiguity here is the source of most bad-faith claims arising from these letters.",
    fix: "State plainly whether the insurer is defending, under what reservation, and who is appointed or approved as defense counsel.",
    sev: "critical",
  },
  {
    id: "INS-117",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Independent-counsel trigger",
    cite: stateLaw(
      "independent-counsel",
      "independent (Cumis) counsel rights arising from a conflict created by a reservation of rights",
      "https://www.law.cornell.edu/wex/insurance_law",
    ),
    pat: [
      /(independent[-\s]+counsel|cumis)/i,
      /(conflict\s+of\s+interest|entitled\s+to\s+(select|retain)|rate|civil\s+code\s+§?\s*2860)/i,
    ],
    why: "In California and several other states, a reservation that creates a conflict entitles the insured to independent counsel at the insurer's expense, subject to rate limits. Carriers that do not address it invite a demand and a fee fight.",
    fix: "State the insurer's position on independent counsel, whether a conflict is acknowledged, and the applicable rate and qualification standards.",
  },
  {
    id: "INS-118",
    name: "Right to seek declaratory relief reserved",
    cite: practice("ror-dj", "reservation of the right to seek a declaratory judgment"),
    pat: [
      /declaratory/i,
      /(reserves?\s+the\s+right|may\s+(seek|file|commence)|judicial\s+determination|action\s+to\s+determine)/i,
    ],
    why: "If the carrier intends to litigate coverage while defending, reserving the right in the letter is what preserves it and puts the insured on notice.",
    fix: "Reserve the right to seek a declaratory judgment on coverage and to withdraw from the defense on stated conditions and notice.",
  },
]);

export const V5_INSURANCE_RULES: readonly Rule[] = [...DO, ...CYBER, ...ROR];

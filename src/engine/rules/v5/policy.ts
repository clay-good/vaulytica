/**
 * v5 sub-domain O′ — US enterprise compliance policies (spec-v45.md
 * §6.O). Rule ids continue the POL namespace at 101.
 *
 * A policy is not a contract, so these rules check something different
 * from the rest of the catalog: whether the policy states the elements
 * the governing framework enumerates, and whether it names an owner, a
 * scope, and a review cadence. They never assert that an organization is
 * compliant with anything.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { agency, cfr, expressDenial, practice, stateLaw, usc } from "./_helpers.js";

const C = "policy";

const INFOSEC = pack("information-security-policy", C, [
  {
    id: "POL-101",
    name: "Scope, ownership, and review cadence",
    cite: agency(
      "NIST",
      "Cybersecurity Framework 2.0 — the Govern function",
      "https://www.nist.gov/cyberframework",
    ),
    pat: [
      /(scope|applies\s+to)/i,
      /(policy\s+owner|reviewed\s+(annually|at\s+least)|approved\s+by|effective\s+date|version)/i,
    ],
    why: "CSF 2.0 added Govern as a function precisely because policies without an owner, a scope, and a review cycle decay silently. Auditors ask for the approval and review record before they read the content.",
    fix: "State the systems and people in scope, the named policy owner, the approving authority, the effective date, and the review cadence.",
    sev: "critical",
  },
  {
    id: "POL-102",
    name: "Access control and least privilege",
    cite: agency(
      "NIST",
      "SP 800-53 Rev. 5 — Access Control (AC) family",
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    pat: [
      /(access\s+control|least\s+privilege|need-?to-?know)/i,
      /(provisioning|deprovision|role-?based|multi-?factor|privileged\s+access|access\s+review)/i,
    ],
    why: "Access control is the control family every framework and every breach report starts with. Joiner-mover-leaver and privileged-access handling are the two places policies most often stop short.",
    fix: "State the access-control model, MFA requirements, the joiner-mover-leaver process, privileged-access handling, and the periodic access review.",
    sev: "critical",
  },
  {
    id: "POL-103",
    name: "Data classification and encryption standards",
    cite: agency(
      "NIST",
      "SP 800-53 Rev. 5 — System and Communications Protection (SC) family",
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    pat: [
      /(data\s+classification|classification\s+(scheme|levels)|confidential|restricted)/i,
      /(encrypt|at\s+rest|in\s+transit|tls|key\s+management)/i,
    ],
    why: "Encryption obligations, retention rules, and breach-notification safe harbors all key off the classification of the data. A policy with encryption but no classification cannot say what must be encrypted.",
    fix: "Define the classification levels, the handling requirement at each, and the encryption standards for data at rest and in transit with key-management responsibility.",
  },
  {
    id: "POL-104",
    name: "Vulnerability and patch management",
    cite: agency(
      "NIST",
      "SP 800-53 Rev. 5 — Risk Assessment (RA) and System and Information Integrity (SI) families",
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    pat: [
      /(vulnerabilit|patch)/i,
      /(scan|remediat|severity|critical|within\s+\d+\s*\)?\s*days|sla)/i,
    ],
    why: "Unpatched known vulnerabilities remain the leading initial access vector. A policy without remediation timeframes by severity gives nobody a deadline to miss.",
    fix: "State the scanning cadence, the remediation timeframes by severity, the exception process, and the handling of end-of-life systems.",
  },
  {
    id: "POL-105",
    name: "Logging, monitoring, and retention",
    cite: agency(
      "NIST",
      "SP 800-53 Rev. 5 — Audit and Accountability (AU) family",
      "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    pat: [
      /(logging|audit\s+log|monitor)/i,
      /(retain|retention|siem|alert|\d+\s+(days|months|year))/i,
    ],
    why: "Without logs, an incident cannot be scoped, and short retention is the reason many investigations cannot establish what was taken. The retention period is the single most consequential number in the policy.",
    fix: "State what is logged, where logs are centralized, the retention period, the monitoring and alerting expectations, and log-integrity protections.",
  },
  {
    id: "POL-106",
    name: "Third-party and vendor security requirements",
    cite: agency(
      "NIST",
      "Cybersecurity Framework 2.0 — Cybersecurity Supply Chain Risk Management (GV.SC)",
      "https://www.nist.gov/cyberframework",
    ),
    pat: [
      /(third[- ]party|vendor|supplier|service\s+provider)/i,
      /(assessment|due\s+diligence|contractual\s+(requirements|security)|risk\s+tier)/i,
    ],
    why: "Most reportable incidents now begin at a vendor. The policy has to connect procurement to security review and to the contract terms that flow the requirements down.",
    fix: "State the vendor risk-tiering method, the assessment required at each tier, the contractual security requirements, and the reassessment cadence.",
  },
  {
    id: "POL-107",
    name: "Exception process and enforcement",
    cite: practice("policy-exceptions", "exception handling and enforcement in security policies"),
    pat: [
      /(exception|waiver|deviation)/i,
      /(approv|risk\s+accept|expiration|documented|disciplin|enforcement)/i,
    ],
    why: "Every organization grants exceptions. A policy without a documented, time-limited, risk-accepted exception path gets exceptions anyway — undocumented ones that nobody revisits.",
    fix: "State who may approve an exception, the documentation and risk-acceptance required, the maximum duration and renewal, and the consequences of non-compliance.",
  },
]);

const AUP = pack("acceptable-use-policy", C, [
  {
    id: "POL-108",
    name: "Systems covered and users bound",
    cite: practice("aup-scope", "scope definition in acceptable use policies"),
    pat: [
      /(company\s+(systems|resources|equipment|network)|information\s+systems)/i,
      /(applies\s+to|employees,?\s+contractors|all\s+users|personal\s+devices)/i,
    ],
    why: "An AUP that does not say whether it reaches personal devices, personal accounts used for work, or contractors leaves the most common enforcement questions unanswered.",
    fix: "Define the covered systems (including cloud services and personal devices used for work) and the categories of users bound.",
  },
  {
    id: "POL-109",
    name: "Monitoring notice and privacy expectation",
    cite: usc(
      "18",
      "2511",
      "Electronic Communications Privacy Act — interception of communications and the consent exception",
    ),
    pat: [
      /monitor/i,
      /(no\s+expectation\s+of\s+privacy|consent\s+to\s+(such\s+)?monitoring|may\s+(be\s+)?(access|review|inspect))/i,
    ],
    why: "The ECPA consent exception is what makes workplace monitoring lawful, and several states (Connecticut, Delaware, New York) require written notice of electronic monitoring. The notice is the legal basis, not a courtesy.",
    fix: "State that company systems may be monitored, accessed, and disclosed, that users have no expectation of privacy in them, and satisfy any state written-notice requirement.",
    sev: "critical",
  },
  {
    id: "POL-110",
    name: "Prohibited uses enumerated",
    cite: practice("aup-prohibited", "prohibited use enumeration in acceptable use policies"),
    pat: [
      /(prohibit|may\s+not|(?:shall|will)\s+not|unacceptable\s+use)/i,
      /(harass|illegal|unauthorized\s+(access|software)|circumvent|malware|personal\s+(business|gain))/i,
    ],
    why: "Discipline for conduct the policy never named is where employment claims start. The enumeration is what makes enforcement defensible.",
    fix: "Enumerate the prohibited uses, including unauthorized access, circumventing controls, installing unapproved software, harassment, and use of unapproved AI or file-sharing services.",
  },
  {
    id: "POL-111",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "NLRA § 7 protected-activity savings clause",
    cite: usc("29", "157", "National Labor Relations Act § 7 — rights of employees"),
    pat: [
      /(section\s+7|nlra|national\s+labor\s+relations|protected[-\s]+(concerted\s+)?activity)/i,
      /(nothing\s+in\s+this\s+policy|(?:shall|will)\s+not\s+be\s+(construed|interpreted)\s+to\s+(prohibit|restrict)|wages,?\s+hours,?\s+(and|or)\s+(other\s+)?(terms|working\s+conditions))/i,
    ],
    why: "The Board's Stericycle standard treats a work rule as presumptively unlawful if a reasonable employee could read it to chill § 7 activity. A savings clause does not cure every rule, but its absence is a standing exposure for confidentiality and communications rules.",
    fix: "Add a savings clause stating that nothing in the policy restricts employees' rights under Section 7 of the NLRA to discuss wages, hours, and working conditions.",
    sev: "critical",
  },
  {
    id: "POL-112",
    name: "Discipline and enforcement",
    cite: practice("aup-enforcement", "enforcement and discipline in acceptable use policies"),
    pat: [
      /(disciplin|violation)/i,
      /(up\s+to\s+and\s+including\s+termination|report(ing)?\s+(a\s+)?violation|investigat)/i,
    ],
    why: "A policy with no stated consequence is a suggestion. It also needs a reporting channel, or violations reach management only by accident.",
    fix: "State the consequences of violation, the reporting channel for suspected violations, and the non-retaliation commitment for good-faith reports.",
  },
]);

const EXPORT = pack("export-control-policy", C, [
  {
    id: "POL-113",
    name: "Classification procedure",
    cite: cfr("15", "774", "Export Administration Regulations — the Commerce Control List"),
    pat: [
      /(eccn|classification|usml|commerce\s+control\s+list)/i,
      /(classif(y|ication)\s+(procedure|process)|determine\s+the\s+(eccn|classification)|self-?classif|commodity\s+jurisdiction)/i,
    ],
    why: "Every export decision starts with classification. A program without a defined classification procedure and a record of the determinations cannot demonstrate that any license decision was made on a reasoned basis.",
    fix: "State the classification procedure, who performs it, how ECCN or USML determinations are documented, and the commodity jurisdiction process for uncertain items.",
    sev: "critical",
  },
  {
    id: "POL-114",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.2.0",
    name: "Restricted-party and SDN screening",
    cite: cfr("31", "501", "OFAC — Reporting, Procedures and Penalties Regulations"),
    pat: [
      /(restricted[-\s]+part(y|ies)|denied\s+persons|entity\s+list|specially\s+designated\s+nationals|sdn)/i,
      /(screen|check\s+against|prior\s+to\s+(shipment|transaction|onboarding)|re-?screen)/i,
    ],
    why: "OFAC liability is strict — no knowledge is required — and the 50 Percent Rule extends blocking to entities majority-owned by blocked persons. Screening at onboarding only misses designations that happen later.",
    fix: "State which lists are screened, when screening occurs (onboarding, before each transaction, and on list updates), the ownership analysis applied, and how hits are escalated.",
    denied: expressDenial(
      String.raw`(?:SDN|restricted[- ]party|denied[- ]party|sanctions)\s+screening`,
    ),
    sev: "critical",
  },
  {
    id: "POL-115",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Deemed-export controls for foreign nationals",
    cite: cfr("15", "734.13", "EAR — definition of export, deemed exports"),
    pat: [
      /deemed[-\s]+export/i,
      /(foreign\s+national|foreign\s+person|release\s+of\s+technology|within\s+the\s+united\s+states)/i,
    ],
    why: "Releasing controlled technology to a foreign national inside the US is an export to that person's country. Engineering teams and cloud repositories are where this is most often missed.",
    fix: "State the deemed-export rule, the process for determining whether a hire or visitor requires a license, and the technology-access controls that implement it.",
    sev: "critical",
  },
  {
    id: "POL-116",
    name: "License determination and recordkeeping",
    cite: cfr("15", "762", "EAR — recordkeeping"),
    pat: [/licen[cs]/i, /(exception|no\s+license\s+required|nlr|record|retain|five\s+years)/i],
    why: "Part 762 requires five-year retention of export records. The license determination record is what turns a decision into a defensible one during an audit or a voluntary disclosure.",
    fix: "State how license requirements are determined and documented, which license exceptions are used and their conditions, and the five-year retention requirement.",
  },
  {
    id: "POL-117",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.2.0",
    name: "Red-flag escalation and voluntary disclosure",
    cite: cfr("15", "732 Supp. 3", "EAR — BIS 'Know Your Customer' guidance and red flags"),
    pat: [
      // "Red flag" is the BIS term of art, and a compliance policy is not
      // required to use it. An export policy that screens every counterparty
      // against the Consolidated Screening List, stops the transaction on a
      // hit until Trade Compliance clears it in writing, and voluntarily
      // self-discloses was told it addressed neither escalation nor
      // disclosure — because it described the mechanism instead of naming it.
      /(red[-\s]+flags?|screening\s+(?:hit|match)|potential\s+violations?|suspected\s+violations?|indicat(?:or|ion)s?\s+of\s+diversion)/i,
      /(escalat|inquire|resolve|voluntary\s+(self-?)?disclosure|voluntarily\s+self-?disclos|stop(?:s)?\s+the\s+transaction|report)/i,
    ],
    why: "BIS's Know Your Customer guidance requires that red flags be resolved, not ignored — self-blinding is itself a violation. Voluntary self-disclosure is the principal mitigation once something has gone wrong.",
    fix: "List the red flags, require escalation and resolution before proceeding, and describe the voluntary self-disclosure decision process with counsel.",
  },
  {
    id: "POL-118",
    name: "Training and audit cadence",
    cite: agency(
      "Bureau of Industry and Security",
      "Export Compliance Program guidelines — training and audits",
      "https://www.bis.gov/",
    ),
    pat: [/train/i, /(audit|assessment|annual|periodic|refresher)/i],
    why: "BIS and OFAC both weight training and periodic audits in their penalty guidelines. They are among the cheapest mitigating factors an organization can document.",
    fix: "State who receives training, its frequency and content, and the internal audit or assessment cadence with reporting to management.",
  },
  {
    id: "POL-119",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Sanctioned-jurisdiction prohibitions",
    cite: cfr(
      "31",
      "560",
      "OFAC — Iranian Transactions and Sanctions Regulations (as an example of a comprehensive program)",
    ),
    pat: [
      /(embargo|comprehensive(ly)?\s+sanction|sanctioned[-\s]+(countr|jurisdiction|region))/i,
      /(cuba|iran|north\s+korea|syria|crimea|donetsk|luhansk|prohibited)/i,
    ],
    why: "Comprehensive programs prohibit essentially all transactions with the jurisdiction, including services delivered online. Software and SaaS companies routinely discover users in embargoed regions only after the fact.",
    fix: "Name the comprehensively sanctioned jurisdictions, prohibit transactions with them, and describe the geolocation, IP-blocking, and offboarding controls used to enforce it.",
    sev: "critical",
  },
]);

const BCP = pack("business-continuity-plan", C, [
  {
    id: "POL-120",
    name: "Business impact analysis and critical functions",
    cite: agency(
      "ISO",
      "ISO 22301 — Security and resilience, business continuity management systems",
      "https://www.iso.org/standard/75106.html",
    ),
    pat: [
      /(business\s+impact\s+analysis|bia|critical\s+(business\s+)?(function|process))/i,
      /(prioriti|dependenc|impact\s+over\s+time|tier)/i,
    ],
    why: "The BIA is what turns a wish list into a plan: it establishes which functions must be recovered first and what they depend on. A plan without one recovers in whatever order the responders guess.",
    fix: "Identify the critical business functions, their upstream dependencies (systems, vendors, people, facilities), and their prioritized recovery order.",
    sev: "critical",
  },
  {
    id: "POL-121",
    name: "RTO and RPO stated per function",
    cite: agency(
      "ISO",
      "ISO 22301 — recovery time and recovery point objectives",
      "https://www.iso.org/standard/75106.html",
    ),
    pat: [
      /(recovery\s+time\s+objective|rto)/i,
      /(recovery\s+point\s+objective|rpo|maximum\s+tolerable|hours|data\s+loss)/i,
    ],
    why: "RTO and RPO are the two numbers that drive every architecture and vendor decision. A plan that states them only globally cannot tell an engineer what to build.",
    fix: "State the RTO and RPO for each critical function, and confirm the technical architecture and vendor commitments actually support them.",
    sev: "critical",
  },
  {
    id: "POL-122",
    name: "Activation criteria and authority",
    cite: agency(
      "ISO",
      "ISO 22301 — incident response structure and activation",
      "https://www.iso.org/standard/75106.html",
    ),
    pat: [
      /activat/i,
      /(criteria|threshold|who\s+(may|can)\s+(declare|activate)|authority|crisis\s+(management\s+)?team|invoke)/i,
    ],
    why: "Plans fail at the moment of declaration more than at any other point, because nobody is sure they have the authority to call it. Named roles with alternates fix that.",
    fix: "State the activation criteria, who is authorized to declare an event (with alternates), and how the declaration is communicated.",
  },
  {
    id: "POL-123",
    name: "Alternate site and work arrangements",
    cite: practice(
      "bcp-alternate",
      "alternate site and remote work arrangements in continuity planning",
    ),
    pat: [
      /(alternate\s+(site|location|facility)|work\s+from\s+home|remote\s+work)/i,
      /(relocate|hot\s+site|warm\s+site|cloud|failover)/i,
    ],
    why: "Facility loss and system loss need different answers. A plan that addresses only IT failover leaves a flooded office with no instructions for the people in it.",
    fix: "Describe the alternate work arrangements for each critical function — alternate facility, remote work, or failover region — with the capacity and activation lead time.",
  },
  {
    id: "POL-124",
    name: "Communication and notification tree",
    cite: practice(
      "bcp-communication",
      "notification and communication planning in continuity plans",
    ),
    pat: [
      /(communicat|notification)/i,
      /(call\s+tree|contact\s+list|employees|customers|regulators|spokesperson|out-?of-?band)/i,
    ],
    why: "Primary channels are often the first casualty. Plans that rely on corporate email to coordinate a corporate email outage are common and useless.",
    fix: "Include the notification tree with out-of-band contact methods, the internal and external communication owners, and holding statements for customers and regulators.",
  },
  {
    id: "POL-125",
    name: "Testing cadence and plan maintenance",
    cite: agency(
      "ISO",
      "ISO 22301 — exercising and testing",
      "https://www.iso.org/standard/75106.html",
    ),
    pat: [
      /(test|exercis|tabletop|drill)/i,
      /(annual|cadence|after-?action|lessons\s+learned|update\s+the\s+plan|review)/i,
    ],
    why: "An untested plan is a document, not a capability. Regulators and cyber insurers increasingly ask for the exercise record specifically.",
    fix: "State the exercise types and cadence (tabletop, functional, full failover), the after-action review process, and the plan update and re-approval cycle.",
  },
]);

const IRP = pack("security-incident-response-plan", C, [
  {
    id: "POL-126",
    name: "Preparation, detection, containment, and recovery phases",
    cite: agency(
      "NIST",
      "SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management",
      "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    ),
    pat: [
      /(detection\s+and\s+analysis|containment|eradicat|recovery)/i,
      /(preparation|post-?incident|lifecycle|phase)/i,
    ],
    why: "The lifecycle is what makes an IRP usable under pressure — responders need to know what phase they are in and what the exit criteria are. Plans organized only as contact lists do not survive first contact.",
    fix: "Structure the plan around the lifecycle phases with the activities and exit criteria for each.",
    sev: "critical",
  },
  {
    id: "POL-127",
    name: "Severity classification and escalation matrix",
    cite: agency(
      "NIST",
      "SP 800-61r3 — incident prioritization",
      "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    ),
    pat: [/(severity|priorit)/i, /(sev\s?[0-3]|p[0-3]|escalat|classification|criteria|matrix)/i],
    why: "Severity drives who is woken up and how fast. Without objective criteria, severity is set by whoever is on call and the executive notification arrives too late.",
    fix: "Define severity levels with objective criteria, and map each to notification targets and response time expectations.",
    sev: "critical",
  },
  {
    id: "POL-128",
    name: "Roles — incident commander, legal, and communications",
    cite: agency(
      "NIST",
      "SP 800-61r3 — incident response team structure",
      "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    ),
    pat: [
      /(incident\s+(commander|lead|manager)|roles\s+and\s+responsibilities)/i,
      /(legal|counsel|communications|privacy|executive\s+sponsor)/i,
    ],
    why: "Involving counsel early is what supports a privilege claim over the investigation, and a single incident commander is what prevents parallel uncoordinated response.",
    fix: "Name the incident commander role and its alternates, and define the legal, privacy, communications, HR, and executive roles with their decision rights.",
  },
  {
    id: "POL-129",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Evidence preservation and forensic chain of custody",
    cite: agency(
      "NIST",
      "SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response",
      "https://csrc.nist.gov/pubs/sp/800/86/final",
    ),
    pat: [
      /(evidence|forensic)/i,
      /(preserv|chain\s+of\s+custody|image|do\s+not\s+(wipe|reimage)|litigation\s+hold)/i,
    ],
    why: "The reflex to reimage a compromised host destroys the evidence needed to scope the incident and to defend the litigation that follows. The plan has to say so before the incident.",
    fix: "Require memory and disk preservation before remediation on in-scope systems, describe chain-of-custody handling, and connect the plan to the litigation-hold process.",
    denied: expressDenial(String.raw`chain\s+of\s+custody|evidence\s+preservation`),
    sev: "critical",
  },
  {
    id: "POL-130",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Regulatory notification clocks and owners",
    cite: stateLaw(
      "breach-notification",
      "state data breach notification statutes and their notification deadlines (all 50 states, DC, and the territories)",
      "https://www.law.cornell.edu/wex/data_breach",
    ),
    pat: [
      /(notif(y|ication))/i,
      /(72\s*\)?\s*hours|\d+\s*\)?\s*(business\s+)?days|regulator|attorney\s+general|state\s+breach|hhs|securities\s+and\s+exchange|deadline)/i,
    ],
    all: true,
    why: "The clocks are short and they differ: GDPR is 72 hours, the SEC cyber rule is four business days after materiality, HIPAA is 60 days, and the state statutes run from 30 to 90 days with different triggers. Nobody can reconstruct them mid-incident.",
    fix: "Tabulate the applicable notification obligations with their triggers, deadlines, content requirements, and the named owner of each.",
    denied: expressDenial(
      String.raw`regulatory\s+notification|notification\s+(?:clock|deadline|timeline)s?`,
    ),
    sev: "critical",
  },
  {
    id: "POL-131",
    name: "Third-party and vendor incident coordination",
    cite: practice("vendor-incident", "vendor incident coordination in response plans"),
    pat: [
      /(third[- ]party|vendor|supplier|service\s+provider|processor)/i,
      /(notify|coordinate|contractual\s+(notification|obligation)|sub-?processor|incident\s+at\s+a)/i,
    ],
    why: "An incident at a vendor triggers the organization's own notification duties, and its contracts may impose notification duties toward customers on a shorter clock than the law does.",
    fix: "Describe how vendor incidents are triaged, the contractual notification obligations owed to customers, and the coordination path with the vendor's response team.",
  },
  {
    id: "POL-132",
    name: "Post-incident review and plan update",
    cite: agency(
      "NIST",
      "SP 800-61r3 — post-incident activity",
      "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    ),
    pat: [
      /(post-?incident|lessons\s+learned|after-?action)/i,
      /(review|within\s+\d+\s*\)?\s*days|update\s+the\s+plan|corrective\s+action|root\s+cause)/i,
    ],
    why: "The corrective actions from a real incident are the highest-value security work an organization ever identifies, and they evaporate without a review that assigns and tracks them.",
    fix: "Require a post-incident review within a stated period, with root-cause analysis, assigned corrective actions with owners and dates, and a plan update.",
  },
]);

export const V5_POLICY_RULES: readonly Rule[] = [...INFOSEC, ...AUP, ...EXPORT, ...BCP, ...IRP];

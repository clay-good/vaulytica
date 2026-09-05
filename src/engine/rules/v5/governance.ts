/**
 * v5 sub-domain B′ — US entity governance and nonprofit funding
 * (spec-v45.md §6.B). Rule ids continue the GOV namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { agency, cfr, expressDenial, irs, practice, uniformAct } from "./_helpers.js";
import { MODAL_QUALIFIER } from "../_helpers.js";
import { dgcl } from "../v4/governance/_helpers.js";

const C = "governance";

const ARTICLES = pack("articles-of-organization", C, [
  {
    id: "GOV-101",
    name: "Entity name with the required designator",
    cite: uniformAct(
      "Revised Uniform Limited Liability Company Act (RULLCA) § 201",
      "contents of the certificate of organization",
    ),
    pat: [
      /(the\s+name\s+of\s+the\s+(limited\s+liability\s+)?company\s+is|name\s+of\s+the\s+llc\s+is|company\s+name\s*:)/i,
      /(l\.?l\.?c\.?|limited\s+liability\s+company|limited\s+company)/i,
    ],
    all: true,
    why: "Every state requires an LLC's name to include a designator and to be distinguishable on the records of the filing office. A certificate without a conforming name is rejected at filing.",
    fix: "State the exact entity name including the required designator, matching the name reservation if one was filed.",
    sev: "critical",
  },
  {
    id: "GOV-102",
    name: "Registered agent and registered office",
    cite: uniformAct("RULLCA § 113", "registered agent for service of process"),
    pat: [
      /registered\s+(agent|office)/i,
      /(street\s+address|agent\s+for\s+service\s+of\s+process)/i,
    ],
    why: "The registered agent is the entity's address for service of process. A certificate without one cannot be filed, and a lapsed agent leads to administrative dissolution and default judgments.",
    fix: "Name the registered agent and give the registered office street address in the state of formation (a post office box is not sufficient).",
    sev: "critical",
  },
  {
    id: "GOV-103",
    name: "Management structure — member-managed or manager-managed",
    cite: uniformAct("RULLCA § 407", "management of limited liability company"),
    pat: [
      /(member-?managed|manager-?managed)/i,
      /(managed\s+by\s+(its\s+)?(members|managers|one\s+or\s+more))/i,
    ],
    why: "The management election determines who has agency authority to bind the company. Third parties rely on the public filing, and the operating agreement cannot override what the certificate states as to them.",
    fix: "State whether the company is member-managed or manager-managed, and name the initial managers if manager-managed.",
  },
  {
    id: "GOV-104",
    name: "Duration or perpetual existence",
    cite: uniformAct(
      "RULLCA § 104",
      "nature, purpose, and duration of a limited liability company",
    ),
    pat: [/(perpetual|duration)/i, /(dissol|term\s+of\s+existence|until)/i],
    why: "Most modern acts default to perpetual duration, but a stated term or dissolution event is required in a few states and matters for tax and estate planning.",
    fix: "State that the duration is perpetual, or state the term or dissolution event.",
  },
  {
    id: "GOV-105",
    ver: "1.1.0",
    name: "Organizer signature and effective date",
    cite: uniformAct("RULLCA § 201", "signing of the certificate of organization"),
    pat: [
      // States name the filer in their own statutory words, and "organizer" is
      // only one of them: Colorado's form says "the true name and mailing
      // address of the PERSON FORMING the limited liability company", and its
      // perjury notice names "the INDIVIDUAL CAUSING this document to be
      // delivered". A correctly prepared certificate carried neither of the
      // two spellings this pillar knew.
      /(organizer|authori[sz]ed\s+(person|representative|signator\w*)|person\s+forming\s+the\s+(limited\s+liability\s+)?company|individual\s+causing\s+(this\s+)?(document|record))/i,
      /(effective\s+(date|upon\s+filing)|effective\s+on\s+(the\s+date\s+of\s+)?filing)/i,
    ],
    all: true,
    why: "The certificate must be signed by an organizer, and a delayed effective date is often used to align formation with a tax year or a closing.",
    fix: "Add the organizer's signature block and state whether the certificate is effective on filing or on a stated later date.",
  },
]);

const BOARD_RESOLUTION = pack("board-resolution", C, [
  {
    id: "GOV-106",
    // The check's whole subject is the recitals, and the default rule input
    // strips them — so this reported "no recitals establishing the purpose"
    // on a resolution whose second paragraph is one, and could never have
    // done otherwise.
    ver: "1.1.0",
    recitals: true,
    name: "Recitals establishing the purpose",
    cite: uniformAct(
      "Model Business Corporation Act § 8.20",
      "meetings and action of the board of directors",
    ),
    pat: [
      /whereas/i,
      /(the\s+board\s+has\s+determined|it\s+is\s+in\s+the\s+best\s+interests?\s+of\s+the\s+corporation|the\s+purpose\s+of\s+this\s+resolution)/i,
    ],
    why: "Recitals are where the board records the business judgment behind the act. Their absence is what makes a resolution hard to defend years later when the transaction is challenged.",
    fix: "Add whereas clauses stating the facts considered and the board's determination that the action is in the corporation's best interests.",
  },
  {
    id: "GOV-107",
    name: "Quorum or adoption recital",
    cite: uniformAct("Model Business Corporation Act § 8.24", "quorum and voting"),
    pat: [
      /(quorum|duly\s+(adopted|called)|unanimous)/i,
      /(majority\s+of\s+the\s+directors|all\s+of\s+the\s+directors|vote)/i,
    ],
    why: "A resolution adopted without a quorum is void. The recital is the corporate record of validity and is what a bank, transfer agent, or counterparty relies on.",
    fix: "Recite that a quorum was present and that the resolution was duly adopted by the required vote, or that it was adopted by unanimous written consent.",
    sev: "critical",
  },
  {
    id: "GOV-108",
    name: "Specific authorization granted",
    cite: practice("board-authorization", "specificity of board authorizations"),
    pat: [
      /resolved,?\s+that/i,
      /(authori[sz]ed\s+to|approved|hereby\s+(adopts|approves|authori[sz]es))/i,
    ],
    why: "An authorization phrased at a level of generality no counterparty can rely on is worse than none: the bank asks for a new one and the closing slips.",
    fix: "State the specific action authorized — the counterparty, the amount, the instrument — precisely enough for a third party to rely on it.",
    sev: "critical",
  },
  {
    id: "GOV-109",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Officer delegation and further-acts clause",
    cite: practice("further-acts", "omnibus further-acts resolutions"),
    pat: [
      /(any\s+officer|the\s+(chief\s+executive|president|treasurer|secretary))/i,
      /(further[-\s]+(acts|assurances)|take\s+all\s+(such\s+)?actions|execute\s+and\s+deliver)/i,
    ],
    why: "Closings require documents nobody enumerated in advance. The omnibus further-acts resolution is what lets an officer sign them without reconvening the board.",
    fix: "Authorize the officers to execute and deliver all further documents and take all further actions the officer deems necessary to carry out the resolutions.",
  },
  {
    id: "GOV-110",
    name: "Date, secretary certification, and effectiveness",
    cite: practice("secretary-certificate", "secretary's certification of board resolutions"),
    pat: [/(dated|as\s+of\s+the\s+\w+\s+day|adopted\s+on)/i, /(secretary|certif|attest)/i],
    why: "A resolution without a date and a secretary's certification is not usable as evidence of corporate action; every institutional counterparty asks for the certificate.",
    fix: "Date the resolution and add the secretary's certification that it was duly adopted and remains in full force and effect.",
  },
]);

const MINUTES = pack("meeting-minutes", C, [
  {
    id: "GOV-111",
    name: "Notice or waiver of notice recited",
    cite: uniformAct("Model Business Corporation Act § 8.22", "notice of meeting"),
    pat: [
      /notice\s+(of\s+the\s+meeting|was\s+(duly\s+)?given|having\s+been\s+(given|waived))/i,
      /(waive[rd]?\s+of\s+notice|all\s+directors\s+(were\s+)?present)/i,
    ],
    why: "Action at a meeting for which notice was defective is voidable. The minutes are the only record that notice was given or waived.",
    fix: "Recite that notice was given in accordance with the bylaws, or that notice was waived in writing or by attendance without objection.",
  },
  {
    id: "GOV-112",
    // 1.0.1 — written as a synonym OR, but the quorum and the recital that it was present are distinct pillars; `present` alone matches inside "representatives". The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Quorum recited",
    cite: uniformAct("Model Business Corporation Act § 8.24", "quorum and voting"),
    pat: [/quorum/i, /(present|constituting|was\s+present\s+throughout)/i],
    all: true,
    why: "Quorum must exist when the vote is taken, not only at the start. Minutes that record quorum once and then a mid-meeting departure leave later actions open to challenge.",
    fix: "Recite that a quorum was present and, where directors left, note whether a quorum remained for subsequent actions.",
    sev: "critical",
  },
  {
    id: "GOV-113",
    name: "Attendance and who presided",
    cite: practice("minutes-attendance", "attendance records in corporate minutes"),
    pat: [
      /(present\s+(were|at\s+the\s+meeting)|in\s+attendance|attending)/i,
      /(presided|chair|acted\s+as\s+secretary)/i,
    ],
    why: "Attendance is the evidentiary basis for director oversight claims — who was in the room when the issue was raised is the first question in a Caremark case.",
    fix: "List directors present and absent, note guests and their agenda items, and record who presided and who acted as secretary.",
  },
  {
    id: "GOV-114",
    name: "Motions, votes, and abstentions",
    cite: uniformAct("Model Business Corporation Act § 8.24(d)", "director assent and dissent"),
    pat: [/(motion|resolved|moved\s+and\s+seconded)/i, /(vote|unanimous|abstain|dissent|carried)/i],
    why: "§ 8.24(d) deems a director to have assented unless dissent is entered in the minutes. A director who opposed an action and did not have it recorded is treated as having voted for it.",
    fix: "Record each motion, the vote count, and every abstention and dissent by name.",
    sev: "critical",
  },
  {
    id: "GOV-115",
    name: "Conflict-of-interest recusals",
    cite: uniformAct(
      "Model Business Corporation Act § 8.61",
      "director's conflicting interest transaction",
    ),
    pat: [
      /(conflict\s+of\s+interest|interested\s+director|related\s+party)/i,
      /(recus|left\s+the\s+(meeting|room)|did\s+not\s+(vote|participate)|disinterested)/i,
    ],
    why: "Safe-harbor approval of a conflicting-interest transaction requires disclosure and approval by disinterested directors. The minutes are the record that both happened.",
    fix: "Record the disclosure of the interest, the recusal, and that the transaction was approved by a majority of the disinterested directors.",
    when: [
      /(conflict\s+of\s+interest|interested\s+director|related\s+party|affiliate\s+transaction)/i,
    ],
  },
  {
    id: "GOV-116",
    name: "Adjournment and secretary signature",
    cite: practice("minutes-execution", "execution and approval of corporate minutes"),
    pat: [
      /(adjourn|there\s+being\s+no\s+further\s+business)/i,
      /(secretary|respectfully\s+submitted|approved\s+at\s+the\s+.{0,30}meeting)/i,
    ],
    // Both pillars are REQUIRED, not alternatives: minutes that record the
    // adjournment but carry no secretary signature are exactly what this rule
    // says is wrong ("Unsigned, unapproved minutes are a draft"), and without
    // `all` the adjournment alone satisfied it. Same defect as INS-103.
    all: true,
    why: "Unsigned, unapproved minutes are a draft. The approval at the following meeting is what makes them the corporation's record.",
    fix: "Record the adjournment, add the secretary's signature block, and note approval at the subsequent meeting.",
  },
]);

const PROXY = pack("proxy-statement-narrative", C, [
  {
    id: "GOV-117",
    name: "Record date, quorum, and vote standards",
    cite: cfr("17", "240.14a-101", "SEC Schedule 14A — information required in a proxy statement"),
    pat: [
      /record\s+date/i,
      /(quorum|vote\s+required|majority\s+of\s+(the\s+)?(votes|shares)|plurality)/i,
    ],
    why: "Item 21 of Schedule 14A requires the vote required for each matter. Getting the standard wrong — plurality versus majority, and the treatment of abstentions — is a recurring source of vote-count challenges.",
    fix: "State the record date, the shares outstanding and entitled to vote, the quorum requirement, and the vote standard for each proposal.",
    sev: "critical",
  },
  {
    id: "GOV-118",
    name: "Broker non-vote and abstention treatment",
    cite: cfr("17", "240.14a-4", "SEC — requirements as to proxy"),
    pat: [
      /broker\s+non-?vote/i,
      /(abstention|abstain|will\s+(not\s+)?(be\s+)?counted|discretionary\s+authority)/i,
    ],
    why: "Since brokers lost discretionary authority over director elections, whether abstentions and non-votes count against a proposal changes outcomes. The disclosure is required and materially affects solicitation strategy.",
    fix: "Explain broker discretionary authority, which proposals are routine, and how abstentions and broker non-votes are treated for quorum and for each vote.",
  },
  {
    id: "GOV-119",
    name: "Director nominee biographies and independence",
    cite: cfr("17", "240.14a-101", "SEC Schedule 14A Item 7 — directors and executive officers"),
    pat: [
      /(nominee|director\s+since|business\s+experience)/i,
      /(independen(t|ce)|listing\s+standards|audit\s+committee\s+financial\s+expert)/i,
    ],
    why: "Item 7 requires each nominee's experience, qualifications, and directorships, plus the board's independence determinations under the exchange's listing standards.",
    fix: "Provide each nominee's age, tenure, experience, other directorships, the specific qualifications supporting nomination, and the board's independence determination.",
  },
  {
    id: "GOV-120",
    name: "Executive compensation tables and CD&A",
    cite: cfr("17", "229.402", "Regulation S-K Item 402 — executive compensation"),
    pat: [
      /(compensation\s+discussion\s+and\s+analysis|summary\s+compensation\s+table)/i,
      /(pay\s+(ratio|versus\s+performance)|say-?on-?pay|named\s+executive\s+officers)/i,
    ],
    why: "Item 402 prescribes the CD&A and the compensation tables, plus the pay ratio and pay-versus-performance disclosures. Omissions here are the most common comment-letter topic in proxy review.",
    fix: "Include the CD&A, the summary compensation and related tables, the CEO pay ratio, and the pay-versus-performance disclosure.",
  },
  {
    id: "GOV-121",
    name: "Beneficial ownership table",
    cite: cfr(
      "17",
      "229.403",
      "Regulation S-K Item 403 — security ownership of certain beneficial owners and management",
    ),
    pat: [
      /beneficial\s+(owner|ownership)/i,
      /(5%|five[-\s]+percent|directors\s+and\s+executive\s+officers\s+as\s+a\s+group)/i,
    ],
    why: "Item 403 requires ownership of 5% holders, each director and named executive officer, and the group total, computed on the § 13d-3 beneficial-ownership standard including exercisable options.",
    fix: "Include the beneficial ownership table with 5% holders, individual directors and NEOs, the group total, and the 60-day exercisable-securities footnote.",
  },
  {
    id: "GOV-122",
    name: "Auditor fees and ratification",
    cite: cfr("17", "240.14a-101", "SEC Schedule 14A Item 9 — independent public accountants"),
    pat: [
      /(audit\s+fees|independent\s+registered\s+public\s+accounting\s+firm)/i,
      /(ratif|audit-?related\s+fees|tax\s+fees|all\s+other\s+fees|pre-?approval)/i,
    ],
    why: "Item 9 requires the four fee categories and the audit committee's pre-approval policies. Non-audit fees are the disclosure investors read for independence risk.",
    fix: "Disclose audit, audit-related, tax, and all other fees for each of the last two years, and the audit committee's pre-approval policy.",
  },
]);

const DISSOLUTION = pack("dissolution-plan", C, [
  {
    id: "GOV-123",
    name: "Approval and adoption authority",
    cite: uniformAct(
      "Model Business Corporation Act § 14.02",
      "dissolution by board of directors and shareholders",
    ),
    pat: [
      /(board\s+of\s+directors\s+(has\s+)?(adopted|approved)|approved\s+by\s+the\s+(shareholders|stockholders|members))/i,
      /(majority|two-?thirds|required\s+vote)/i,
    ],
    why: "Dissolution requires board adoption and shareholder approval at the statutory threshold. A plan adopted without the required vote leaves the entity undissolved and the directors exposed.",
    fix: "Recite the board's adoption and the shareholder or member approval, with the vote obtained and the threshold required.",
    sev: "critical",
  },
  {
    id: "GOV-124",
    name: "Notice to known and unknown claimants",
    cite: uniformAct(
      "Model Business Corporation Act § 14.06",
      "known claims against dissolved corporation",
    ),
    pat: [
      /(known\s+claimants?|notice\s+to\s+creditors)/i,
      /(publication|unknown\s+claim|bar\s+date|deadline\s+for\s+claims)/i,
    ],
    why: "§§ 14.06 and 14.07 give a dissolved corporation a claims-bar procedure only if it gives the statutory notices. Skipping them leaves directors and shareholders exposed to claims for years.",
    fix: "Describe the written notice to known claimants with the deadline (not less than the statutory minimum), and the newspaper publication for unknown claims.",
  },
  {
    id: "GOV-125",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Contingent-liability reserve",
    cite: practice("dissolution-reserve", "reserves for contingent liabilities in winding up"),
    pat: [/reserve/i, /(contingent[-\s]+(liabilit|claim)|unknown\s+liabilit|holdback)/i],
    why: "Distributing without an adequate reserve exposes directors and receiving shareholders to clawback for the amount distributed. The reserve is the directors' principal protection.",
    fix: "State the amount and basis of the reserve for contingent and unknown liabilities and the conditions on which the remainder is released.",
  },
  {
    id: "GOV-126",
    name: "Distribution priority",
    cite: uniformAct("Model Business Corporation Act § 14.09", "director duties in dissolution"),
    pat: [
      /(priority|first,?\s+to|order\s+of\s+(payment|distribution))/i,
      /(creditors?|liabilities|then\s+to\s+(the\s+)?(shareholders|members|stockholders))/i,
    ],
    why: "Creditors must be paid or provided for before any owner distribution. Reversing the order is the classic fiduciary breach in a wind-up.",
    fix: "State the waterfall: expenses of dissolution, then creditors, then preferred, then common or member interests.",
    sev: "critical",
  },
  {
    id: "GOV-127",
    name: "Final tax filings and certificate of dissolution",
    cite: irs("IRS Form 966", "corporate dissolution or liquidation"),
    pat: [
      /(final\s+(tax\s+)?return|form\s+966|tax\s+clearance)/i,
      /(articles\s+of\s+dissolution|certificate\s+of\s+dissolution|filed\s+with\s+the\s+secretary\s+of\s+state)/i,
    ],
    why: "The entity is not dissolved until the certificate is filed, and Form 966 is due within 30 days of adopting the plan. States that require tax clearance will refuse the filing without it.",
    fix: "Provide for Form 966 within 30 days, final federal and state returns, any required tax clearance, and the filing of articles of dissolution.",
  },
]);

const FISCAL_SPONSORSHIP = pack("fiscal-sponsorship-agreement", C, [
  {
    id: "GOV-128",
    name: "Model A versus Model C characterization",
    cite: practice(
      "fiscal-sponsorship-models",
      "the six fiscal sponsorship models (Colvin taxonomy)",
    ),
    pat: [
      /(model\s+[ac]|comprehensive\s+fiscal\s+sponsorship|pre-?approved\s+grant\s+relationship)/i,
      /(the\s+project\s+is\s+(a\s+)?(programme?|activity)\s+of\s+the\s+sponsor|regrant|grantee)/i,
    ],
    why: "Model A makes the project a program of the sponsor with the sponsor as employer and owner; Model C makes it a grantee. The tax, employment, and liability consequences are entirely different.",
    fix: "State which model applies, and align the employment, ownership, and liability provisions with it.",
    sev: "critical",
  },
  {
    id: "GOV-129",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Variance power retained by the sponsor",
    cite: cfr("26", "1.507-2(a)(8)", "Treasury regulations — variance power in a component fund"),
    pat: [
      /variance\s+power/i,
      /(sole\s+discretion|ultimate\s+(authority|control)|may\s+redirect\s+the\s+funds)/i,
    ],
    why: "Without express variance power the sponsor is a conduit and the donor's deduction is at risk; the IRS treats earmarked pass-throughs as gifts to the ultimate recipient.",
    fix: "State that the sponsor retains complete discretion and control over the funds, including the power to redirect them to a similar charitable purpose.",
    denied: expressDenial(String.raw`variance\s+power`),
    sev: "critical",
  },
  {
    id: "GOV-130",
    name: "Administrative fee and fund accounting",
    cite: practice("fiscal-sponsorship-fee", "administrative fees in fiscal sponsorship"),
    pat: [
      /(administrative\s+fee|sponsor['’]?s?\s+fee|indirect\s+cost)/i,
      /(project\s+fund|restricted\s+fund|separate\s+account|accounting)/i,
    ],
    why: "The fee and the accounting rules are where the parties fall out. A project that cannot see its own fund balance or reconcile the fee has no way to manage its budget.",
    fix: "State the fee percentage and base, the accounting the sponsor will provide, and the project's access to fund statements.",
  },
  {
    id: "GOV-131",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Charitable-purpose limitation on use",
    cite: irs(
      "26 U.S.C. § 501(c)(3)",
      "exemption for organizations operated exclusively for charitable purposes",
    ),
    pat: [
      /(charitable[-\s]+purpose|exempt\s+purpose|501\(c\)\(3\))/i,
      /(may\s+not\s+be\s+used|(?:shall|will|must)\s+be\s+used\s+(only|exclusively)|prohibited\s+(use|activit))/i,
    ],
    why: "Funds must be used exclusively for § 501(c)(3) purposes; private benefit, substantial lobbying, or political intervention through the project jeopardizes the sponsor's own exemption.",
    fix: "Limit use to the stated charitable purpose, prohibit political campaign intervention and substantial lobbying, and require pre-approval of any change in program.",
  },
  {
    id: "GOV-132",
    name: "Termination and transfer of the project fund",
    cite: practice(
      "fiscal-sponsorship-exit",
      "successor transfer on termination of fiscal sponsorship",
    ),
    pat: [
      /(terminat|withdraw)/i,
      /(successor\s+(sponsor|organi[sz]ation)|transfer\s+(the\s+)?(fund|balance)|remaining\s+funds)/i,
    ],
    why: "Projects graduate to their own exempt status. Without a transfer mechanism the accumulated fund can be stranded, and the sponsor's variance power makes the transfer discretionary by design.",
    fix: "State the notice for termination, the conditions for transferring the balance to a successor § 501(c)(3), and what happens if no qualified successor exists.",
  },
]);

const GRANT = pack("grant-agreement", C, [
  {
    id: "GOV-133",
    name: "Grant amount, period, and payment schedule",
    cite: cfr("2", "200.211", "Uniform Guidance — information contained in a federal award"),
    pat: [
      /(grant\s+(amount|award)|award\s+amount|[$€£¥₹₩₽])/i,
      /(grant\s+period|period\s+of\s+performance|payment\s+schedule|disburse)/i,
    ],
    why: "The period of performance bounds which costs are allowable. Costs incurred outside it are unallowable even when the work was necessary.",
    fix: "State the award amount, the period of performance with start and end dates, and the disbursement schedule or reimbursement basis.",
    sev: "critical",
  },
  {
    id: "GOV-134",
    name: "Restricted purpose and budget deviation limits",
    cite: cfr("2", "200.308", "Uniform Guidance — revision of budget and program plans"),
    pat: [
      /(restricted\s+(purpose|use)|(?:shall|will|must)\s+be\s+used\s+(solely|only)\s+for|approved\s+budget)/i,
      /(budget\s+(revision|modification|deviation)|prior\s+(written\s+)?approval|reallocat)/i,
    ],
    why: "Restricted funds used outside the stated purpose are a breach and, for federal funds, a questioned cost. § 200.308 requires prior approval for specific budget changes.",
    fix: "State the restricted purpose, attach the approved budget, and state the threshold above which line-item reallocation needs prior written approval.",
  },
  {
    id: "GOV-135",
    name: "Narrative and financial reporting deadlines",
    cite: cfr("2", "200.329", "Uniform Guidance — monitoring and reporting program performance"),
    pat: [
      /report(ing|s)?/i,
      /(due\s+(no\s+later\s+than|within)|annual|interim|final\s+report|days\s+after)/i,
    ],
    why: "Late or missing reports are the most common cause of suspension and of ineligibility for future awards. The deadlines and the content have to be in the agreement, not only in a portal.",
    fix: "State the narrative and financial report deadlines, their required content, and the consequence of late submission.",
  },
  {
    id: "GOV-136",
    name: "Unexpended funds and clawback",
    cite: cfr("2", "200.344", "Uniform Guidance — closeout"),
    pat: [
      /(unexpended|unused|remaining)\s+funds/i,
      /(return|refund|repay|revert|clawback|recoup)/i,
    ],
    why: "A grantee that keeps unexpended restricted funds has converted them. The return obligation and its deadline need to be explicit for the grantee's own audit.",
    fix: "State whether unexpended funds must be returned or may be carried forward, the deadline, and the grounds for recovering funds already disbursed.",
  },
  {
    id: "GOV-137",
    name: "Lobbying, political activity, and use restrictions",
    cite: byrdAmendment(),
    pat: [
      /(lobby|lobbying)/i,
      /(political\s+(campaign|activity|contribution)|(?:shall|will|must)\s+not\s+be\s+used\s+to\s+(influence|support))/i,
    ],
    why: "Federal funds may not be used for lobbying (the Byrd Amendment and § 501(c)(3) limits), and a charitable grantee's political intervention endangers exemption for both parties.",
    fix: "Prohibit use of grant funds for lobbying or political campaign intervention, and require the Byrd Amendment certification where federal funds are involved.",
  },
  {
    id: "GOV-138",
    name: "Audit, records access, and retention",
    cite: cfr("2", "200.334", "Uniform Guidance — retention requirements for records"),
    pat: [
      /(audit|records)/i,
      /(retain|three\s+years|access\s+to\s+(the\s+)?records|single\s+audit|inspect)/i,
    ],
    why: "The Uniform Guidance requires three-year retention from final report submission and a Single Audit above the federal expenditure threshold. Grantees frequently discover the obligation only at audit.",
    fix: "State the record-retention period, the funder's access rights, and the Single Audit obligation where federal expenditures exceed the threshold.",
  },
]);

/**
 * The DGCL § 145 director-and-officer indemnification agreement.
 *
 * Every VC-backed company signs one per director, and it is the document a
 * director actually reads before joining a board — yet the catalog had no
 * family for it. The family it did have, `indemnification-agreement`, is the
 * COMMERCIAL anti-indemnity one (NY Gen. Oblig. § 5-322.1, Cal. Civ. Code
 * § 2782, Tex. Ins. Code ch. 151) and applies the construction Type I / II /
 * III taxonomy, which a D&O agreement has nothing to do with. A real one
 * routed there and was told to add a recital identifying its indemnity Type.
 *
 * The columns below are the ones the statute makes available and the ones a
 * director's counsel negotiates: whether advancement is mandatory and
 * unconditional, who decides entitlement and under what presumption, and
 * whether the protection survives both the director's service and a later
 * board's change of heart. Every one is a term that is either in the document
 * or is not.
 */
const DO_INDEMNIFICATION = pack("director-indemnification-agreement", C, [
  {
    id: "GOV-139",
    name: "Indemnification to the fullest extent permitted by law",
    cite: dgcl("145(a)"),
    pat: [
      /fullest\s+extent\s+(?:permitted|authori[sz]ed|allowed)/i,
      /good\s+faith|best\s+interests\s+of\s+the\s+(?:corporation|company)/i,
    ],
    all: true,
    why: "§ 145(a) permits indemnification only where the person acted in good faith and in a manner reasonably believed to be in or not opposed to the corporation's best interests. An agreement that omits the standard of conduct, or that grants less than the fullest extent the law allows, gives the director less than the charter already does.",
    fix: "Grant indemnification to the fullest extent permitted by applicable law, and state the § 145(a) standard of conduct the grant is measured against.",
  },
  {
    id: "GOV-140",
    name: "Mandatory indemnification on success on the merits",
    cite: dgcl("145(c)"),
    pat: [
      /success(?:ful)?[^.;]{0,60}?(?:on\s+the\s+merits|or\s+otherwise)/i,
      new RegExp(
        `(?:(?:shall|will)|must|is\\s+entitled\\s+to\\s+be)${MODAL_QUALIFIER}indemnif\\w+`,
        "i",
      ),
    ],
    all: true,
    why: "§ 145(c) makes indemnification MANDATORY, not permissive, where the director succeeds on the merits or otherwise in defense of a proceeding or of any claim in it. Restating it contractually removes the argument that a dismissal without prejudice or a favorable settlement was not a 'success'.",
    fix: "State that on success on the merits or otherwise, in whole or in part, the corporation shall indemnify against all expenses actually and reasonably incurred, with no determination of entitlement required.",
  },
  {
    id: "GOV-141",
    name: "Advancement of expenses before final disposition",
    cite: dgcl("145(e)"),
    pat: [
      /advance(?:ment|d|s)?\s+(?:of\s+)?(?:all\s+|the\s+)?expenses|expenses[^.;]{0,60}?(?:shall|will|must)\s+be\s+advanced/i,
      // The deadline is written with the numeral in a parenthetical —
      // "within twenty (20) days after receipt of a written request" — which
      // a `\w+ days` window does not span. The check reported the advancement
      // clause missing, at `critical`, on the paragraph that grants it.
      /(?:in\s+advance\s+of|prior\s+to|before)\s+(?:the\s+)?final\s+disposition|within\s+[\w\s()-]{1,30}?days/i,
    ],
    all: true,
    why: "Advancement is the term that decides whether the protection is real: defense costs are incurred for years before any determination of entitlement, and a director who must fund them personally is unprotected in the only period that matters. § 145(e) authorizes advancement in advance of the final disposition of the proceeding.",
    fix: "Make advancement mandatory and unconditional, state the deadline for payment after a written request, and state that no determination of entitlement is a precondition.",
    sev: "critical",
  },
  {
    id: "GOV-142",
    // 1.0.1 — the undertaking is as often a verb as a noun. "Indemnitee
    // undertakes to repay the amounts advanced" is the ordinary drafting,
    // and only the noun form ("undertaking to repay") was matched, so an
    // agreement carrying the § 145(e) undertaking verbatim was told it had
    // none.
    // 1.0.2 — § 145(e)'s own sentence is "an undertaking BY OR ON BEHALF OF
    // SUCH DIRECTOR OR OFFICER to repay", and a drafter who names the person
    // instead writes "an undertaking BY THE INDEMNITEE to repay". Both put an
    // actor between the noun and the verb, and neither branch allowed one: the
    // first wanted them adjacent, the second stopped at "on behalf" and never
    // reached "to repay". A D&O agreement carrying the § 145(e) undertaking in
    // the statute's own shape was told it had none.
    //
    // The second pillar gained the negated form for the same reason. The
    // undertaking is as often made unsecured by saying what is NOT required —
    // "no security, interest, or credit evaluation is required" — as by the
    // adjective "unsecured".
    ver: "1.0.2",
    name: "Undertaking to repay, unsecured and without regard to ability to pay",
    cite: dgcl("145(e)"),
    pat: [
      /(?:undertaking|undertakes?|undertake|agrees?|covenants?|promises?)\s+(?:by\s+(?:or\s+on\s+behalf\s+of\s+)?[^.]{0,60}?\s+)?to\s+(?:repay|reimburse)/i,
      /unsecured|without\s+(?:security|bond|interest|reference\s+to|regard\s+to)|no\s+(?:security|bond|collateral)[^.]{0,60}?\b(?:is|shall\s+be|will\s+be|are)?\s*(?:required|necessary)|need\s+not\s+be\s+secured/i,
    ],
    all: true,
    why: "§ 145(e) conditions advancement on an undertaking to repay if it is ultimately determined the person is not entitled to be indemnified. An undertaking that must be secured, or that is measured against the director's ability to repay, converts the right into one only a wealthy director can use.",
    fix: "Require only a written undertaking to repay, and state that it is accepted without security, without interest, and without regard to the Indemnitee's financial ability to make repayment.",
  },
  {
    id: "GOV-143",
    name: "Derivative-proceeding limit and the court's saving determination",
    cite: dgcl("145(b)"),
    pat: [
      /by\s+or\s+in\s+the\s+right\s+of\s+the\s+(?:corporation|company)|derivative/i,
      /adjudged[^.;]{0,80}?liable|(?:court\s+of\s+chancery|the\s+court\s+in\s+which)[^.;]{0,100}?(?:determin|deem)/i,
    ],
    all: true,
    why: "In a proceeding by or in the right of the corporation, § 145(b) bars indemnification for a person adjudged liable to the corporation unless the Court of Chancery, or the court in which the proceeding was brought, determines the person is fairly and reasonably entitled to indemnity. An agreement silent on the limit purports to grant more than the statute allows and is unenforceable to that extent.",
    fix: "Address derivative proceedings separately: indemnify expenses, state the adjudged-liable bar, and preserve the court's authority to award indemnity notwithstanding.",
  },
  {
    id: "GOV-144",
    ver: "1.1.0",
    name: "Determination of entitlement and who makes it",
    cite: dgcl("145(d)"),
    pat: [
      /independent\s+counsel|disinterested\s+directors|special\s+legal\s+counsel|by\s+the\s+stockholders/i,
      // The sentence runs the other way as readily: "Entitlement to
      // indemnification IS DETERMINED by the disinterested directors."
      /determination\s+of\s+entitlement|determin\w+[^.;]{0,80}?entitle|entitle\w*[^.;]{0,60}?\bdetermin/i,
    ],
    all: true,
    why: "§ 145(d) requires a determination that indemnification is proper, made by disinterested directors, by independent legal counsel, or by the stockholders. Who decides is the whole question after a change in control, when the directors making the determination are the ones the Indemnitee may be adverse to.",
    fix: "Name the decision-maker and the process, and provide that following a Change in Control the determination is made by Independent Counsel selected by the Indemnitee.",
  },
  {
    id: "GOV-145",
    name: "Presumption of entitlement and burden of proof",
    cite: practice(
      "do-indemnification-presumption",
      "Presumption of entitlement and allocation of the burden of proof in a director indemnification agreement",
    ),
    pat: [
      /presum\w+[^.;]{0,80}?entitle|entitle\w+[^.;]{0,60}?presum/i,
      /burden\s+of\s+(?:proof|persuasion)|clear\s+and\s+convincing/i,
    ],
    all: true,
    why: "Without a stated presumption the Indemnitee bears the practical burden of proving entitlement against the corporation that holds the records. The negotiated term reverses it: the Indemnitee is presumed entitled and the corporation must overcome the presumption, often by clear and convincing evidence.",
    fix: "State that the Indemnitee is presumed entitled to indemnification on submitting a request, that the corporation bears the burden of overcoming the presumption, and that a settlement or nolo plea creates no adverse presumption.",
  },
  {
    id: "GOV-146",
    ver: "1.1.0",
    name: "Non-exclusivity and directors' and officers' liability insurance",
    cite: dgcl("145(f)"),
    pat: [
      // "are NOT EXCLUSIVE of any other rights" is the DGCL § 145(f) wording.
      /non-?exclusiv|not\s+exclusive|in\s+addition\s+to\s+(?:any\s+)?(?:other\s+)?rights/i,
      /(?:d\s*&\s*o|directors[’']?\s+and\s+officers[’']?)[^.;]{0,40}?insurance|liability\s+insurance/i,
    ],
    all: true,
    why: "§ 145(f) preserves rights under the certificate, the bylaws, and any agreement, and § 145(g) authorizes insurance whether or not the corporation could indemnify. Insurance is the source of actual payment in most cases, so a covenant to maintain it — and to give notice of cancellation — is the term that makes the rest collectible.",
    fix: "State that the rights granted are not exclusive of any other rights, and covenant to maintain D&O liability insurance on terms no less favorable than those provided to any other director or officer.",
  },
  {
    id: "GOV-147",
    ver: "1.1.0",
    name: "Survival after service ends and against later amendment",
    cite: practice(
      "do-indemnification-survival",
      "Contractual survival of indemnification rights against a later charter or bylaw amendment",
    ),
    pat: [
      // "survive the CESSATION OF the Indemnitee's service" is the nominal
      // form, and the verb forms alone missed it.
      /(?:continue|survive)[^.;]{0,100}?(?:ceas\w+\s+to\s+serve|cessation\s+of[^.;]{0,40}?service|termination\s+of[^.;]{0,40}?service|no\s+longer\s+(?:serves|a\s+director|an\s+officer))/i,
      /(?:amendment|repeal|modification|alteration)[^.;]{0,100}?(?:certificate\s+of\s+incorporation|by-?laws|charter)|binds?\s+(?:any\s+)?successors?|successors?[^.;]{0,80}?(?:merger|consolidation)/i,
    ],
    all: true,
    why: "The reason a director takes a contract rather than relying on the bylaws is that a later board can amend the bylaws and a successor can disclaim them. Both halves are needed: the rights must outlive the service, and they must outlive a change to the charter or a change of control.",
    fix: "State that the rights continue for so long as the Indemnitee may be subject to any proceeding by reason of Corporate Status, notwithstanding that service has ended, and that they survive any amendment or repeal of the certificate or bylaws and bind any successor by merger, consolidation, or sale of assets.",
  },
  {
    id: "GOV-148",
    name: "Notice, defense, and settlement-consent procedure",
    cite: practice(
      "do-indemnification-procedure",
      "Notice, assumption of the defense, and consent to settlement in a director indemnification agreement",
    ),
    pat: [
      /(?:notif\w+|written\s+notice)[^.;]{0,140}?(?:proceeding|claim|action)/i,
      /assume\s+(?:the\s+)?defen[sc]e|separate\s+counsel|counsel\s+(?:reasonably\s+)?satisfactory/i,
      /(?:shall|will|must)\s+not\s+settle|consent\s+to\s+(?:any\s+)?settlement|settle[^.;]{0,120}?prior\s+written\s+consent/i,
    ],
    all: true,
    why: "Late notice is the corporation's standard defense to a claim for indemnity, and control of the defense decides whether the Indemnitee gets counsel of their own where interests diverge. A settlement that imposes liability or an admission on the Indemnitee without consent is the outcome the clause exists to prevent.",
    fix: "State the notice obligation and that a delay relieves the corporation only to the extent it is actually prejudiced; state who may assume the defense and when the Indemnitee is entitled to separate counsel at the corporation's expense; and require consent before either party settles in a way that binds the other.",
  },
]);

/** 31 U.S.C. § 1352 — the Byrd Amendment lobbying restriction. */
function byrdAmendment() {
  return agency(
    "Byrd Amendment",
    "31 U.S.C. § 1352 — limitation on use of appropriated funds to influence certain federal contracting and financial transactions",
    "https://www.law.cornell.edu/uscode/text/31/1352",
  );
}

export const V5_GOVERNANCE_RULES: readonly Rule[] = [
  ...ARTICLES,
  ...BOARD_RESOLUTION,
  ...MINUTES,
  ...PROXY,
  ...DISSOLUTION,
  ...FISCAL_SPONSORSHIP,
  ...GRANT,
  ...DO_INDEMNIFICATION,
];

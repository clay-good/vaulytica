/**
 * v4 Corporate-governance ruleset — ~80 rules (spec-v4.md §6.B, Step 45).
 *
 * Each rule is scoped to one of the eight governance playbook ids
 * (see [`_helpers.ts`](./_helpers.ts)) and cites either the DGCL, MBCA,
 * DE LLC Act, DRULPA, RUPA, NYSE / Nasdaq listing standards, SOX § 301,
 * IRC § 501(c)(3) and Form 990, or a practitioner-baseline source.
 *
 * Rule IDs are flat `GOV-NNN` (001..080); each rule's `applies_to_playbooks`
 * restricts execution. The barrel re-exports the array as
 * `GOVERNANCE_RULES`.
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  buildV4CompoundRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
  type V4CompoundSpec,
} from "../_helpers.js";
import {
  GOV_PLAYBOOK_BYLAWS,
  GOV_PLAYBOOK_OP_AGREEMENT,
  GOV_PLAYBOOK_CHARTER,
  GOV_PLAYBOOK_STOCKHOLDERS,
  GOV_PLAYBOOK_WRITTEN_CONSENT,
  GOV_PLAYBOOK_COMMITTEE_CHARTER,
  GOV_PLAYBOOK_PARTNERSHIP,
  GOV_PLAYBOOK_NONPROFIT,
  dgcl,
  delllca,
  drulpa,
  rupa,
  sox301,
  nyse303A,
  nasdaq,
  irc,
  form990,
  govPractice,
} from "./_helpers.js";

const CATEGORY = "governance";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });
const compound = (s: Omit<V4CompoundSpec, "category">): Rule =>
  buildV4CompoundRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// B.1 — Bylaws (corporation). DGCL §§ 109, 141, 211–229; MBCA §§ 2.06,
// 7.01–7.32. 12 rules, GOV-001..GOV-012.
// ────────────────────────────────────────────────────────────────────

const BYLAWS_RULES: Rule[] = [
  presence({
    id: "GOV-001",
    name: "Bylaws adoption / amendment authority stated",
    description:
      "Bylaws must state who may adopt and amend them (board, stockholders, or both) per DGCL § 109 / MBCA § 10.20.",
    citation: dgcl("109"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Bylaws amendment authority clause missing",
    missing_description: "No clause was found stating who may adopt, amend, or repeal the bylaws.",
    explanation:
      "DGCL § 109 reserves bylaw-amendment power to the stockholders unless the certificate of incorporation also confers it on the board. The bylaws should explicitly state which body holds that power.",
    recommendation:
      "Add an 'Amendment of Bylaws' article identifying the stockholders' default power and the board's concurrent power if conferred by the charter.",
    present_patterns: [
      /amend(ed|ment)?\s+(of|to)?\s*(these\s+)?bylaws/i,
      /repeal.{0,30}(these\s+)?bylaws/i,
    ],
  }),
  presence({
    id: "GOV-002",
    name: "Annual meeting of stockholders specified",
    description:
      "Bylaws must designate the time / place / mode of the annual meeting of stockholders (DGCL § 211; MBCA § 7.01).",
    citation: dgcl("211"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Annual stockholders meeting clause missing",
    missing_description: "No annual-meeting-of-stockholders clause was found in the bylaws.",
    explanation:
      "DGCL § 211(b) and MBCA § 7.01 require corporations to hold an annual meeting at which directors are elected. The bylaws should fix when and how that meeting is held.",
    recommendation:
      "Add an 'Annual Meeting' section specifying the date / time / place (or remote-only authorization), notice procedures, and election of directors as a stated purpose.",
    present_patterns: [
      /annual\s+meeting\s+of\s+(the\s+)?stockholders/i,
      /annual\s+meeting\s+of\s+(the\s+)?shareholders/i,
    ],
  }),
  presence({
    id: "GOV-003",
    name: "Special meeting call right specified",
    description:
      "Bylaws should state who may call a special meeting of stockholders (DGCL § 211(d); MBCA § 7.02).",
    citation: dgcl("211(d)"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Special-meeting call right clause missing",
    missing_description: "No special-meeting call-right clause was found in the bylaws.",
    explanation:
      "DGCL § 211(d) permits special meetings to be called by the board or by such persons as the bylaws authorize. Without the clause, only the directors may call one, foreclosing stockholder-initiated meetings.",
    recommendation:
      "Add a 'Special Meeting' section specifying the call right (board, chair, or stockholders holding ≥X% of voting power) and notice timing.",
    present_patterns: [/special\s+meeting/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-004",
    name: "Notice of meetings provisions",
    description:
      "Bylaws must set notice timing for stockholder meetings (DGCL § 222; MBCA § 7.05).",
    citation: dgcl("222"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Stockholder meeting notice clause missing",
    missing_description: "No notice-of-meeting clause was found in the bylaws.",
    explanation:
      "DGCL § 222(b) requires written notice not less than 10 nor more than 60 days before a stockholder meeting (subject to limited exceptions). The bylaws should restate this window and the manner of delivery.",
    recommendation:
      "Add a 'Notice of Meetings' section specifying the 10-to-60-day window and acceptable delivery modes (including electronic delivery under DGCL § 232).",
    present_patterns: [
      /notice\s+of\s+(the\s+)?(annual|special|stockholders?|meeting)/i,
      /written\s+notice.{0,60}(stockholders?|meeting)/i,
      /notice.{0,60}(annual|special)\s+meeting/is,
    ],
  }),
  presence({
    id: "GOV-005",
    name: "Quorum for stockholder meetings",
    description:
      "Bylaws must state the quorum required for stockholder meetings (DGCL § 216; MBCA § 7.25).",
    citation: dgcl("216"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Stockholder quorum clause missing",
    missing_description: "No quorum requirement for stockholder meetings was found.",
    explanation:
      "DGCL § 216 defaults to a majority of shares entitled to vote unless the charter or bylaws specify otherwise. The bylaws should restate this default explicitly.",
    recommendation:
      "Add a 'Quorum' section stating that the holders of a majority of the voting power entitled to vote, present in person or by proxy, constitute a quorum.",
    present_patterns: [/quorum/i],
  }),
  presence({
    id: "GOV-006",
    name: "Directors — number, election, term",
    description:
      "Bylaws must specify the number of directors, election procedure, and term (DGCL § 141; MBCA § 8.03).",
    citation: dgcl("141"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Board composition / election clause missing",
    missing_description:
      "No clause was found establishing the number of directors and their election.",
    explanation:
      "DGCL § 141(b) and MBCA § 8.03 require the corporation's bylaws (or charter) to fix the number of directors and the manner of election.",
    recommendation:
      "Add an 'Election and Term' section setting the number of directors (or a range), the term length, and the plurality / majority voting standard.",
    present_patterns: [/board\s+of\s+directors/i, /(elect|appoint).{0,30}directors?/i],
  }),
  presence({
    id: "GOV-007",
    name: "Directors — removal and vacancies",
    description:
      "Bylaws should address director removal and vacancy filling (DGCL §§ 141(k), 223; MBCA §§ 8.08, 8.10).",
    citation: dgcl("141(k)"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Director removal / vacancy clause missing",
    missing_description: "No clause was found addressing director removal or filling of vacancies.",
    explanation:
      "DGCL § 141(k) governs removal (with cause for classified boards, with or without cause otherwise) and § 223 governs vacancies. Silence creates uncertainty and litigation risk.",
    recommendation:
      "Add a 'Removal and Vacancies' section covering removal standards and that vacancies may be filled by the remaining directors (or stockholders, per the charter).",
    present_patterns: [/(removal|vacanc(y|ies))/i],
  }),
  presence({
    id: "GOV-008",
    name: "Indemnification of directors and officers",
    description:
      "Bylaws should provide for indemnification of D&O to the fullest extent of DGCL § 145 / MBCA § 8.50.",
    citation: dgcl("145"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "D&O indemnification clause missing",
    missing_description: "No indemnification clause was found in the bylaws.",
    explanation:
      "DGCL § 145 authorizes indemnification but it is not self-executing; bylaws must provide for it or directors lose the protection.",
    recommendation:
      "Add an 'Indemnification' article extending mandatory indemnification to D&O to the fullest extent permitted by DGCL § 145, including advancement of expenses.",
    present_patterns: [/indemnif(ication|y|ied)/i],
  }),
  presence({
    id: "GOV-009",
    name: "Officers — designation",
    description: "Bylaws must designate officers and their authority (DGCL § 142; MBCA § 8.40).",
    citation: dgcl("142"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Officer-designation clause missing",
    missing_description: "No officer-designation clause was found.",
    explanation:
      "DGCL § 142 requires that the bylaws (or board) identify the officers and their authority. Standard slate: Chair / President / Treasurer / Secretary.",
    recommendation:
      "Add an 'Officers' article enumerating the standard slate, election by the board, and authority of each office.",
    present_patterns: [/officers?\s+(of|elected|appointed)/i, /chief\s+executive/i],
  }),
  presence({
    id: "GOV-010",
    name: "Stock certificates / uncertificated shares",
    description:
      "Bylaws should address the form of shares — certificated or uncertificated (DGCL § 158).",
    citation: dgcl("158"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Stock certificate / book-entry clause missing",
    missing_description: "No clause was found addressing certificated or uncertificated shares.",
    explanation:
      "DGCL § 158 allows shares to be represented by certificates or held in uncertificated form by board resolution. Modern bylaws default to uncertificated unless requested.",
    recommendation:
      "Add a 'Form of Shares' section stating that shares are uncertificated unless the board authorizes certificates and that a stockholder may request a certificate at any time.",
    present_patterns: [/(certificat|uncertificated|book.entry).{0,40}shares?/is],
    default_severity: "warning",
  }),
  language({
    id: "GOV-011",
    name: "Exclusive-forum bylaw — federal-claims overreach",
    description:
      "A Delaware exclusive-forum bylaw cannot validly designate Delaware Chancery as the exclusive forum for Securities Act claims (Boilermakers / Sciabacucchi / Salzberg lineage; cf. CA & WA pushback).",
    citation: govPractice(
      "sciabacucchi-salzberg",
      "Salzberg v. Sciabacucchi, 227 A.3d 102 (Del. 2020) (federal-forum bylaws upheld) and contrast California / 9th Circuit treatment.",
      "https://courts.delaware.gov/Opinions/Download.aspx?id=300600",
    ),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    bad_patterns: [
      /exclusive\s+forum.{0,120}(state\s+of\s+delaware|chancery).{0,200}(exchange\s+act|1934\s+act|federal\s+securities)/is,
    ],
    exclude_if: [
      /(?:shall|will|does|do)\s+not\s+apply\s+to[^.]{0,100}(?:exchange\s+act|federal\s+securities|1934\s+act)/i,
      /(?:exclud(?:e|es|ing)|except\s+for|other\s+than)[^.]{0,60}(?:exchange\s+act|federal\s+securities|1934\s+act)/i,
    ],
    bad_title: "Exclusive-forum bylaw extends to Exchange Act claims",
    bad_description:
      "The exclusive-forum bylaw appears to designate Delaware as the exclusive forum for Securities Exchange Act of 1934 claims.",
    explanation:
      "Sciabacucchi / Salzberg upheld Delaware-forum bylaws for Securities Act of 1933 claims but expressly declined to extend that holding to Exchange Act claims, which carry exclusive federal-court jurisdiction under § 27.",
    recommendation:
      "Limit the exclusive-forum provision to internal-affairs claims (Delaware Chancery) and Securities Act 1933 claims (federal court), and exclude Exchange Act claims.",
  }),
  presence({
    id: "GOV-012",
    name: "Books and records inspection right",
    description:
      "Bylaws should acknowledge the DGCL § 220 stockholder inspection right or its MBCA § 16.02 equivalent.",
    citation: dgcl("220"),
    playbooks: [GOV_PLAYBOOK_BYLAWS],
    missing_title: "Books-and-records inspection right not addressed",
    missing_description:
      "No clause was found acknowledging stockholders' DGCL § 220 inspection right.",
    explanation:
      "DGCL § 220 inspection rights are statutory, but bylaws commonly restate them, specify the demand procedure, and limit inspection of confidential materials.",
    recommendation:
      "Add an 'Inspection of Books and Records' section restating the § 220 demand procedure (proper purpose, sworn statement) and the corporation's reasonable confidentiality limits.",
    present_patterns: [/books?\s+and\s+records/i, /section\s+220/i, /right\s+to\s+inspect/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.2 — Operating Agreement (LLC). DE LLC Act §§ 18-201, 18-402.
// 10 rules, GOV-013..GOV-022.
// ────────────────────────────────────────────────────────────────────

const OP_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "GOV-013",
    name: "Management structure (member-managed vs. manager-managed)",
    description: "LLC operating agreement must specify management structure (DE LLC Act § 18-402).",
    citation: delllca("402"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "LLC management-structure clause missing",
    missing_description:
      "No clause was found designating the LLC as member-managed or manager-managed.",
    explanation:
      "DE LLC Act § 18-402 defaults to member-managed unless the operating agreement provides otherwise. Members deserve an explicit statement.",
    recommendation:
      "Add a 'Management' section explicitly designating the LLC as member-managed or manager-managed and listing the initial managers.",
    present_patterns: [/member.managed/i, /manager.managed/i, /the\s+manager(s)?\s+shall/i],
  }),
  presence({
    id: "GOV-014",
    name: "Capital contributions clause",
    description:
      "Operating agreement must address initial capital contributions and obligations for additional capital (DE LLC Act § 18-501).",
    citation: delllca("501"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Capital contributions clause missing",
    missing_description: "No capital-contributions clause was found.",
    explanation:
      "Without a capital-contributions clause the LLC has no record of members' initial buy-in and no authority to call for more.",
    recommendation:
      "Add a 'Capital Contributions' section listing each member's initial contribution and the conditions (if any) under which additional contributions may be required.",
    present_patterns: [/capital\s+contribution/i, /initial\s+(investment|contribution)/i],
  }),
  presence({
    id: "GOV-015",
    name: "Distributions clause",
    description:
      "Operating agreement must address distributions of cash and property to members (DE LLC Act § 18-504).",
    citation: delllca("504"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Distributions clause missing",
    missing_description: "No distributions clause was found.",
    explanation:
      "DE LLC Act § 18-504 defaults distributions to be made in proportion to agreed value of contributions. Members usually intend percentage interests or waterfall — silence defaults to the statutory rule.",
    recommendation:
      "Add a 'Distributions' section specifying the timing and allocation method (pro rata by interest, waterfall, tax-distribution covenant, etc.).",
    present_patterns: [/distribution(s)?\s+(of|to|made|shall)/i],
  }),
  presence({
    id: "GOV-016",
    name: "Allocations of profits and losses",
    description:
      "Operating agreement must address tax allocations of profits and losses (IRC § 704(b) and 'substantial economic effect').",
    citation: irc("704(b)", "Allocations and substantial economic effect"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Allocations of profits / losses clause missing",
    missing_description: "No allocations clause for profits and losses was found.",
    explanation:
      "IRC § 704(b) tax allocations require 'substantial economic effect' or compliance with the partners-interests-in-the-partnership safe harbor. A bare distributions clause without an allocations clause invites IRS reallocation.",
    recommendation:
      "Add an 'Allocations' section addressing § 704(b) capital-account maintenance, qualified income offset, minimum-gain chargeback, and a § 704(c) tax-allocations rule.",
    present_patterns: [/profits?\s+and\s+losses/i, /allocations?\s+of/i, /704/i],
  }),
  presence({
    id: "GOV-017",
    name: "Transfers of membership interests",
    description:
      "Operating agreement should restrict transfers of membership interests (DE LLC Act § 18-702).",
    citation: delllca("702"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Membership-transfer restriction clause missing",
    missing_description: "No clause was found restricting transfers of membership interests.",
    explanation:
      "DE LLC Act § 18-702 makes membership interests freely assignable in economic terms unless restricted. Most LLCs want consent-based or ROFR-based transfer controls.",
    recommendation:
      "Add a 'Transfers of Interests' section requiring manager / member consent or ROFR for transfers, with carve-outs for permitted transferees.",
    present_patterns: [/transfer.{0,40}interest/is, /restrict.{0,40}transfer/is],
  }),
  presence({
    id: "GOV-018",
    name: "Dissociation / withdrawal of members",
    description:
      "Operating agreement should address voluntary and involuntary withdrawal of members (DE LLC Act § 18-603).",
    citation: delllca("603"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Member-withdrawal clause missing",
    missing_description:
      "No clause was found addressing voluntary or involuntary withdrawal of members.",
    explanation:
      "DE LLC Act § 18-603 forbids a member from resigning without the agreement of the other members unless the operating agreement says otherwise. Silence locks members in.",
    recommendation:
      "Add a 'Withdrawal / Dissociation' section specifying voluntary-withdrawal terms, buyout mechanics, and involuntary-withdrawal triggers (bankruptcy, death, bad acts).",
    present_patterns: [/(withdraw|resign|dissociat)/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-019",
    name: "Dissolution and winding up",
    description:
      "Operating agreement should specify dissolution triggers and the winding-up process (DE LLC Act §§ 18-801, 18-803).",
    citation: delllca("801"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Dissolution / winding-up clause missing",
    missing_description: "No dissolution clause was found.",
    explanation:
      "Without dissolution triggers and a winding-up procedure, the parties default to § 18-801's statutory triggers and dispute resolution is harder.",
    recommendation:
      "Add a 'Dissolution and Winding Up' section listing dissolution triggers (member vote, court order, agreed event) and the liquidation-distribution waterfall.",
    present_patterns: [/dissolution/i, /winding[\s-]?up/i],
  }),
  presence({
    id: "GOV-020",
    name: "Fiduciary duty waiver / modification (DE LLC Act § 18-1101)",
    description:
      "DE LLC Act § 18-1101(c) allows fiduciary duties to be modified or eliminated but not the implied covenant of good faith and fair dealing. A clause is either expected (waiver) or expected to acknowledge default duties.",
    citation: delllca("1101"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Fiduciary-duty treatment unaddressed",
    missing_description: "No clause was found addressing fiduciary duties of managers or members.",
    explanation:
      "DE LLC Act § 18-1101 lets members tailor fiduciary duties broadly. Without an explicit treatment, default common-law duties apply — investors often want the question answered.",
    recommendation:
      "Add a 'Fiduciary Duties' section either (a) preserving default common-law fiduciary duties or (b) modifying them subject to the implied covenant of good faith and fair dealing.",
    present_patterns: [/fiduciary\s+(duty|duties)/i, /implied\s+covenant/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-021",
    name: "Books and records / inspection",
    description:
      "Operating agreement should address member access to books and records (DE LLC Act § 18-305).",
    citation: delllca("305"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    missing_title: "Books-and-records access clause missing",
    missing_description: "No books-and-records clause was found.",
    explanation:
      "DE LLC Act § 18-305 grants members a statutory right to information; the operating agreement can refine it (proper purpose, confidentiality).",
    recommendation:
      "Add a 'Books and Records' section restating the § 18-305 access right and any reasonable conditions (proper purpose, confidentiality undertaking).",
    present_patterns: [/books?\s+and\s+records/i, /right\s+to\s+inspect/i],
    default_severity: "warning",
  }),
  language({
    id: "GOV-022",
    name: "Implied covenant cannot be waived",
    description:
      "DE LLC Act § 18-1101(c) prohibits waiver of the implied covenant of good faith and fair dealing.",
    citation: delllca("1101(c)"),
    playbooks: [GOV_PLAYBOOK_OP_AGREEMENT],
    bad_patterns: [
      /waiv(e|er|ed|es).{0,80}implied\s+covenant.{0,40}good\s+faith/is,
      /waive.{0,40}good\s+faith\s+and\s+fair\s+dealing/i,
    ],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:be\s+deemed\s+to\s+)?waive/i,
      /\bnothing\b[^.]{0,60}waive/i,
    ],
    bad_title: "Implied-covenant waiver is statutorily prohibited",
    bad_description:
      "The agreement appears to waive the implied covenant of good faith and fair dealing.",
    explanation:
      "DE LLC Act § 18-1101(c) permits modification of fiduciary duties but expressly forbids waiver of the implied covenant of good faith and fair dealing. The clause is unenforceable to that extent.",
    recommendation:
      "Strike the implied-covenant waiver; modifying or eliminating fiduciary duties is permitted, but the implied covenant must remain.",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.3 — Charter / Articles of Incorporation. DGCL § 102; MBCA § 2.02.
// 10 rules, GOV-023..GOV-032.
// ────────────────────────────────────────────────────────────────────

const CHARTER_RULES: Rule[] = [
  presence({
    id: "GOV-023",
    name: "Corporate name complies with statutory naming",
    description:
      "Charter must state the corporate name; DGCL § 102(a)(1) and MBCA § 4.01 require a recognized corporate suffix.",
    citation: dgcl("102(a)(1)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Corporate-name clause missing",
    missing_description: "No corporate-name clause with a statutory suffix was found.",
    explanation:
      "DGCL § 102(a)(1) requires the corporate name to contain 'corporation,' 'incorporated,' 'company,' 'limited,' or an abbreviation thereof.",
    recommendation:
      "Add Article I 'Name' identifying the corporation by its full legal name including a statutory suffix.",
    present_patterns: [
      /name\s+of\s+(the\s+)?corporation/i,
      /\b(corporation|incorporated|inc\.|corp\.|company|co\.|limited|ltd\.)\b/i,
    ],
  }),
  presence({
    id: "GOV-024",
    name: "Registered office and registered agent",
    description: "Charter must designate registered office and agent (DGCL § 102(a)(2)).",
    citation: dgcl("102(a)(2)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Registered office / agent clause missing",
    missing_description: "No registered-office or agent clause was found.",
    explanation:
      "Service of process and franchise-tax notices both flow through the registered agent. The charter must name both.",
    recommendation:
      "Add 'Registered Office and Agent' identifying the in-state office and the agent for service of process.",
    present_patterns: [/registered\s+(office|agent)/i, /agent\s+for\s+service\s+of\s+process/i],
  }),
  presence({
    id: "GOV-025",
    name: "Purpose clause",
    description: "Charter must state the corporate purpose (DGCL § 102(a)(3); MBCA § 3.01).",
    citation: dgcl("102(a)(3)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Purpose clause missing",
    missing_description: "No purpose clause was found.",
    explanation:
      "DGCL § 102(a)(3) authorizes a broad 'any lawful business' purpose clause; some banks / regulated industries require narrower purpose.",
    recommendation:
      "Add a 'Purpose' clause stating the corporation may engage in any lawful business or activity under the DGCL.",
    present_patterns: [
      /any\s+lawful\s+(business|act|activity|purpose)/i,
      /purpose\s+of\s+(the\s+)?corporation/i,
    ],
  }),
  presence({
    id: "GOV-026",
    name: "Authorized capital stock",
    description:
      "Charter must state the authorized capital stock — classes, shares, par value (DGCL § 102(a)(4); MBCA § 6.01).",
    citation: dgcl("102(a)(4)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Authorized capital stock clause missing",
    missing_description: "No authorized-capital-stock clause was found.",
    explanation:
      "DGCL § 102(a)(4) requires the charter to set the total number of shares the corporation is authorized to issue and the classes / par values.",
    recommendation:
      "Add 'Capital Stock' identifying authorized common (and preferred, if any) shares, par value, and class designations.",
    present_patterns: [
      /authorized\s+(capital|stock|shares?)/i,
      /(common|preferred)\s+stock/i,
      /shares?\s+of\s+stock/i,
    ],
  }),
  presence({
    id: "GOV-027",
    name: "Incorporator name and address",
    description: "Charter must identify the incorporator (DGCL § 102(a)(5); MBCA § 2.01).",
    citation: dgcl("102(a)(5)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Incorporator clause missing",
    missing_description: "No incorporator-identification clause was found.",
    explanation:
      "DGCL § 102(a)(5) requires the certificate to identify the incorporator(s). Most filings list one.",
    recommendation:
      "Add an 'Incorporator' line identifying the name and mailing address of the incorporator.",
    present_patterns: [/incorporator/i],
  }),
  presence({
    id: "GOV-028",
    name: "Director-exculpation clause (DGCL § 102(b)(7))",
    description:
      "Charter should include the optional § 102(b)(7) director-exculpation clause; absent it, directors are exposed to monetary liability for breaches of fiduciary duty of care.",
    citation: dgcl("102(b)(7)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Director-exculpation clause missing",
    missing_description: "No DGCL § 102(b)(7) director-exculpation clause was found.",
    explanation:
      "§ 102(b)(7) allows the charter to eliminate director liability for monetary damages for breaches of the duty of care (with the four statutory carve-outs). Most modern charters include it.",
    recommendation:
      "Add the standard § 102(b)(7) clause exculpating directors (and, per the 2022 amendment, certain officers) to the fullest extent permitted.",
    present_patterns: [
      /section\s+102\s*\(b\)\s*\(7\)/i,
      /eliminat(e|ed|ing)\s+.{0,40}liability\s+of\s+(a\s+)?director/is,
      /director(s)?\s+shall\s+not\s+be\s+personally\s+liable/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-029",
    name: "Indemnification authorization in charter",
    description:
      "Charter should authorize indemnification under DGCL § 145; bylaws then implement.",
    citation: dgcl("145"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Charter indemnification authorization missing",
    missing_description: "No charter clause authorizing § 145 indemnification was found.",
    explanation:
      "While the bylaws typically carry the operational text, including an indemnification authorization in the charter prevents future bylaw amendments from being read to limit existing rights.",
    recommendation:
      "Add an article stating the corporation shall indemnify D&O to the fullest extent permitted by DGCL § 145, and that any amendment may not retroactively limit indemnification.",
    present_patterns: [/indemnif/i],
  }),
  presence({
    id: "GOV-030",
    name: "Stockholder action by written consent (DGCL § 228) addressed",
    description:
      "Charter should address whether stockholders may act by written consent (DGCL § 228).",
    citation: dgcl("228"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Stockholder-written-consent treatment unaddressed",
    missing_description:
      "No charter clause was found addressing stockholder action by written consent.",
    explanation:
      "DGCL § 228 permits stockholder action by written consent of holders of the minimum number of votes that would be required at a meeting; charters often eliminate this for public companies.",
    recommendation:
      "Add a clause either permitting or eliminating stockholder action by written consent in lieu of a meeting (typical for public-company charters: eliminate).",
    present_patterns: [/written\s+consent.{0,80}(stockholders?|shareholders?)/is],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-031",
    name: "Preferred-stock blank check authority",
    description:
      "Charter should grant the board blank-check preferred-stock authority (DGCL § 151(g)).",
    citation: dgcl("151(g)"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Blank-check preferred-stock authority missing",
    missing_description: "No blank-check preferred-stock clause was found.",
    explanation:
      "Boards routinely grant themselves authority to designate preferred-stock series without further stockholder approval. This is the standard NVCA / DGCL pattern.",
    recommendation:
      "Add a clause authorizing the board to designate one or more series of preferred stock pursuant to DGCL § 151(g) without further stockholder action.",
    present_patterns: [
      /blank.check/i,
      /series\s+of\s+preferred/i,
      /board\s+may.{0,40}designate.{0,40}preferred/is,
    ],
    default_severity: "info",
  }),
  presence({
    id: "GOV-032",
    name: "Amendment of certificate of incorporation",
    description: "Charter should address amendment procedures (DGCL § 242).",
    citation: dgcl("242"),
    playbooks: [GOV_PLAYBOOK_CHARTER],
    missing_title: "Charter-amendment procedure clause missing",
    missing_description: "No charter-amendment clause was found.",
    explanation:
      "DGCL § 242 provides the default amendment procedure but many charters add supermajority or class-vote requirements for certain amendments.",
    recommendation:
      "Add 'Amendment' specifying the § 242 default or any supermajority / class-vote overrides.",
    present_patterns: [
      /amend(ment)?\s+(of|to)?\s*(the\s+)?certificate/i,
      /article.{0,30}amendment/i,
    ],
    default_severity: "info",
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.4 — Stockholders Agreement. DGCL §§ 202, 218.
// 10 rules, GOV-033..GOV-042.
// ────────────────────────────────────────────────────────────────────

const STOCKHOLDERS_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "GOV-033",
    name: "Drag-along provision",
    description:
      "Stockholders' agreements in venture-backed companies should contain a drag-along to enforce sale liquidity.",
    citation: govPractice(
      "nvca-model-sha",
      "NVCA Model Voting / Stockholders' Agreement",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Drag-along clause missing",
    missing_description: "No drag-along clause was found.",
    explanation:
      "Drag-along rights allow a majority of preferred (sometimes with founders) to force minority stockholders to sell in an approved exit. NVCA model includes one.",
    recommendation:
      "Add a 'Drag-Along' section conditioned on requisite preferred / board approval and the appraisal-protection carve-out.",
    present_patterns: [/drag.along/i],
  }),
  presence({
    id: "GOV-034",
    name: "Tag-along provision",
    description: "Tag-along rights protect minority stockholders when majority sells.",
    citation: govPractice(
      "nvca-model-sha-tag",
      "NVCA Model Voting / Stockholders' Agreement — Tag-Along",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Tag-along clause missing",
    missing_description: "No tag-along clause was found.",
    explanation:
      "Tag-along (or co-sale) lets minority stockholders join a sale by the founders / majority. Standard in venture-backed cap tables.",
    recommendation:
      "Add a 'Tag-Along / Co-Sale' section letting investors participate pro rata in any transfer above a threshold.",
    present_patterns: [/tag.along/i, /co.sale/i],
  }),
  presence({
    id: "GOV-035",
    name: "Right of first refusal (ROFR)",
    description: "ROFRs are baseline secondary-transfer control under DGCL § 202.",
    citation: dgcl("202"),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Right-of-first-refusal clause missing",
    missing_description: "No ROFR clause was found.",
    explanation:
      "DGCL § 202 makes transfer restrictions enforceable only if noted on the certificate (or the corporation maintains uncertificated-share records). The stockholders agreement is the typical home.",
    recommendation:
      "Add a 'Right of First Refusal' section requiring the transferring stockholder to offer the shares to the corporation / preferred holders first.",
    present_patterns: [/right\s+of\s+first\s+refusal/i, /\brofr\b/i],
  }),
  presence({
    id: "GOV-036",
    name: "Board composition / designation rights",
    description: "Stockholders' agreement should set out board designation rights.",
    citation: dgcl("141(a)"),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Board-designation clause missing",
    missing_description: "No board-designation clause was found.",
    explanation:
      "Investor designations are the standard governance mechanism in venture deals. The clause names each investor's designee right and the size of the board.",
    recommendation:
      "Add a 'Composition of the Board' section identifying each investor's designation right (Series A / B / etc.) and any independent / common designees.",
    present_patterns: [
      /designate.{0,40}director/i,
      /series\s+a\s+director/i,
      /preferred\s+director/i,
    ],
  }),
  presence({
    id: "GOV-037",
    name: "Information rights for investors",
    description:
      "Standard NVCA information-rights package (quarterly + annual financials, budget).",
    citation: govPractice(
      "nvca-ira",
      "NVCA Model Investor Rights Agreement",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Information-rights clause missing",
    missing_description:
      "No clause was found granting financial / operating information rights to investors.",
    explanation:
      "Information rights (quarterly unaudited, annual audited, budget) are standard for major investors. Without them, investors rely on § 220 inspection only.",
    recommendation:
      "Add an 'Information Rights' section for major investors with quarterly / annual financials, an annual budget, and customary confidentiality.",
    present_patterns: [
      /information\s+rights/i,
      /financial\s+statements?.{0,40}(quarterly|annual)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-038",
    name: "Preemptive (pro rata participation) rights",
    description: "Major-investor preemptive rights to maintain ownership in future financings.",
    citation: govPractice(
      "nvca-ira-preemptive",
      "NVCA Model Investor Rights Agreement — Preemptive Rights",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Preemptive / pro rata rights clause missing",
    missing_description: "No preemptive-rights clause was found.",
    explanation:
      "Pro rata participation rights let major investors maintain their ownership percentage in subsequent rounds. NVCA model includes one.",
    recommendation:
      "Add a 'Right to Maintain Proportionate Ownership' section with the customary excluded-issuances list.",
    present_patterns: [
      /preemptive\s+rights?/i,
      /pro.rata.{0,40}(participation|right)/is,
      /right\s+to\s+maintain.{0,40}ownership/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-039",
    name: "Protective provisions / consent rights",
    description: "Preferred stockholders' consent rights over enumerated corporate actions.",
    citation: govPractice(
      "nvca-protective",
      "NVCA Model Certificate of Incorporation / Stockholders Agreement — Protective Provisions",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Protective provisions clause missing",
    missing_description: "No protective-provisions / preferred-consent clause was found.",
    explanation:
      "Investor protective provisions list actions requiring preferred-class consent (e.g., charter amendment, sale, indebtedness above a threshold).",
    recommendation:
      "Add 'Protective Provisions' covering the NVCA-baseline list (charter amendments, redemption, new senior series, sale of the company, indebtedness, etc.).",
    present_patterns: [
      /protective\s+provisions?/i,
      /(consent\s+of|approval\s+of)\s+(the\s+)?(holders?\s+of\s+)?(a\s+)?majority\s+of\s+(the\s+)?preferred/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-040",
    name: "Voting agreement / proxy",
    description: "Voting commitments under DGCL § 218(c).",
    citation: dgcl("218"),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Voting-agreement clause missing",
    missing_description: "No voting-agreement clause was found.",
    explanation:
      "DGCL § 218(c) permits voting agreements; the standard stockholders' agreement uses one to enforce board designation and approved-sale provisions.",
    recommendation:
      "Add a 'Voting Agreement' section binding stockholders to vote in favor of board designations and approved sale transactions.",
    present_patterns: [
      /vote\s+(in\s+favor|to\s+approve)/i,
      /agree\s+to\s+vote/i,
      /irrevocable\s+proxy/i,
    ],
  }),
  presence({
    id: "GOV-041",
    name: "Termination upon IPO",
    description: "Most provisions in a stockholders' agreement should terminate on IPO.",
    citation: govPractice(
      "nvca-termination-ipo",
      "NVCA Model Stockholders' Agreement — Termination Upon IPO",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "IPO-termination clause missing",
    missing_description: "No clause was found terminating the agreement upon a qualified IPO.",
    explanation:
      "Most stockholders' agreements terminate (other than registration rights) upon a qualified IPO. Without an IPO-termination clause, transfer restrictions and ROFRs could survive the listing.",
    recommendation:
      "Add a 'Termination' section ending the agreement on the earliest of an IPO, sale of the company, or written agreement of the parties.",
    present_patterns: [
      /termin(ate|ation).{0,80}(initial\s+public\s+offering|ipo|qualified\s+ipo)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-042",
    name: "Governing law and forum",
    description: "Governing-law and forum selection are baseline.",
    citation: dgcl("115"),
    playbooks: [GOV_PLAYBOOK_STOCKHOLDERS],
    missing_title: "Governing-law / forum clause missing",
    missing_description: "No governing-law or forum-selection clause was found.",
    explanation:
      "DGCL § 115 permits Delaware-forum selection for internal-affairs claims. The stockholders' agreement should pick a governing law and forum.",
    recommendation:
      "Add 'Governing Law' (Delaware) and 'Exclusive Forum' (Delaware Chancery) clauses.",
    present_patterns: [/governing\s+law/i, /governed\s+by\s+the\s+laws/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.5 — Written Consent in Lieu of Meeting. DGCL § 141(f), § 228.
// 8 rules, GOV-043..GOV-050.
// ────────────────────────────────────────────────────────────────────

const WRITTEN_CONSENT_RULES: Rule[] = [
  presence({
    id: "GOV-043",
    name: "Written consent identifies the consenting body",
    description:
      "Consent must state whether it is from the board (DGCL § 141(f)) or stockholders (DGCL § 228).",
    citation: dgcl("141(f)"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Consenting body not identified",
    missing_description:
      "No clause was found identifying whether the consent is by the board or by the stockholders.",
    explanation:
      "DGCL § 141(f) authorizes board action by unanimous written consent; § 228 authorizes stockholder action by less-than-unanimous written consent. The consent must say which.",
    recommendation:
      "Open with 'The undersigned, constituting [all of the directors / the holders of [X]% of the outstanding stock]...' as appropriate.",
    present_patterns: [
      /written\s+consent.{0,40}(of|by)\s+(the\s+)?(board\s+of\s+directors|directors|stockholders|shareholders)/is,
      /undersigned.{0,40}(directors|stockholders)/is,
    ],
  }),
  presence({
    id: "GOV-044",
    name: "In-lieu-of-meeting recital",
    description: "The consent should recite that it is in lieu of a meeting (DGCL §§ 141(f), 228).",
    citation: dgcl("228"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "In-lieu-of-meeting recital missing",
    missing_description: "No 'in lieu of a meeting' recital was found.",
    explanation:
      "Standard recital language anchors the consent to the statutory authority for action without a meeting.",
    recommendation:
      "Include 'pursuant to DGCL § [141(f) / 228] and in lieu of a [meeting of the Board of Directors / annual or special meeting of the stockholders]'.",
    present_patterns: [/in\s+lieu\s+of\s+a\s+meeting/i],
  }),
  presence({
    id: "GOV-045",
    name: "Unanimous-consent statement (board consents only)",
    description: "DGCL § 141(f) board consents must be unanimous.",
    citation: dgcl("141(f)"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Unanimous-consent statement missing",
    missing_description: "No statement that the board consent is unanimous was found.",
    explanation:
      "DGCL § 141(f) requires unanimous written consent of the directors for action without a meeting. A consent missing one or more director signatures is invalid.",
    recommendation:
      "Add 'The undersigned constitute all of the directors then in office'; have every director sign.",
    present_patterns: [
      /constitute\s+all\s+of\s+the\s+directors/i,
      /unanimous(ly)?\s+(consent|adopt)/i,
    ],
  }),
  presence({
    id: "GOV-046",
    name: "Stockholder consent — minimum-vote threshold recital",
    description:
      "Stockholder consents must recite that the signing stockholders hold the requisite vote (DGCL § 228).",
    citation: dgcl("228"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Stockholder consent threshold recital missing",
    missing_description:
      "No recital was found establishing that the signers hold the minimum vote that would be required at a meeting.",
    explanation:
      "DGCL § 228 requires that consents represent the minimum number of votes necessary to authorize the action at a meeting at which all shares entitled to vote were present.",
    recommendation:
      "Add 'The undersigned represent and warrant that they are the holders of at least [X]% of the outstanding [class] entitled to vote on this action' as applicable.",
    present_patterns: [
      /holders?\s+of.{0,40}outstanding\s+(stock|shares)/is,
      /at\s+least\s+a\s+majority\s+of\s+the\s+(voting\s+)?(power|stock)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-047",
    name: "Resolutions enumerated",
    description: "Consents should contain numbered or otherwise itemized resolutions.",
    citation: dgcl("228"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Itemized resolutions missing",
    missing_description: "No enumerated 'RESOLVED, that ...' resolutions were found.",
    explanation:
      "Standard practice: the consent itemizes each resolution so the action taken is unambiguous.",
    recommendation:
      "Format the action items as 'RESOLVED, that ...' clauses, one per substantive decision.",
    present_patterns: [/\bresolved,?\s+that\b/i],
  }),
  presence({
    id: "GOV-048",
    name: "Notice to non-signing stockholders (DGCL § 228(e))",
    description:
      "Less-than-unanimous stockholder consents require prompt notice to non-signing stockholders.",
    citation: dgcl("228(e)"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Non-signing stockholder notice missing",
    missing_description:
      "No clause was found addressing notice to non-consenting stockholders under DGCL § 228(e).",
    explanation:
      "DGCL § 228(e) requires the corporation to give prompt notice of the action to stockholders who did not sign the consent.",
    recommendation:
      "Add a closing recital directing the secretary to deliver notice to non-consenting stockholders under § 228(e).",
    present_patterns: [
      /notice.{0,40}non.?consenting\s+stockholders?/is,
      /section\s+228\s*\(?e\)?/i,
    ],
  }),
  presence({
    id: "GOV-049",
    name: "Effective date / dating",
    description: "Consent should be dated as of a specific date.",
    citation: dgcl("228(c)"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Effective date missing",
    missing_description: "No effective-date clause was found.",
    explanation:
      "DGCL § 228(c) starts a 60-day clock from the earliest-dated consent — leaving the consent undated invites challenge.",
    recommendation: "Add 'This consent is effective as of [date]' near the signature block.",
    present_patterns: [/effective\s+(as\s+of|date)/i, /dated\s+(as\s+of|the)/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-050",
    name: "Signature block on each consent page",
    description:
      "Each director / stockholder signing must sign — typically with a counterparts clause.",
    citation: dgcl("228(d)"),
    playbooks: [GOV_PLAYBOOK_WRITTEN_CONSENT],
    missing_title: "Signature / counterparts clause missing",
    missing_description: "No signature block or counterparts clause was found.",
    explanation:
      "DGCL § 228(d) permits electronic delivery; counterparts and electronic signatures are standard.",
    recommendation:
      "Add a signature block per signer and a 'Counterparts and Electronic Signatures' closing.",
    present_patterns: [/counterparts?/i, /electronic\s+signature/i, /\bby:\s*_+/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.6 — Committee Charter (audit / comp / nom). SOX § 301; NYSE 303A;
// Nasdaq 5605. 10 rules, GOV-051..GOV-060.
// ────────────────────────────────────────────────────────────────────

const COMMITTEE_CHARTER_RULES: Rule[] = [
  presence({
    id: "GOV-051",
    name: "Committee purpose stated",
    description:
      "Committee charter must state the committee's purpose (NYSE 303A.06 / Nasdaq 5605).",
    citation: nyse303A("06"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Committee purpose clause missing",
    missing_description: "No purpose clause was found.",
    explanation:
      "NYSE Listed Company Manual § 303A and Nasdaq Listing Rule 5605 require committee charters to specify the committee's purpose.",
    recommendation: "Open the charter with 'Purpose' setting out the committee's mandate.",
    present_patterns: [/\bpurpose\b/i],
  }),
  presence({
    id: "GOV-052",
    name: "Composition and independence",
    description: "Committee charter must address composition and director independence.",
    citation: nasdaq("5605"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Composition / independence clause missing",
    missing_description: "No clause was found addressing composition and director independence.",
    explanation:
      "Audit (SOX § 301; NYSE 303A.07; Nasdaq 5605(c)) requires all-independent membership. Comp / Nom committees have related (often softer) requirements.",
    recommendation:
      "Add 'Composition' specifying the number of members, independence standard, and any specialized qualifications (e.g., audit-committee financial expert).",
    present_patterns: [
      /independent\s+director/i,
      /composition/i,
      /financial(ly)?\s+(literate|expert)/i,
    ],
  }),
  presence({
    id: "GOV-053",
    name: "Audit committee — § 301 oversight authority",
    description:
      "Audit-committee charter must reflect SOX § 301 oversight of the registered public accounting firm.",
    citation: sox301(),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Audit-committee oversight authority clause missing",
    missing_description:
      "No clause was found establishing the audit committee's direct responsibility for the appointment, compensation, retention, and oversight of the external auditor.",
    explanation:
      "SOX § 301 mandates that the audit committee be directly responsible for the registered public accounting firm. The auditor reports directly to the committee.",
    recommendation:
      "Add a clause stating the audit committee shall be 'directly responsible for the appointment, compensation, retention, and oversight of the work of any registered public accounting firm'.",
    present_patterns: [
      /(directly\s+responsible|appointment.{0,20}compensation.{0,20}retention).{0,60}(auditor|registered\s+public\s+accounting\s+firm)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-054",
    name: "Whistleblower / complaint procedures (SOX § 301(4))",
    description:
      "Audit committee must have procedures for receiving and addressing complaints regarding accounting / internal-controls / auditing matters.",
    citation: sox301(),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Whistleblower / complaint-handling clause missing",
    missing_description: "No SOX § 301(4) complaint-handling clause was found.",
    explanation:
      "SOX § 301(4) requires the audit committee to establish procedures for the receipt, retention, and treatment of complaints regarding accounting, internal accounting controls, or auditing matters, including a confidential / anonymous channel.",
    recommendation:
      "Add a clause establishing complaint-handling procedures including a confidential / anonymous channel.",
    present_patterns: [
      /complaints?.{0,80}(accounting|internal\s+controls|auditing)/is,
      /(confidential|anonymous).{0,80}submission/is,
      /whistleblower/i,
    ],
  }),
  presence({
    id: "GOV-055",
    name: "Funding authority for advisors (SOX § 301(5))",
    description:
      "Audit committee must have authority to engage and pay independent counsel / advisors.",
    citation: sox301(),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Advisor-funding authority clause missing",
    missing_description:
      "No clause was found granting the committee independent funding for counsel and advisors.",
    explanation:
      "SOX § 301(5) requires the audit committee to have the authority to engage independent counsel and other advisors, with the company providing appropriate funding.",
    recommendation:
      "Add a clause granting the committee authority to engage independent counsel / advisors at the company's expense.",
    present_patterns: [
      /authority\s+to\s+(engage|retain).{0,40}(counsel|advisor)/is,
      /appropriate\s+funding/i,
    ],
  }),
  presence({
    id: "GOV-056",
    name: "Meetings — frequency and minimum",
    description: "Committee charter must specify meeting frequency.",
    citation: nyse303A("07"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Meeting-frequency clause missing",
    missing_description: "No clause was found specifying committee meeting frequency.",
    explanation:
      "NYSE / Nasdaq listing standards expect a stated meeting cadence — at least quarterly for audit, periodic for comp / nom.",
    recommendation:
      "Add a 'Meetings' section specifying at least four meetings per year (audit) or as the committee determines necessary (comp / nom).",
    present_patterns: [
      /meeting(s)?\s+(of|at\s+least|frequency)/i,
      /at\s+least\s+(four|quarterly)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-057",
    name: "Annual self-evaluation",
    description:
      "Audit, comp, and nom committees must conduct an annual performance evaluation (NYSE 303A.07(b), 303A.05(b), 303A.04(b)).",
    citation: nyse303A("05(b)"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Annual self-evaluation clause missing",
    missing_description: "No annual-self-evaluation clause was found.",
    explanation: "NYSE 303A requires each committee to perform an annual self-evaluation.",
    recommendation:
      "Add an 'Annual Self-Evaluation' clause requiring an annual review of the committee's performance.",
    present_patterns: [/annual\s+(self.|performance.)?evaluation/is, /annual\s+review/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-058",
    name: "Reporting to the full board",
    description: "Committee charter must require periodic reporting to the full board.",
    citation: nyse303A("06"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Reporting-to-board clause missing",
    missing_description: "No clause was found requiring the committee to report to the full board.",
    explanation:
      "Standard practice — committees report at each regular board meeting on their activities and recommendations.",
    recommendation:
      "Add a 'Reports' clause requiring the committee to report periodically to the board.",
    present_patterns: [
      /report\s+to\s+the\s+(full\s+)?board/i,
      /\breport(s)?\s+to\s+the\s+board\b/i,
    ],
  }),
  presence({
    id: "GOV-059",
    name: "Charter review and amendment",
    description: "Committee charter must be reviewed and reassessed annually.",
    citation: nasdaq("5605"),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    missing_title: "Charter-review clause missing",
    missing_description: "No annual charter-review clause was found.",
    explanation: "NYSE 303A and Nasdaq 5605 require annual reassessment of the committee charter.",
    recommendation: "Add a 'Review of Charter' clause requiring annual reassessment.",
    present_patterns: [
      /review.{0,40}charter/is,
      /annually\s+reassess/i,
      /reviewed\s+at\s+least\s+annually/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "GOV-060",
    name: "Audit committee — non-independent member prohibited",
    description:
      "Charter cannot allow a non-independent member to serve on the audit committee absent the § 301 controlled-company / phase-in exception.",
    citation: sox301(),
    playbooks: [GOV_PLAYBOOK_COMMITTEE_CHARTER],
    bad_patterns: [
      /non.independent\s+(director|member).{0,40}(may|shall|can)\s+serve.{0,40}audit/is,
    ],
    bad_title: "Audit-committee independence override flagged",
    bad_description:
      "The charter appears to permit a non-independent director to sit on the audit committee.",
    explanation:
      "SOX § 301 / Rule 10A-3 forbid non-independent audit-committee members except for narrow phase-in / controlled-company exceptions.",
    recommendation:
      "Strike the override or limit it to the specific phase-in exceptions in Exchange Act Rule 10A-3.",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.7 — Partnership / LP Agreement. RUPA; DRULPA.
// 10 rules, GOV-061..GOV-070.
// ────────────────────────────────────────────────────────────────────

const PARTNERSHIP_RULES: Rule[] = [
  presence({
    id: "GOV-061",
    name: "Identification of partners and partnership type",
    description:
      "Partnership agreement must identify the partners and the type of partnership (general / limited / LLP).",
    citation: rupa("103"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partner-identification clause missing",
    missing_description: "No clause was found identifying the partners and partnership type.",
    explanation:
      "RUPA § 103 governs the role of the partnership agreement. Identification of partners and partnership type is the baseline.",
    recommendation:
      "Add 'Parties and Formation' identifying each partner and the type of partnership (general, limited, or LLP).",
    present_patterns: [/general\s+partner/i, /limited\s+partner/i, /partnership\s+is\s+formed/i],
  }),
  presence({
    id: "GOV-062",
    name: "Contributions and capital accounts",
    description:
      "Partnership agreement should address contributions and capital-account maintenance.",
    citation: drulpa("502"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Contributions / capital-accounts clause missing",
    missing_description:
      "No clause was found addressing partner contributions or capital accounts.",
    explanation:
      "DRULPA § 17-502 governs LP contributions; § 704(b) tax allocations require capital accounts. Both belong in the agreement.",
    recommendation:
      "Add 'Capital Contributions and Accounts' setting out initial contributions and § 704(b) capital-account maintenance.",
    present_patterns: [
      /capital\s+(contribution|account)/i,
      /contributions?\s+to\s+the\s+partnership/i,
    ],
  }),
  presence({
    id: "GOV-063",
    name: "Profit and loss allocations",
    description: "Partnership agreement must allocate profits and losses (IRC § 704(b)).",
    citation: irc("704(b)", "Partnership tax allocations"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partnership-allocations clause missing",
    missing_description: "No allocations clause was found.",
    explanation:
      "Without § 704(b)-compliant allocations the IRS can reallocate income / loss under partners-interests-in-the-partnership.",
    recommendation:
      "Add 'Allocations' including substantial-economic-effect provisions and a § 704(c) tax-allocations rule.",
    present_patterns: [/profits?\s+and\s+losses/i, /allocations?\s+of/i],
  }),
  presence({
    id: "GOV-064",
    name: "Management authority — general partner / partners",
    description: "Partnership agreement should set out management authority.",
    citation: rupa("401"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partnership-management clause missing",
    missing_description: "No partnership-management clause was found.",
    explanation:
      "RUPA § 401 defaults to equal management rights; DRULPA reserves management to the general partner. The agreement should restate or modify the default.",
    recommendation:
      "Add 'Management' setting out general-partner / partner management authority and any required partner consents.",
    present_patterns: [
      /management.{0,40}(general\s+partner|partner)/is,
      /general\s+partner\s+shall\s+manage/i,
    ],
  }),
  presence({
    id: "GOV-065",
    name: "LP limited liability acknowledgment (DRULPA § 17-303)",
    description:
      "Limited partners are not liable for partnership obligations unless they participate in control.",
    citation: drulpa("303"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "LP limited-liability acknowledgment missing",
    missing_description:
      "No clause was found acknowledging that limited partners are not liable for partnership obligations.",
    explanation:
      "DRULPA § 17-303(a) provides that limited partners are not personally liable for partnership obligations solely by reason of being a limited partner.",
    recommendation: "Add a 'Limited Partner Liability' clause restating the § 17-303(a) default.",
    present_patterns: [
      /limited\s+partner.{0,80}not.{0,40}liable/is,
      /limited\s+liability.{0,40}limited\s+partner/is,
    ],
  }),
  presence({
    id: "GOV-066",
    name: "Transfers of partnership interests",
    description: "Partnership agreement should restrict transfers (RUPA § 502; DRULPA § 17-702).",
    citation: drulpa("702"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partnership-transfer clause missing",
    missing_description: "No transfer-restriction clause was found.",
    explanation:
      "Default RUPA / DRULPA rules permit only economic-interest transfers; admission as a partner requires unanimous consent unless the agreement says otherwise.",
    recommendation:
      "Add 'Transfers of Interests' specifying transfer restrictions and admission of substituted partners.",
    present_patterns: [/transfer.{0,40}(partnership|interest)/is, /admit.{0,40}partner/i],
  }),
  presence({
    id: "GOV-067",
    name: "Dissolution events",
    description:
      "Partnership agreement should enumerate dissolution events (RUPA § 801; DRULPA § 17-801).",
    citation: rupa("801"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partnership-dissolution clause missing",
    missing_description: "No dissolution clause was found.",
    explanation:
      "Default RUPA / DRULPA dissolution triggers may not match commercial expectations; partners should agree on the precise list.",
    recommendation:
      "Add 'Dissolution' listing dissolution triggers (term expiration, partner vote, judicial decree).",
    present_patterns: [/dissolution/i],
  }),
  presence({
    id: "GOV-068",
    name: "Indemnification of general partner",
    description: "GP indemnification under DRULPA § 17-108 should be addressed.",
    citation: drulpa("108"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "GP indemnification clause missing",
    missing_description: "No GP-indemnification clause was found.",
    explanation:
      "DRULPA § 17-108 permits broad indemnification of GPs. Practice baseline is to grant it expressly.",
    recommendation:
      "Add 'Indemnification' covering the GP to the fullest extent permitted by DRULPA § 17-108.",
    present_patterns: [/indemnif/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-069",
    name: "Tax matters / partnership representative",
    description:
      "BBA partnership-audit rules require designation of a Partnership Representative (IRC § 6223).",
    citation: irc("6223", "Partnership Representative"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    missing_title: "Partnership-Representative clause missing",
    missing_description:
      "No clause was found designating a Partnership Representative under IRC § 6223.",
    explanation:
      "Under the BBA centralized partnership audit regime (effective 2018+), each partnership must designate a Partnership Representative or one will be designated by the IRS.",
    recommendation:
      "Add a 'Partnership Representative' clause designating a PR with binding authority for IRS proceedings under IRC § 6223.",
    present_patterns: [
      /partnership\s+representative/i,
      /tax\s+matters\s+partner/i,
      /section\s+6223/i,
    ],
  }),
  language({
    id: "GOV-070",
    name: "Implied covenant cannot be eliminated (DRULPA § 17-1101(d))",
    description:
      "DRULPA § 17-1101(d) prohibits elimination of the implied covenant of good faith and fair dealing.",
    citation: drulpa("1101"),
    playbooks: [GOV_PLAYBOOK_PARTNERSHIP],
    bad_patterns: [/(waive|eliminate|disclaim).{0,80}implied\s+covenant.{0,40}good\s+faith/is],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:waive|eliminate|disclaim)/i,
      /\bnothing\b[^.]{0,60}(?:waive|eliminate|disclaim)/i,
    ],
    bad_title: "Implied-covenant waiver flagged",
    bad_description:
      "The agreement appears to waive or eliminate the implied covenant of good faith and fair dealing.",
    explanation:
      "DRULPA § 17-1101(d) permits modification of partner duties but expressly forbids elimination of the implied covenant.",
    recommendation: "Strike the implied-covenant waiver and keep duties-modification language.",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// B.8 — Nonprofit Bylaws / 501(c)(3). IRC § 501(c)(3); Form 990;
// ABA Model Nonprofit Corp Act. 10 rules, GOV-071..GOV-080.
// ────────────────────────────────────────────────────────────────────

const NONPROFIT_RULES: Rule[] = [
  presence({
    id: "GOV-071",
    name: "501(c)(3) exempt purpose recital",
    description:
      "Nonprofit bylaws should recite the § 501(c)(3) exempt purposes (charitable, religious, educational, scientific, etc.).",
    citation: irc("501(c)(3)", "Tax-exempt purposes"),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "§ 501(c)(3) purpose recital missing",
    missing_description: "No § 501(c)(3) exempt-purpose recital was found.",
    explanation:
      "Treas. Reg. § 1.501(c)(3)-1(b) requires the organizing documents to limit the entity's purposes to one or more exempt purposes. The bylaws typically restate the charter.",
    recommendation:
      "Add 'Purpose' restating the § 501(c)(3) exempt purposes (charitable, religious, educational, scientific, etc.).",
    present_patterns: [
      /501\s*\(?c\)?\s*\(?3\)?/i,
      /tax.exempt\s+purpose/i,
      /charitable\s+purposes?/i,
    ],
  }),
  presence({
    id: "GOV-072",
    name: "Inurement prohibition",
    description:
      "Bylaws must prohibit inurement of net earnings to private individuals (IRC § 501(c)(3); Treas. Reg. § 1.501(c)(3)-1(c)(2)).",
    citation: irc("501(c)(3)", "Inurement prohibition"),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Inurement-prohibition clause missing",
    missing_description: "No inurement-prohibition clause was found.",
    explanation:
      "Treas. Reg. § 1.501(c)(3)-1(c)(2) requires that no part of the net earnings inure to the benefit of private shareholders or individuals. Failure to include this provision can cost the exemption.",
    recommendation:
      "Add 'No part of the net earnings of the corporation shall inure to the benefit of, or be distributable to, its members, trustees, officers, or other private persons...'.",
    present_patterns: [/inure\s+to/i, /no\s+part\s+of\s+the\s+net\s+earnings/i],
  }),
  presence({
    id: "GOV-073",
    name: "Political-activity prohibition",
    description:
      "Bylaws must prohibit participation in political campaigns and limit lobbying (IRC § 501(c)(3)).",
    citation: irc("501(c)(3)", "Political-activity prohibition"),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Political-activity prohibition clause missing",
    missing_description: "No clause was found prohibiting political campaign activity.",
    explanation:
      "IRC § 501(c)(3) absolutely prohibits intervention in political campaigns and limits lobbying to an insubstantial part of activities (subject to § 501(h) election).",
    recommendation:
      "Add a clause prohibiting political-campaign intervention and restricting lobbying to permitted limits.",
    present_patterns: [
      /political\s+campaign/i,
      /no\s+substantial\s+part.{0,40}lobby/is,
      /shall\s+not\s+participate.{0,40}political/is,
    ],
  }),
  presence({
    id: "GOV-074",
    name: "Dissolution clause (assets distributed to 501(c)(3))",
    description:
      "Dissolution clause must require distribution of remaining assets to another § 501(c)(3) organization (Treas. Reg. § 1.501(c)(3)-1(b)(4)).",
    citation: irc("501(c)(3)", "Dissolution / assets clause"),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Compliant dissolution clause missing",
    missing_description:
      "No dissolution clause was found that distributes residual assets to another § 501(c)(3) organization.",
    explanation:
      "Treas. Reg. § 1.501(c)(3)-1(b)(4) requires the organizing documents to provide that upon dissolution residual assets be distributed for one or more exempt purposes (e.g., to another § 501(c)(3) organization) or to a federal / state / local government.",
    recommendation:
      "Add a 'Dissolution' clause directing residual assets 'to be distributed to one or more organizations qualifying as exempt under § 501(c)(3) of the Internal Revenue Code'.",
    present_patterns: [/dissolution.{0,200}(501\s*\(?c\)?\s*\(?3\)?|exempt\s+organization)/is],
  }),
  presence({
    id: "GOV-075",
    name: "Conflict-of-interest policy",
    description:
      "IRS Form 990 governance section asks whether a written conflict-of-interest policy exists.",
    citation: form990(),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Conflict-of-interest policy clause missing",
    missing_description: "No conflict-of-interest policy was found.",
    explanation:
      "Form 990 Part VI asks whether the organization has a written COI policy. Bylaws / a separate policy is best practice and is heavily expected by the IRS.",
    recommendation:
      "Add (or incorporate by reference) a 'Conflict of Interest Policy' substantially in the form of the IRS Appendix A model.",
    present_patterns: [/conflict\s+of\s+interest/i],
  }),
  presence({
    id: "GOV-076",
    name: "Board composition and quorum",
    description: "Nonprofit bylaws must specify board composition and quorum.",
    citation: govPractice(
      "aba-model-nonprofit",
      "ABA Model Nonprofit Corporation Act (4th ed.)",
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/nonprofit-corporations/",
    ),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Board composition / quorum clause missing",
    missing_description: "No board-composition or quorum clause was found.",
    explanation:
      "ABA Model Nonprofit Corp Act expects bylaws to fix the board's number and quorum.",
    recommendation:
      "Add 'Board of Directors — Composition and Quorum' setting the number of directors (or range) and the quorum requirement.",
    present_patterns: [/board\s+of\s+directors/i, /quorum/i],
  }),
  presence({
    id: "GOV-077",
    name: "Member vs. non-member structure",
    description: "Bylaws should specify whether the nonprofit has voting members.",
    citation: govPractice(
      "aba-model-nonprofit-members",
      "ABA Model Nonprofit Corporation Act (4th ed.) — Members",
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/nonprofit-corporations/",
    ),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Member-or-non-member clause missing",
    missing_description:
      "No clause was found establishing the nonprofit as a member or non-member organization.",
    explanation:
      "Whether the nonprofit has voting members materially changes governance — the bylaws must say so explicitly.",
    recommendation: "Add 'Members' (or 'No Members') specifying the membership structure.",
    present_patterns: [
      /the\s+corporation\s+shall\s+have\s+(no\s+)?members/i,
      /members?\s+of\s+the\s+corporation/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-078",
    name: "Annual meeting / required meetings",
    description: "Bylaws must specify annual / regular board meetings.",
    citation: govPractice(
      "aba-model-nonprofit-meetings",
      "ABA Model Nonprofit Corporation Act (4th ed.) — Meetings",
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/nonprofit-corporations/",
    ),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Annual / regular meetings clause missing",
    missing_description: "No annual-meeting clause was found.",
    explanation: "ABA Model Nonprofit Corp Act calls for at least an annual meeting of the board.",
    recommendation:
      "Add 'Meetings of the Board' specifying an annual meeting and regular-meeting cadence.",
    present_patterns: [/annual\s+meeting/i, /regular\s+meeting/i],
    default_severity: "warning",
  }),
  presence({
    id: "GOV-079",
    name: "Indemnification of directors and officers",
    description: "Bylaws should provide for indemnification of directors and officers.",
    citation: govPractice(
      "aba-model-nonprofit-indemnification",
      "ABA Model Nonprofit Corporation Act (4th ed.) — Indemnification",
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/nonprofit-corporations/",
    ),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    missing_title: "Indemnification clause missing",
    missing_description: "No indemnification clause was found.",
    explanation:
      "ABA Model Nonprofit Corp Act permits broad indemnification; nonprofits typically grant it expressly to attract qualified directors.",
    recommendation:
      "Add an 'Indemnification' article granting directors and officers indemnification to the fullest extent permitted by state law.",
    present_patterns: [/indemnif/i],
  }),
  compound({
    id: "GOV-080",
    name: "Three-pillar 501(c)(3) charter recitals present (inurement + political + dissolution)",
    description:
      "Treas. Reg. § 1.501(c)(3)-1(b) requires three organizing-document pillars: (1) exempt-purpose limitation, (2) inurement / political prohibition, (3) dissolution-to-exempt-organization.",
    citation: irc("501(c)(3)", "Three organizational-test pillars"),
    playbooks: [GOV_PLAYBOOK_NONPROFIT],
    required_patterns: [
      /(charitable|religious|educational|scientific).{0,40}(purpose|under\s+section\s+501)/is,
      /(inure|political\s+campaign|no\s+substantial\s+part)/i,
      /dissolution.{0,200}(exempt|501)/is,
    ],
    min_match: 3,
    missing_title: "Organizational-test pillars incomplete",
    missing_description:
      "One or more of the three Treas. Reg. § 1.501(c)(3)-1(b) organizational pillars (purpose, inurement / political, dissolution) is missing.",
    explanation:
      "All three pillars must appear in the organizing documents for the entity to meet the § 501(c)(3) organizational test.",
    recommendation:
      "Include all three pillars: an exempt-purposes recital, an inurement / political-activity prohibition, and a dissolution clause directing residual assets to another § 501(c)(3).",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. Order matches doc order within the file; the runner
// sorts by id lexicographically before execution.
// ────────────────────────────────────────────────────────────────────

export const GOVERNANCE_RULES: Rule[] = [
  ...BYLAWS_RULES,
  ...OP_AGREEMENT_RULES,
  ...CHARTER_RULES,
  ...STOCKHOLDERS_AGREEMENT_RULES,
  ...WRITTEN_CONSENT_RULES,
  ...COMMITTEE_CHARTER_RULES,
  ...PARTNERSHIP_RULES,
  ...NONPROFIT_RULES,
];

export {
  BYLAWS_RULES,
  OP_AGREEMENT_RULES,
  CHARTER_RULES,
  STOCKHOLDERS_AGREEMENT_RULES,
  WRITTEN_CONSENT_RULES,
  COMMITTEE_CHARTER_RULES,
  PARTNERSHIP_RULES,
  NONPROFIT_RULES,
};

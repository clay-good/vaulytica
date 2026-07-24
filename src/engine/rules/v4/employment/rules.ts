/**
 * v4 Employment ruleset — 50 rules (spec-v4.md §6.F, Step 49).
 *
 * Seven new playbooks: executive employment, offer letter,
 * separation / severance, employment-side restrictive covenant,
 * PIIA, performance-improvement plan, employee handbook. Citations
 * anchor to OWBPA / ADEA § 626(f), NLRB *McLaren Macomb*, IRC § 409A
 * and § 280G, the FTC Non-Compete Rule, state non-compete law, CA
 * Lab. § 2870, NLRA § 7, FLSA, Reg S-K Item 402, and EEOC guidance.
 *
 * Rule ids are flat `EMP-NNN` (001..050); each rule's
 * `applies_to_playbooks` restricts execution.
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  EMP_PLAYBOOK_EXEC,
  EMP_PLAYBOOK_OFFER,
  EMP_PLAYBOOK_SEPARATION,
  EMP_PLAYBOOK_RC,
  EMP_PLAYBOOK_PIIA,
  EMP_PLAYBOOK_PIP,
  EMP_PLAYBOOK_HANDBOOK,
  owbpa,
  mclarenMacomb,
  irc,
  ftcNcr,
  stateNonCompete,
  caLab2870,
  nlraSec7,
  eeocGuidance,
  secRule21F17,
  flsa,
  regSk402,
  empPractice,
} from "./_helpers.js";

const CATEGORY = "employment";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// F.2 — Executive Employment Agreement. 8 rules: EMP-001..EMP-008.
// ────────────────────────────────────────────────────────────────────

const EXEC_EMPLOYMENT_RULES: Rule[] = [
  presence({
    id: "EMP-001",
    name: "Title, duties, and reporting line",
    description:
      "Executive agreement must state title, duties, and reporting line (CEO / Board / supervising executive).",
    citation: empPractice(
      "exec-baseline",
      "Executive employment baseline (Reg S-K Item 402)",
      "https://www.law.cornell.edu/cfr/text/17/229.402",
    ),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Title / duties / reporting clause missing",
    missing_description: "No clause was found stating title, duties, and reporting line.",
    explanation:
      "Title and reporting line trigger 'Good Reason' termination protections; without them the protection is unusable.",
    recommendation: "Add 'Position and Duties' with title, duties, and reporting relationship.",
    present_patterns: [
      /(title|position|role)/i,
      /(duties|responsibilities)/i,
      /(report(s|ing)?\s+to|reporting\s+line)/i,
    ],
  }),
  presence({
    id: "EMP-002",
    name: "Base salary and bonus structure",
    description: "Executive agreement must state base salary and bonus / incentive structure.",
    citation: regSk402(),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Base salary / bonus clause missing",
    missing_description: "No base-salary or bonus clause was found.",
    explanation:
      "Reg S-K Item 402 requires disclosure of compensation arrangements for named executive officers.",
    recommendation:
      "Add 'Compensation' specifying base salary, target bonus, and any equity awards.",
    present_patterns: [/base\s+salary/i, /annual\s+(bonus|incentive)/i, /target\s+bonus/i],
  }),
  presence({
    id: "EMP-003",
    name: "§ 409A compliance language",
    description:
      "Executive agreements with deferred compensation must comply with IRC § 409A or carry an exclusion / cure recital.",
    citation: irc("409A", "Deferred compensation"),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "§ 409A compliance clause missing",
    missing_description: "No IRC § 409A compliance clause was found.",
    explanation:
      "Severance, deferred bonuses, and certain equity grants implicate § 409A. Violation triggers 20% additional tax + interest on the executive — a § 409A compliance recital is universal in modern agreements.",
    recommendation:
      "Add 'Section 409A' with a compliance recital, the 6-month delay for specified employees, and reformation authority.",
    present_patterns: [/(section\s+409a|\b409a\b)/i, /(specified\s+employee|six.month\s+delay)/i],
  }),
  presence({
    id: "EMP-004",
    name: "§ 280G parachute-payment treatment",
    description:
      "Executive agreement with change-of-control benefits should address IRC § 280G parachute-payment treatment.",
    citation: irc("280G", "Golden parachute payments"),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "§ 280G clause missing",
    missing_description: "No clause was found addressing § 280G parachute treatment.",
    explanation:
      "If CIC payments exceed 3x base amount, the excess is non-deductible to the company and subject to a 20% excise tax on the executive. Standard pattern: 'best-net' (cap or full-pay, whichever is better after tax) or stockholder vote (private company).",
    recommendation: "Add 'Section 280G' with best-net or cleansing-vote treatment.",
    present_patterns: [/(section\s+280g|\b280g\b)/i, /(parachute\s+payment|excise\s+tax)/i],
  }),
  presence({
    id: "EMP-005",
    name: "Termination definitions (Cause, Good Reason, CIC, Disability)",
    description: "Executive agreement must define termination triggers.",
    citation: empPractice(
      "exec-termination",
      "Executive termination definitions baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Termination definitions clause missing",
    missing_description:
      "No clause was found defining Cause, Good Reason, Change in Control, or Disability.",
    explanation: "Severance benefits turn on these definitions; ambiguity is a litigation trigger.",
    recommendation:
      "Define each of Cause, Good Reason, Change in Control, and Disability with cure periods.",
    present_patterns: [
      /\bcause\b/i,
      /good\s+reason/i,
      /change\s+(in|of)\s+control/i,
      /disability/i,
    ],
  }),
  presence({
    id: "EMP-006",
    name: "Severance schedule",
    description: "Executive agreement must specify severance benefits on qualifying terminations.",
    citation: empPractice(
      "exec-severance",
      "Executive severance baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Severance schedule clause missing",
    missing_description: "No severance-schedule clause was found.",
    explanation: "Termination protection is the central economic feature of executive agreements.",
    recommendation:
      "Add 'Severance Benefits' with cash multiple, COBRA, accelerated vesting, and bonus treatment.",
    present_patterns: [/severance/i, /salary\s+continuation/i, /(cobra|continuation\s+coverage)/i],
  }),
  presence({
    id: "EMP-007",
    name: "Clawback policy reference (Dodd-Frank § 954)",
    description:
      "Listed-issuer executive agreements should reference the clawback policy (Dodd-Frank § 954; SEC Rule 10D-1).",
    citation: regSk402(),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Clawback policy reference missing",
    missing_description: "No clawback / Dodd-Frank clawback reference was found.",
    explanation:
      "Listed issuers must adopt Rule 10D-1 clawback policies (2023+); executive agreements typically incorporate by reference.",
    recommendation:
      "Add 'Clawback' incorporating the company's Rule 10D-1 / Dodd-Frank § 954 clawback policy.",
    present_patterns: [/clawback/i, /(section\s+954|rule\s+10d.1)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-008",
    name: "Restrictive covenants subordinated to non-compete / NDA terms",
    description:
      "Executive agreement should incorporate or carry restrictive covenants by reference.",
    citation: ftcNcr(),
    playbooks: [EMP_PLAYBOOK_EXEC],
    missing_title: "Restrictive-covenants reference missing",
    missing_description: "No restrictive-covenants clause / reference was found.",
    explanation:
      "Executives need non-disclosure, non-solicit, and (where enforceable) non-compete coverage.",
    recommendation:
      "Add 'Restrictive Covenants' incorporating a NDA + non-solicit (and non-compete only where enforceable).",
    present_patterns: [/restrictive\s+covenant/i, /(non.?disclosure|non.?solicit)/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.3 — Offer Letter. 6 rules: EMP-009..EMP-014.
// ────────────────────────────────────────────────────────────────────

const OFFER_LETTER_RULES: Rule[] = [
  presence({
    id: "EMP-009",
    name: "Position, start date, base compensation",
    description: "Offer letter must state position, start date, and base compensation.",
    citation: empPractice(
      "offer-letter-baseline",
      "Offer letter baseline content",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "Position / start date / compensation clause missing",
    missing_description: "No clause was found stating position, start date, and base compensation.",
    explanation: "These three terms are universal — without them the offer is incomplete.",
    recommendation: "Add 'Position', 'Start Date', and 'Base Compensation' lines.",
    present_patterns: [/(position|title)/i, /start\s+date/i, /base\s+(salary|compensation)/i],
  }),
  presence({
    id: "EMP-010",
    name: "At-will employment statement",
    description: "Offer letter (outside MT) should state that employment is at-will.",
    citation: empPractice(
      "at-will",
      "At-will employment doctrine (all states except Montana)",
      "https://www.law.cornell.edu/wex/employment-at-will_doctrine",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "At-will statement missing",
    missing_description: "No at-will employment statement was found.",
    explanation:
      "Outside Montana, employment is at-will by default; the offer letter should explicitly state this to avoid creating implied contracts.",
    recommendation:
      "Add 'At-Will Employment' stating employment is at-will and may be terminated by either party with or without cause / notice.",
    present_patterns: [/at.will/i, /at\s+will\s+employment/i, /terminated\s+at\s+any\s+time/i],
  }),
  presence({
    id: "EMP-011",
    name: "Conditions of employment (I-9, background, references)",
    description: "Offer letter should condition the offer on customary pre-employment checks.",
    citation: empPractice(
      "offer-conditions",
      "Offer letter conditions baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "Pre-employment conditions clause missing",
    missing_description: "No clause was found conditioning the offer on pre-employment checks.",
    explanation:
      "I-9 work authorization, background check, and reference checks are standard pre-employment conditions.",
    recommendation:
      "Add 'Conditions of Employment' including I-9, background check, and reference check completion.",
    present_patterns: [
      /(i.9|work\s+authorization)/i,
      /background\s+check/i,
      /references?\s+check/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-012",
    name: "Equity grant outline (if offered)",
    description:
      "Offer letter offering equity should outline the grant (number / share class / vesting).",
    citation: empPractice(
      "offer-equity",
      "Offer letter equity-grant outline baseline",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "Equity grant outline missing",
    missing_description: "No equity-grant outline was found.",
    explanation:
      "If equity is part of the offer, the letter should outline number of shares / units, class, and vesting schedule — subject to board approval and the plan.",
    recommendation:
      "Add 'Equity Grant' outlining number of shares, class, and vesting subject to board approval and plan terms.",
    present_patterns: [
      /(stock\s+option|option\s+grant|rsu|restricted\s+stock\s+unit|equity\s+grant)/i,
      /vesting/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-013",
    name: "Non-binding language for non-binding terms",
    description:
      "Offer letter should clarify that bonus / equity / benefit terms are subject to plans and board approval.",
    citation: empPractice(
      "offer-non-binding",
      "Offer letter non-binding-terms baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "Plan-subject / non-binding clause missing",
    missing_description:
      "No clause was found subjecting bonus / equity / benefits to plans and approvals.",
    explanation:
      "Offer letters are commonly read as creating contractual rights; the plan-subject clause defends against that reading.",
    recommendation: "Add 'Subject to Plans and Approval' language for variable comp components.",
    present_patterns: [
      /subject\s+to.{0,40}(plan|approval)/is,
      /(board|compensation\s+committee)\s+approval/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-014",
    name: "Acceptance and signature line",
    description: "Offer letter must have an acceptance / signature line with a deadline.",
    citation: empPractice(
      "offer-acceptance",
      "Offer letter acceptance baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_OFFER],
    missing_title: "Acceptance / signature line missing",
    missing_description: "No acceptance or signature line was found.",
    explanation: "Without an acceptance line the offer can be perpetually open.",
    recommendation:
      "Add an 'Accepted and Agreed' signature line with a stated acceptance deadline.",
    present_patterns: [/accepted\s+and\s+agreed/i, /please\s+sign\s+and\s+return/i, /\bby:\s*_+/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.4 — Separation / Severance Agreement. 9 rules: EMP-015..EMP-023.
// ────────────────────────────────────────────────────────────────────

const SEPARATION_RULES: Rule[] = [
  presence({
    id: "EMP-015",
    version: "1.1.0",
    name: "OWBPA / ADEA waiver — 21 / 45-day consideration period",
    description:
      "Separation agreements with employees 40+ must give 21 days (or 45 days for group terminations) to consider the ADEA waiver.",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "OWBPA consideration-period clause missing",
    missing_description: "No 21 / 45-day consideration-period clause was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(F) requires 21-day consideration (45 days for group terminations) for ADEA waivers to be 'knowing and voluntary'.",
    recommendation:
      "Add 'Consideration Period' giving 21 or 45 days (as applicable) to consider the agreement.",
    present_patterns: [
      // Tolerate the spelled-then-parenthetical-numeric form legal drafting
      // universally uses: "twenty-one (21) days to consider". The "(21)"
      // between the spelled number and "days" defeated the adjacent match.
      /(21|twenty.one|45|forty.five)\s*(?:\(\s*\d{1,2}\s*\)\s*)?days?\s+(to\s+)?(consider|review)/is,
      /consideration\s+period/i,
    ],
  }),
  presence({
    id: "EMP-016",
    version: "1.1.0",
    name: "OWBPA — 7-day revocation period",
    description: "ADEA waivers must give a 7-day revocation period after signing (§ 626(f)(1)(G)).",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "7-day revocation-period clause missing",
    missing_description: "No 7-day revocation-period clause was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(G) requires a 7-day revocation period during which the employee may rescind the waiver.",
    recommendation: "Add 'Revocation' giving the employee 7 days after signing to revoke.",
    present_patterns: [
      // Same spelled-then-parenthetical form: "seven (7) days", "revoke it
      // within seven (7) days after signing".
      /(7|seven)\s*(?:\(\s*\d\s*\)\s*)?days?\s+(to\s+|after\s+|in\s+which\s+to\s+|within\s+which\s+to\s+)?(revoke|rescind)/i,
      /(revoke|rescind).{0,40}within\s+(7|seven)\s*(?:\(\s*\d\s*\)\s*)?days?/i,
      /revocation\s+period/i,
    ],
  }),
  presence({
    id: "EMP-017",
    name: "OWBPA — advised to consult counsel",
    description:
      "ADEA waiver must advise the employee to consult counsel in writing (§ 626(f)(1)(E)).",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "Consult-counsel advisory missing",
    missing_description: "No advisory recommending the employee consult counsel was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(E) requires the agreement to advise the employee in writing to consult an attorney.",
    recommendation:
      "Add an advisory: 'You are advised to consult with an attorney before signing this Agreement'.",
    present_patterns: [
      /advised\s+to\s+consult/i,
      /(consult|seek).{0,40}(attorney|counsel|lawyer)/is,
    ],
  }),
  presence({
    id: "EMP-018",
    name: "OWBPA — specific reference to ADEA",
    description:
      "ADEA waiver must specifically reference ADEA / 29 U.S.C. § 621 et seq. (§ 626(f)(1)(B)).",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "Specific ADEA reference missing",
    missing_description:
      "No specific ADEA / Age Discrimination in Employment Act reference was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(B) requires the waiver to specifically refer to rights or claims under ADEA.",
    recommendation:
      "Add a recital that the release includes claims under the Age Discrimination in Employment Act.",
    present_patterns: [
      /age\s+discrimination\s+in\s+employment\s+act/i,
      /\badea\b/i,
      /29\s+u\.?s\.?c\.?\s+§?\s*621/i,
    ],
  }),
  presence({
    id: "EMP-019",
    name: "Group termination — § 626(f)(1)(H) disclosure",
    description:
      "Group terminations (RIF) must include the § 626(f)(1)(H) decisional-unit / job-titles-and-ages disclosure.",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "Group-termination disclosure clause missing",
    missing_description: "No group-termination decisional-unit disclosure was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(H) requires, for group terminations, disclosure of (i) the decisional unit, (ii) eligibility factors, (iii) time limits, and (iv) job titles and ages of those selected and not selected.",
    recommendation:
      "Add 'Group Termination Information' covering the four § 626(f)(1)(H) elements where applicable.",
    present_patterns: [
      /decisional\s+unit/i,
      /(eligibility\s+factor|selection\s+factor)/i,
      /(job\s+titles?\s+and\s+ages|ages\s+of\s+(individuals|persons)\s+selected)/is,
    ],
    default_severity: "warning",
  }),
  language({
    id: "EMP-020",
    version: "1.1.0",
    name: "McLaren Macomb — overbroad confidentiality / non-disparagement",
    description:
      "NLRB *McLaren Macomb* (Feb. 21, 2023) found that overbroad confidentiality or non-disparagement provisions in separation agreements violate NLRA § 7.",
    citation: mclarenMacomb(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    bad_patterns: [
      /(employee|you)\s+shall\s+not\s+(disclose|disparage).{0,80}(any|all)\s+(person|individual|terms)/is,
      /(non.?disparag).{0,200}(broadly|any\s+(person|individual|entity))/is,
      /confidentiality.{0,80}(terms\s+of\s+this\s+agreement|any\s+aspect)/is,
      // The dominant McLaren Macomb non-disparagement form is "shall not MAKE
      // any disparaging … statement", and the dominant confidentiality form is
      // "keep the terms … of this Agreement confidential" — neither the
      // "shall not disclose/disparage" verb list nor the exact "terms of this
      // agreement" phrase above reaches them.
      /(?:employee|you)\s+shall\s+not\s+make\s+any\s+(?:disparaging|negative|critical|derogatory)/is,
      /keep\s+(?:the\s+)?(?:terms|amount|existence|contents?)[^.]{0,60}\bof\s+this\s+agreement[^.]{0,40}\bconfidential/is,
    ],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:restrict|prohibit|prevent|preclude|limit|bar|apply\s+to)\b/i,
      /\bnothing\b[^.]{0,60}(?:restrict|prohibit|prevent|preclude|limit|bar|interfere)/i,
    ],
    bad_title: "Overbroad confidentiality / non-disparagement flagged",
    bad_description:
      "The separation agreement appears to contain confidentiality or non-disparagement language broad enough to chill protected concerted activity.",
    explanation:
      "Under *McLaren Macomb*, overbroad confidentiality / non-disparagement clauses are unlawful as to non-supervisory employees; the NLRB has signaled aggressive enforcement.",
    recommendation:
      "Narrow the clause with carve-outs for protected concerted activity, Section 7 rights, communication with government agencies, and discussion of unlawful conduct.",
    default_severity: "warning",
  }),
  presence({
    id: "EMP-021",
    version: "1.1.0",
    name: "Protected-rights carve-out",
    description:
      "Separation agreements must preserve employee's right to communicate with government agencies (SEC Rule 21F-17, EEOC, NLRB).",
    citation: secRule21F17(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "Protected-rights carve-out missing",
    missing_description: "No protected-rights / agency-communication carve-out was found.",
    explanation:
      "SEC Rule 21F-17 forbids impeding whistleblower communications; EEOC / NLRB / SOX similarly. Standard carve-out preserves these rights and any bounty entitlement.",
    recommendation:
      "Add 'Protected Rights' carve-out preserving rights to communicate with SEC / EEOC / NLRB / DOL and retain any bounty.",
    present_patterns: [
      /protected\s+rights?/i,
      // A government-agency mention counts as a carve-out only when the clause
      // PRESERVES the right (may / nothing prevents / retains the right /
      // right to file). "shall not disclose … to any government agency" names
      // the same words but is the prohibition the carve-out is supposed to
      // undo, so it must not satisfy this presence check.
      /(?:may|nothing[^.]{0,40}(?:prevent|prohibit|restrict|limit)|retains?\s+the\s+right|right\s+to\s+(?:file|report|communicate)|permitted\s+to)[^.]{0,80}(government\s+agency|sec|eeoc|nlrb)/is,
      /(whistleblower|whistle.blower)/i,
    ],
  }),
  presence({
    id: "EMP-022",
    name: "Severance consideration over and above accrued amounts",
    description:
      "Severance must be consideration over and above what employee is otherwise entitled to (§ 626(f)(1)(D) requirement for ADEA waiver).",
    citation: owbpa(),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "Consideration-over-accrued clause missing",
    missing_description:
      "No clause stating severance is consideration over and above what employee is otherwise entitled to was found.",
    explanation:
      "29 U.S.C. § 626(f)(1)(D) requires that the waiver be supported by consideration in addition to anything the employee is already entitled to.",
    recommendation:
      "Add 'Consideration' clause clarifying severance is over and above accrued wages / vested benefits.",
    present_patterns: [
      /(over\s+and\s+above|in\s+addition\s+to).{0,80}(entitled|owe|accrued)/is,
      /consideration.{0,40}(to\s+which\s+(you|the\s+employee)\s+(would|are)\s+not\s+otherwise)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-023",
    version: "1.1.0",
    name: "California — § 1542 waiver (if applicable)",
    description:
      "California separations should include the § 1542 waiver to release unknown claims.",
    citation: empPractice(
      "ca-civ-1542",
      "Cal. Civ. Code § 1542 (general release of unknown claims)",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1542",
    ),
    playbooks: [EMP_PLAYBOOK_SEPARATION],
    missing_title: "California § 1542 waiver missing (if applicable)",
    missing_description: "No California Civil Code § 1542 waiver was found.",
    explanation:
      "For California employees, releases do not cover unknown claims unless § 1542 is specifically waived.",
    recommendation: "If California law applies, add a § 1542 waiver with the statutory text.",
    present_patterns: [/section\s+1542/i, /(unknown\s+claims|do\s+not\s+know\s+or\s+suspect)/is],
    // § 1542 is a California statute; a separation under another state's law is
    // not missing it. Gate on a California connection, matching SET-003.
    applicable_if: [/california/i, /\bcal\.\s*(?:civ|civil|lab|labor|code)/i, /,\s*CA\s+\d{5}/],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.5 — Employment Restrictive Covenant. 8 rules: EMP-024..EMP-031.
// ────────────────────────────────────────────────────────────────────

const EMP_RESTRICTIVE_COVENANT_RULES: Rule[] = [
  language({
    id: "EMP-024",
    name: "Worker non-compete — state-law enforceability scrutiny",
    description:
      "Worker non-competes turn on state law; the FTC's 2024 rule that would have banned most of them (16 C.F.R. Part 910) was vacated and never took effect.",
    citation: ftcNcr(),
    playbooks: [EMP_PLAYBOOK_RC],
    bad_patterns: [
      /(employee|worker).{0,40}shall\s+not.{0,40}(compete|engage\s+in\s+any\s+business)/is,
      /non.?compete\s+(period|covenant).{0,200}(employee|worker)/is,
    ],
    // "Employee shall not be subject to any covenant not to compete" satisfies
    // the `shall not … compete` pattern while saying the OPPOSITE — reporting
    // that the agreement "contains a non-compete covenant" is then flatly
    // contradicted by the clause it quotes.
    exclude_if: [
      /\bno\s+non.?compete\b/i,
      /not\s+be\s+subject\s+to[^.]{0,60}(?:non.?compete|covenant\s+not\s+to\s+compete)/i,
    ],
    bad_title: "Worker non-compete flagged for state-law enforceability scrutiny",
    bad_description:
      "The agreement contains an employee / worker non-compete covenant whose enforceability turns on state law.",
    explanation:
      "The FTC Non-Compete Rule (2024) would have banned most worker non-competes, but it was set aside nationwide in Ryan LLC v. FTC (N.D. Tex. 2024) and never took effect; the FTC dismissed its appeals in September 2025 and retains only case-by-case FTC Act § 5 enforcement. The state-law trend (statutory bans in CA, MN, ND, OK, WY; targeted bans and thresholds in NY, MA, WA, CO, VA, IL, DC) remains sharply restrictive.",
    recommendation:
      "Confirm enforceability under the applicable state's non-compete law; consider narrower non-solicits or NDA-only protection.",
    default_severity: "warning",
  }),
  presence({
    id: "EMP-025",
    version: "1.1.0",
    name: "Non-compete duration stated",
    description: "Where permitted, non-compete duration must be stated.",
    citation: stateNonCompete(),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Non-compete duration missing",
    missing_description: "No duration was specified for the non-compete obligation.",
    explanation:
      "Unbounded non-competes are unenforceable in every state. State norm: 6–12 months for non-supervisory; up to 2 years for senior executives.",
    recommendation: "Add 'Duration' (typically 6–24 months) and consider state-specific maximums.",
    present_patterns: [
      /non.?compete.{0,80}(\d{1,2})\s+(months?|years?)/is,
      /(\d{1,2})\s+(months?|years?).{0,40}non.?compete/is,
      /restricted\s+period/i,
      // "1. Non-Competition. During employment and for twelve (12) months
      // after termination …" — 'Non-Competition' does not contain the literal
      // 'compete', and the spelled-then-numeric duration wraps its digits in
      // a parenthetical, so neither branch above matched the textbook clause.
      /non.?competit\w*.{0,80}?\(?(\d{1,2})\)?\s*(months?|years?)/is,
      /(?:twelve|eighteen|twenty-four|six|nine)\s+\(\d{1,2}\)\s+months?[^.]{0,60}(?:shall\s+not|restrict)/is,
    ],
  }),
  presence({
    id: "EMP-026",
    name: "Non-solicit of customers and employees",
    description: "Employment RC should include customer / employee non-solicits.",
    citation: stateNonCompete(),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Customer / employee non-solicit clause missing",
    missing_description: "No customer or employee non-solicit was found.",
    explanation:
      "Even where non-competes are unenforceable, customer / employee non-solicits typically survive — they should be drafted separately.",
    recommendation: "Add 'Non-Solicitation of Customers' and 'Non-Solicitation of Employees'.",
    present_patterns: [/non.?solicit/i, /not\s+to\s+solicit/i, /no.?(hire|poach)/i],
  }),
  presence({
    id: "EMP-027",
    name: "Geographic scope tied to actual market",
    description: "Geographic scope should be reasonable and tied to where the employee worked.",
    citation: stateNonCompete(),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Geographic scope clause missing",
    missing_description: "No geographic scope clause was found.",
    explanation:
      "Open-ended geographic scope is unenforceable; scope should track employee's actual market presence.",
    recommendation:
      "Add 'Geographic Scope' tied to the territory where the employee worked or had customer relationships.",
    present_patterns: [
      /(geographic|territory|scope)/i,
      /worldwide/i,
      /(state|county|country|zip\s+code)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-028",
    name: "Consideration for restrictive covenants",
    description:
      "Restrictive covenants must be supported by consideration; some states require independent consideration mid-employment (e.g., MA, IL).",
    citation: stateNonCompete(),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Consideration clause missing",
    missing_description: "No consideration clause was found.",
    explanation:
      "MA / IL / NH / OR / WA / similar states require independent consideration for non-competes signed mid-employment.",
    recommendation:
      "Add 'Consideration' recital tying the covenants to the employment offer or to specified additional consideration (sign-on bonus, equity grant).",
    present_patterns: [
      /(consideration|in\s+consideration)/i,
      /(sign.?on\s+bonus|signing\s+bonus|garden\s+leave)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-029",
    version: "1.1.0",
    name: "Garden-leave option (MA / WA where required)",
    description:
      "Massachusetts and Washington require garden leave or other consideration for post-employment non-competes.",
    citation: stateNonCompete(),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Garden-leave / continuing-pay clause missing",
    missing_description: "No garden-leave or continuing-pay clause was found.",
    explanation:
      "Mass. G.L. c. 149 § 24L requires either garden leave (50% of highest base salary) or 'mutually agreed-upon consideration'.",
    recommendation:
      "Where required by state law, add a 'Garden Leave' clause paying 50% of highest base salary during the restricted period.",
    // Garden leave is a MASSACHUSETTS (and, for certain workers, Washington)
    // requirement — a Vermont agreement is not missing one. Fire the absence
    // only when the document shows the MA/WA nexus.
    applicable_if: [/massachusetts/i, /\bwashington\b/i, /,\s*(?:MA|WA)\s+\d{5}/],
    present_patterns: [/garden\s+leave/i, /continuing\s+pay/i, /(50|fifty)\s*%.{0,40}salary/is],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-030",
    name: "Blue-pencil / reformation clause",
    description: "Restrictive-covenant agreement should empower courts to reform overbroad terms.",
    citation: empPractice(
      "blue-pencil-emp",
      "Blue-pencil doctrine (state-law variant)",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Blue-pencil / reformation clause missing",
    missing_description: "No blue-pencil / reformation clause was found.",
    explanation:
      "Reformation is permissive in many states (TX, MO); strict-construction states (CA, GA pre-2011) ignore it. Including the clause increases the chance of partial enforcement.",
    recommendation:
      "Add a 'Reformation' clause authorizing the court to modify any overbroad covenant.",
    present_patterns: [/blue.?pencil/i, /reformation/i],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-031",
    name: "Equitable relief and injunction",
    description: "Restrictive covenants should authorize injunctive relief.",
    citation: empPractice(
      "equitable-relief-emp",
      "Standard equitable-relief / injunction practice",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_RC],
    missing_title: "Equitable relief clause missing",
    missing_description: "No equitable-relief / injunction clause was found.",
    explanation: "Damages are usually inadequate for restrictive-covenant breaches.",
    recommendation:
      "Add 'Equitable Remedies' acknowledging irreparable harm and authorizing injunctive relief.",
    present_patterns: [/injunctive\s+relief/i, /irreparable/i, /specific\s+performance/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.6 — PIIA / IP Assignment Agreement. 7 rules: EMP-032..EMP-038.
// ────────────────────────────────────────────────────────────────────

const PIIA_RULES: Rule[] = [
  presence({
    id: "EMP-032",
    name: "Confidentiality / proprietary information obligation",
    description:
      "PIIA must include a confidentiality obligation covering employer's proprietary information.",
    citation: empPractice(
      "piia-confidentiality",
      "PIIA confidentiality baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "Confidentiality / proprietary-information clause missing",
    missing_description: "No confidentiality / proprietary-information clause was found.",
    explanation:
      "The 'PI' half of PIIA — employee maintains confidentiality of employer's proprietary information.",
    recommendation:
      "Add 'Proprietary Information' obligation with standard carve-outs (publicly available, independently developed).",
    present_patterns: [/(confidential|proprietary)\s+information/i, /non.?disclosure/i],
  }),
  presence({
    id: "EMP-033",
    name: "Assignment of inventions",
    description: "PIIA must assign work-related inventions to employer.",
    citation: empPractice(
      "piia-assignment",
      "PIIA invention-assignment baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "Invention-assignment clause missing",
    missing_description: "No invention-assignment clause was found.",
    explanation:
      "The 'IA' half of PIIA — employee assigns work-related inventions and IP rights to employer.",
    recommendation:
      "Add 'Assignment of Inventions' assigning inventions made during employment and within the scope of employer's business.",
    present_patterns: [
      /assign.{0,40}inventions?/is,
      /(invention|patent|intellectual\s+property)\s+assignment/i,
    ],
  }),
  presence({
    id: "EMP-034",
    name: "Prior inventions disclosure",
    description: "PIIA should include a prior-inventions disclosure / carve-out.",
    citation: empPractice(
      "piia-prior",
      "PIIA prior-inventions disclosure",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "Prior-inventions disclosure clause missing",
    missing_description: "No prior-inventions disclosure clause was found.",
    explanation:
      "Practice baseline: employee schedules prior inventions to carve them out of the assignment.",
    recommendation: "Add 'Prior Inventions' schedule and a carve-out from the assignment.",
    present_patterns: [/prior\s+inventions?/i, /schedule.{0,40}(invention|ip)/is],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-035",
    version: "1.1.0",
    name: "California § 2870 carve-out (where applicable)",
    description:
      "California PIIAs must carve out the § 2870 exception (no assignment of inventions developed on employee's own time without employer resources).",
    citation: caLab2870(),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "Cal. Lab. § 2870 carve-out missing",
    missing_description: "No Cal. Lab. § 2870 carve-out was found.",
    explanation:
      "California Labor Code § 2870 voids invention-assignment provisions that try to assign inventions developed entirely on the employee's own time, without employer equipment / facilities / proprietary info, unless they relate to employer's business or anticipated R&D.",
    recommendation:
      "If California law applies, add the § 2870 carve-out language verbatim or by reference.",
    present_patterns: [
      /section\s+2870/i,
      /labor\s+code.{0,40}2870/is,
      /own\s+time.{0,40}without.{0,40}employer.{0,40}(equipment|facilities)/is,
    ],
    // Cal. Lab. § 2870 governs California PIIAs; a PIIA under another state's
    // law is not missing its carve-out. Gate on a California connection.
    applicable_if: [/california/i, /\bcal\.\s*(?:civ|civil|lab|labor|code)/i, /,\s*CA\s+\d{5}/],
  }),
  presence({
    id: "EMP-036",
    name: "Power of attorney for IP filings",
    description: "PIIA typically grants employer a power of attorney to file IP applications.",
    citation: empPractice(
      "piia-poa",
      "PIIA POA baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "POA for IP filings clause missing",
    missing_description: "No POA-for-IP-filings clause was found.",
    explanation:
      "Without a POA, employer cannot file patent applications if the inventor refuses or cannot be reached.",
    recommendation:
      "Add 'Power of Attorney' irrevocably appointing the employer to file IP applications.",
    present_patterns: [/power\s+of\s+attorney/i, /coupled\s+with\s+an\s+interest/i],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-037",
    name: "DTSA whistleblower-immunity notice",
    description: "PIIA / employee NDA must contain the 18 U.S.C. § 1833(b) DTSA notice.",
    citation: empPractice(
      "dtsa-piia",
      "18 U.S.C. § 1833(b) — DTSA whistleblower immunity",
      "https://www.law.cornell.edu/uscode/text/18/1833",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "DTSA notice missing",
    missing_description: "No 18 U.S.C. § 1833(b) DTSA notice was found.",
    explanation:
      "Without the immunity notice the employer cannot recover exemplary damages or attorneys' fees under DTSA against an employee.",
    recommendation: "Add the DTSA notice using the statutory three-prong language.",
    present_patterns: [/(18\s+u\.?s\.?c\.?\s+§?\s*1833|defend\s+trade\s+secrets\s+act)/i],
  }),
  presence({
    id: "EMP-038",
    name: "Return of materials on termination",
    description: "PIIA should require return of proprietary materials on termination.",
    citation: empPractice(
      "piia-return",
      "PIIA return-of-materials baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIIA],
    missing_title: "Return-of-materials clause missing",
    missing_description: "No return-of-materials clause was found.",
    explanation: "On termination employee should return / destroy all proprietary materials.",
    recommendation: "Add 'Return of Materials' on termination including digital copies.",
    present_patterns: [
      /return\s+(or\s+destroy\s+)?.{0,40}materials/is,
      /return.{0,40}company\s+(property|information)/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.8 — Performance Improvement Plan (PIP). 6 rules: EMP-039..EMP-044.
// ────────────────────────────────────────────────────────────────────

const PIP_RULES: Rule[] = [
  presence({
    id: "EMP-039",
    name: "Specific performance deficiencies identified",
    description: "PIP must identify specific performance deficiencies.",
    citation: eeocGuidance(),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "Performance deficiencies clause missing",
    missing_description: "No clause was found identifying specific performance deficiencies.",
    explanation:
      "EEOC views vague PIPs as evidence of pretext; specificity defends the disciplinary record.",
    recommendation: "Add 'Performance Deficiencies' enumerating each deficiency with examples.",
    present_patterns: [
      /performance\s+(deficienc|issues?|concerns?)/i,
      /(deficien|gap|fall(ing|en)\s+short)/i,
    ],
  }),
  presence({
    id: "EMP-040",
    name: "Measurable performance goals",
    description: "PIP must include measurable performance goals.",
    citation: eeocGuidance(),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "Measurable goals clause missing",
    missing_description: "No measurable performance goals were found.",
    explanation: "Standard practice: SMART goals with quantitative thresholds.",
    recommendation: "Add 'Performance Goals' with specific, measurable, time-bound metrics.",
    present_patterns: [
      /performance\s+goals?/i,
      /(measurable|quantitative|specific)\s+(goals?|metrics?|targets?)/is,
    ],
  }),
  presence({
    id: "EMP-041",
    version: "1.1.0",
    name: "Duration and review schedule (30 / 60 / 90 days)",
    description: "PIP must specify duration and review schedule.",
    citation: eeocGuidance(),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "PIP duration / review schedule clause missing",
    missing_description: "No PIP duration or review schedule was found.",
    explanation: "Practice baseline: 30 / 60 / 90 day milestones with biweekly check-ins.",
    recommendation: "Add 'Duration and Review Schedule' specifying 30 / 60 / 90 day milestones.",
    present_patterns: [
      /(30|60|90)\s*[-\s/]\s*(60|90)?\s*day/i,
      // Tolerate the spelled number and the parenthetical-numeric form a PIP
      // actually writes: "a period of ninety (90) days", "within the ninety
      // (90) day period". The numeric-only "(90)" and the singular "day" both
      // defeated the old adjacent "(30|60|90) days" match.
      /(30|60|90|thirty|sixty|ninety)\s*(?:\(\s*\d{1,3}\s*\)\s*)?days?/i,
      /(weekly|bi-?weekly|every\s+(?:two|other)\s+weeks?)\s+(check.in|review|meeting)/i,
      /(check.in|review|meet).{0,30}(weekly|bi-?weekly|every\s+(?:two|other)\s+weeks?)/i,
    ],
  }),
  presence({
    id: "EMP-042",
    name: "Support and resources committed by employer",
    description: "PIP should identify support / resources the employer commits.",
    citation: empPractice(
      "pip-support",
      "PIP support / resources baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "Employer-support clause missing",
    missing_description: "No clause was found identifying employer-committed support.",
    explanation:
      "Defensible PIPs commit specific support (coaching, training, manager check-ins). Absence of support fuels pretext claims.",
    recommendation:
      "Add 'Support and Resources' committing coaching / training / manager check-ins.",
    present_patterns: [
      /(coaching|mentoring|training)/i,
      /(check.in|one.on.one)/i,
      /(support|resources?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-043",
    name: "Consequences of failure to improve",
    description:
      "PIP should state consequences of failure to improve (termination is the typical end-state).",
    citation: eeocGuidance(),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "Consequences clause missing",
    missing_description: "No consequences-of-failure clause was found.",
    explanation:
      "Without stated consequences the PIP is read as warning-only; termination on failure must be explicit.",
    recommendation:
      "Add 'Consequences of Failure' stating that failure to meet goals may result in further discipline up to and including termination.",
    present_patterns: [
      /(further\s+discipline|including\s+termination)/i,
      /(consequences?\s+of\s+failure|failure\s+to\s+improve)/i,
    ],
  }),
  presence({
    id: "EMP-044",
    name: "Acknowledgment and signature",
    description:
      "PIP should include employee acknowledgment with a 'signing does not equal agreement' qualifier.",
    citation: empPractice(
      "pip-acknowledgment",
      "PIP acknowledgment baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_PIP],
    missing_title: "Acknowledgment / signature clause missing",
    missing_description: "No acknowledgment / signature clause was found.",
    explanation:
      "Signature confirms receipt; not agreement. Practitioner baseline includes the qualifier.",
    recommendation:
      "Add an acknowledgment line with the 'signature confirms receipt, not agreement' qualifier.",
    present_patterns: [
      /acknowledge.{0,40}receipt/is,
      /signature\s+(does\s+not|is\s+not)\s+(equal|imply|constitute)\s+agreement/is,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// F.9 — Employee Handbook (scoped subset). 6 rules: EMP-045..EMP-050.
// ────────────────────────────────────────────────────────────────────

const HANDBOOK_RULES: Rule[] = [
  presence({
    id: "EMP-045",
    name: "At-will employment statement / no contract disclaimer",
    description: "Handbook must contain an at-will / no-contract disclaimer.",
    citation: empPractice(
      "handbook-at-will",
      "At-will / no-contract disclaimer baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    missing_title: "At-will / no-contract disclaimer missing",
    missing_description: "No at-will / no-contract disclaimer was found.",
    explanation:
      "Without an at-will statement the handbook may be read to create an implied contract.",
    recommendation:
      "Add a conspicuous at-will / no-contract disclaimer at the front of the handbook.",
    present_patterns: [
      /at.will/i,
      /(does\s+not|is\s+not\s+intended\s+to)\s+create\s+(an?\s+)?(contract|implied)/is,
    ],
  }),
  presence({
    id: "EMP-046",
    name: "EEO / anti-harassment policy",
    description: "Handbook must include an EEO / anti-harassment policy with complaint procedure.",
    citation: eeocGuidance(),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    missing_title: "EEO / anti-harassment policy clause missing",
    missing_description: "No EEO / anti-harassment policy was found.",
    explanation:
      "*Faragher / Ellerth* affirmative defense requires a policy with a complaint procedure and anti-retaliation provision.",
    recommendation:
      "Add 'EEO and Anti-Harassment' with prohibited conduct, complaint procedure (with alternative reporting paths), and anti-retaliation.",
    present_patterns: [
      /equal\s+employment\s+opportunity/i,
      /\beeo\b/i,
      /(harassment|discrimination).{0,40}policy/is,
      /complaint\s+procedure/i,
    ],
  }),
  presence({
    id: "EMP-047",
    name: "FLSA / wage and hour compliance section",
    description: "Handbook should address FLSA compliance — classification, overtime, timekeeping.",
    citation: flsa(),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    missing_title: "FLSA / wage-and-hour section missing",
    missing_description: "No FLSA / wage-and-hour section was found.",
    explanation:
      "Wage-and-hour compliance — exempt / non-exempt classification, overtime, meal periods — is the most common class-action exposure.",
    recommendation:
      "Add 'Wage and Hour' covering classification, overtime, meal / rest periods, and timekeeping.",
    present_patterns: [
      /(flsa|fair\s+labor\s+standards\s+act)/i,
      /(exempt|non.exempt)/i,
      /overtime/i,
      /meal\s+(period|break)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EMP-048",
    name: "Leave policies (FMLA + state)",
    description: "Handbook should cover FMLA + state-required leaves (CFRA, NYPFL, etc.).",
    citation: empPractice(
      "fmla",
      "FMLA (29 U.S.C. § 2601 et seq.); state-specific leave statutes",
      "https://www.law.cornell.edu/uscode/text/29/chapter-28",
    ),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    missing_title: "Leave policies clause missing",
    missing_description: "No FMLA / state-leave policies were found.",
    explanation:
      "FMLA notice obligations and state-specific leaves (CFRA, NYPFL, paid sick leave) require disclosure.",
    recommendation:
      "Add 'Leaves of Absence' covering FMLA, state-required leaves, paid sick leave, and bereavement.",
    present_patterns: [
      /(fmla|family\s+and\s+medical\s+leave)/i,
      /(paid\s+sick\s+leave|cfra|nypfl)/i,
      /leaves?\s+of\s+absence/i,
    ],
  }),
  language({
    id: "EMP-049",
    name: "NLRA § 7 overbroad confidentiality / social-media policy",
    description:
      "Overbroad confidentiality / social-media / non-disparagement rules can chill protected concerted activity (NLRA § 7).",
    citation: nlraSec7(),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    bad_patterns: [
      /employees?\s+(shall|may)\s+not\s+(discuss|disclose).{0,80}(wages?|salary|compensation|working\s+conditions)/is,
      /(social\s+media|online).{0,80}(prohibit|may\s+not).{0,80}company/is,
    ],
    bad_title: "Handbook policy potentially chills § 7 rights",
    bad_description:
      "A handbook policy appears to broadly restrict discussion of wages / working conditions or social-media activity — protected by NLRA § 7.",
    explanation:
      "NLRB's 2023 *Stericycle* decision tightened scrutiny of work rules that could be reasonably interpreted to chill § 7 activity. Wage-discussion bans are per-se unlawful.",
    recommendation:
      "Narrow the policy with explicit carve-outs for § 7 / protected concerted activity, wage / working-condition discussions, and post-employment communications.",
    default_severity: "warning",
  }),
  presence({
    id: "EMP-050",
    name: "Handbook acknowledgment receipt page",
    description: "Handbook must include an acknowledgment-of-receipt page.",
    citation: empPractice(
      "handbook-ack",
      "Handbook acknowledgment baseline",
      "https://www.americanbar.org/groups/labor_law/",
    ),
    playbooks: [EMP_PLAYBOOK_HANDBOOK],
    missing_title: "Acknowledgment-of-receipt page missing",
    missing_description: "No acknowledgment-of-receipt page was found.",
    explanation:
      "Acknowledgment evidences that the employee received and reviewed the handbook — essential for *Faragher / Ellerth* and disciplinary defense.",
    recommendation: "Add an 'Acknowledgment of Receipt' page with employee signature and date.",
    present_patterns: [
      /acknowledgment\s+of\s+receipt/i,
      /(employee|i).{0,40}acknowledge.{0,40}received.{0,40}handbook/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 50 rules total.
// ────────────────────────────────────────────────────────────────────

export const EMPLOYMENT_RULES: Rule[] = [
  ...EXEC_EMPLOYMENT_RULES,
  ...OFFER_LETTER_RULES,
  ...SEPARATION_RULES,
  ...EMP_RESTRICTIVE_COVENANT_RULES,
  ...PIIA_RULES,
  ...PIP_RULES,
  ...HANDBOOK_RULES,
];

export {
  EXEC_EMPLOYMENT_RULES,
  OFFER_LETTER_RULES,
  SEPARATION_RULES,
  EMP_RESTRICTIVE_COVENANT_RULES,
  PIIA_RULES,
  PIP_RULES,
  HANDBOOK_RULES,
};

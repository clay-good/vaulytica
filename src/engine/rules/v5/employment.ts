/**
 * v5 sub-domain F′ — US employment and labor (spec-v45.md §6.F). Rule
 * ids continue the EMP namespace at 101.
 */

import type { Finding, Rule, RuleContext } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { topPosition } from "../_helpers.js";
import { pack } from "./_pack.js";
import { agency, cfr, expressDenial, irs, practice, stateLaw, usc } from "./_helpers.js";

const C = "employment";

const ARBITRATION = pack("arbitration-agreement-employment", C, [
  {
    id: "EMP-101",
    name: "Mutuality of the obligation to arbitrate",
    cite: practice("arbitration-mutuality", "mutuality as a substantive unconscionability factor"),
    pat: [
      /(both\s+part(ies|y)\s+(agree|(?:shall|will)|must)|mutually\s+agree\s+to\s+arbitrat|the\s+(company|employer)\s+and\s+(the\s+)?employee\s+(each\s+)?agree)/i,
      /arbitrat/i,
    ],
    all: true,
    why: "A one-sided agreement — the employee must arbitrate, the employer may sue — is the single most common ground for finding substantive unconscionability and refusing enforcement.",
    fix: "Make the obligation mutual on its face, and carve out only the claims that are mutually excluded (such as workers' compensation and unemployment).",
    sev: "critical",
  },
  {
    id: "EMP-102",
    name: "EFAA carve-out for sexual harassment and assault claims",
    cite: usc(
      "9",
      "402",
      "Ending Forced Arbitration of Sexual Assault and Sexual Harassment Act — no validity or enforceability",
    ),
    pat: [
      /(sexual\s+(harassment|assault))/i,
      /(at\s+the\s+(employee['’]?s?|claimant['’]?s?)\s+(election|option)|(?:shall|will)\s+not\s+(be\s+subject\s+to|apply)|9\s+u\.?s\.?c\.?\s*§?\s*40[12]|ending\s+forced\s+arbitration)/i,
    ],
    why: "Since March 2022, 9 U.S.C. § 402 makes a pre-dispute arbitration agreement unenforceable at the claimant's election for sexual harassment and sexual assault disputes. An agreement that does not reflect it is drafting to a rule that no longer exists.",
    fix: "Add an express carve-out stating that claims of sexual harassment or sexual assault are arbitrable only at the employee's election, consistent with 9 U.S.C. §§ 401-402.",
    sev: "critical",
  },
  {
    id: "EMP-103",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Employer payment of arbitration costs",
    cite: practice(
      "arbitration-costs",
      "cost-shifting as an unconscionability factor in employment arbitration",
    ),
    pat: [
      /(the\s+(company|employer)\s+(shall|will)\s+pay|at\s+the\s+(company['’]?s?|employer['’]?s?)\s+(sole\s+)?(cost|expense))/i,
      /(arbitrat(or|ion)\s+(fees|costs)|filing\s+fee|administrative\s+fees)/i,
    ],
    why: "Requiring an employee to bear forum costs they would not bear in court is the classic ground for refusing enforcement, and the AAA Employment Rules cap the employee's share at a filing fee regardless.",
    fix: "State that the employer pays all arbitrator and administrative fees beyond any filing fee the employee would pay in court.",
    // The topic is the EMPLOYER'S UNDERTAKING, not the cost itself. A bare
    // "arbitration costs" makes the frames subject-blind, and the compliant
    // drafting is itself a negation about those costs — "the employee shall
    // not be required to bear arbitration costs beyond a court filing fee" —
    // which then reads as a denial of the very clause it satisfies.
    denied: expressDenial(
      String.raw`(?:pay|pays|paying|payment\s+of)\s+(?:any\s+|all\s+)?(?:the\s+)?(?:arbitrator['’]?s?\s+|administrative\s+)?(?:arbitration\s+)?(?:fees|costs)`,
    ),
    sev: "critical",
  },
  {
    id: "EMP-104",
    name: "Adequate discovery",
    cite: practice("arbitration-discovery", "discovery adequacy in employment arbitration"),
    pat: [
      /discovery/i,
      /(depositions?|document\s+requests?|interrogator|adequate|as\s+the\s+arbitrator\s+(deems|determines))/i,
    ],
    why: "An employee cannot prove a discrimination case without documents and depositions. Discovery limits that make the claim unprovable are a substantive unconscionability finding.",
    fix: "Provide for discovery sufficient to vindicate statutory rights — a stated minimum of depositions and document requests, with arbitrator discretion to allow more.",
  },
  {
    id: "EMP-105",
    name: "Remedies parity with court",
    cite: practice("arbitration-remedies", "remedial parity in employment arbitration agreements"),
    pat: [
      /(same\s+remedies|all\s+remedies\s+(available|that\s+would\s+be\s+available)|any\s+relief\s+(that\s+)?(a\s+court|available))/i,
      /(punitive|attorneys['’]?\s+fees|statutory\s+(damages|remedies))/i,
    ],
    why: "An agreement that strips punitive damages, statutory fee-shifting, or injunctive relief prevents the employee from vindicating statutory rights and is routinely struck.",
    fix: "State that the arbitrator may award any relief a court could award on the same claim, including statutory damages, punitive damages, and attorneys' fees.",
    sev: "critical",
  },
  {
    id: "EMP-106",
    name: "Class or collective waiver and PAGA severability",
    cite: usc("9", "2", "Federal Arbitration Act — validity of arbitration agreements"),
    pat: [
      /(class|collective)\s+(action\s+)?(waiver|basis)/i,
      /(paga|representative\s+(action|claim)|sever|individual\s+basis)/i,
    ],
    why: "Class waivers are enforceable after Epic Systems, but California PAGA representative claims are not waivable wholesale. Without severability, an invalid PAGA waiver can take the whole agreement down.",
    fix: "State the class and collective waiver, add a savings clause for non-waivable representative claims, and make the waiver severable so invalidity does not void the agreement.",
  },
  {
    id: "EMP-107",
    name: "Arbitrator selection neutrality",
    cite: practice(
      "arbitrator-selection",
      "neutral arbitrator selection in employment arbitration",
    ),
    pat: [
      /(arbitrator\s+((?:shall|will)\s+be\s+)?(selected|chosen|appointed))/i,
      /(neutral|aaa|jams|mutually\s+agree|strike)/i,
    ],
    why: "Employer control over the arbitrator or the panel list is procedural unconscionability. Adopting a neutral administrator's employment rules is the simplest cure.",
    fix: "Adopt a neutral administrator's employment arbitration rules and a selection process by mutual agreement or alternate striking from a neutral list.",
  },
  {
    id: "EMP-108",
    name: "Opt-out mechanism and consideration",
    cite: practice(
      "arbitration-consideration",
      "consideration and opt-out rights in employment arbitration agreements",
    ),
    pat: [
      /(opt\s?-?out|decline\s+to\s+(participate|be\s+bound))/i,
      /(within\s+\d+\s*\)?\s*days|consideration|continued\s+employment|no\s+(adverse|retaliat))/i,
    ],
    why: "An opt-out with a real window and no retaliation is strong evidence against procedural unconscionability, and in states where continued employment alone is not consideration, it may be the only support for the agreement.",
    fix: "Provide a stated opt-out period with a simple method, promise no adverse action for opting out, and recite the consideration supporting the agreement.",
  },
]);

const COMMISSION = pack("commission-plan", C, [
  {
    id: "EMP-109",
    name: "When a commission is earned versus paid",
    cite: stateLaw(
      "wage-payment",
      "state wage payment statutes treating earned commissions as wages",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(earned|is\s+earned\s+(when|upon))/i,
      /(booking|invoice|collection|payment\s+(is\s+)?received|shipment)/i,
    ],
    why: "Most state wage statutes make an earned commission a wage that cannot be forfeited. Whether it is earned at booking, invoicing, or collection is the term that decides the outcome of every termination dispute.",
    fix: "State precisely the event that causes a commission to be earned and the separate date on which earned commissions are paid.",
    sev: "critical",
  },
  {
    id: "EMP-110",
    name: "Post-termination and trailing commissions",
    cite: stateLaw(
      "commission-forfeiture",
      "limits on forfeiture of earned commissions after termination",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(after\s+(the\s+)?termination|post-?termination|following\s+(your\s+)?separation)/i,
      /(commission|trailing|(?:shall|will)\s+(not\s+)?be\s+(paid|entitled))/i,
    ],
    all: true,
    why: "A clause requiring employment on the payment date to receive a commission already earned is unenforceable in California, Massachusetts, and several other states, and is the most litigated term in sales compensation.",
    fix: "State whether commissions on deals closed before termination are paid, and for how long trailing commissions continue, consistent with the governing state's wage law.",
    sev: "critical",
  },
  {
    id: "EMP-111",
    name: "Chargebacks and clawbacks",
    cite: stateLaw(
      "wage-deduction",
      "state limits on deductions from wages, including commission chargebacks",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(chargeback|clawback|recoup)/i,
      /(cancel(l)?ation|refund|non-?payment\s+by\s+the\s+customer|returned)/i,
    ],
    why: "Deducting a chargeback from a later paycheck is a wage deduction that many states permit only with written authorization, and some prohibit outright where the loss is a cost of doing business.",
    fix: "State the chargeback events and the recovery method, and obtain the written authorization the governing state requires for any deduction from wages.",
  },
  {
    id: "EMP-112",
    name: "Unilateral modification of quotas and rates",
    cite: practice(
      "commission-modification",
      "prospective modification of sales compensation plans",
    ),
    pat: [
      /(modify|change|amend|revise)\s+(the\s+)?(plan|quota|rate)/i,
      /(prospective(ly)?|upon\s+\d+\s*\)?\s*days['’]?\s+notice|at\s+any\s+time|in\s+its\s+(sole\s+)?discretion)/i,
    ],
    why: "Mid-year quota or rate changes applied retroactively to closed deals are wage claims. Prospective-only modification with notice is the enforceable form.",
    fix: "Reserve modification prospectively only, on stated notice, and confirm that deals closed before the effective date are paid under the prior plan.",
  },
  {
    id: "EMP-113",
    name: "Recoverable versus non-recoverable draw",
    cite: agency(
      "US Department of Labor",
      "Field Operations Handbook treatment of draws against commissions under the FLSA",
      "https://www.dol.gov/agencies/whd/field-operations-handbook",
    ),
    pat: [
      /draw/i,
      /(recoverable|non-?recoverable|advance\s+against|repay|offset\s+against\s+future)/i,
    ],
    why: "A recoverable draw is an advance the employee may owe back; a non-recoverable draw is a guaranteed minimum. Recovering a draw cannot take pay below minimum wage for the workweek.",
    fix: "State whether the draw is recoverable, how it is recovered, and that recovery will never reduce pay below the applicable minimum wage.",
  },
  {
    id: "EMP-114",
    name: "Dispute and reconciliation procedure",
    cite: practice("commission-reconciliation", "commission statements and dispute procedures"),
    pat: [
      /(commission\s+statement|reconcil|report\s+of\s+commissions)/i,
      /(dispute|object|within\s+\d+\s*\)?\s*days\s+of\s+receipt|inquir)/i,
    ],
    why: "Commission math is opaque and errors are routine. A statement plus a short dispute window is how both sides avoid a multi-year reconstruction at termination.",
    fix: "Require a periodic commission statement showing the calculation, and set a window and method for raising disputes.",
  },
]);

const BONUS = pack("bonus-plan", C, [
  {
    id: "EMP-115",
    name: "Performance metrics and measurement period",
    cite: practice("bonus-metrics", "performance metric definition in annual incentive plans"),
    pat: [
      /(performance\s+(metric|goal|objective|criteria)|target)/i,
      /(measurement\s+period|performance\s+period|fiscal\s+year|calendar\s+year)/i,
    ],
    why: "A bonus with undefined metrics is discretionary in fact whatever the plan says, and in a few states an announced bonus becomes an enforceable promise once the conditions are met.",
    fix: "State the metrics, their weightings, the threshold/target/maximum payout curve, and the performance period.",
  },
  {
    id: "EMP-116",
    name: "Discretion reserved and its limits",
    cite: practice("bonus-discretion", "reserved discretion in incentive plans"),
    pat: [
      /(discretion|discretionary)/i,
      /(committee|the\s+company\s+(may|reserves)|adjust|no\s+(entitlement|right)\s+to\s+(a\s+)?bonus)/i,
    ],
    why: "Unqualified discretion is what keeps a bonus outside wage-claim treatment in most states, but it also undermines the plan's motivational purpose. The scope of discretion should be a decision, not an accident.",
    fix: "State whether the bonus is discretionary, and if the plan is formulaic, define the narrow circumstances in which the committee may adjust the calculated amount.",
  },
  {
    id: "EMP-117",
    name: "Employed-on-payment-date condition",
    cite: stateLaw(
      "bonus-forfeiture",
      "state treatment of employment conditions on bonus payment",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(must\s+be\s+(actively\s+)?employed|remain\s+employed)/i,
      /(on\s+the\s+(payment|payout)\s+date|at\s+the\s+time\s+of\s+payment|forfeit)/i,
    ],
    why: "This condition is enforced in most states and rejected in some (notably for earned wages in Massachusetts and California) where the bonus is non-discretionary. Its absence means an employee who leaves in January is owed the prior year's bonus.",
    fix: "State the employment condition and its exceptions (death, disability, retirement, involuntary termination without cause), confirming it against the governing state's wage law.",
    sev: "critical",
  },
  {
    id: "EMP-118",
    name: "Section 409A short-term deferral timing",
    cite: irs(
      "26 U.S.C. § 409A",
      "inclusion in gross income of nonqualified deferred compensation",
    ),
    pat: [
      /(409a|short-?term\s+deferral)/i,
      /(2\s?½|two\s+and\s+one-?half\s+months|march\s+15|by\s+the\s+15th\s+day\s+of\s+the\s+third\s+month)/i,
    ],
    why: "A bonus paid within 2½ months after the year in which it vests is exempt from § 409A. Payment later without a compliant deferral election triggers immediate income inclusion plus a 20% additional tax on the employee.",
    fix: "Require payment by the 15th day of the third month after the end of the year in which the bonus vests, or state a § 409A-compliant payment schedule.",
    sev: "critical",
  },
  {
    id: "EMP-119",
    name: "Proration on leave, hire, or termination",
    cite: practice("bonus-proration", "proration of annual incentives"),
    pat: [/prorat/i, /(hired\s+(during|after)|leave\s+of\s+absence|partial\s+year|termination)/i],
    why: "Mid-year hires, protected leaves, and terminations all need a rule. Failing to prorate for protected leave can itself be a discrimination claim.",
    fix: "State the proration method for mid-year hires and terminations, and confirm that protected leave is treated no less favorably than other paid time off.",
  },
]);

const RELOCATION = pack("relocation-agreement", C, [
  {
    id: "EMP-120",
    name: "Benefits provided and dollar cap",
    cite: practice("relocation-benefits", "scope and caps in relocation benefit agreements"),
    pat: [
      /(relocation\s+(benefits|expenses|assistance)|moving\s+expenses)/i,
      /(up\s+to\s+\$|not\s+to\s+exceed|maximum\s+of|lump\s+sum)/i,
    ],
    why: "Relocation packages are commonly described in an offer letter and never bounded. Without a cap and a category list, the reimbursement argument arrives with the invoices.",
    fix: "Enumerate the reimbursable categories, the dollar cap, and the documentation and deadline for submitting expenses.",
  },
  {
    id: "EMP-121",
    name: "Repayment trigger and proration schedule",
    cite: practice("relocation-repayment", "repayment obligations in relocation agreements"),
    pat: [
      /repay/i,
      /(voluntar(y|ily)\s+(resign|terminate)|within\s+(twelve|12|24|twenty-?four)\s+months|prorat|declining\s+(balance|schedule))/i,
    ],
    all: true,
    why: "A cliff repayment — full amount if the employee leaves one day before the anniversary — reads as a penalty and is unenforceable in some states. A monthly proration is defensible.",
    fix: "State the repayment trigger, exclude involuntary termination without cause, and prorate the obligation monthly over the retention period.",
    sev: "critical",
  },
  {
    id: "EMP-122",
    // 1.0.1 — written as a synonym OR, but the deduction and the state-law limit are distinct pillars; `authoriz` alone is satisfied by "authorized representatives" in the signature block. The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Wage-deduction authorization and state limits",
    cite: stateLaw(
      "final-pay-deduction",
      "state limits on deductions from final wages",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(deduct|withhold)/i,
      /(final\s+(paycheck|pay|wages)|authori[sz]|to\s+the\s+extent\s+permitted\s+by\s+(applicable\s+)?law)/i,
    ],
    all: true,
    why: "Many states prohibit deducting a debt from final wages even with authorization, and California prohibits it outright. A clause that assumes the deduction is available creates a wage claim on the way out the door.",
    fix: "Obtain a written deduction authorization, limit it to what applicable state law permits, and provide an alternative repayment route where deduction is prohibited.",
    sev: "critical",
  },
  {
    id: "EMP-123",
    name: "Tax gross-up treatment",
    cite: irs(
      "IRS Publication 521",
      "moving expenses — taxability of employer-paid relocation after the 2017 Act",
    ),
    pat: [
      /(gross-?up|tax\s+assistance|taxable\s+income)/i,
      /(withhold|imputed|w-?2|reported\s+as\s+(wages|income))/i,
    ],
    why: "Since 2018 nearly all employer-paid relocation is taxable wages. An employee who expected a $20,000 move and receives a $12,000 net has a complaint the agreement should have anticipated.",
    fix: "State that benefits are taxable wages, whether a gross-up is provided and how it is computed, and how repayment interacts with taxes already withheld.",
  },
  {
    id: "EMP-124",
    name: "Involuntary-termination carve-out",
    cite: practice(
      "relocation-carveout",
      "involuntary termination carve-outs in repayment agreements",
    ),
    pat: [
      /(involuntar|terminated\s+(by\s+the\s+company\s+)?without\s+cause|reduction\s+in\s+force|layoff)/i,
      /(no\s+repayment|(?:shall|will)\s+not\s+(be\s+)?(required|obligated)\s+to\s+repay|waive)/i,
    ],
    why: "Requiring repayment from an employee the company laid off is both unenforceable in several states and reputationally costly. The carve-out is standard and cheap.",
    fix: "Waive repayment where the company terminates without cause, and on death or disability.",
  },
]);

const REMOTE = pack("remote-work-agreement", C, [
  {
    id: "EMP-125",
    name: "Designated work location and change notice",
    cite: practice(
      "remote-location",
      "work location designation and multi-state exposure in telework",
    ),
    pat: [
      /(designated\s+(work\s+)?location|primary\s+work\s+location|remote\s+(work\s+)?location)/i,
      /(notify|prior\s+(written\s+)?(approval|consent)|change\s+(of|in)\s+(the\s+)?location|may\s+not\s+relocate)/i,
    ],
    why: "The employee's physical location determines which state's wage, leave, tax, and non-compete law applies, and whether the employer has nexus there. An unannounced move creates all of it at once.",
    fix: "Designate the work location, require advance notice and approval before working from another state or country, and reserve the right to decline.",
    sev: "critical",
  },
  {
    id: "EMP-126",
    name: "Business-expense reimbursement",
    cite: stateLaw(
      "expense-reimbursement",
      "state statutes requiring reimbursement of necessary business expenses (e.g., Cal. Lab. Code § 2802)",
      "https://www.law.cornell.edu/wex/wages_and_hours",
    ),
    pat: [
      /(expense\s+reimburse|reimburse\s+(the\s+)?(employee\s+)?for)/i,
      /(internet|phone|home\s+office|equipment|stipend|necessary\s+(business\s+)?expenses)/i,
    ],
    why: "California, Illinois, and several other states require reimbursement of necessary business expenses; a home-office stipend policy is the standard compliance mechanism and its absence is a class-action theory.",
    fix: "State which remote-work expenses are reimbursed, the stipend or reimbursement method, and the submission process.",
    sev: "critical",
  },
  {
    id: "EMP-127",
    name: "Timekeeping and off-the-clock controls for non-exempt staff",
    cite: usc("29", "207", "Fair Labor Standards Act — maximum hours and overtime"),
    pat: [
      /(non-?exempt|hourly)/i,
      /(record\s+(all\s+)?(hours|time)|timekeeping|meal\s+(and\s+rest\s+)?(period|break)|overtime\s+(must\s+be\s+)?(pre-?)?approv)/i,
    ],
    why: "Remote non-exempt work is where off-the-clock claims come from. The employer must have a reasonable timekeeping system and a rule about unapproved overtime — and must pay it if worked.",
    fix: "Require accurate recording of all hours, state the meal and rest period obligations, and state that unapproved overtime is still paid but is subject to discipline.",
    when: [/(non-?exempt|hourly|overtime)/i],
  },
  {
    id: "EMP-128",
    name: "Equipment, security, and data handling",
    cite: practice("remote-security", "equipment and information security in telework agreements"),
    pat: [
      /(company\s+(equipment|property)|laptop|device)/i,
      /(security|confidential|vpn|encrypt|return\s+(of|all)\s+(company\s+)?(property|equipment))/i,
    ],
    why: "Company data on home networks and personal devices is the largest practical security exposure in remote work, and equipment return at separation is a recurring problem.",
    fix: "List the equipment provided, state the security requirements (device encryption, VPN, no shared accounts, secure disposal), and state the return obligation and deadline at separation.",
  },
  {
    id: "EMP-129",
    name: "Revocation and return-to-office rights",
    cite: practice("remote-revocation", "revocability of telework arrangements"),
    pat: [
      /(revoke|discontinue|terminate\s+(this\s+)?(arrangement|agreement))/i,
      /(at\s+any\s+time|upon\s+\d+\s*\)?\s*days['’]?\s+notice|return\s+to\s+the\s+office|in\s+its\s+discretion)/i,
    ],
    why: "A remote arrangement described as permanent becomes an accommodation the employer cannot withdraw. Reserving revocability with notice preserves flexibility and clarifies the ADA analysis separately.",
    fix: "State that the arrangement is not permanent, may be revoked on stated notice, and is separate from any reasonable accommodation the employee may request.",
  },
]);

const INTERNSHIP = pack("internship-agreement", C, [
  {
    id: "EMP-130",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Paid or unpaid status and the FLSA primary-beneficiary factors",
    cite: agency(
      "US Department of Labor Wage and Hour Division",
      "Fact Sheet #71 — primary beneficiary test for internship programs under the FLSA",
      "https://www.dol.gov/agencies/whd/fact-sheets/71-flsa-internships",
    ),
    pat: [
      /(unpaid|paid\s+internship|compensation)/i,
      /(primary[-\s]+beneficiary|educational|academic|training\s+similar\s+to)/i,
    ],
    why: "Since 2018 the DOL applies the primary-beneficiary test: if the employer is the primary beneficiary, the intern is an employee owed minimum wage and overtime. An unpaid internship that does not address the factors is an exposure.",
    fix: "State whether the internship is paid, and if unpaid, recite the facts supporting the primary-beneficiary factors (educational integration, academic calendar, no entitlement to a job, no displacement of paid staff).",
    sev: "critical",
  },
  {
    id: "EMP-131",
    name: "Academic credit and educational benefit",
    cite: agency(
      "US Department of Labor Wage and Hour Division",
      "Fact Sheet #71 — integration with formal education",
      "https://www.dol.gov/agencies/whd/fact-sheets/71-flsa-internships",
    ),
    pat: [
      /(academic\s+credit|course\s+credit|for\s+credit)/i,
      /(school|university|educational\s+institution|faculty\s+(advisor|supervisor)|learning\s+objectives)/i,
    ],
    why: "Integration with formal education is one of the strongest primary-beneficiary factors, and the school's own requirements often bind the host employer.",
    fix: "State whether credit is awarded, name the institution and faculty contact, and attach the learning objectives and any school-required terms.",
    when: [/(unpaid|academic\s+credit|for\s+credit|student)/i],
  },
  {
    id: "EMP-132",
    name: "No promise of employment",
    cite: practice(
      "internship-no-promise",
      "no-entitlement-to-a-job recitals in internship agreements",
    ),
    pat: [
      /(no\s+(promise|guarantee|entitlement)\s+(of|to)\s+(a\s+)?(job|employment|offer))/i,
      /(does\s+not\s+(entitle|guarantee)|at\s+the\s+conclusion\s+of\s+the\s+internship)/i,
    ],
    why: "An implied promise of a job at the end weighs toward employee status and, separately, supports a promissory estoppel claim if the offer does not come.",
    fix: "State that the internship does not entitle the intern to a paid job at its conclusion and creates no employment relationship.",
  },
  {
    id: "EMP-133",
    name: "IP assignment and confidentiality",
    cite: practice("intern-ip", "IP assignment and confidentiality in internship agreements"),
    pat: [
      /(assign|ownership\s+of\s+(any\s+)?(work|inventions))/i,
      /(confidential|proprietary\s+information|non-?disclosure)/i,
    ],
    why: "Interns build real things. Without an assignment, the work belongs to the intern (the work-made-for-hire doctrine reaches employees, and an unpaid intern may not be one).",
    fix: "Add a present assignment of inventions and works created in the internship, with the state-mandated prior-inventions carve-out, and a confidentiality obligation.",
    sev: "critical",
  },
  {
    id: "EMP-134",
    name: "Workers' compensation and insurance coverage",
    cite: stateLaw(
      "intern-coverage",
      "workers' compensation coverage of unpaid interns and volunteers",
      "https://www.law.cornell.edu/wex/workers_compensation",
    ),
    pat: [
      /(workers['’]?\s+compensation|insurance)/i,
      /(covered|coverage|injur|intern\s+is\s+(not\s+)?(an\s+employee|covered))/i,
    ],
    why: "Unpaid interns are outside workers' compensation coverage in many states, which means an on-site injury is a negligence claim rather than a covered one.",
    fix: "State whether the intern is covered by workers' compensation and, if not, describe the insurance arranged (school policy, general liability, or voluntary coverage).",
  },
]);

const CBA = pack("union-cba", C, [
  {
    id: "EMP-135",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Recognition and bargaining-unit description",
    cite: usc("29", "159", "National Labor Relations Act § 9 — representatives and elections"),
    pat: [
      /recogni(z|s)e/i,
      /(bargaining[-\s]+unit|exclusive\s+(bargaining\s+)?representative|all\s+(full-?time\s+and\s+regular\s+part-?time\s+)?employees)/i,
    ],
    why: "The recognition clause and unit description define who the contract covers. Disputes about whether a classification is in the unit are the most common day-one grievance.",
    fix: "State the recognition and describe the bargaining unit by classification with the exclusions (supervisors, guards, confidential employees).",
    sev: "critical",
  },
  {
    id: "EMP-136",
    name: "Union security and dues checkoff",
    cite: usc("29", "164", "National Labor Relations Act § 14(b) — right-to-work savings clause"),
    pat: [
      /(union\s+security|maintenance\s+of\s+membership|agency\s+fee)/i,
      /(dues\s+(check-?off|deduction)|written\s+authori[sz]ation|right-?to-?work)/i,
    ],
    why: "Union security clauses are unlawful in right-to-work states under § 14(b), and dues checkoff requires individual written authorization under § 302(c)(4). A national form applied in a right-to-work state is unenforceable there.",
    fix: "State the union security obligation with a right-to-work savings clause, and require individual written checkoff authorizations that comply with § 302(c)(4).",
    sev: "critical",
  },
  {
    id: "EMP-137",
    name: "Grievance and arbitration steps with deadlines",
    cite: usc(
      "29",
      "185",
      "Labor Management Relations Act § 301 — suits by and against labor organizations",
    ),
    pat: [
      /grievance/i,
      /(step\s+(one|1|two|2)|arbitration|within\s+\d+\s+(working\s+)?days|time\s+limits)/i,
    ],
    why: "The grievance procedure with binding arbitration is what makes the no-strike clause enforceable and gives the contract its § 301 forum. Missing deadlines forfeit grievances.",
    fix: "Set out the grievance steps with time limits at each stage, the arbitration selection procedure, the arbitrator's authority and its limits, and cost allocation.",
  },
  {
    id: "EMP-138",
    name: "No-strike and no-lockout clause",
    cite: usc(
      "29",
      "173",
      "Labor Management Relations Act — national emergencies and conciliation",
    ),
    pat: [/no\s+strike/i, /(no\s+lock-?out|work\s+stoppage|slowdown|picket)/i],
    why: "The no-strike clause is the employer's principal consideration for arbitration. Its scope — sympathy strikes, unfair labor practice strikes, safety refusals — determines what conduct is actually barred.",
    fix: "State the no-strike and no-lockout obligations, define the covered conduct, and state any carve-outs and the remedy for breach.",
  },
  {
    id: "EMP-139",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Management-rights reservation",
    cite: practice(
      "management-rights",
      "management rights clauses in collective bargaining agreements",
    ),
    pat: [/management[-\s]+rights/i, /(retains?|reserves?|exclusive\s+right\s+to)/i],
    why: "Every right not reserved is a mandatory subject the employer must bargain before changing. A thin management-rights clause turns routine operational decisions into unfair labor practice charges.",
    fix: "Enumerate the reserved rights (direction of the workforce, staffing levels, scheduling, technology, subcontracting, discipline) and state that the enumeration is not exhaustive.",
  },
  {
    id: "EMP-140",
    name: "Seniority, layoff, and recall",
    cite: practice("cba-seniority", "seniority, layoff, and recall provisions"),
    pat: [/seniority/i, /(layoff|recall|bump|reduction\s+in\s+force|job\s+posting)/i],
    why: "Seniority governs layoff order, recall rights, bidding, and often benefits. Ambiguity about how seniority accrues during leave or after transfer produces grievances for the life of the contract.",
    fix: "Define seniority, how it accrues and is lost, and the layoff order, bumping rights, recall period, and posting/bidding procedure.",
  },
  {
    id: "EMP-141",
    name: "Term, reopener, and evergreen clause",
    cite: usc(
      "29",
      "158",
      "National Labor Relations Act § 8(d) — obligation to bargain collectively",
    ),
    pat: [
      /(term\s+of\s+this\s+agreement|effective\s+from|(?:shall|will)\s+remain\s+in\s+(full\s+force\s+and\s+)?effect)/i,
      /(reopen|automatic(ally)?\s+renew|sixty\s+\(?60\)?\s+days|notice\s+of\s+(intent\s+to\s+)?(terminate|modify))/i,
    ],
    why: "§ 8(d) requires 60 days' notice to modify or terminate and 30 days' notice to the FMCS. An evergreen clause without those notice mechanics leaves both sides unsure whether the contract has rolled over.",
    fix: "State the term, the § 8(d) notice requirements for modification or termination, any reopener subjects, and the evergreen renewal terms.",
  },
]);

const WARN = pack("warn-notice", C, [
  {
    id: "EMP-143",
    name: "Permanent or temporary and expected separation date",
    cite: cfr("20", "639.7", "WARN regulations — what must the notice contain"),
    pat: [
      /(permanent|temporary)/i,
      /(expected\s+(date|schedule)|separation\s+date|anticipated\s+schedule\s+for\s+(the\s+)?separations)/i,
    ],
    why: "§ 639.7(d) requires a statement of whether the action is permanent or temporary and the expected date of the action and of the employee's separation. Vague timing invalidates the notice.",
    fix: "State whether the closing or layoff is permanent or temporary, the expected date of the action, and the expected separation date or 14-day schedule for the individual employee.",
    sev: "critical",
  },
  {
    id: "EMP-144",
    name: "Bumping-rights statement",
    cite: cfr("20", "639.7(d)(3)", "WARN regulations — bumping rights"),
    pat: [/bumping/i, /(rights?|whether|do\s+not\s+exist|seniority)/i],
    why: "§ 639.7(d)(3) requires an explicit statement of whether bumping rights exist. Its omission is a standard defect in WARN notices and is easy to correct.",
    fix: "State whether bumping rights exist and, if so, how they operate — including a plain statement that they do not exist if that is the case.",
  },
  {
    id: "EMP-145",
    name: "Job titles and number of affected employees",
    cite: cfr(
      "20",
      "639.7(c)",
      "WARN regulations — notice to the state dislocated worker unit and local government",
    ),
    pat: [
      /(job\s+titles?|classifications?|positions?\s+affected)/i,
      /(number\s+of\s+(affected\s+)?(employees|workers)|names\s+of|by\s+title)/i,
    ],
    why: "The notice to the state rapid-response unit and the chief elected local official must include job titles and the number of affected employees in each, which is what enables the state to deploy services.",
    fix: "List the affected job titles with the number of employees in each, and the name and address of the affected site.",
  },
  {
    id: "EMP-146",
    // 1.0.1 — a notice that names its official and gives a number, but writes
    // "Please direct any questions about this notice to Rosalie Dumont,
    // Director of Human Resources, at (775) 555-0148", used neither the word
    // "contact" nor the word "telephone" and was told it had no contact
    // official. The regulation requires a name and a number, not a vocabulary.
    ver: "1.0.1",
    name: "Company contact for further information",
    cite: cfr("20", "639.7(d)(4)", "WARN regulations — company official to contact"),
    pat: [
      /(contact|for\s+(further|more)\s+information|direct\s+(?:any\s+)?questions|questions\s+(?:about|regarding)[^.]{0,80}\bto\b|may\s+be\s+reached)/i,
      /(telephone|phone|name\s+and\s+(title|telephone))/i,
    ],
    why: "§ 639.7(d)(4) requires the name and telephone number of a company official who can supply further information. A notice without it fails on its face.",
    fix: "Give the name, title, and telephone number of a company official available to answer questions.",
  },
  {
    id: "EMP-147",
    // 1.0.1 — written as a synonym OR, but the state and the mini-WARN citation are distinct pillars; `state` alone is satisfied by "State of Delaware" in any governing-law clause. The check could not
    // fire on any realistic document.
    //
    // 1.0.2 — the two pillars were never independent. The bare `state` pillar
    // carried no information the citation pillar did not already carry, and
    // conjoining them made the check demand a word: a Nevada notice reciting
    // "Nevada Revised Statutes Chapter 613 to the extent they apply" was told
    // at `critical` that it addressed no state overlay, because it happened
    // not to use the word "state" near it. One pillar, tightened: a state
    // mini-WARN statute is cited by its own code name, and the federal-only
    // notice this check exists to catch cites the U.S. Code and the C.F.R.
    // and none of these.
    // 1.1.0 — the check fired in all fifty states, and its own `why` says it
    // should not: "A federal-only notice is non-compliant IN THOSE STATES."
    // A plant closing in Akron, Ohio — a state with no plant-closing statute
    // at all — was told at `critical` that it addressed no state overlay, for
    // a notice that was federal-only because federal is all there is. The
    // check now gates on the three states the sentence above names, which
    // makes no legal claim the rule was not already making.
    //
    // The gate is deliberately NARROWER than the law: Illinois, Wisconsin,
    // Tennessee, Hawaii, Maryland, Maine, Minnesota, New Hampshire, and Iowa
    // all have plant-closing statutes this gate will not fire on, and adding
    // them means asserting a statute and a citation for each, which is the
    // work of a sourced overlay node (`src/dkb/state-overlays.ts`), not of a
    // pattern. A missed flag in Illinois is the safer side of a check whose
    // false form is a `critical` on a compliant notice.
    ver: "1.1.0",
    name: "State mini-WARN overlay",
    cite: stateLaw(
      "mini-warn",
      "state plant-closing statutes with lower thresholds and longer notice periods (California, New York, New Jersey, and others)",
      "https://www.law.cornell.edu/wex/labor_law",
    ),
    pat: [
      /(mini-?warn|state\s+(warn|plant[-\s]closing)|labou?r\s+code\s+§?\s*1400|worker\s+adjustment.{0,40}state|revised\s+statutes|compiled\s+statutes|statutes\s+annotated|code\s+annotated|general\s+business\s+law|labou?r\s+(?:code|law)\s+§|consolidated\s+laws)/i,
    ],
    when: [/\b(?:California|New\s+York|New\s+Jersey)\b/i],
    why: "California triggers at 50 employees regardless of percentage, New York requires 90 days, and New Jersey requires 90 days plus mandatory severance. A federal-only notice is non-compliant in those states.",
    fix: "Identify the states involved and satisfy the longest notice period and broadest content requirement among the federal and applicable state statutes.",
    sev: "critical",
  },
]);

const FCRA = pack("background-check-disclosure", C, [
  {
    id: "EMP-148",
    ver: "1.1.0",
    name: "Stand-alone disclosure with no extraneous terms",
    cite: usc(
      "15",
      "1681b",
      "Fair Credit Reporting Act § 604(b) — conditions for furnishing and using consumer reports for employment purposes",
    ),
    pat: [
      // A COMPLIANT disclosure says none of these: it does not describe itself
      // as stand-alone, it simply IS one, carrying nothing but the § 604(b)
      // disclosure statement. Requiring the meta-claim made the column
      // unsatisfiable by the very document it exists to bless — the rule's own
      // `fix` text does not satisfy it either. The disclosure STATEMENT is
      // what a compliant document carries, so that is what is recognized.
      /(clear\s+and\s+conspicuous\s+(written\s+)?disclosure|in\s+a\s+document\s+that\s+consists\s+solely|stand-?alone\s+(disclosure|document)|separate\s+document\s+(containing|consisting)|consumer\s+report(?:ing\s+agency)?[^.]{0,120}?\bfor\s+employment\s+purposes|for\s+employment\s+purposes[^.]{0,120}?\bconsumer\s+report)/i,
      /(consumer\s+report|background\s+(check|report))/i,
    ],
    all: true,
    why: "§ 1681b(b)(2)(A)(i) requires the disclosure be in a document consisting solely of the disclosure. The Supreme Court's Spokeo/TransUnion line has narrowed standing, but the statutory violation and state analogs remain live.",
    fix: "Put the disclosure in its own document containing nothing but the disclosure and the authorization, with no liability waiver, no state-law notices, and no employment terms.",
    sev: "critical",
  },
  {
    id: "EMP-149",
    // 1.1.0 — GATED on a waiver actually being present. As an ungated presence
    // column it could not be satisfied by a compliant document: one that
    // carries no release says nothing about carrying none, so a lawful
    // stand-alone disclosure reported at `critical` that it had an embedded
    // waiver problem. The gate turns it into what it always meant — a document
    // that DOES release the employer or the agency fails, and one that does
    // not is never asked.
    ver: "1.1.0",
    name: "Disclosure free of an embedded liability waiver",
    missing:
      "This disclosure contains a release or waiver of liability. FCRA § 604(b)(2)(A)(i) requires the disclosure to be in a document consisting solely of the disclosure, and an embedded release defeats that outright.",
    when: [
      /(?:releases?|waives?|discharges?)\b[^.]{0,90}?\b(?:from\s+)?(?:any|all|the)\b[^.]{0,90}?\b(?:liabilit|claims?|causes?\s+of\s+action)/i,
    ],
    cite: usc("15", "1681b", "FCRA § 604(b)(2) — stand-alone disclosure requirement"),
    pat: [
      /(no\s+(liability\s+)?(waiver|release)|does\s+not\s+(contain|include)\s+(a\s+)?(waiver|release))/i,
      /(this\s+document\s+(contains|consists\s+of)\s+only|solely\s+(of|for)\s+(the\s+)?(purpose\s+of\s+)?(this\s+)?disclosure)/i,
    ],
    why: "An embedded release of the employer or the consumer reporting agency is the single most-litigated FCRA defect. It defeats the stand-alone requirement outright.",
    fix: "Remove any release or waiver of liability from the disclosure document and place it, if used at all, in a separate document signed separately.",
    sev: "critical",
  },
  {
    id: "EMP-150",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Clear written authorization",
    cite: usc("15", "1681b", "FCRA § 604(b)(2)(A)(ii) — written authorization"),
    pat: [
      /authori[sz]/i,
      /(i\s+(hereby\s+)?authori[sz]e|sign(ed|ature)?\s+(below|of\s+(the\s+)?(applicant|consumer|employee))|written\s+authori[sz]ation)/i,
    ],
    all: true,
    why: "The report may not be procured without the consumer's written authorization. A disclosure without a signature line is a compliance failure that also leaves the employer without evidence of consent.",
    fix: "Include a clear authorization statement and a signature and date line, and retain the signed original.",
    denied: expressDenial(String.raw`written\s+authorization`),
    sev: "critical",
  },
  {
    id: "EMP-151",
    name: "Investigative consumer report notice",
    cite: usc("15", "1681d", "FCRA § 606 — disclosure of investigative consumer reports"),
    pat: [
      /investigative\s+consumer\s+report/i,
      /(three\s+days|nature\s+and\s+scope|upon\s+(written\s+)?request|personal\s+interviews)/i,
    ],
    why: "Where the report includes interviews about character or reputation, § 606 requires a separate disclosure within three days and a right to request the nature and scope of the investigation.",
    fix: "Add the investigative consumer report disclosure, the three-day timing statement, and the right to request a written description of the nature and scope.",
    when: [
      /(investigative\s+consumer\s+report|personal\s+interview|character,?\s+general\s+reputation)/i,
    ],
  },
  {
    id: "EMP-152",
    name: "Summary of Rights delivery",
    cite: cfr("12", "1022 App. K", "Regulation V — Summary of Consumer Rights"),
    pat: [
      /(summary\s+of\s+(your\s+)?rights|a\s+summary\s+of\s+your\s+rights\s+under\s+the\s+fair\s+credit\s+reporting\s+act)/i,
      /(provided|attached|enclosed|delivered)/i,
    ],
    why: "The CFPB's Summary of Consumer Rights must accompany the pre-adverse action notice, and its current form is prescribed by regulation. Using an outdated version is a recurring defect.",
    fix: "Attach the current CFPB Summary of Consumer Rights and confirm the version in use.",
  },
  {
    id: "EMP-153",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Pre-adverse and adverse action sequence",
    cite: usc("15", "1681m", "FCRA § 615 — requirements on users of consumer reports"),
    pat: [
      /(pre-?adverse\s+action|adverse\s+action)/i,
      /(copy\s+of\s+the\s+report|reasonable\s+(time|period)|dispute|before\s+taking\s+(any\s+)?adverse\s+action)/i,
    ],
    why: "§ 1681b(b)(3) requires a pre-adverse notice with a copy of the report and the Summary of Rights, a reasonable interval to respond, then a separate adverse-action notice. Compressing the two steps is the classic violation, and several cities' fair-chance ordinances add more.",
    fix: "Describe the two-step sequence with the intervening waiting period, the documents delivered at each step, and the individualized-assessment requirement any applicable fair-chance ordinance imposes.",
    denied: expressDenial(String.raw`pre[- ]adverse\s+action\s+(?:notice|letter)?`),
    sev: "critical",
  },
]);

/**
 * EMP-142 — Sixty-day advance timing (critical). COMPUTED, not read.
 *
 * The check shipped as a compliance-matrix column, which is a search for
 * words: `/(60|sixty) (calendar )?days/` OR `/advance (written )?notice/`. A
 * WARN notice is one of the few documents where that is wrong in BOTH
 * directions at once.
 *
 * It was wrong on the COMPLIANT notice. A plant-closing notice does not do the
 * arithmetic out loud — it gives its own date and the expected date of the
 * action and lets the reader subtract. A notice dated September 1 for a
 * November 30 closing gives NINETY days, exceeds § 2102 outright, and was told
 * at `critical` that it did not give sixty.
 *
 * And it was wrong on the VIOLATING one. A notice handed out ten days before
 * the plant closes, opening "this is your 60-day advance notice under the WARN
 * Act", matched both patterns and passed. The column was measuring vocabulary,
 * and vocabulary is the one thing a ten-day notice gets right.
 *
 * § 2102 is a rule about an INTERVAL, so this reads the interval. The notice
 * date is the earliest resolvable calendar date in the document; the action
 * date is the latest one standing in a paragraph that names the action — the
 * closing, the layoff, the separation, the last day of work. Sixty or more
 * days between them and the check is silent.
 *
 * Two deliberate silences:
 *
 *   - **A stated statutory exception.** § 2102(b) lets a faltering company, an
 *     unforeseeable business circumstance, or a natural disaster shorten the
 *     period. A notice invoking one is not answering this question; EMP-146 is
 *     the check that asks whether the basis was explained.
 *   - **Nothing to subtract.** With no pair of resolvable dates the interval is
 *     unknown, and the check falls back to the words — which is the right
 *     standard for a notice that states no dates at all, and the only case the
 *     original patterns were ever right about.
 */
const WARN_ACTION_PARAGRAPH =
  /\b(?:clos(?:ing|ure|e|ed)|layoffs?|laid\s+off|separations?|separated|terminat\w*|reduction\s+in\s+force|last\s+day\s+of\s+(?:work|employment))\b/i;

/** § 2102(b) — the three exceptions that lawfully shorten the period. */
const WARN_EXCEPTION =
  /\b(?:faltering\s+compan\w*|unforeseeable\s+business\s+circumstance\w*|natural\s+disaster|2102\s*\(\s*b\s*\))/i;

/** The words the shipped column looked for, kept as the no-dates fallback. */
const WARN_TIMING_WORDS =
  /\b(?:60|sixty)\s+(?:calendar\s+)?days\b|\badvance\s+(?:written\s+)?notice\b|\bprior\s+to\s+the\s+(?:separation|closing|layoff)\b/i;

/** § 2102 itself, cited on the finding the way the pack cites its columns. */
const WARN_2102 = usc(
  "29",
  "2102",
  "Worker Adjustment and Retraining Notification Act — notice required before plant closings and mass layoffs",
);

const WARN_NOTICE_DAYS = 60;
const MS_PER_DAY = 86_400_000;

const WARN_ADVANCE_TIMING: Rule = {
  id: "EMP-142",
  version: "2.0.0",
  name: "Sixty-day advance timing",
  category: C,
  default_severity: "critical",
  description:
    "Measures the interval between the notice date and the expected date of the plant closing or mass layoff against the sixty days § 2102 requires.",
  dkb_citations: [WARN_2102.id],
  applies_to_playbooks: ["warn-notice"],

  check(ctx: RuleContext): Finding | null {
    const paragraphs: { text: string; start: number; end: number }[] = [];
    forEachParagraph(ctx.tree, (p) =>
      paragraphs.push({ text: p.text, start: p.start, end: p.end }),
    );
    const whole = paragraphs.map((p) => p.text).join(" ");
    if (WARN_EXCEPTION.test(whole)) return null;

    const calendar = ctx.extracted.dates
      .filter((d) => d.type === "absolute" && typeof d.iso === "string")
      .map((d) => ({ d, ms: Date.parse(`${d.iso!}T00:00:00Z`) }))
      .filter((x) => Number.isFinite(x.ms))
      .sort((a, b) => a.ms - b.ms);

    const actionParagraphs = paragraphs.filter((p) => WARN_ACTION_PARAGRAPH.test(p.text));
    const notice = calendar[0];
    const action = [...calendar]
      .reverse()
      .find((x) =>
        actionParagraphs.some((p) => x.d.position.start >= p.start && x.d.position.end <= p.end),
      );

    if (!notice || !action || action.ms <= notice.ms) {
      if (WARN_TIMING_WORDS.test(whole)) return null;
      return makeFinding({
        rule: WARN_ADVANCE_TIMING,
        title: "Sixty-day advance timing — not found",
        description:
          "This notice states neither a sixty-day advance period nor a pair of dates from which the period can be computed.",
        excerptText: paragraphs[0]?.text.slice(0, 200) ?? "",
        explanation:
          "§ 2102 requires 60 days' notice before a covered plant closing or mass layoff. A notice that gives no date for the action cannot be measured against that period by its reader either.",
        recommendation:
          "State the date of the notice and the expected date of the closing or layoff, or state the statutory exception relied on and the basis for reducing the period.",
        position: topPosition(ctx),
        source_citations: [WARN_2102],
      });
    }

    const days = Math.round((action.ms - notice.ms) / MS_PER_DAY);
    if (days >= WARN_NOTICE_DAYS) return null;

    return makeFinding({
      rule: WARN_ADVANCE_TIMING,
      title: `Sixty-day advance timing — ${days} days given`,
      description: `The notice is dated ${notice.d.iso} and the action is expected on ${action.d.iso}, which is ${days} days, not the ${WARN_NOTICE_DAYS} that § 2102 requires.`,
      excerptText: action.d.raw_text,
      explanation:
        "§ 2102 requires 60 days' notice before a covered plant closing or mass layoff, with only three narrow exceptions (faltering company, unforeseeable business circumstances, natural disaster) that must themselves be explained in the notice. This notice states none of them.",
      recommendation:
        "Give the notice at least 60 days before the first separation, or state the statutory exception relied on and the basis for reducing the period.",
      position: action.d.position,
      source_citations: [WARN_2102],
    });
  },
};

export const V5_EMPLOYMENT_RULES: readonly Rule[] = [
  ...ARBITRATION,
  ...COMMISSION,
  ...BONUS,
  ...RELOCATION,
  ...REMOTE,
  ...INTERNSHIP,
  ...CBA,
  ...WARN,
  WARN_ADVANCE_TIMING,
  ...FCRA,
];

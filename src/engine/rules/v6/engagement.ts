/**
 * v6 pack A — law-practice engagement documents (spec-v46.md §5).
 *
 * Six families a firm produces for its own clients, checked against the
 * ABA Model Rules of Professional Conduct. Namespace: `ENG`.
 *
 * The honesty constraint here is sharper than anywhere else in the
 * catalog: the Model Rules bind nobody. Every citation says so, every
 * recommendation is phrased as drafting advice, and no finding asserts
 * that a lawyer has violated a duty — only that a term the Model Rules
 * contemplate was not found in the document.
 */

import type { Rule } from "../../finding.js";
import { pack, modelRule, practice } from "./_helpers.js";

const C = "law-practice";

const ENGAGEMENT = pack("engagement-letter", C, [
  {
    id: "ENG-001",
    // 1.0.1 — the exclusion pillar read only the affirmative framings of the
    // boundary ("this engagement is limited to", "matters not covered"). The
    // commonest drafting states it as a negative sentence — "We will not
    // represent the Company in any appeal, in any tax matter, or in any other
    // matter" — which the pillar missed, so a letter that drew the boundary
    // exactly as Rule 1.2(c) contemplates was told at `critical` that it had
    // not drawn one.
    //
    // 1.0.2 — the same pillar, two more misses found by running the rule on a
    // hand-written engagement letter. The limiting sentence takes a possessive
    // as readily as a demonstrative ("**Our** representation is limited to the
    // Matter"), and the exclusion is as often stated as an undertaking not
    // taken on ("we **are not undertaking** to advise you on tax, accounting,
    // or regulatory matters") as it is with a bare "we will not represent".
    // Both are Rule 1.2(c) drafting; both were reported as its absence.
    ver: "1.0.2",
    name: "Scope of the representation",
    cite: modelRule("1.2(c)", "scope of representation and allocation of authority"),
    pat: [
      /(scope\s+of\s+(the\s+)?(representation|engagement)|we\s+(will|have\s+agreed\s+to)\s+represent\s+you\s+in)/i,
      /((?:this|our|the)\s+(engagement|representation|retention)\s+(is\s+limited\s+to|covers|does\s+not\s+include)|matters?\s+(not\s+)?(covered|included)|we\s+(will|do|shall)\s+not\s+represent|(?:our\s+)?(?:engagement|representation|retention)\s+does\s+not\s+(?:include|extend|cover)|not\s+(?:being\s+)?(?:engaged|retained)\s+to\b|(?:are|is|am)\s+not\s+undertaking\s+to\b|outside\s+the\s+scope\s+of\s+(?:this|our))/i,
    ],
    all: true,
    why: "Rule 1.2(c) permits limiting the scope only if the limitation is reasonable and the client gives informed consent. A letter that does not draw the boundary leaves the client believing the lawyer is handling adjacent matters — tax consequences, appeals, related claims — that the lawyer never took on.",
    fix: "State what the engagement covers and, expressly, what it does not (appeals, tax advice, related matters, other entities and affiliates).",
    sev: "critical",
  },
  {
    id: "ENG-002",
    // 1.0.1 — the naming pillar read "we represent" but not "we will
    // represent", which is how a letter written before the work begins says
    // it.
    //
    // 1.0.2 — the *disclaimer* pillar had the mirror of the same gap: it read
    // only "do not represent its officers", while the constituent disclaimer
    // is just as often written as an undertaking not taken on ("we are not
    // undertaking to represent any parent, subsidiary, affiliate, officer,
    // director, or employee of the Client"). A letter that named its client
    // and disclaimed its constituents exactly as Rule 1.13 contemplates was
    // told at `critical` that it had done neither.
    ver: "1.0.4",
    name: "Identity of the client",
    cite: modelRule("1.13", "organization as client"),
    pat: [
      // "Our client IN THIS MATTER is …" is how a letter that opens more than
      // one matter says it, and the adjacent-words form could not see past the
      // qualifier.
      /(our\s+client\b[^.]{0,40}?\s(?:is|will\s+be)\b|we\s+(?:will\s+|shall\s+|have\s+agreed\s+to\s+)?represent|the\s+client\s+(is|for\s+purposes\s+of))/i,
      // 1.0.4 — the disclaimer wanted the constituent noun immediately after
      // "any", and in the plural. A flat-fee engagement letter writes it "We
      // do not represent you individually, and we do not represent any OTHER
      // MEMBER, officer, employee, or investor of the company" — an adjective
      // in between and a singular noun — and names its client in the trailing
      // form, "Our client is Chandrasekaran Robotics, LLC ONLY". Both pillars
      // were plainly satisfied by the letter's first section, headed THE
      // CLIENT, and it was told at `critical` that neither was.
      /(only\s+(the\s+)?(company|entity|you)|our\s+client\b[^.]{0,60}\bonly\b|(?:do|will|shall|must)\s+not\s+represent\s+(?:you\s+individually|(?:its|your|any|the)\s+(?:other\s+|individual\s+)?(?:officers?|directors?|affiliates?|shareholders?|stockholders?|members?|employees?|investors?|owners?|principals?|parent|subsidiar\w*))|(?:are|is|am)\s+not\s+(?:undertaking\s+to\s+represent|representing)\s+(?:its|your|any)\s+(?:officers?|directors?|affiliates?|shareholders?|members?|parent|subsidiar\w*))/i,
    ],
    all: true,
    why: "Rule 1.13 makes the organization the client, not its constituents. When the letter does not say so, officers, affiliates, and investors reasonably believe they are clients too — which creates conflicts and privilege problems nobody intended.",
    fix: "Name the client precisely and state that the firm does not represent its affiliates, owners, officers, or directors absent a separate engagement.",
    sev: "critical",
  },
  {
    id: "ENG-003",
    name: "Fee basis and rates",
    cite: modelRule("1.5(b)", "fees — communication of the basis or rate"),
    pat: [
      /(hourly\s+rate|fixed\s+fee|flat\s+fee|contingen|our\s+fees?\s+(are|will\s+be))/i,
      /(\$\s?\d|rate\s+of|per\s+hour|billed\s+at)/i,
    ],
    all: true,
    why: "Rule 1.5(b) requires the basis or rate of the fee to be communicated, preferably in writing, before or within a reasonable time after commencing the representation. A letter without a rate is the most common fee-dispute fact pattern there is.",
    fix: "State the fee basis, the rates for each timekeeper or category, and how and when rates may change.",
    sev: "critical",
  },
  {
    id: "ENG-004",
    name: "Costs and expenses",
    cite: modelRule("1.5(b)", "fees — expenses for which the client will be responsible"),
    pat: [
      /(costs?|expenses?|disbursements?)/i,
      /(filing\s+fees?|court\s+reporter|expert|travel|copying|responsible\s+for|advanced\s+by\s+(the\s+)?firm)/i,
    ],
    all: true,
    why: "Rule 1.5(b) covers expenses as well as fees. Clients who were never told about expert fees, e-discovery hosting, or deposition costs experience the first invoice as a surprise, and surprise is where fee disputes begin.",
    fix: "List the expense categories the client will bear, state whether the firm advances them, and set any threshold above which the client's approval is required.",
  },
  {
    id: "ENG-005",
    name: "Billing frequency and payment terms",
    cite: practice("billing-terms", "billing and payment terms in engagement letters"),
    pat: [
      /(invoice|bill(ed|ing)?|statement)/i,
      /(monthly|quarterly|due\s+(within|upon)|days\s+of\s+receipt|interest|late\s+charge)/i,
    ],
    all: true,
    why: "The billing cadence and the payment deadline are what let a client budget and what let the firm act on nonpayment. Without them, a firm that stops work over an unpaid invoice has no agreed trigger to point to.",
    fix: "State the billing frequency, the payment due date, any interest or late charge, and the consequence of nonpayment.",
  },
  {
    id: "ENG-006",
    name: "Retainer or advance fee and where it is held",
    cite: modelRule("1.15(c)", "safekeeping property — advance fees and expenses"),
    pat: [
      /(retainer|advance\s+(fee|payment)|deposit)/i,
      /(trust[-\s]+account|iolta|client\s+funds|withdraw|applied\s+(to|against))/i,
    ],
    all: true,
    why: "Rule 1.15(c) requires advance fees and expenses to be held in a client trust account and withdrawn only as earned or incurred. Treating an advance as the firm's own money on receipt is one of the most common disciplinary findings in the country.",
    fix: "State the retainer amount, that it is held in the firm's trust account, when it is applied, and whether an unearned balance is refundable.",
    when: [/(retainer|advance\s+(fee|payment)|deposit|trust[-\s]+account)/i],
    sev: "critical",
  },
  {
    id: "ENG-007",
    name: "Conflicts and future-conflict consent",
    cite: modelRule("1.7(b)", "conflict of interest — informed consent, confirmed in writing"),
    pat: [
      /conflicts?\s+(of\s+interest|check|search)/i,
      /(waiv|consent|adverse\s+to\s+you|other\s+clients|future\s+(representation|matters))/i,
    ],
    all: true,
    why: "Rule 1.7(b) requires informed consent confirmed in writing for a concurrent conflict, and Comment [22] permits advance waivers only where the client reasonably understands the material risks. Advance waivers that describe no risk are routinely held ineffective.",
    fix: "Describe the conflicts check performed and, if an advance waiver is sought, describe the kinds of adverse matters it covers and the material risks in concrete terms.",
  },
  {
    id: "ENG-008",
    name: "Termination, withdrawal, and file return",
    cite: modelRule(
      "1.16(d)",
      "declining or terminating representation — surrendering papers and property",
    ),
    pat: [
      /(terminat|withdraw|end\s+(the\s+)?(engagement|representation))/i,
      /(file|papers|documents|return|retain|records)/i,
    ],
    all: true,
    why: "Rule 1.16(d) requires surrendering papers and property to which the client is entitled and refunding any unearned advance. Firms that never wrote down their retention policy end up litigating what 'the file' means years later.",
    fix: "State each party's right to terminate, the firm's withdrawal grounds, the file-return policy, the retention period, and the format in which the file is delivered.",
    sev: "critical",
  },
]);

const CONTINGENCY = pack("contingency-fee-agreement", C, [
  {
    id: "ENG-009",
    name: "Signed writing stating the contingency method",
    cite: modelRule("1.5(c)", "contingent fee agreements — writing signed by the client"),
    pat: [/(contingen)/i, /(percentage|\d{1,2}\s?%|one-?third|33|40)/i],
    all: true,
    why: "Rule 1.5(c) requires a contingent fee agreement to be in a writing signed by the client, stating the method by which the fee is determined — including the percentage that accrues at each stage.",
    fix: "State the percentage and the stage at which each applies (pre-suit, after filing, after appeal), and provide for the client's signature.",
    sev: "critical",
  },
  {
    id: "ENG-010",
    name: "Expenses deducted before or after the fee",
    cite: modelRule(
      "1.5(c)",
      "contingent fee agreements — whether expenses are deducted before or after the fee is calculated",
    ),
    pat: [
      /(expenses?|costs?|disbursements?)/i,
      /(before|after|deducted|net\s+(recovery|of)|gross\s+recovery)/i,
    ],
    all: true,
    why: "Rule 1.5(c) requires the agreement to state whether expenses are deducted before or after the contingent fee is calculated. The difference is thousands of dollars, and it is the single most-litigated term in contingency practice.",
    fix: "State expressly whether the fee is computed on the gross recovery or on the recovery net of expenses, and include a worked example.",
    sev: "critical",
  },
  {
    id: "ENG-011",
    name: "Expenses owed if there is no recovery",
    cite: modelRule(
      "1.5(c)",
      "contingent fee agreements — expenses for which the client is liable whether or not the client prevails",
    ),
    pat: [
      /(no\s+recovery|do\s+not\s+(prevail|recover)|unsuccessful|lose)/i,
      /(expenses?|costs?|owe|responsible|not\s+(be\s+)?(liable|responsible))/i,
    ],
    all: true,
    why: "The rule requires the agreement to state the expenses for which the client is liable whether or not the client prevails. Clients who lose and then receive a costs bill they were never warned about have a fee-arbitration claim and a grievance.",
    fix: "State plainly whether the client owes case expenses if there is no recovery, and if so, which ones.",
    sev: "critical",
  },
  {
    id: "ENG-012",
    ver: "1.1.0",
    name: "Matters excluded from the contingent fee",
    cite: modelRule("1.5(c)", "contingent fee agreements — scope"),
    pat: [
      // The exclusion is written as a promise, not as a label: "The Firm will
      // not represent the Client on appeal, in a bankruptcy, or in any other
      // matter unless the parties sign a separate agreement" is the ordinary
      // drafting, and it carried none of the tokens this column wanted.
      /(not\s+(covered|included)|exclud|separate\s+(fee|engagement|agreement|retainer)|does\s+not\s+(cover|include|extend\s+to|apply\s+to)|will\s+not\s+represent)/i,
      /(appeal|counterclaim|collection|bankruptcy|related\s+matter|enforce)/i,
    ],
    all: true,
    why: "Appeals, collection of the judgment, defense of a counterclaim, and related matters are commonly outside the contingency. If the agreement does not say so, the client will reasonably expect them included.",
    fix: "List the matters outside the contingent fee and state how each would be charged if the client asks the firm to handle it.",
  },
  {
    id: "ENG-013",
    name: "Client's settlement authority",
    cite: modelRule("1.2(a)", "allocation of authority — the client decides whether to settle"),
    pat: [
      /(settle|settlement)/i,
      /(client(\s+alone)?\s+(shall\s+)?(decide|has\s+the\s+(sole\s+)?(right|authority))|your\s+decision|will\s+not\s+settle\s+without)/i,
    ],
    all: true,
    why: "Rule 1.2(a) reserves the settlement decision to the client. Contingency agreements that read as though counsel may accept an offer are unenforceable on that point and invite a malpractice claim.",
    fix: "State that the decision whether to settle is the client's alone, and that the firm will present every offer.",
    sev: "critical",
  },
  {
    id: "ENG-014",
    name: "Statement of the outcome at conclusion",
    cite: modelRule(
      "1.5(c)",
      "contingent fee agreements — written statement at the conclusion of the matter",
    ),
    pat: [
      /(at\s+the\s+(conclusion|end)|upon\s+(conclusion|recovery|settlement)|when\s+the\s+matter\s+(ends|concludes))/i,
      /(written\s+statement|closing\s+statement|itemi[sz]|accounting|remittance)/i,
    ],
    all: true,
    why: "The rule requires a written statement at the conclusion showing the outcome, the remittance to the client, and the method of its determination. It is a rule obligation, and it is also the firm's own record if the fee is later challenged.",
    fix: "Commit to a written closing statement showing the recovery, each deduction, the fee calculation, and the net to the client.",
  },
  {
    id: "ENG-015",
    name: "Lien and third-party payor obligations",
    cite: modelRule("1.15(d)", "safekeeping property — third persons with an interest in funds"),
    pat: [
      /(lien|subrogation|medicare|medicaid|erisa\s+plan|health\s+insurer|provider)/i,
      /(satisf|resolv|withhold|escrow|pay(ment)?\s+(of|from)\s+the\s+recovery)/i,
    ],
    all: true,
    why: "Rule 1.15(d) requires a lawyer holding funds in which a third person has an interest to deliver them promptly. Medicare conditional payments and ERISA plan reimbursement rights attach to the recovery, and disbursing over them exposes both client and firm.",
    fix: "Describe how liens and subrogation claims are identified, held, and resolved before disbursement, and who bears responsibility for negotiating them.",
    when: [/(lien|subrogation|medicare|medicaid|health\s+insur|personal\s+injury|provider)/i],
  },
]);

const FLAT_FEE = pack("flat-fee-agreement", C, [
  {
    id: "ENG-016",
    name: "Services the flat fee covers",
    cite: modelRule("1.5(b)", "fees — communication of the basis or rate"),
    pat: [
      /(flat\s+fee|fixed\s+fee|the\s+fee\s+(of|is)\s+[$€£¥₹₩₽])/i,
      /(covers?|includes?|for\s+the\s+following|scope\s+of\s+(the\s+)?(work|services))/i,
    ],
    all: true,
    why: "A flat fee only works if both sides know what it buys. Undefined scope produces the two failure modes flat fees are meant to avoid: unpaid overruns and disputes about what was included.",
    fix: "Enumerate the services included in the flat fee and the milestones at which it is billed.",
    sev: "critical",
  },
  {
    id: "ENG-017",
    name: "Work outside the flat fee",
    cite: practice("flat-fee-scope", "out-of-scope work in flat fee arrangements"),
    pat: [
      /(outside|beyond|not\s+(covered|included)|additional\s+(work|services))/i,
      /(hourly|separate(ly)?\s+(charged|billed)|additional\s+fee|amended\s+(fee|engagement))/i,
    ],
    all: true,
    why: "Every flat-fee matter encounters work nobody scoped. Without a stated mechanism, the firm either absorbs it or bills it unilaterally, and both damage the relationship.",
    fix: "State how out-of-scope work is identified, approved in advance, and charged.",
  },
  {
    id: "ENG-018",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Trust-account treatment of the advance",
    cite: modelRule("1.15(c)", "safekeeping property — advance fees"),
    pat: [
      /(flat\s+fee|advance|paid\s+(in\s+advance|up\s+front))/i,
      /(trust[-\s]+account|iolta|earned\s+upon\s+receipt|deemed\s+earned|held\s+until)/i,
    ],
    all: true,
    why: "Whether a flat fee paid in advance may be deposited in the operating account is one of the sharpest state-to-state splits in the Model Rules' adoption. Several states prohibit 'earned upon receipt' outright, and some require specific disclosure language.",
    fix: "State where the advance is held and when it is earned, and confirm the treatment against the licensing state's own version of Rule 1.15.",
    sev: "critical",
  },
  {
    id: "ENG-019",
    name: "Refund of the unearned portion on early termination",
    cite: modelRule(
      "1.16(d)",
      "declining or terminating representation — refunding any advance payment not earned",
    ),
    pat: [
      /(terminat|withdraw|discharge|end\s+(the\s+)?representation)/i,
      /(refund|unearned|prorat|quantum\s+meruit|return\s+(of|any))/i,
    ],
    all: true,
    why: "Rule 1.16(d) requires refunding any advance payment of fee that has not been earned, whatever the agreement calls the fee. A non-refundable flat fee is unenforceable to that extent in every jurisdiction.",
    fix: "State the method for determining the earned portion on early termination and commit to refunding the balance.",
    sev: "critical",
  },
  {
    id: "ENG-020",
    name: "Expenses treated separately from the fee",
    cite: modelRule("1.5(b)", "fees — expenses for which the client will be responsible"),
    pat: [
      /(expenses?|costs?|disbursements?)/i,
      /(separate|in\s+addition\s+to|not\s+included\s+in\s+the\s+(flat\s+)?fee|billed\s+at\s+cost)/i,
    ],
    all: true,
    why: "Clients read a flat fee as all-in. If filing fees, service, or expert costs are extra, the agreement has to say so before the first invoice, not after.",
    fix: "State that expenses are separate from the flat fee, list the categories, and describe how they are billed.",
  },
]);

const JOINT_REP = pack("joint-representation-waiver", C, [
  {
    id: "ENG-021",
    ver: "1.1.0",
    name: "Identification of every jointly represented client",
    cite: modelRule("1.7", "conflict of interest — current clients"),
    pat: [
      /(joint(ly)?\s+represent|common\s+representation|both\s+of\s+you|each\s+of\s+you)/i,
      // A joint-representation letter identifies its clients by ADDRESSING
      // them — the address block, the salutation, the consent signature blocks
      // — and almost never says "the clients are". Requiring that made the
      // column unsatisfiable by a well-drafted letter.
      /(client(s)?\s+(are|is)|the\s+following\s+(parties|persons|entities)|you\s+have\s+each\s+asked|each\s+of\s+you\s+(?:has|have)\s+asked|represent(?:ing)?\s+both\s+of\s+you|(?:joint|common)\s+representation\s+of)/i,
    ],
    all: true,
    why: "A joint-representation waiver that does not name every client cannot establish informed consent from each of them, which is the only thing that makes the joint representation permissible.",
    fix: "Name each jointly represented client and confirm each is signing in their own capacity.",
    sev: "critical",
  },
  {
    id: "ENG-022",
    name: "No confidentiality among the joint clients",
    cite: modelRule(
      "1.7",
      "conflict of interest — comment [30] on common representation and confidentiality",
    ),
    pat: [
      /(confidential|privileg)/i,
      /(among|between|as\s+(to|between)\s+(each\s+other|one\s+another|the\s+(joint\s+)?clients)|no\s+(confidences|secrets)|share\s+with\s+(the\s+)?other)/i,
    ],
    all: true,
    why: "In a common representation the lawyer generally cannot keep one client's information from the other, and the privilege does not apply between them if they later litigate. Clients almost never assume this without being told.",
    fix: "State that information from one joint client will be shared with the others, and that the attorney-client privilege will not protect their communications from each other in a later dispute between them.",
    sev: "critical",
  },
  {
    id: "ENG-023",
    ver: "1.1.0",
    name: "Consequence if a conflict later develops",
    cite: modelRule(
      "1.7",
      "conflict of interest — comment [29] on withdrawal from common representation",
    ),
    pat: [
      // A letter writes it "If a disagreement arises between you" and "if a
      // conflict becomes actual" as readily as "if a conflict arises", and a
      // section HEADED "What happens if a conflict becomes actual" was
      // reported as missing at `critical`.
      /(if\s+(?:an?\s+)?(?:actual\s+)?(conflict|dispute|disagreement)\s+(arises|develops|becomes)|should\s+an?\s+(?:actual\s+)?(?:conflict|dispute|disagreement)|(?:conflict|dispute)\s+becomes\s+actual)/i,
      /(withdraw|cease\s+to\s+represent|resign|may\s+be\s+required\s+to)/i,
    ],
    all: true,
    why: "When common clients fall out, the lawyer usually must withdraw from representing all of them. Telling clients that in advance is what makes the consent informed and what avoids a second dispute about the withdrawal itself.",
    fix: "State that the firm may be required to withdraw from representing all joint clients if a material conflict develops, and whether it may continue for any of them.",
    sev: "critical",
  },
  {
    id: "ENG-024",
    name: "Advantages and risks of the common representation",
    cite: modelRule("1.0(e)", "terminology — informed consent"),
    pat: [
      /(advantage|benefit|risk)/i,
      /(common\s+representation|joint\s+representation|separate\s+counsel|independent[-\s]+counsel)/i,
    ],
    all: true,
    why: "Rule 1.0(e) defines informed consent as agreement after the lawyer explains the material risks and reasonably available alternatives. A waiver reciting consent without describing risk is form without substance.",
    fix: "Describe the advantages (cost, coordination) and the concrete risks, and state that each client may retain separate counsel instead.",
  },
  {
    id: "ENG-025",
    name: "Opportunity to consult independent counsel",
    cite: modelRule("1.0(e)", "terminology — informed consent"),
    pat: [
      /(independent|separate)\s+(counsel|lawyer|attorney)/i,
      /(opportunity|encouraged|may\s+(wish\s+to\s+)?consult|advised\s+to\s+(seek|consult))/i,
    ],
    all: true,
    why: "An express opportunity to consult independent counsel is the most persuasive single fact supporting an informed-consent finding, and it costs nothing to include.",
    fix: "State that each client has been advised of the right to consult independent counsel and has had an opportunity to do so.",
  },
  {
    id: "ENG-026",
    name: "Written confirmation signed by each client",
    cite: modelRule("1.7(b)(4)", "conflict of interest — informed consent, confirmed in writing"),
    // 1.0.1 — both pillars were satisfied by ordinary execution boilerplate:
    // `agree` matches inside "entire agreement", and `signature` matches the
    // signature block every document has. The consent pillar now has to name
    // a consent rather than an agreement, and the signing pillar has to be
    // about the CLIENTS signing this waiver.
    ver: "1.0.1",
    pat: [
      /(informed\s+consent|consents?\s+(?:in\s+writing\s+)?to\b|each\s+client\s+(?:consents|agrees|acknowledges)|waives?\s+(?:any\s+)?conflict)/i,
      /(sign(?:ed)?\s+below|by\s+signing\s+(?:this|below)|each\s+client\s+(?:(?:shall|will|must)\s+)?sign|signed\s+by\s+each\s+client)/i,
    ],
    all: true,
    why: "Rule 1.7(b)(4) requires informed consent confirmed in writing. An unsigned waiver in the file is not the confirmation the rule contemplates.",
    fix: "Add a signature block for each jointly represented client with a date.",
    sev: "critical",
  },
]);

const LIMITED_SCOPE = pack("limited-scope-representation", C, [
  {
    id: "ENG-027",
    ver: "1.1.0",
    name: "Tasks the lawyer will and will not perform",
    cite: modelRule("1.2(c)", "scope of representation — limiting the scope"),
    pat: [
      /(limited\s+(scope|representation)|unbundled|discrete\s+task)/i,
      // A limited-scope agreement LISTS the tasks: "The lawyer will draft the
      // petition, prepare the financial declaration, and appear at the status
      // conference. The client will gather and provide bank statements, serve
      // the petition, and appear at all other hearings." None of the three
      // forms below appears in that, and the first pillar is met by the
      // family's own title — so the whole check rested on words nobody writes.
      // A letter says "WE", not "the lawyer". The two headings a limited-scope
      // letter is built around are "WHAT WE WILL DO" and "WHAT WE WILL NOT
      // DO", and the actor list held lawyer / attorney / firm / client and not
      // the first person every engagement letter is written in — so the
      // defining clause of the document was invisible and the check fired at
      // `critical` on a letter that enumerates both halves.
      /(will\s+(not\s+)?(perform|handle|include|do\b)|the\s+lawyer\s+(shall|will|must)\s+only|excluded\s+tasks|(?:lawyer|attorney|firm|client|we)\s+will\s+(?:not\s+)?[a-z]+)/i,
    ],
    all: true,
    why: "Rule 1.2(c) permits a limited scope only if it is reasonable and the client consents after being informed. An itemized division of labor is what makes both findings possible.",
    fix: "List, task by task, what the lawyer will do and what the client will do.",
    sev: "critical",
  },
  {
    id: "ENG-028",
    name: "Reasonableness of the limitation for this matter",
    cite: modelRule("1.2(c)", "scope of representation — reasonableness"),
    pat: [
      /(reasonab|appropriate\s+(for|given)|sufficient\s+for\s+(the|your))/i,
      /(limitation|limited\s+scope|circumstances\s+of\s+(this|the)\s+matter)/i,
    ],
    all: true,
    why: "A limitation that leaves the client unable to accomplish the objective is not reasonable, and the resulting representation can be worse than none. The reasonableness assessment belongs in the document.",
    fix: "State why the limitation is reasonable for this matter, and identify the objective the limited services are intended to accomplish.",
  },
  {
    id: "ENG-029",
    name: "Client's responsibility for everything else",
    cite: practice("limited-scope-client-duties", "allocation of unbundled tasks to the client"),
    pat: [
      /(you\s+(are|will\s+be)\s+responsible|the\s+client\s+(is|shall\s+be)\s+responsible)/i,
      /(deadline|filing|service|appear|hearing|discovery|court)/i,
    ],
    all: true,
    why: "In unbundled work the client carries the deadlines the lawyer is not handling. Saying so specifically — including which court dates the client must attend — is the difference between an informed client and a defaulted one.",
    fix: "State the client's responsibilities by task, and identify the deadlines and appearances the client must handle personally.",
    sev: "critical",
  },
  {
    id: "ENG-030",
    name: "Court disclosure of limited-scope appearance",
    cite: modelRule("3.3", "candor toward the tribunal"),
    pat: [
      /(court|tribunal|judge|clerk)/i,
      /(notice\s+of\s+limited\s+(scope|appearance)|disclos|file\s+a\s+(notice|substitution)|local\s+rule)/i,
    ],
    all: true,
    why: "Many jurisdictions require a notice of limited appearance and a separate withdrawal, and some require disclosure of drafting assistance. What the court is told is a rule question, not a client-preference question.",
    fix: "State what will be filed with the court about the limited scope, and how and when the appearance ends.",
    when: [/(court|litigation|filing|hearing|pleading|complaint|motion)/i],
  },
  {
    id: "ENG-031",
    ver: "1.1.0",
    name: "How and when the representation ends",
    cite: modelRule("1.16(d)", "declining or terminating representation"),
    pat: [
      /(conclu(de|sion)|end(s)?|complete(d|s)?|terminat)/i,
      // "The representation ends when the transaction closes" and "we will
      // confirm the end of the representation in writing" are how a letter
      // says it; none of the tokens below appears in either.
      /(upon\s+(delivery|filing|completion|closing)|when\s+[^.;]{0,60}?\b(?:closes|is\s+completed|concludes)\b|closing\s+letter|no\s+further\s+(obligation|services)|confirm[^.;]{0,60}?end\s+of\s+the\s+representation)/i,
    ],
    all: true,
    why: "Limited-scope engagements end at a task, not at a matter, and a client who does not know the engagement is over will keep relying on the lawyer. A defined endpoint plus a closing letter is the fix.",
    fix: "State the event that ends the engagement and commit to a written closing confirmation.",
  },
]);

const TERMINATION = pack("termination-of-representation", C, [
  {
    id: "ENG-032",
    ver: "1.1.0",
    name: "Statement that the representation has ended",
    cite: modelRule("1.16", "declining or terminating representation"),
    pat: [
      // "our representation OF YOU IN THIS MATTER has ended" puts the scope
      // between the noun and the verb, which the adjacent form cannot see.
      /(representation\b[^.;]{0,40}?\s(?:has\s+)?(?:ended|concluded|is\s+(?:now\s+)?(?:complete|terminated))|we\s+(are\s+)?(no\s+longer|have\s+concluded))/i,
      /(this\s+(letter|matter)|as\s+of\s+\w+\s+\d{1,2}|effective)/i,
    ],
    all: true,
    why: "A closing letter's purpose is to fix the date the duty ended, which is what starts the malpractice limitations period and ends the conflicts obligation. Ambiguity here defeats both.",
    fix: "State plainly that the representation has concluded and the date on which it did.",
    sev: "critical",
  },
  {
    id: "ENG-033",
    name: "No continuing obligation to monitor deadlines",
    cite: modelRule("1.3", "diligence"),
    pat: [
      /(no\s+(further|continuing)\s+(obligation|duty|responsibility)|we\s+will\s+not\s+(be\s+)?(monitor|track|advise))/i,
      /(deadline|statute\s+of\s+limitations|appeal|filing|renewal)/i,
    ],
    all: true,
    why: "Clients assume the firm is still watching the calendar. Saying that it is not — and naming the deadlines the client must now track — is what makes the closing effective rather than a formality.",
    fix: "State that the firm has no continuing duty to monitor deadlines, and identify any known upcoming deadline the client must handle.",
    sev: "critical",
  },
  {
    id: "ENG-034",
    name: "Return or retention of the client file",
    cite: modelRule("1.16(d)", "surrendering papers and property to which the client is entitled"),
    pat: [
      /(file|papers|documents|records)/i,
      /(return|deliver|retain|destroy|available\s+(to|upon)|retention\s+period)/i,
    ],
    all: true,
    why: "Rule 1.16(d) requires surrender of the client's papers and property. A closing letter that states the retention period and the destruction date is the firm's authority to destroy the file later.",
    fix: "State how the client may obtain the file, the retention period, and that the file may be destroyed after it without further notice.",
    sev: "critical",
  },
  {
    id: "ENG-035",
    name: "Final accounting and refund of unearned funds",
    cite: modelRule("1.15(d)", "safekeeping property — prompt accounting and delivery"),
    pat: [
      /(final\s+(invoice|statement|accounting)|balance)/i,
      /(refund|remit|unearned|trust[-\s]+account|enclosed\s+is)/i,
    ],
    all: true,
    why: "Rules 1.15(d) and 1.16(d) require a prompt accounting and return of any unearned advance. Trust-account balances left after a matter closes are a recurring source of discipline.",
    fix: "Include the final accounting, state any trust balance, and refund or apply it with the client's direction.",
  },
  {
    id: "ENG-036",
    name: "Post-engagement conflicts posture",
    cite: modelRule("1.9", "duties to former clients"),
    pat: [
      /(former\s+client|after\s+(this|the)\s+(matter|engagement)|in\s+the\s+future)/i,
      /(adverse|conflict|represent\s+(other|another)|substantially\s+related)/i,
    ],
    all: true,
    why: "Rule 1.9 governs once the client becomes a former client, and the standard is narrower than Rule 1.7. Saying so in the closing letter avoids a later surprise when the firm takes an adverse matter.",
    fix: "Note that the client is now a former client for conflicts purposes and describe the firm's obligations under the former-client rule.",
  },
]);

export const ENGAGEMENT_RULES: readonly Rule[] = [
  ...ENGAGEMENT,
  ...CONTINGENCY,
  ...FLAT_FEE,
  ...JOINT_REP,
  ...LIMITED_SCOPE,
  ...TERMINATION,
];

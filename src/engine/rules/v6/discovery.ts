/**
 * v6 pack B — discovery instruments (spec-v46.md §6).
 *
 * Seven families a litigator produces under the Federal Rules of Civil
 * Procedure. Namespace: `DISC`.
 *
 * These checks read format and completeness, never substance. Whether a
 * request is proportional, an objection meritorious, or a privilege claim
 * sound are judgments no deterministic tool can make. What it can check is
 * whether the document does the things the rule text requires of it: state
 * the response deadline, state whether responsive material is being
 * withheld, describe withheld documents well enough for the claim to be
 * assessed, and so on.
 */

import type { Rule } from "../../finding.js";
import { pack, frcp, fre, practice } from "./_helpers.js";

const C = "discovery";

const RFP = pack("document-requests", C, [
  {
    id: "DISC-001",
    // 1.0.1 — Rule 34 asks for PRODUCTION, and that is the verb the requests
    // themselves use: "produce the following documents for inspection and
    // copying within 30 days of service" states the deadline the rule wants
    // and contains none of respond/response/answer, so the deadline pillar
    // missed it and the check fired at `critical` on a request that had
    // stated its deadline.
    ver: "1.0.1",
    name: "Response deadline stated",
    cite: frcp("34(b)(2)(A)", "producing documents — time to respond"),
    pat: [
      /(respond|response|answer|produce|production)/i,
      /(30\s+days|thirty\s+\(?30\)?\s+days|within\s+\d+\s+days|no\s+later\s+than)/i,
    ],
    all: true,
    why: "Rule 34(b)(2)(A) gives 30 days from service (or, for requests delivered before the Rule 26(f) conference, 30 days after that conference). Stating the date on the face of the requests avoids the most common calendaring dispute in discovery.",
    fix: "State the response deadline and the rule it runs from, adjusting for any Rule 26(d)(2) early-delivery timing.",
    sev: "critical",
  },
  {
    id: "DISC-002",
    name: "Definitions and instructions",
    cite: frcp(
      "34(b)(1)(A)",
      "producing documents — the request must describe with reasonable particularity",
    ),
    pat: [
      /(definitions?|as\s+used\s+herein)/i,
      /(instructions?|you\s+are\s+(requested|instructed))/i,
    ],
    all: true,
    why: "Reasonable particularity is judged against what the request actually asks for. Definitions and instructions are how a request achieves it without repeating itself forty times — and overbroad definitions are equally where objections come from.",
    fix: "Include a definitions section and instructions, keeping the definitions no broader than the requests genuinely need.",
  },
  {
    id: "DISC-003",
    name: "Relevant time period",
    cite: frcp("26(b)(1)", "scope of discovery — proportionality"),
    pat: [
      /(time\s+period|relevant\s+period|from\s+\w+\s+\d{1,2},?\s+\d{4}|between\s+\w+\s+\d{4})/i,
      /(unless\s+otherwise\s+(stated|specified)|these\s+requests\s+(cover|seek)|applicable\s+to\s+the\s+period)/i,
    ],
    all: true,
    why: "An unbounded time period is the first proportionality objection any responding party makes, and often a well-taken one. Stating the period up front removes it.",
    fix: "State the relevant time period the requests cover, and note any request that reaches outside it.",
  },
  {
    id: "DISC-004",
    ver: "1.1.0",
    name: "Form of production for electronically stored information",
    cite: frcp(
      "34(b)(1)(C)",
      "producing documents — specifying the form for electronically stored information",
    ),
    pat: [
      /(electronically\s+stored\s+information|esi|native|tiff|pdf|load\s+file|metadata)/i,
      // The instruction is written in the imperative as often as the passive:
      // "Produce electronically stored information in single-page TIFF images
      // with a document-level load file" specifies the form completely and
      // carried none of these tokens.
      /(form(at)?\s+of\s+production|production\s+format|\bproduc(?:e|ed|tion)\b[^.;]{0,80}?\bin\b|shall\s+be\s+produced\s+as)/i,
    ],
    all: true,
    why: "Rule 34(b)(1)(C) lets the requesting party specify the form. A party that does not specify takes whatever form the producing party chooses, which is routinely a form that strips the metadata the case needs.",
    fix: "Specify the production form — native with metadata, or TIFF with load files and named metadata fields — and address de-duplication and family relationships.",
    sev: "critical",
  },
  {
    id: "DISC-005",
    // 1.0.1 — the `m` flag on the numbered-paragraph recognizer used to be
    // dropped when the pillars were conjoined, so this column read only the
    // very start of the document (`v5/_pack.ts`).
    ver: "1.0.1",
    name: "Numbered requests",
    cite: frcp("34(b)(1)(A)", "producing documents — each item or category must be described"),
    pat: [
      /(request\s+(for\s+production\s+)?no\.?\s*\d|^\s*\d+\.\s)/im,
      /(all\s+documents|produce|documents\s+(concerning|relating|referring))/i,
    ],
    all: true,
    why: "Responses are keyed to request numbers; an unnumbered narrative cannot be answered request by request or ruled on request by request.",
    fix: "Number each request sequentially and describe one category per request.",
  },
  {
    id: "DISC-006",
    ver: "1.1.0",
    name: "Certificate of service",
    cite: frcp(
      "5(d)(1)(B)",
      "serving and filing pleadings and other papers — certificate of service",
    ),
    pat: [
      // The federal name for it. State practice says "Proof of Service"
      // (California, New York), "Declaration of Service", or "Affidavit of
      // Service" — the same document under the name its own rules give it,
      // and a served California set of requests was told at `critical` that
      // it had none.
      /(?:certificate|proof|declaration|affidavit)\s+of\s+service/i,
      /(served|serve[d]?\s+(a\s+)?(copy|true\s+copy)|e-?mail|electronic\s+service)/i,
    ],
    all: true,
    why: "Discovery requests are served, not filed, so the certificate of service is the only record of the date the response clock started.",
    fix: "Add a certificate of service stating the date, the method, and every party served.",
    sev: "critical",
  },
]);

const ROGS = pack("interrogatories", C, [
  {
    id: "DISC-007",
    name: "Numerical limit respected or leave obtained",
    cite: frcp("33(a)(1)", "interrogatories — number"),
    pat: [
      /(25|twenty-?five|rule\s+33)/i,
      /(discrete\s+subparts|limit|leave\s+of\s+court|stipulat|exceed)/i,
    ],
    all: true,
    why: "Rule 33(a)(1) caps interrogatories at 25 including all discrete subparts, absent stipulation or leave. Serving over the limit invites a blanket objection that costs a motion to resolve.",
    fix: "Confirm the count including discrete subparts, and recite any stipulation or order permitting more.",
    sev: "critical",
  },
  {
    id: "DISC-008",
    name: "Response deadline stated",
    cite: frcp("33(b)(2)", "interrogatories — time to respond"),
    pat: [/(respond|answer)/i, /(30\s+days|thirty\s+\(?30\)?\s+days|within\s+\d+\s+days)/i],
    all: true,
    why: "Rule 33(b)(2) gives 30 days after service. Stating it on the face of the interrogatories fixes the date both sides calendar.",
    fix: "State the response deadline and the rule it runs from.",
  },
  {
    id: "DISC-009",
    name: "Answers under oath required",
    cite: frcp("33(b)(3)", "interrogatories — answering party must answer under oath"),
    pat: [
      /(under\s+oath|verif|sworn)/i,
      /(answer|respond|signed\s+by\s+the\s+(party|person\s+(making|answering)))/i,
    ],
    all: true,
    why: "Rule 33(b)(3) and (b)(5) require answers under oath signed by the person answering, with objections signed by counsel. Unsworn interrogatory answers are not evidence and cannot support summary judgment.",
    fix: "Instruct that answers be made under oath and signed by the answering party, with objections signed by counsel.",
    sev: "critical",
  },
  {
    id: "DISC-010",
    name: "Definitions and relevant time period",
    cite: frcp("26(b)(1)", "scope of discovery — proportionality"),
    pat: [
      /(definitions?|as\s+used\s+herein)/i,
      /(time\s+period|relevant\s+period|from\s+\w+\s+\d{4})/i,
    ],
    all: true,
    why: "The same proportionality objection that meets an unbounded document request meets an unbounded interrogatory, and definitions carry more weight here because each interrogatory is scarce.",
    fix: "Include definitions and state the relevant time period the interrogatories cover.",
  },
  {
    id: "DISC-011",
    ver: "1.1.0",
    name: "Certificate of service",
    cite: frcp("5(d)(1)(B)", "certificate of service"),
    pat: [
      // The federal name for it. State practice says "Proof of Service"
      // (California, New York), "Declaration of Service", or "Affidavit of
      // Service" — the same document under the name its own rules give it,
      // and a served California set of requests was told at `critical` that
      // it had none.
      /(?:certificate|proof|declaration|affidavit)\s+of\s+service/i,
      /(served|e-?mail|electronic\s+service|method\s+of\s+service)/i,
    ],
    all: true,
    why: "Interrogatories are served rather than filed; the certificate is the only record of the service date.",
    fix: "Add a certificate of service stating the date, method, and parties served.",
  },
]);

const RFA = pack("requests-for-admission", C, [
  {
    id: "DISC-012",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Response deadline and the deemed-admitted consequence",
    cite: frcp("36(a)(3)", "requests for admission — time to respond and the effect of failing to"),
    pat: [
      /(30\s+days|thirty\s+\(?30\)?\s+days|within\s+\d+\s+days)/i,
      /(deemed[-\s]+admitted|admitted\s+if\s+(you\s+)?(fail|do\s+not)|automatically\s+admitted)/i,
    ],
    all: true,
    why: "Rule 36(a)(3) deems a matter admitted if no timely written answer or objection is served — the only discovery device with an automatic, case-dispositive default. Stating it removes any argument that the responding party did not understand the stakes.",
    fix: "State the 30-day deadline and that unanswered requests are deemed admitted under Rule 36(a)(3).",
    sev: "critical",
  },
  {
    id: "DISC-013",
    // 1.0.1 — the `m` flag on the numbered-paragraph recognizer used to be
    // dropped when the pillars were conjoined, so this column read only the
    // very start of the document (`v5/_pack.ts`).
    ver: "1.0.1",
    name: "One fact per request",
    cite: frcp("36(a)(2)", "requests for admission — each matter must be separately stated"),
    pat: [
      /(request\s+(for\s+admission\s+)?no\.?\s*\d|^\s*\d+\.\s)/im,
      /(admit\s+that|admit\s+or\s+deny)/i,
    ],
    all: true,
    why: "Rule 36(a)(2) requires each matter to be separately stated. Compound requests draw an objection that the request cannot be admitted or denied as phrased, and the objection is usually sustained.",
    fix: "Number each request and state exactly one fact, opinion, or document authentication in each.",
  },
  {
    id: "DISC-014",
    name: "Answer, denial, or explained inability",
    cite: frcp("36(a)(4)", "requests for admission — the answer"),
    pat: [
      /(admit|deny|denial)/i,
      /(reasonable\s+inquiry|information\s+.{0,30}known\s+or\s+readily\s+obtainable|lack\s+of\s+(knowledge|information))/i,
    ],
    all: true,
    why: "Rule 36(a)(4) permits a lack-of-knowledge response only after stating that reasonable inquiry was made and the information known or readily obtainable is insufficient. Bare 'unable to admit or deny' is not a compliant answer.",
    fix: "Instruct that each request be admitted, denied, or answered with the Rule 36(a)(4) reasonable-inquiry statement.",
    sev: "critical",
  },
  {
    id: "DISC-015",
    name: "Document authentication requests identified",
    cite: fre("901", "authenticating or identifying evidence"),
    pat: [/(genuine|authentic)/i, /(document|exhibit|attached\s+as|bates|produced\s+at)/i],
    all: true,
    why: "Rule 36(a)(1)(B) reaches the genuineness of described documents, which is the cheapest route to authentication under FRE 901. Requests that describe the document only loosely produce admissions that authenticate nothing.",
    fix: "Attach or Bates-identify each document whose genuineness is requested, and describe it precisely in the request.",
    when: [/(genuine|authentic|document|exhibit|bates)/i],
  },
  {
    id: "DISC-016",
    ver: "1.1.0",
    name: "Certificate of service",
    cite: frcp("5(d)(1)(B)", "certificate of service"),
    pat: [
      // The federal name for it. State practice says "Proof of Service"
      // (California, New York), "Declaration of Service", or "Affidavit of
      // Service" — the same document under the name its own rules give it,
      // and a served California set of requests was told at `critical` that
      // it had none.
      /(?:certificate|proof|declaration|affidavit)\s+of\s+service/i,
      /(served|e-?mail|electronic\s+service|method\s+of\s+service)/i,
    ],
    all: true,
    why: "The deemed-admitted consequence runs from service, so the service record is doing more work here than anywhere else in discovery.",
    fix: "Add a certificate of service stating the date, method, and parties served.",
    sev: "critical",
  },
]);

const RESPONSES = pack("discovery-responses", C, [
  {
    id: "DISC-017",
    ver: "1.1.0",
    name: "Objections stated with specificity",
    cite: frcp(
      "34(b)(2)(B)",
      "responding to document requests — stating objections with specificity",
    ),
    pat: [
      /object/i,
      // A specific objection is written "objects to this request as overbroad
      // BECAUSE it seeks documents from 2011, six years before the parties
      // first did business" — the specificity Rule 34(b)(2)(B) asks for, in
      // the form practitioners write it.
      /(on\s+the\s+grounds?\s+that|specifically\s+because|to\s+the\s+extent\s+(that\s+)?it\s+(seeks|requires|calls)|because\s+it\s+(seeks|requires|would|calls)|\bas\s+[a-z]+(?:\s+[a-z]+){0,3}\s+because\b)/i,
    ],
    all: true,
    why: "The 2015 amendments require objections to be stated with specificity. Boilerplate lists — overbroad, unduly burdensome, not reasonably calculated — are treated as waived by a growing number of courts.",
    fix: "State each objection with the specific ground and, where burden is asserted, the facts that make it burdensome.",
    sev: "critical",
  },
  {
    id: "DISC-018",
    ver: "1.2.0",
    name: "Whether responsive material is being withheld",
    cite: frcp(
      "34(b)(2)(C)",
      "responding to document requests — an objection must state whether any responsive materials are being withheld",
    ),
    pat: [
      /(withh(e|o)ld|privilege\s+log)/i,
      // The statement is as often ACTIVE as passive: "Defendant is withholding
      // documents responsive to this request on the basis of the
      // attorney-client privilege" is the plainest compliant drafting.
      // Undertaking to serve a PRIVILEGE LOG is the Rule 26(b)(5)(A)
      // withholding statement: it says responsive material is being held
      // back and on what basis, in the form the rule prescribes for it.
      /(no\s+(responsive\s+)?(documents?|materials?)\s+(?:are|is|were)\s+(?:being\s+)?withheld|withh(?:eld|olding)\b[^.;]{0,80}?\bon\s+the\s+basis\s+of)|(?:produce|serve|provide|prepare)[^.;]{0,50}?\bprivilege\s+log|will\s+log\s+(?:privileged|withheld)/i,
    ],
    all: true,
    why: "Rule 34(b)(2)(C) requires the response to state whether any responsive materials are being withheld on the basis of the objection. This is the single most-missed requirement in modern discovery practice, and its absence is what makes an objection unreviewable.",
    fix: "For each objection, state expressly whether responsive material is being withheld on its basis.",
    sev: "critical",
  },
  {
    id: "DISC-019",
    ver: "1.2.0",
    name: "No 'subject to and without waiving' boilerplate",
    cite: practice(
      "subject-to-objections",
      "the 'subject to and without waiving objections' formulation after the 2015 amendments",
    ),
    pat: [
      /(subject\s+to\s+(and\s+without\s+waiving|the\s+foregoing)|without\s+waiving\s+(the\s+foregoing|any)\s+objections?)/i,
      // The Rule 34(b)(2)(C) statement is written "is withholding documents
      // on the basis of the attorney-client privilege" or "no responsive
      // documents are being withheld" — the plainest compliant drafting, and
      // the column could see neither.
      /(nevertheless|notwithstanding|the\s+withholding\s+statement\s+(above|below)|withh(?:old|olding|eld)[^.;]{0,90}?(?:on\s+the\s+basis|pursuant\s+to|because)|no\s+(?:responsive\s+)?documents?\s+(?:are|is|were)\s+(?:being\s+)?withheld)|(?:produce|serve|provide|prepare)[^.;]{0,50}?\bprivilege\s+log|will\s+log\s+(?:privileged|withheld)/i,
    ],
    all: true,
    why: "Answering 'subject to and without waiving' objections leaves the requesting party unable to tell what was produced and what was held back — which is exactly what Rule 34(b)(2)(C) was amended to stop. Courts increasingly treat the formulation as a waiver of the objections it purports to preserve.",
    fix: "Drop the formulation, or pair it with an explicit statement of what is being withheld under each objection.",
    when: [/(subject\s+to\s+(and\s+without\s+waiving|the\s+foregoing)|without\s+waiving)/i],
    sev: "critical",
  },
  {
    id: "DISC-020",
    // 1.0.1 — the date pillar read only "by <Month> <D>, <YYYY>", and the
    // formulation a discovery response actually uses is "on or before" (or
    // "no later than"). "Defendant will complete its production of responsive
    // documents on or before December 15, 2026" is the Rule 34(b)(2)(B) date
    // stated exactly as the rule asks, and the check reported it missing at
    // `critical`. A bare "before" is deliberately NOT admitted: "documents
    // created before January 1, 2026" is a relevant-period bound, not a
    // production date, and the first pillar is satisfied by every discovery
    // response ever written.
    ver: "1.0.1",
    name: "Production completion date",
    cite: frcp("34(b)(2)(B)", "responding to document requests — time for production"),
    pat: [
      /(produc(e|tion))/i,
      /((?:by|on\s+or\s+before|no[t]?\s+later\s+than)\s+\w+\s+\d{1,2},?\s+\d{4}|on\s+a\s+rolling\s+basis|complete[d]?\s+by|within\s+\d+\s+days\s+of)/i,
    ],
    all: true,
    why: "Rule 34(b)(2)(B) permits production by a stated later date but requires that date to be stated. 'Will produce responsive documents' with no date is not a compliant response and gives the requesting party nothing to enforce.",
    fix: "State the date production will be complete, or the rolling schedule and its completion date.",
    sev: "critical",
  },
  {
    id: "DISC-021",
    name: "Signature of counsel",
    cite: frcp("26(g)(1)", "signing disclosures and discovery requests, responses, and objections"),
    pat: [/(signature|\/s\/|respectfully\s+submitted)/i, /(attorney|counsel\s+for|bar\s+no|esq)/i],
    all: true,
    why: "Rule 26(g) requires every response and objection to be signed by at least one attorney of record, and the signature certifies that the response is complete and correct and not interposed for an improper purpose. An unsigned response is subject to being struck.",
    fix: "Add the signing attorney's signature block with the certification Rule 26(g) attaches to it.",
    sev: "critical",
  },
  {
    id: "DISC-022",
    name: "Verification for interrogatory answers",
    cite: frcp("33(b)(5)", "interrogatories — signature of the answering party"),
    pat: [
      /(verif|under\s+oath|sworn|penalty\s+of\s+perjury)/i,
      /(the\s+(answers|foregoing)\s+(are|is)|signed\s+by\s+the\s+(party|answering))/i,
    ],
    all: true,
    why: "Interrogatory answers require the answering party's signature under oath; only objections are signed by counsel alone. An unverified set of answers is not usable evidence.",
    fix: "Attach a verification signed by the answering party under penalty of perjury.",
    when: [/interrogator/i],
    sev: "critical",
  },
  {
    id: "DISC-023",
    ver: "1.1.0",
    name: "Certificate of service",
    cite: frcp("5(d)(1)(B)", "certificate of service"),
    pat: [
      // The federal name for it. State practice says "Proof of Service"
      // (California, New York), "Declaration of Service", or "Affidavit of
      // Service" — the same document under the name its own rules give it,
      // and a served California set of requests was told at `critical` that
      // it had none.
      /(?:certificate|proof|declaration|affidavit)\s+of\s+service/i,
      /(served|e-?mail|electronic\s+service|method\s+of\s+service)/i,
    ],
    all: true,
    why: "The service date fixes the meet-and-confer and motion-to-compel clock.",
    fix: "Add a certificate of service stating the date, method, and parties served.",
  },
]);

const PRIV_LOG = pack("privilege-log", C, [
  {
    id: "DISC-024",
    name: "Express claim of privilege or protection",
    cite: frcp(
      "26(b)(5)(A)(i)",
      "claiming privilege or protecting trial-preparation materials — expressly making the claim",
    ),
    pat: [
      /(privileg|work[-\s]+product|attorney-?client|common\s+interest)/i,
      /(claim|assert|withheld\s+(on\s+the\s+basis|pursuant)|basis\s+for\s+(the\s+)?withholding)/i,
    ],
    all: true,
    why: "Rule 26(b)(5)(A)(i) requires the claim to be made expressly. A log that lists documents without naming the protection asserted for each cannot be assessed and is routinely ordered redone.",
    fix: "State the specific privilege or protection claimed for each entry.",
    sev: "critical",
  },
  {
    id: "DISC-025",
    name: "Description sufficient to assess the claim",
    cite: frcp(
      "26(b)(5)(A)(ii)",
      "describing the nature of the documents without revealing privileged information",
    ),
    pat: [
      /(description|subject\s+matter|nature\s+of\s+the\s+document)/i,
      /(without\s+revealing|sufficient\s+to\s+(enable|assess)|general\s+(nature|subject))/i,
    ],
    all: true,
    why: "The rule requires a description that enables other parties to assess the claim without revealing the protected information itself. 'Email re: legal advice' does neither job.",
    fix: "Describe each document's nature and general subject matter specifically enough that the claim can be evaluated on its face.",
    sev: "critical",
  },
  {
    id: "DISC-026",
    // 1.0.1 — both pillars were satisfied by ordinary execution boilerplate,
    // so the check could not fire on a real log: `author` matches inside
    // "authorized representatives", and `to\b` matches the word "to". Each
    // alternative now has to look like a log FIELD rather than a word that
    // happens to appear.
    ver: "1.0.1",
    name: "Author, recipients, and copyees",
    cite: frcp("26(b)(5)(A)(ii)", "describing the documents"),
    pat: [
      /(\bauthor(?:s|ed\s+by)?\b|\bfrom\s*:|\bsender\b)/i,
      /(\brecipients?\b|\bto\s*:|\bcc\s*:|\bbcc\s*:|copie[ds]\s+to|\bcopyees?\b)/i,
    ],
    all: true,
    why: "Privilege turns on who was in the communication. A log without full recipient lists cannot show that no third party broke confidentiality, which is the first thing an opposing party tests.",
    fix: "List the author and every recipient and copyee for each entry, and mark which participants are attorneys.",
    sev: "critical",
  },
  {
    id: "DISC-027",
    name: "Date of each document",
    cite: frcp("26(b)(5)(A)(ii)", "describing the documents"),
    pat: [/date/i, /(\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}|document\s+date|created)/i],
    all: true,
    why: "Work-product protection depends on whether the document was prepared in anticipation of litigation, which is a question about when it was made.",
    fix: "Give each entry's date, and where a document is undated, say so and give the best available date evidence.",
  },
  {
    id: "DISC-028",
    name: "Attorneys identified as such",
    cite: practice("privilege-log-attorneys", "identifying attorneys on a privilege log"),
    pat: [/(attorney|counsel|esq|in-?house)/i, /(identified|denoted|marked\s+with|asterisk|\*)/i],
    all: true,
    why: "A reviewing party cannot evaluate an attorney-client claim without knowing which participants are lawyers, and in-house counsel acting in a business role is the most common ground for a successful challenge.",
    fix: "Mark every attorney participant and note where in-house counsel was acting in a legal rather than business capacity.",
  },
  {
    id: "DISC-029",
    name: "Bates or control number for each entry",
    cite: practice("privilege-log-identifiers", "unique identifiers on a privilege log"),
    pat: [
      /(bates|control\s+number|document\s+id|beg\s?bates)/i,
      /(each\s+(entry|document)|log\s+entry|number)/i,
    ],
    all: true,
    why: "Entries need stable identifiers so a challenge, an in camera submission, and a later production of the same document all refer to the same thing.",
    fix: "Assign a unique Bates or control number to each logged document and use it consistently.",
  },
]);

const RULE_26F = pack("rule-26f-report", C, [
  {
    id: "DISC-030",
    ver: "1.1.0",
    name: "Proposed discovery plan with the required subjects",
    cite: frcp("26(f)(3)", "conference of the parties — discovery plan"),
    pat: [
      /(discovery\s+plan|rule\s+26\(f\))/i,
      // A Rule 26(f) report states its plan as DEADLINES — "fact discovery
      // closing December 18, 2026" — not as the rule's own vocabulary.
      /(subjects?\s+on\s+which\s+discovery|completion\s+date|phases?|limits?\s+on\s+discovery|discovery\s+(?:closes|closing|cutoff|cut-off|deadline)|\bdeadlines?\b)/i,
    ],
    all: true,
    why: "Rule 26(f)(3) enumerates six subjects the plan must state. A report that omits them leaves the scheduling order to be written by the court without the parties' input.",
    fix: "Address each Rule 26(f)(3) subject: initial disclosures, subjects and timing of discovery, ESI, privilege issues, changes to the limits, and other orders.",
    sev: "critical",
  },
  {
    id: "DISC-031",
    name: "ESI preservation and production form",
    cite: frcp(
      "26(f)(3)(C)",
      "discovery plan — issues about disclosure or discovery of electronically stored information",
    ),
    pat: [
      /(electronically\s+stored\s+information|esi)/i,
      /(preserv|form\s+of\s+production|native|tiff|metadata|search\s+terms|custodian)/i,
    ],
    all: true,
    why: "ESI disputes are cheapest to resolve before collection. Rule 26(f)(3)(C) makes the parties address form of production and preservation at the outset for exactly that reason.",
    fix: "State the preservation steps taken, the custodians and sources in scope, the search methodology, and the agreed production form.",
    sev: "critical",
  },
  {
    id: "DISC-032",
    name: "FRE 502(d) order requested",
    cite: fre("502(d)", "controlling effect of a court order on privilege waiver"),
    pat: [
      /(502\(d\)|rule\s+502)/i,
      /(order|clawback|non-?waiver|inadvertent\s+(production|disclosure))/i,
    ],
    all: true,
    why: "A Rule 502(d) order is the only mechanism that protects against waiver in other federal and state proceedings, and it costs nothing to request at the 26(f) stage. Relying on 502(b) instead leaves waiver to a reasonableness fight after the fact.",
    fix: "Request a Rule 502(d) order and attach the proposed form, with the clawback and sequestration procedure.",
    sev: "critical",
  },
  {
    id: "DISC-033",
    name: "Initial disclosure timing",
    cite: frcp("26(a)(1)(C)", "required disclosures — time for initial disclosures"),
    pat: [
      /(initial\s+disclosures?|rule\s+26\(a\)\(1\))/i,
      /(within\s+14\s+days|by\s+\w+\s+\d{1,2},?\s+\d{4}|have\s+been\s+(made|exchanged)|will\s+be\s+(made|served))/i,
    ],
    all: true,
    why: "Initial disclosures are due within 14 days after the Rule 26(f) conference unless the parties or the court set another time. The report is where that other time gets set.",
    fix: "State when initial disclosures have been or will be made, and any agreed variation from the 14-day default.",
  },
  {
    id: "DISC-034",
    ver: "1.1.0",
    name: "Proposed limits and case-management deadlines",
    cite: frcp("16(b)(3)", "scheduling — required contents of the order"),
    pat: [
      // A report states its schedule by the events themselves — "fact
      // discovery closing December 18, 2026; dispositive motions due
      // February 12, 2027; trial-ready June 7, 2027" — without ever using
      // the word "deadline".
      /(deadline|cut-?off|schedul|discovery\s+clos\w+|\bdue\s+[A-Z][a-z]+\s+\d|trial-?ready)/,
      /(amend\s+the\s+pleadings|join\s+(additional\s+)?parties|expert\s+(disclosure|report)|dispositive\s+motion|fact\s+discovery)/i,
    ],
    all: true,
    why: "Rule 16(b)(3) requires the scheduling order to set deadlines for joinder, amendment, discovery, and motions. The parties' proposals are what the court usually adopts.",
    fix: "Propose dates for amendment and joinder, fact discovery, expert disclosures and rebuttal, and dispositive motions.",
  },
  {
    id: "DISC-035",
    ver: "1.1.0",
    name: "Settlement and ADR posture",
    cite: frcp("26(f)(2)", "conference of the parties — discussing settlement"),
    pat: [
      /(settle|settlement|mediat|adr|alternative\s+dispute)/i,
      // A report states its posture by what the parties DID and what they ask
      // the court for: "the parties exchanged settlement positions on April 28
      // and did not resolve the case … they request a settlement conference
      // before the assigned magistrate judge". None of the words below appears
      // in that, and the section is headed "SETTLEMENT AND ALTERNATIVE DISPUTE
      // RESOLUTION".
      /(discussed|discussions?|prospects?|referral|refer(?:red)?\s+to|willing|premature|exchanged|conferred|request(?:s|ed)?\s+a[^.;]{0,40}?(?:conference|mediation)|(?:did\s+not|have\s+not)\s+(?:resolve|settle))/i,
    ],
    all: true,
    why: "Rule 26(f)(2) requires the parties to discuss settlement prospects, and most districts require the report to state the ADR posture.",
    fix: "State whether settlement was discussed, the parties' ADR position, and any proposed referral and timing.",
  },
]);

const DEPO = pack("deposition-notice", C, [
  {
    id: "DISC-036",
    name: "Reasonable written notice with time and place",
    cite: frcp("30(b)(1)", "depositions by oral examination — notice of the deposition"),
    pat: [
      /(notice\s+of\s+(the\s+)?(taking\s+of\s+)?deposition|please\s+take\s+notice)/i,
      /(on\s+\w+\s+\d{1,2},?\s+\d{4}|at\s+\d{1,2}:\d{2}|commencing\s+at|located\s+at)/i,
    ],
    all: true,
    why: "Rule 30(b)(1) requires reasonable written notice stating the time and place. Notice that omits either is a ground to quash and a wasted reporter fee.",
    fix: "State the date, start time, and physical or remote location, and confirm the notice period is reasonable under local practice.",
    sev: "critical",
  },
  {
    id: "DISC-037",
    name: "Deponent identified",
    cite: frcp("30(b)(1)", "depositions — naming the deponent"),
    // 1.0.1 — both pillars were satisfied by ordinary execution boilerplate:
    // `witness` matches inside "IN WITNESS WHEREOF", which opens the
    // execution clause of nearly every document, and `name` matches the
    // "Name: ____" line of every signature block. The deponent pillar now
    // requires a word that names the person to be deposed.
    ver: "1.0.1",
    pat: [
      /(deponent|the\s+deposition\s+of|person\s+to\s+be\s+(deposed|examined)|witness\s+to\s+be\s+(deposed|examined))/i,
      /(name\s+of\s+the\s+(deponent|witness)|if\s+the\s+name\s+is\s+not\s+known|general\s+description\s+sufficient\s+to\s+identify|\bname\s*:)/i,
    ],
    all: true,
    why: "The rule requires naming the deponent or, if the name is unknown, a description sufficient to identify the person or the class or group to which the person belongs.",
    fix: "Name the deponent, or give the Rule 30(b)(1) description sufficient to identify them.",
  },
  {
    id: "DISC-038",
    name: "Rule 30(b)(6) topics described with reasonable particularity",
    cite: frcp("30(b)(6)", "notice or subpoena directed to an organization"),
    pat: [
      /30\(b\)\(6\)/i,
      /(matters?\s+for\s+examination|topics?|described\s+with\s+reasonable\s+particularity|confer\s+in\s+good\s+faith)/i,
    ],
    all: true,
    why: "Rule 30(b)(6) requires topics described with reasonable particularity and, since 2020, a good-faith conferral about them. Overbroad topics are the leading cause of 30(b)(6) motion practice.",
    fix: "List the matters for examination with reasonable particularity, and recite the conferral the 2020 amendment requires.",
    when: [/30\(b\)\(6\)|organization|corporate\s+representative|designate\s+one\s+or\s+more/i],
    sev: "critical",
  },
  {
    id: "DISC-039",
    name: "Method of recording",
    cite: frcp("30(b)(3)(A)", "depositions — method of recording"),
    pat: [/(record(ed|ing)?|transcri)/i, /(stenograph|audio|video|audiovisual|by\s+means\s+of)/i],
    all: true,
    why: "Rule 30(b)(3)(A) requires the notice to state the method of recording. A party that wants video and did not notice it cannot use video at trial.",
    fix: "State the method or methods of recording, including video where it may be used at trial.",
  },
  {
    id: "DISC-040",
    name: "Documents requested with the deposition",
    cite: frcp("30(b)(2)", "depositions — producing documents"),
    pat: [
      /(document|material|produce)/i,
      /(rule\s+34|attached|schedule\s+[a-z]|request(ed)?\s+(to\s+be\s+)?produced|subpoena\s+duces\s+tecum)/i,
    ],
    all: true,
    why: "Rule 30(b)(2) allows a document request with the notice, but it must comply with Rule 34 — which means the deponent gets the full Rule 34 response period, not until the deposition date.",
    fix: "Attach the Rule 34 request as a schedule and set the production date accounting for the full response period.",
    when: [/(document|produce|duces\s+tecum|bring\s+with\s+you)/i],
  },
]);

export const DISCOVERY_RULES: readonly Rule[] = [
  ...RFP,
  ...ROGS,
  ...RFA,
  ...RESPONSES,
  ...PRIV_LOG,
  ...RULE_26F,
  ...DEPO,
];

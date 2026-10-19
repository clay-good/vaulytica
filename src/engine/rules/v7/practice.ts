/**
 * v7 — families with no controlling authority (spec-v49.md §3).
 *
 * A service level agreement, a pilot agreement and a roommate agreement are
 * three of the documents people bring that the catalog had no name for. No
 * statute or rule lists what any of them must say, so every column here is
 * cited as customary drafting practice and reports at `warning` or below: a
 * missing column is a term the document's own purpose calls for, never a
 * legal defect.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice } from "../v5/_helpers.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";
import { DATE_SHAPE } from "../../../extract/dates.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

/** A sum of money, in digits or in words. */
const SUM = String.raw`(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`;

// ── Service level agreement ─────────────────────────────────────────
const SERVICE_LEVEL = pack("service-level-agreement", "commercial", [
  {
    id: "SLA-001",
    // 1.1.0 — reads "per cent", the UK and Commonwealth spelling, as well as "percent".
    ver: "1.1.0",
    name: "Uptime commitment and measurement window",
    cite: practice("sla-uptime", "an availability percentage and the period it is measured over"),
    all: true,
    pat: [
      /(\b(availab\w+|up-?time)\b[\s\S]{0,200}?\d{2,3}(\.\d+)?\s?(%|per\s?cent)|\d{2,3}(\.\d+)?\s?(%|per\s?cent)[\s\S]{0,200}?\b(availab\w+|up-?time)\b)/i,
      /\b(calendar\s+(month|quarter|year)|(each|per|every|any|a\s+given)\s+(month|quarter|year)|monthly|quarterly|measurement\s+period|billing\s+(period|cycle|month))\b/i,
    ],
    why: "An availability figure means nothing without the period it is measured over: 99.9% of a month allows about 43 minutes of downtime, and 99.9% of a year allows almost nine hours in one outage. A commitment with no number, or a number with no window, cannot be measured or missed.",
    fix: "State the availability commitment as a percentage and name the measurement window — for example, 99.9% availability in each calendar month.",
  },
  {
    id: "SLA-002",
    name: "Exclusions from the commitment",
    cite: practice("sla-exclusions", "what does not count as downtime"),
    pat: [
      /\b(exclud\w+|exclusions?|does\s+not\s+include|(?:shall|will|must)\s+not\s+include|not\s+count(ed)?\s+(as|toward|against))\b[\s\S]{0,240}?\b(maintenance|force\s+majeure|third[- ]party|customer(?:['’]s)?\s+(acts?|equipment|network|systems?|breach)|reasonable\s+control|emergency|suspension)\b/i,
    ],
    why: "What is left out of the availability calculation decides what the commitment is worth. Scheduled maintenance, emergency maintenance and events outside the provider's control are commonly excluded; when the document does not say, both sides will read the percentage their own way after the first outage.",
    fix: "List what is excluded from the availability calculation — scheduled maintenance and its notice period, force majeure, and failures caused by the customer or its third parties.",
  },
  {
    id: "SLA-003",
    // 1.1.0 — reads "per cent", the UK and Commonwealth spelling, as well as "percent".
    ver: "1.1.0",
    name: "Service credit schedule",
    cite: practice("sla-credits", "the credit owed when the commitment is missed"),
    pat: [
      /\bcredits?\b[\s\S]{0,200}?\d+(\.\d+)?\s?(%|per\s?cent)|(?<!\d)\d+(\.\d+)?\s?(%|per\s?cent)[\s\S]{0,120}?\bcredits?\b/i,
    ],
    why: "A service level with no stated consequence is a target, not a commitment. The credit schedule is the remedy the customer actually receives, and it is the first thing either side looks for when availability falls short.",
    fix: "Add a schedule that ties each band of availability to a credit, stated as a percentage of the fees for the affected period.",
  },
  {
    id: "SLA-004",
    name: "Deadline and process for claiming a credit",
    cite: practice("sla-claim-deadline", "how and by when a credit must be requested"),
    pat: [
      /\b(credits?|claims?)\b[\s\S]{0,240}?\bwithin\s+[\w()\s-]{0,24}?\b(days?|months?)\b|\bwithin\s+[\w()\s-]{0,24}?\b(days?|months?)\b[\s\S]{0,160}?\b(credits?|claims?)\b|\bcredits?\b[\s\S]{0,160}?\b(automatically|without\s+(a\s+)?request)\b/i,
    ],
    why: "Most service level agreements make the credit something the customer must ask for, and forfeit it when the request is late. A reader needs to know whether credits are automatic and, if not, how long there is to claim one.",
    fix: "State whether credits apply automatically or on request, and if on request, the number of days the customer has to claim one and what the claim must include.",
  },
  {
    id: "SLA-005",
    name: "Whether credits are the exclusive remedy",
    cite: practice("sla-sole-remedy", "the relationship between credits and other remedies"),
    pat: [
      /\b(sole|exclusive|only)\s+(and\s+(exclusive|sole)\s+)?remed(y|ies)\b|\b(in\s+addition\s+to|without\s+(limiting|prejudice\s+to))\s+[\w\s'’]{0,40}?\b(rights|remedies)\b/i,
    ],
    why: "Whether a credit is the customer's only remedy for an outage, or sits alongside damages and termination under the main agreement, changes what the commitment is worth by an order of magnitude. A document silent on the point leaves it to the main agreement and to argument.",
    fix: "Say whether service credits are the sole and exclusive remedy for a missed service level, or are in addition to the customer's other rights under the main agreement.",
    sev: "info",
  },
  {
    id: "SLA-006",
    name: "Termination right for repeated failure",
    cite: practice("sla-chronic-failure", "a way out when the commitment is missed repeatedly"),
    pat: [
      /\bterminat\w+\b[\s\S]{0,240}?\b(consecutive|chronic|repeated(ly)?|(two|three|four|2|3|4)\s+(or\s+more\s+)?(calendar\s+)?(months|quarters)|any\s+(twelve|12|six|6)[- ]month)\b|\b(consecutive|chronic|repeated(ly)?)\b[\s\S]{0,240}?\bterminat\w+/i,
    ],
    why: "Credits compensate one bad month. They do nothing for a customer whose service misses its commitment month after month, and a credit-only document with no exit keeps that customer paying for a service that does not work.",
    fix: "Add a right to terminate the affected service, with a refund of prepaid fees, when the commitment is missed in a stated number of months — for example, three consecutive months or any four in twelve.",
  },
]);

// ── Pilot and evaluation agreement ──────────────────────────────────
const PILOT = pack("pilot-evaluation-agreement", "commercial", [
  {
    id: "PILOT-001",
    name: "License limited to evaluation",
    cite: practice("pilot-evaluation-license", "a grant confined to testing the product"),
    pat: [
      /\b(solely|only|exclusively)\s+(for|to)\s+(\w+\s+){0,5}?(evaluat\w+|test\w*|assess\w*)|\b(internal|non-?production)\s+(evaluation|testing|use)\b|\bevaluation\s+purposes\b|\bnot\s+(for|in)\s+(a\s+)?production\b/i,
    ],
    why: "A pilot is a look at the product, not a license to run a business on it. A grant that does not say it is confined to evaluation reads as an ordinary license with no fee.",
    fix: "State that the license is for the customer's internal evaluation only, and not for production use.",
  },
  {
    id: "PILOT-002",
    name: "Length of the pilot",
    cite: practice("pilot-length", "a stated start and end"),
    pat: [
      new RegExp(
        String.raw`\b(pilot|evaluation|trial)\s+(period|term)\b[\s\S]{0,200}?${PERIOD_COUNT}\s+(days?|weeks?|months?)\b`,
        "i",
      ),
      new RegExp(
        String.raw`\bfor\s+(a\s+period\s+of\s+)?${PERIOD_COUNT}\s+(days?|weeks?|months?)\b`,
        "i",
      ),
      new RegExp(
        String.raw`\b(ends?|expires?|terminates?|continues?\s+(until|through))\s+(on\s+)?${DATE_SHAPE}`,
        "i",
      ),
    ],
    why: "A pilot with no end date is an indefinite free license. The length also sets when the as-is terms stop applying and a paid agreement has to take over.",
    fix: "State how long the pilot runs — a number of days from a named start date, or a fixed end date — and whether it can be extended.",
  },
  {
    id: "PILOT-003",
    name: "What happens when the pilot ends",
    cite: practice("pilot-conversion", "conversion to a paid agreement, or none"),
    pat: [
      /\b(convert\w*|conversion|(commercial|definitive|paid|subscription|master)\s+(subscription\s+)?(agreement|contract|licen[sc]e|plan)|order\s+form|no\s+obligation\s+to\s+(purchase|buy|enter|continue|licen[sc]e|subscribe)|not\s+obligated\s+to\s+(purchase|buy|enter|continue|licen[sc]e|subscribe))\b/i,
    ],
    why: "The commonest pilot dispute is about what was owed at the end: whether use continued on paid terms, at what price, and whether either side had committed to buy or sell. A document that stops at the last day of the pilot answers none of it.",
    fix: "Say what happens at the end of the pilot: that access stops unless the parties sign a commercial agreement, that neither party is obligated to enter one, and any pricing already agreed for conversion.",
  },
  {
    id: "PILOT-004",
    name: "Rights in feedback",
    cite: practice("pilot-feedback", "who may use what the customer tells the vendor"),
    pat: [/\bfeedback\b[\s\S]{0,240}?\b(licen[sc]es?|assigns?|own(s|ed|ership)?|use|rights?)\b/i],
    why: "Feedback is most of what a vendor gets from a free pilot. Without a license the vendor cannot safely build on a suggestion, and without a limit the customer may have handed over more than a suggestion.",
    fix: "Add a feedback clause: the customer grants the vendor a license to use feedback about the product, and the feedback does not include the customer's confidential information or data.",
  },
  {
    id: "PILOT-005",
    name: "Return or deletion of data at the end",
    cite: practice("pilot-data-return", "what happens to the customer's data"),
    pat: [
      /\b(return\w*|delet\w+|destroy\w*|eras\w+|purg\w+)\b[\s\S]{0,160}?\b(data|confidential\s+information|content|materials)\b|\b(data|confidential\s+information|content)\b[\s\S]{0,160}?\b(returned|deleted|destroyed|erased|purged)\b/i,
    ],
    why: "A pilot usually ends without a contract to replace it, so nothing else governs the data the customer loaded. The customer needs it back or gone, and the vendor needs a date after which it holds none.",
    fix: "State that at the end of the pilot the vendor will return or delete the customer's data within a stated number of days, and that the customer will stop using and delete the vendor's software and materials.",
  },
  {
    id: "PILOT-006",
    name: "As-is disclaimer",
    cite: practice("pilot-as-is", "a product on trial carries no warranty"),
    pat: [
      /\bas[- ]is\b|\bwithout\s+(any\s+)?warrant(y|ies)\b|\bdisclaims?\s+all\s+warrant(y|ies)\b/i,
    ],
    why: "A product offered free for evaluation is normally offered without warranty. A pilot agreement with no disclaimer leaves the implied warranties in place on a product the customer is not paying for.",
    fix: "State that the product is provided as is for the pilot, without warranty of any kind, and say whether any service level applies.",
    sev: "info",
  },
]);

// ── Roommate agreement ──────────────────────────────────────────────
const ROOMMATE = pack("roommate-agreement", "real-estate", [
  {
    id: "ROOM-001",
    name: "Each person's share of rent and utilities",
    cite: practice("roommate-rent-shares", "who pays how much, and for what"),
    all: true,
    pat: [
      new RegExp(
        String.raw`\brent\b[\s\S]{0,200}?(${SUM}|\b(half|equal(ly)?|percent|share|portion|one-(half|third|quarter))\b|%)`,
        "i",
      ),
      new RegExp(
        String.raw`\butilit(y|ies)\b[\s\S]{0,200}?(${SUM}|\b(split|shared?|equal(ly)?|divid\w+|percent|half|portion|responsible|pays?)\b|%)`,
        "i",
      ),
    ],
    why: "The landlord looks to everyone on the lease for the whole rent. The split among the people living there exists only in this document, and so does the answer to who pays for electricity, gas and internet.",
    fix: "State each person's share of the monthly rent as a dollar amount or a fraction, and how utilities are divided and who pays the provider.",
  },
  {
    id: "ROOM-002",
    name: "Each person's share of the security deposit",
    cite: practice("roommate-deposit", "who paid it, and who gets it back"),
    pat: [
      new RegExp(
        String.raw`\bdeposit\b[\s\S]{0,240}?(${SUM}|\b(each|half|equal(ly)?|share|portion|contribut\w+|paid|return\w*|refund\w*|deduct\w*)\b)`,
        "i",
      ),
    ],
    why: "The landlord returns one deposit, usually to whoever is on the lease when it ends. Who paid what, and who bears a deduction for damage to one person's room, is settled only if it is written down.",
    fix: "Record how much of the security deposit each person paid, how deductions are allocated, and how a departing person's share is returned.",
  },
  {
    id: "ROOM-003",
    name: "Moving out early",
    cite: practice("roommate-move-out", "notice, and rent owed after leaving"),
    pat: [
      /\b(mov\w+\s+out|vacat\w+|leav\w+\s+(the\s+)?(apartment|premises|unit|home|house|residence))\b[\s\S]{0,240}?\b(notice|days|early|remains?\s+(liable|responsible)|continues?\s+to\s+(pay|owe))\b/i,
    ],
    why: "A person who leaves in the middle of the lease usually still owes the landlord rent. Whether that person keeps paying a share, and how much warning the others get, is the question this document is most often opened to answer.",
    fix: "State how much written notice a person must give before moving out, and whether that person keeps paying a share of the rent until the lease ends or a replacement moves in.",
  },
  {
    id: "ROOM-004",
    name: "Finding a replacement",
    cite: practice("roommate-replacement", "who finds one, and who approves"),
    pat: [
      /\b(replacement|substitute|new)\s+(roommate|tenant|occupant|subtenant|housemate)\b|\bsublet\w*|\bsubleas\w+|\bfind\w*\s+(a\s+)?(replacement|someone\s+to\s+take)/i,
    ],
    why: "A replacement has to be acceptable to the people who stay and, under most leases, approved by the landlord. A document that requires a replacement without saying who approves one invites a stranger or a vacancy.",
    fix: "Say who is responsible for finding a replacement, that the remaining people must approve the person, and that the landlord's consent is required where the lease calls for it.",
  },
  {
    id: "ROOM-005",
    name: "Relationship to the lease with the landlord",
    cite: practice("roommate-master-lease", "this agreement does not change the lease"),
    pat: [/\b(master\s+lease|landlord|lessor|property\s+manager|the\s+lease)\b/i],
    why: "An agreement among the people sharing a home does not bind the landlord and does not change the lease. Saying so, and naming the lease, tells every signer that the landlord can still look to any of them for the full rent.",
    fix: "Identify the lease with the landlord, state that each person will comply with it, and state that this agreement is among the roommates only and does not change what any of them owes the landlord.",
  },
]);

export const SERVICE_LEVEL_RULES: readonly Rule[] = SERVICE_LEVEL;
export const PILOT_RULES: readonly Rule[] = PILOT;
export const ROOMMATE_RULES: readonly Rule[] = ROOMMATE;

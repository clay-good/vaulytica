/**
 * v7 — the residential solar lease or power purchase agreement
 * (spec-v49.md §3).
 *
 * The FTC's Cooling-Off Rule, 16 C.F.R. Part 429, applies to a door-to-door
 * sale: one solicited in person and agreed to away from the seller's place of
 * business (§ 429.0(a)). Most home solar contracts are signed that way, but
 * nothing in the contract says where it was signed, so the two checks that
 * read for the rule's cancellation terms report at `info` and name the
 * condition (spec-v49 §6). Read at ecfr.gov on 2026-10-10. The rest is
 * practice.
 */

import type { Rule } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { pack } from "../v5/_pack.js";
import { languageRule, practice, v4Cite } from "../v5/_helpers.js";
import { COGNOVIT_DISCLAIMED, COGNOVIT_PATTERNS } from "../v4/banking/rules.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";

const PLAYBOOK = "residential-solar-agreement";
const C = "commercial";

function coolingOff(paragraph: string, label: string): SourceCitation {
  return v4Cite({
    id: `cfr-16-429-1-${paragraph}`,
    source: `16 C.F.R. § 429.1(${paragraph}) — ${label} (applies to a door-to-door sale as defined in § 429.0(a))`,
    source_url: "https://www.ecfr.gov/current/title-16/part-429",
    retrieved_at: "2026-10-10T00:00:00Z",
  });
}

const IF_HOME_SOLICITATION =
  "This applies where the contract was a door-to-door sale: solicited in person and signed somewhere other than the seller's place of business, such as the home. The document does not say where it was signed, so check that before relying on this note.";

const CANCEL_WAIVER = languageRule({
  id: "SOL-003",
  name: "Confession of judgment, or waiver of the right to cancel",
  category: C,
  description:
    "A confession of judgment, or a waiver of the buyer's right to cancel, in a contract with a homeowner.",
  citation: practice(
    "solar-confession-or-cancel-waiver",
    "no confession of judgment or cancellation waiver in a homeowner's contract (16 C.F.R. § 429.1(d) forbids both in a door-to-door sale)",
  ),
  playbooks: [PLAYBOOK],
  bad_patterns: [
    ...COGNOVIT_PATTERNS,
    /\bwaiv\w+\b[^.]{0,120}?\bright\s+to\s+cancel\b/i,
    /\bright\s+to\s+cancel\b[^.]{0,80}?\b(is|are)\s+(hereby\s+)?waived\b/i,
  ],
  exclude_if: [
    ...COGNOVIT_DISCLAIMED,
    /\b(?:not|no|never|cannot|may\s+not)\b[^.]{0,60}?\bwaiv\w+\b[^.]{0,120}?\bright\s+to\s+cancel\b/i,
  ],
  bad_title: "Confession of judgment or cancellation waiver present",
  bad_description:
    "The agreement has the homeowner confess judgment in advance, or give up the right to cancel.",
  explanation:
    "A confession of judgment lets the provider obtain a judgment against the homeowner without notice or a hearing, and a waiver of the right to cancel removes the three business days a homeowner has to back out of a contract signed at home. In a door-to-door sale the Cooling-Off Rule makes it an unfair practice to put either in the contract.",
  recommendation:
    "Remove the confession of judgment and any waiver of the homeowner's right to cancel.",
  default_severity: "warning",
});

const COLUMNS = pack(PLAYBOOK, C, [
  {
    id: "SOL-001",
    name: "Statement of the right to cancel within three business days",
    cite: coolingOff("a", "the buyer's right to cancel, stated near the signature"),
    pat: [
      /\bcancel\w*\b[^.]{0,240}?\b(third|three|3)\b[^.]{0,24}?\bbusiness\s+days?\b/i,
      /\b(third|three|3)\b[^.]{0,24}?\bbusiness\s+days?\b[^.]{0,240}?\bcancel\w*\b/i,
    ],
    why: `In a door-to-door sale the seller must state, near the buyer's signature, that the buyer may cancel at any time before midnight of the third business day after the transaction. ${IF_HOME_SOLICITATION}`,
    fix: "Add the cancellation statement next to the homeowner's signature: that the homeowner may cancel the transaction at any time prior to midnight of the third business day after the date of the transaction, and where the cancellation form is.",
    sev: "info",
  },
  {
    id: "SOL-002",
    name: "Notice of Cancellation form",
    cite: coolingOff("b", "a completed form captioned Notice of Cancellation, in duplicate"),
    pat: [/\bnotice\s+of\s+(cancellation|right\s+to\s+cancel)\b/i],
    why: `In a door-to-door sale the seller must give the buyer, at signing, a completed form in duplicate captioned "Notice of Cancellation" or "Notice of Right to Cancel", with the seller's name and address, the date of the transaction and the last day to cancel. ${IF_HOME_SOLICITATION}`,
    fix: 'Attach the completed "Notice of Cancellation" form in duplicate and refer to it in the cancellation statement.',
    sev: "info",
  },
  {
    id: "SOL-004",
    // 1.1.0 — reads "per cent", the UK and Commonwealth spelling, as well as "percent".
    ver: "1.1.0",
    name: "Whether the price rises, and by how much each year",
    cite: practice("solar-escalator", "the annual escalator, or a statement that there is none"),
    pat: [
      /\bescalat\w+/i,
      /\bincreas\w+\s+by\s+\d+(\.\d+)?\s?(%|per\s?cent)/i,
      /\b(will|shall|must|does)\s+not\s+increase\b|\bfixed\s+(price|rate|payment)\b|\bno\s+(annual\s+)?(increase|escalat\w+)\b/i,
    ],
    why: "Over a term of twenty years or more, a small annual increase compounds: at 2.9% a year the price in year 25 is nearly double the price in year one. The homeowner needs the rate, or a statement that the price is fixed, to compare the contract with the utility bill it replaces.",
    fix: "State the annual increase in the price or payment as a percentage, or state that the price is fixed for the term.",
  },
  {
    id: "SOL-005",
    name: "Length of the term",
    cite: practice("solar-term", "how many years the homeowner is bound"),
    pat: [
      new RegExp(
        String.raw`\b(term|period)\b[^.]{0,120}?${PERIOD_COUNT}\s+(years?|months?)\b`,
        "i",
      ),
      new RegExp(String.raw`${PERIOD_COUNT}[-\s]+(year|month)\s+(term|period)\b`, "i"),
    ],
    why: "A solar lease or power purchase agreement usually binds the homeowner for 20 to 25 years — longer than most people own a home. The term, and when it starts, is the first thing a homeowner or a later buyer of the home needs to know.",
    fix: "State the length of the term in years and the event that starts it, such as the date the system is placed in service.",
  },
  {
    id: "SOL-006",
    name: "Production guarantee",
    cite: practice("solar-production-guarantee", "what the system is promised to produce"),
    pat: [
      /\b(production|performance|output|energy)\s+guarant\w+/i,
      /\bguarant\w+\b[^.]{0,120}?\b(production|output|kilowatt[-\s]hours?|kWh)\b/i,
    ],
    why: "The homeowner pays for the system's output, or a fixed amount that assumes it. Without a production guarantee the homeowner bears the risk that the system underperforms, and has no remedy if it produces less than the sales estimate.",
    fix: "State the annual production the provider guarantees, how it is measured, and what the provider pays or credits the homeowner if the system falls short.",
  },
  {
    id: "SOL-007",
    name: "What happens when the home is sold",
    cite: practice("solar-transfer-on-sale", "assumption by the buyer, buyout or prepayment"),
    pat: [
      /\b(sells?|sale\s+of|selling|transfers?|conveys?)\b[^.]{0,120}?\b(home|house|property|residence)\b[\s\S]{0,300}?\b(assum\w+|buy[-\s]?out|purchase\s+the\s+system|prepay\w*|transfer\w*|relocat\w+)\b/i,
    ],
    why: "The agreement outlasts most homeowners' time in the house, so the sale of the home is an event the contract will almost certainly meet. The buyer must qualify and agree to take the contract over, or the seller must pay it off; the terms decide whether the home can be sold on schedule.",
    fix: "State the homeowner's options on a sale of the home: transfer to a buyer who meets stated credit criteria, a buyout at a stated price or schedule, or prepayment of the remaining payments, and how long the provider has to approve a transfer.",
  },
  {
    id: "SOL-008",
    name: "Filings against the home",
    cite: practice("solar-fixture-filing", "a fixture filing or lien, and its release"),
    pat: [
      /\bfixture\s+filing\b|\bUCC[-\s]?1\b|\bfinancing\s+statement\b|\b(lien|encumbrance)\b[^.]{0,120}?\b(home|house|property|title|system)\b/i,
    ],
    why: "A provider that owns the system usually records a fixture filing in the county land records. It is not a lien on the house, but it appears in a title search and has to be dealt with when the homeowner refinances or sells. The contract should say whether one will be filed and when it comes off.",
    fix: "State whether the provider will record a fixture filing or other notice against the property, that it is not a lien on the home, and that the provider will subordinate or release it on request for a refinancing or sale.",
  },
]);

export const RESIDENTIAL_SOLAR_RULES: readonly Rule[] = [
  ...COLUMNS.slice(0, 2),
  CANCEL_WAIVER,
  ...COLUMNS.slice(2),
];

/**
 * v7 — the buyer representation agreement (spec-v49.md §3).
 *
 * Four of the checks read for terms that come from the 2024 settlement of the
 * commission litigation against the National Association of REALTORS®. That
 * settlement binds NAR members and MLS participants; it is **not law**, and
 * every citation says so (spec-v49 §6). The terms are the ones NAR's own
 * settlement FAQ names (nar.realtor, read 2026-10-10). The other three checks
 * are practice. Texas has since put most of the list in a statute — Occ. Code
 * § 1101.563, effective January 1, 2026 — which is carried as a governing-law
 * overlay (`buyer-rep-us-tx`) and appears only on a document that names Texas
 * law.
 */

import type { Rule } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { pack } from "../v5/_pack.js";
import { languageRule, practice, v4Cite } from "../v5/_helpers.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";
import { DATE_SHAPE } from "../../../extract/dates.js";

const PLAYBOOK = "buyer-representation-agreement";
const C = "real-estate";

function settlement(topic: string, label: string): SourceCitation {
  return v4Cite({
    id: `nar-settlement-2024-${topic}`,
    source: `2024 NAR settlement practice changes, in effect since August 17, 2024 — ${label} (an industry settlement that binds NAR members and MLS participants; not law)`,
    source_url: "https://www.nar.realtor/the-facts/nar-settlement-faqs",
    retrieved_at: "2026-10-10T00:00:00Z",
    license: "Industry settlement terms (citation only)",
    license_url: "https://www.nar.realtor/the-facts/nar-settlement-faqs",
  });
}

const NOT_LAW =
  "This is industry practice under the 2024 settlement, which binds NAR members and MLS participants. It is not required by federal law; some states have since adopted similar rules of their own.";

const OPEN_ENDED = languageRule({
  id: "BUY-002",
  name: "Compensation left open-ended",
  category: C,
  description:
    "Compensation stated as whatever the seller offers, or left to be determined, rather than as an amount the buyer can work out.",
  citation: settlement(
    "ascertainable",
    "compensation must be objectively ascertainable and not open-ended",
  ),
  playbooks: [PLAYBOOK],
  bad_patterns: [
    /\bwhatever\b[^.]{0,60}?\b(seller|listing\s+broker|listing\s+agent)\b[^.]{0,60}?\b(offer\w*|pay\w*|agree\w*)\b/i,
    /\b(any|the)\s+(amount|compensation|commission)\s+(that\s+is\s+|that\s+may\s+be\s+)?(offered|paid)\s+by\s+(the\s+)?(seller|listing\s+broker|listing\s+agent)\b/i,
    /\b(compensation|commission|fee)\b[^.]{0,80}?\b(to\s+be\s+(determined|agreed|negotiated)|TBD)\b/i,
  ],
  bad_title: "Broker compensation is open-ended",
  bad_description:
    "The agreement sets the broker's compensation by reference to what someone else will offer, or leaves it to be decided later.",
  explanation: `A buyer cannot tell from this term what the broker will be paid. Under the settlement the amount or rate must be objectively ascertainable and may not be open-ended. ${NOT_LAW}`,
  recommendation:
    "State the broker's compensation as a specific dollar amount, a percentage of the purchase price, or an hourly rate.",
  default_severity: "warning",
});

const COLUMNS = pack(PLAYBOOK, C, [
  {
    id: "BUY-001",
    // 1.1.0 — reads "per cent", the UK and Commonwealth spelling, as well as "percent".
    ver: "1.1.0",
    name: "Compensation as a specific amount or rate",
    cite: settlement(
      "amount-or-rate",
      "a specific and conspicuous disclosure of the amount or rate",
    ),
    pat: [
      new RegExp(
        String.raw`\b(compensation|commission|fee)s?\b[^.]{0,200}?(\d+(\.\d+)?\s?(%|per\s?cent)|(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS}|\bflat\s+fee\b|\bper\s+hour\b|\bhourly\b)`,
        "i",
      ),
    ],
    why: `The buyer is agreeing to see that the broker is paid, so the agreement has to say how much: a dollar amount, a percentage of the price, or an hourly rate. ${NOT_LAW}`,
    fix: "State the broker's compensation as a dollar amount, a percentage of the purchase price, or an hourly rate, and how it is determined.",
  },
  {
    id: "BUY-003",
    name: "Broker may not receive more than the agreed amount",
    cite: settlement(
      "no-excess",
      "no compensation from any source above the agreed amount or rate",
    ),
    pat: [
      /\b(not|no)\b[^.]{0,80}?\b(receive|accept|collect|retain|keep)\b[^.]{0,200}?\b(exceed\w*|more\s+than|greater\s+than|in\s+excess\s+of|above)\b/i,
      /\b(exceed\w*|in\s+excess\s+of)\b[^.]{0,200}?\b(credited|refunded|returned|paid)\s+to\s+(the\s+)?buyer\b/i,
    ],
    why: `If the seller or the listing broker offers the buyer's broker more than the buyer agreed to, the broker may not keep the difference. Saying so in the agreement tells the buyer that the stated figure is a ceiling. ${NOT_LAW}`,
    fix: "State that the broker may not receive compensation for its services from any source that exceeds the amount or rate in this agreement.",
  },
  {
    id: "BUY-004",
    name: "Statement that compensation is not set by law and is fully negotiable",
    cite: settlement("negotiable", "a conspicuous statement that fees are negotiable"),
    all: true,
    pat: [/\bnot\s+(set|fixed|established|determined)\s+by\s+law\b/i, /\bnegotiable\b/i],
    why: `Many buyers assume a broker's commission is a standard rate. The agreement should say, where the buyer will see it, that it is not. ${NOT_LAW}`,
    fix: "Add a conspicuous statement that broker compensation is not set by law and is fully negotiable.",
  },
  {
    id: "BUY-005",
    name: "The date the agreement ends",
    cite: practice("buyer-rep-term", "a stated end date"),
    pat: [
      new RegExp(
        String.raw`\b(ends?|expires?|terminates?|termination\s+date)\b[^.]{0,80}?${DATE_SHAPE}`,
        "i",
      ),
      new RegExp(String.raw`\b(term|period)\b[^.]{0,120}?${PERIOD_COUNT}\s+(days?|months?)\b`, "i"),
    ],
    why: "A buyer who signs an exclusive agreement owes the broker compensation on any purchase made while it runs, including one the buyer finds alone. The end date is what limits that.",
    fix: "State the date the agreement ends, or its length in days or months from signing, and how either party may end it early.",
  },
  {
    id: "BUY-006",
    name: "Whether the agreement is exclusive",
    cite: practice("buyer-rep-exclusivity", "exclusive or non-exclusive, in so many words"),
    pat: [/\b(non-?exclusive|exclusive(ly)?)\b/i],
    why: "Under an exclusive agreement the buyer may work with no other broker and owes this one on any purchase in the area covered. Under a non-exclusive one the buyer owes only on homes this broker introduced. The agreement should say which it is.",
    fix: "State whether the agreement is exclusive or non-exclusive, and the area and type of property it covers.",
  },
  {
    id: "BUY-007",
    name: "The services the broker will provide",
    cite: practice("buyer-rep-services", "what the buyer is paying for"),
    pat: [
      /\bservices?\b[^.]{0,200}?\b(locat\w+|show\w*|negotiat\w+|prepar\w+|advis\w+|assist\w*|present\w*)\b/i,
      /\bbroker\s+(will|shall|must|agrees\s+to)\b[^.]{0,200}?\b(locat\w+|show\w*|negotiat\w+|prepar\w+|advis\w+|present\w*)\b/i,
      /\b(agent|broker)\b[^.]{0,80}?\bto\s+(locate|find|show|negotiate|identify)\b/i,
    ],
    why: "Compensation is now agreed with the buyer up front, so the agreement should say what the broker does for it — finding and showing homes, preparing and presenting offers, negotiating, and seeing the purchase through to closing.",
    fix: "List the services the broker will provide, such as locating and showing properties, preparing and presenting offers, negotiating, and coordinating the closing.",
  },
]);

export const BUYER_REPRESENTATION_RULES: readonly Rule[] = [
  COLUMNS[0]!,
  OPEN_ENDED,
  ...COLUMNS.slice(1),
];

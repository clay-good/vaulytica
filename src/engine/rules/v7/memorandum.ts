/**
 * v7 — the memorandum of understanding (spec-v49.md §4, tranche B).
 *
 * "Memorandum of understanding" was a title keyword of the M&A letter-of-intent
 * type, so a library and an arts group agreeing to run a summer program were
 * told, eight times at `critical`, that their memorandum had no exclusivity
 * period, no purchase price and no transaction structure. Most memoranda of
 * understanding are cooperation documents between two organizations. No
 * authority lists what one must say; every check is practice.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice } from "../v5/_helpers.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";
import { DATE_SHAPE } from "../../../extract/dates.js";

const MEMORANDUM = pack("memorandum-of-understanding", "commercial", [
  {
    id: "MOU-001",
    name: "What the parties are setting out to do",
    cite: practice("mou-purpose", "the shared purpose, in a sentence"),
    pat: [
      /\b(purpose|objectives?|goals?|scope)\b[^.]{0,200}?\b(is|are|of\s+this)\b/i,
      /\b(work\s+together|collaborat\w+|cooperat\w+|partner\w*)\b[^.]{0,200}?\b(to|on|in)\b/i,
    ],
    why: "A memorandum of understanding records an intention to work together. If it does not say on what, there is nothing for either side to measure the other's effort against, and nothing to tell a successor what was meant.",
    fix: "State the purpose in a sentence or two: what the parties intend to do together, for whom, and over what period.",
  },
  {
    id: "MOU-002",
    name: "What each party will do",
    cite: practice("mou-roles", "each side's contribution, named separately"),
    pat: [
      /\b(roles?|responsibilit(y|ies)|contributions?|commitments?|undertakings?)\b/i,
      /\b(will|shall|must|agrees\s+to)\s+(provide|supply|contribute|furnish|host|staff|fund|make\s+available|be\s+responsible\s+for)\b/i,
    ],
    why: "Most disputes under a memorandum are about who was supposed to do what. Listing each party's contribution separately — people, space, money, equipment — is the document's main job.",
    fix: "List what each party will contribute and be responsible for, under its own name.",
  },
  {
    id: "MOU-003",
    name: "Whether the memorandum is legally binding",
    cite: practice("mou-binding", "binding, non-binding, or which parts are which"),
    pat: [
      /\b(non-?binding|not\s+(legally\s+)?binding|legally\s+binding|binding\s+(on|upon|agreement|obligations?|contract)|not\s+(intended\s+to\s+)?(create|constitute)\b[^.]{0,60}?\b(legal|binding|enforceable|contract\w*)|not\s+(a\s+)?(legally\s+)?enforceable|statement\s+of\s+intent)\b/i,
    ],
    why: "Whether a memorandum of understanding can be enforced depends on what it says and how it is written, and parties often assume opposite answers. A court asked to decide will look first for a statement of what the parties intended. Saying it — binding, not binding, or binding only as to named sections such as confidentiality — removes the question.",
    fix: "State whether the memorandum is intended to be legally binding. If only some sections are, name them.",
  },
  {
    id: "MOU-004",
    name: "Who pays for what",
    cite: practice("mou-costs", "each party's costs, and any money that changes hands"),
    pat: [
      /\b(costs?|expenses?|funding|funds|budget|payment|compensation|in-kind)\b[^.]{0,200}?\b(bear\w*|pay\w*|responsible|share\w*|provid\w+|own|no\s+(funds|money|payment))\b/i,
      /\b(bears?|pays?|shares?)\b[^.]{0,80}?\b(its\s+own\s+)?(costs?|expenses?)\b/i,
      /\bno\s+(funds|money|payment|compensation)\b/i,
    ],
    why: "A cooperative arrangement with no cost term leaves each side assuming the other is paying. Even 'each party bears its own costs' settles it.",
    fix: "State who bears which costs, whether any money changes hands, and whether either party may commit the other to an expense.",
  },
  {
    id: "MOU-005",
    ver: "1.1.0",
    name: "How long it runs, and how either party ends it",
    cite: practice("mou-term", "a start, an end, and a way out"),
    pat: [
      new RegExp(
        String.raw`\b(term|period|duration|effective|runs?|remains?\s+in\s+effect|expires?|ends?|until|through)\b[^.]{0,120}?(${DATE_SHAPE}|${PERIOD_COUNT}\s+(?:calendar\s+)?(days?|months?|years?))`,
        "i",
      ),
      /\b(either|any)\s+party\s+may\s+(end|terminate|withdraw\s+from)\b/i,
    ],
    why: "A memorandum with no end date and no way out continues, in the eyes of whoever inherits it, until someone is willing to say it is over. A term and a notice period cost one sentence.",
    fix: "State when the memorandum starts and ends, and how much notice a party must give to end it early.",
  },
]);

export const MEMORANDUM_RULES: readonly Rule[] = MEMORANDUM;

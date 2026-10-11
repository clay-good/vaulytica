/**
 * v7 — the management services agreement between a management company and a
 * medical or dental practice (spec-v49.md §4, tranche B).
 *
 * Held back at first because the two statutes that now govern it had been
 * read only in secondary sources. Both were then read in primary text on
 * 2026-10-11: Cal. Health & Safety Code §§ 1190–1191 at
 * leginfo.legislature.ca.gov, and Oregon S.B. 951 (2025) as enrolled, at
 * olis.oregonlegislature.gov. They are state law, so they are carried as
 * governing-law overlays (`mso-us-ca`, `mso-us-or`) and appear only on an
 * agreement that names that state. The six checks below are practice: the
 * terms a management agreement uses, in any state, to show that clinical
 * decisions stay with the licensed practice.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice } from "../v5/_helpers.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

const SUM = String.raw`(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`;
const PERCENT = String.raw`\d+(?:\.\d+)?\s?(?:%|percent)`;
const CLINICIAN = String.raw`(?:physicians?|dentists?|clinicians?|providers?|licensed\s+(?:professionals?|personnel|staff)|clinical\s+(?:staff|personnel))`;

const MANAGEMENT_SERVICES = pack("management-services-agreement", "healthcare", [
  {
    id: "MSO-001",
    name: "Clinical decisions stay with the practice",
    cite: practice("mso-clinical-control", "the licensed practice, not the manager, decides care"),
    pat: [
      /\b(clinical|medical|dental|professional)\s+(decisions?|judge?ment|matters|care)\b[^.]{0,200}?\b(sole(ly)?|exclusive(ly)?|retain\w*|responsib\w+|make|made\s+by|not\s+(interfere|control|direct))\b/i,
      /\b(sole(ly)?|exclusive(ly)?|retain\w*|responsib\w+|makes?|decides?|controls?)\b[^.]{0,120}?\b(clinical|medical|dental|professional)\s+(decisions?|judge?ment|matters|care)\b/i,
    ],
    why: "Most states bar anyone but a licensed professional from practicing medicine or dentistry, and a management company that controls clinical decisions is practicing through the practice it manages. The agreement's first job is to say that it does not: diagnosis, treatment, referrals and how many patients a clinician sees are the practice's alone.",
    fix: "State that the practice and its licensed professionals have sole and exclusive authority over all clinical decisions, and that the manager will not interfere with their professional judgment.",
  },
  {
    id: "MSO-002",
    name: "The services the manager provides",
    cite: practice("mso-services", "administrative and business services, named"),
    pat: [
      /\b(billing|collections?|staffing|purchasing|payroll|accounting|bookkeeping|human\s+resources|scheduling|information\s+technology|marketing|office\s+space|facilities|equipment|non-?clinical)\b/i,
    ],
    why: "A manager's services are lawful because they are administrative. Listing them — billing, staffing, purchasing, space, technology — is what shows the fee pays for business support and not for control of the practice.",
    fix: "List the administrative and business services the manager provides, and state that it provides no clinical services.",
  },
  {
    id: "MSO-003",
    name: "The management fee, and how it is set",
    cite: practice("mso-fee", "a stated fee for the services, not a share of the practice"),
    pat: [
      new RegExp(
        String.raw`\b(management\s+fee|service\s+fee|fees?)\b[^.]{0,200}?(${SUM}|${PERCENT}|fair\s+market\s+value|cost\s+plus)`,
        "i",
      ),
    ],
    why: "The fee is where a management arrangement is most often attacked: a percentage of the practice's revenue can look like the manager sharing in professional fees, which many states prohibit. The agreement should state the fee and the basis for it.",
    fix: "State the management fee and how it is set — a fixed amount, cost plus a margin, or another basis consistent with the fair market value of the services — and how it is adjusted.",
  },
  {
    id: "MSO-004",
    name: "Who hires and supervises the clinicians",
    cite: practice("mso-clinical-staff", "the practice employs and directs its licensed staff"),
    pat: [
      new RegExp(
        String.raw`\b(hir\w+|employ\w*|engag\w+|terminat\w+|supervis\w+|credential\w*|select\w*)\b[^.]{0,200}?\b${CLINICIAN}\b`,
        "i",
      ),
      new RegExp(
        String.raw`\b${CLINICIAN}\b[^.]{0,200}?\b(hired|employed|engaged|supervised|terminated)\s+by\b`,
        "i",
      ),
    ],
    why: "The manager usually employs the front-office staff; the practice has to employ and direct the clinicians. An agreement that lets the manager hire, fire or set the schedules of licensed professionals hands it the control the law reserves to the practice.",
    fix: "State that the practice alone hires, supervises, schedules and terminates its licensed professionals, and that the manager employs only non-clinical staff.",
  },
  {
    id: "MSO-005",
    name: "Patient records belong to the practice",
    cite: practice("mso-patient-records", "the practice owns and controls the records"),
    pat: [/\b(patient|medical|dental|clinical)\s+records\b/i],
    why: "A manager often runs the record system. The records themselves, and what goes into them, are the practice's: it owes its patients confidentiality and continuity of care, and must be able to take the records with it when the agreement ends.",
    fix: "State that the practice owns and controls all patient records, that the manager handles them only as the practice directs, and that they stay with the practice when the agreement ends.",
  },
  {
    id: "MSO-006",
    name: "Billing, and contracts with payers",
    cite: practice(
      "mso-billing-payers",
      "billed in the practice's name; the practice decides its payer contracts",
    ),
    pat: [
      /\b(payers?|payors?|insurers?|health\s+plans?|third[-\s]party\s+pay\w+)\b/i,
      /\bbill\w*\b[^.]{0,120}?\b(in\s+the\s+name\s+of|on\s+behalf\s+of)\b/i,
    ],
    why: "A manager typically bills and collects for the practice. It should do so in the practice's name and as its agent, and the decision to sign or leave a payer contract — and on what terms — should remain the practice's.",
    fix: "State that the manager bills and collects in the practice's name and as its agent, that coding decisions are the practice's, and that the practice approves every contract with a payer.",
  },
]);

export const MANAGEMENT_SERVICES_RULES: readonly Rule[] = MANAGEMENT_SERVICES;

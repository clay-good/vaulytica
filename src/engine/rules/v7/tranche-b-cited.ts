/**
 * v7 — tranche B, the two types with an authority (spec-v49.md §4, Step 312).
 *
 * **Student data privacy agreement.** FERPA lets a school share education
 * records with a vendor as a "school official" on three conditions — the
 * vendor performs a service the school would otherwise use employees for, is
 * under the school's direct control as to the records, and is bound by the
 * redisclosure limits of § 99.33(a) (34 C.F.R. § 99.31(a)(1)(i)(B), read at
 * ecfr.gov on 2026-10-11). The rule sets conditions; it does not prescribe
 * contract clauses, and the two checks that cite it say so. The rest is
 * practice. California does prescribe clauses — nine of them, in Educ. Code
 * § 49073.1(b) — and is carried as a governing-law overlay.
 *
 * **Used vehicle purchase agreement.** The FTC's Used Car Rule requires a
 * dealer's contract of sale to say that the window form is part of it and
 * overrides contrary terms (16 C.F.R. § 455.3(b), read at ecfr.gov on
 * 2026-10-11). It binds a "dealer" — someone who has sold five or more used
 * vehicles in twelve months — which the contract does not establish, so the
 * check reports at `info` and names the condition (spec-v49 §6).
 */

import type { Rule } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { pack } from "../v5/_pack.js";
import { practice, v4Cite } from "../v5/_helpers.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

const SUM = String.raw`(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`;

function ferpa(sub: string, label: string): SourceCitation {
  return v4Cite({
    id: `cfr-34-99-31-a-1-i-b-${sub}`,
    source: `34 C.F.R. § 99.31(a)(1)(i)(B)(${sub}) — ${label} (a condition for treating a vendor as a school official; the rule does not prescribe contract clauses)`,
    source_url: "https://www.ecfr.gov/current/title-34/section-99.31",
    retrieved_at: "2026-10-11T00:00:00Z",
  });
}

const STUDENT_DATA = pack("student-data-privacy-agreement", "privacy", [
  {
    id: "SDP-001",
    name: "Student data stays the school's, under its control",
    cite: ferpa("2", "under the direct control of the agency or institution"),
    pat: [
      /\b(property\s+of|owned\s+by|belongs?\s+to)\b[^.]{0,80}?\b(district|school|agency|institution|LEA)\b/i,
      /\b(direct\s+control|under\s+the\s+control\s+of|school\s+official)\b/i,
    ],
    why: "A school may share education records with a vendor without each parent's consent only if the vendor acts as a school official, and one condition of that is that the vendor is under the school's direct control as to the records. A contract that says the data remains the school's, under its control, is how a school shows the condition is met.",
    fix: "State that student data remains the property of and under the direct control of the school or district, and that the provider acts as a school official with a legitimate educational interest.",
  },
  {
    id: "SDP-002",
    name: "Use limited to the service, and no further disclosure",
    cite: ferpa("3", "subject to the use and redisclosure requirements of § 99.33(a)"),
    all: true,
    pat: [
      /\b(only|solely|exclusively)\b[^.]{0,120}?\b(to\s+provide|for\s+the\s+purpose|purposes?\s+of|as\s+(permitted|authori[sz]ed|directed))\b|\b(not|no)\b[^.]{0,60}?\buse\b[^.]{0,120}?\b(other\s+than|except|any\s+other\s+purpose)\b/i,
      /\b(not|no|never|nor)\b[^.]{0,80}?\b(disclos\w+|redisclos\w+|shar\w+|sell|sold|transfer\w*)\b/i,
    ],
    why: "A vendor acting as a school official may use education records only for the purpose for which they were shared and may not pass them on. Both halves belong in the contract: what the data may be used for, and that it goes no further.",
    fix: "State that the provider will use student data only to provide the contracted service, and will not disclose it to anyone else except its own subcontractors bound to the same terms.",
  },
  {
    id: "SDP-003",
    name: "No targeted advertising, and no sale of student data",
    cite: practice("student-data-advertising", "no advertising to students from their own records"),
    pat: [
      /\b(targeted|behaviou?ral)\s+advertis\w+\b|\b(not|no|never)\b[^.]{0,60}?\b(sell|sale\s+of|market\w*|advertis\w+)\b[^.]{0,80}?\b(student|pupil)\b/i,
    ],
    why: "The commonest objection to classroom software is that it builds advertising profiles of children. Many states now prohibit it by statute, and districts expect the promise in the contract wherever they are.",
    fix: "State that the provider will not use student data for targeted advertising, will not build a profile of a student except to provide the service, and will not sell student data.",
  },
  {
    id: "SDP-004",
    name: "Security measures",
    cite: practice("student-data-security", "what the provider does to keep the records secure"),
    pat: [
      /\bsafeguards?\b|\bencrypt\w+|\baccess\s+controls?\b|\bsecurity\s+(measures|controls|standards|practices)\b/i,
    ],
    why: "The district remains answerable to parents for records it has handed to a vendor. It needs to know what the vendor does to protect them — encryption, access limits, staff training — not only that the vendor will be 'reasonable'.",
    fix: "Describe the security measures the provider will maintain, including encryption, access controls, and the training of staff who handle student data.",
  },
  {
    id: "SDP-005",
    name: "Notice of an unauthorized disclosure",
    cite: practice(
      "student-data-breach-notice",
      "telling the district, and through it the parents",
    ),
    pat: [
      /\b(notif\w+|notice|report\w*)\b[^.]{0,200}?\b(breach\w*|unauthori[sz]ed\s+(access|disclosure|acquisition|use)|security\s+incident)\b/i,
      /\b(breach\w*|unauthori[sz]ed\s+(access|disclosure|acquisition|use)|security\s+incident)\b[^.]{0,200}?\b(notif\w+|notice|report\w*)\b/i,
    ],
    why: "When student records are exposed the district has to tell parents, and it cannot until the vendor tells the district. The contract should fix how soon, and what the notice says.",
    fix: "State that the provider will notify the district of any unauthorized disclosure of student data within a stated number of days, with the facts the district needs to notify parents.",
  },
  {
    id: "SDP-006",
    name: "Parents' access to, and correction of, the records",
    cite: practice(
      "student-data-parent-access",
      "how a parent reviews and corrects what the provider holds",
    ),
    pat: [
      /\b(parents?|guardians?|eligible\s+(students?|pupils?))\b[^.]{0,200}?\b(review|inspect|access|correct|amend)\b/i,
      /\b(review|inspect|access|correct|amend)\b[^.]{0,200}?\b(parents?|guardians?|eligible\s+(students?|pupils?))\b/i,
    ],
    why: "Parents have a right to see and seek correction of their child's education records, and it does not stop at the vendor's door. The contract should say how a request the district receives is carried out on the vendor's systems.",
    fix: "Describe how a parent, guardian or eligible student may review the student's records held by the provider and have errors corrected, through the district.",
  },
  {
    id: "SDP-007",
    name: "Deletion or return of student data at the end",
    cite: practice("student-data-deletion", "the provider keeps nothing when the contract ends"),
    pat: [
      /\b(delet\w+|destroy\w*|return\w*|purg\w+|dispos\w+)\b[^.]{0,200}?\b(student|pupil|data|records)\b/i,
      /\b(student|pupil)\s+(data|records)\b[^.]{0,200}?\b(deleted|destroyed|returned|purged|not\s+(be\s+)?retained)\b/i,
    ],
    why: "A vendor that keeps student records after the contract ends holds them with no purpose and no oversight. The district needs a deadline for deletion and a way to confirm it.",
    fix: "State that the provider will delete or return all student data within a stated number of days after the contract ends or the district asks, and will certify that it has.",
  },
]);

const VEHICLE = pack("vehicle-purchase-agreement", "commercial", [
  {
    id: "VEH-001",
    name: "The vehicle, by VIN and odometer reading",
    cite: practice("vehicle-identification", "which car, and how far it has been driven"),
    all: true,
    pat: [/\b(VIN|vehicle\s+identification\s+number)\b/i, /\b(odometer|mileage|miles)\b/i],
    why: "The vehicle identification number is what ties the contract to one car and lets the buyer check its title and history. The odometer reading is what the price is based on, and misstating it is the classic used-car fraud.",
    fix: "State the year, make and model, the vehicle identification number, and the odometer reading at the time of sale.",
  },
  {
    id: "VEH-002",
    name: "The price, and each fee added to it",
    cite: practice("vehicle-price", "the cash price and an itemized list of what is added"),
    pat: [new RegExp(String.raw`\b(price|total|amount\s+due)\b[^.]{0,120}?${SUM}`, "i")],
    why: "The figure a buyer agreed to on the lot and the figure on the contract differ by taxes, title and registration, and dealer fees. Itemizing them is how a buyer sees which are the government's and which are the dealer's.",
    fix: "State the cash price of the vehicle and list separately each tax, government fee and dealer fee added to it, with the total.",
  },
  {
    id: "VEH-003",
    name: "Statement that the window form is part of the contract",
    cite: v4Cite({
      id: "cfr-16-455-3-b",
      source:
        "16 C.F.R. § 455.3(b) — the Buyers Guide is incorporated into the contract of sale and overrides contrary provisions (applies to a dealer, as defined in § 455.1(d), selling a used vehicle to a consumer)",
      source_url: "https://www.ecfr.gov/current/title-16/part-455",
      retrieved_at: "2026-10-11T00:00:00Z",
    }),
    pat: [/\bwindow\s+form\b/i, /\bbuyers?['’]?s?\s+guide\b/i],
    why: "A dealer selling a used vehicle to a consumer must include in the contract of sale a statement that the information on the window form for the vehicle is part of the contract and overrides any contrary provisions. It is what makes the warranty terms on the window sticker binding. This applies to a dealer — someone who has sold or offered five or more used vehicles in the past twelve months — and the document does not say whether the seller is one, so check that before relying on this note.",
    fix: "Add, conspicuously: “The information you see on the window form for this vehicle is part of this contract. Information on the window form overrides any contrary provisions in the contract of sale.”",
    sev: "info",
  },
  {
    id: "VEH-004",
    name: "Warranty, or a sale as is",
    cite: practice("vehicle-warranty", "what the seller stands behind, if anything"),
    pat: [/\bas[-\s]is\b|\bwarrant(y|ies)\b|\bservice\s+contract\b/i],
    why: "Whether the car comes with a warranty, with implied warranties only, or as is decides who pays when something fails in the first month. It should be stated in the contract in the same terms as on the window form.",
    fix: "State whether the vehicle is sold with a dealer warranty and what it covers, with implied warranties only, or as is with no dealer warranty.",
  },
  {
    id: "VEH-005",
    name: "Title, and any lien on the vehicle",
    cite: practice("vehicle-title", "clear title, and when the buyer gets it"),
    pat: [
      /\b(title|certificate\s+of\s+title)\b[^.]{0,200}?\b(transfer\w*|deliver\w*|free\s+(and\s+clear|of)|clear|liens?|encumbrances?|sign\w*\s+over)\b/i,
      /\b(liens?|encumbrances?)\b[^.]{0,120}?\b(title|vehicle)\b/i,
    ],
    why: "A buyer who pays for a car and does not receive clear title owns nothing a lender or the motor vehicle office will recognize. The contract should say that title is free of liens and when it will be delivered.",
    fix: "State that the seller will deliver title to the vehicle free of liens, and when — at the sale, or within a stated number of days after the seller's lender is paid off.",
  },
]);

export const TRANCHE_B_CITED_RULES: readonly Rule[] = [...STUDENT_DATA, ...VEHICLE];

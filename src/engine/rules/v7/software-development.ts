/**
 * v7 — the software development agreement (spec-v49.md §3).
 *
 * The one column here with an authority is ownership. Under 17 U.S.C. § 101 a
 * commissioned work is "made for hire" only if it falls in one of nine listed
 * categories and the parties say so in a signed writing; a computer program is
 * not one of the nine (read at copyright.gov on 2026-10-10). Custom software
 * can still qualify through another category — a contribution to a collective
 * work, a compilation — so the finding says "usually", and asks for the
 * assignment that works either way. The other five columns are practice.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice, v4Cite } from "../v5/_helpers.js";

const SOFTWARE_DEVELOPMENT = pack("software-development-agreement", "ip-licensing", [
  {
    id: "SDA-001",
    name: "Specifications the software is built to",
    cite: practice("software-specifications", "a written description of what is to be built"),
    pat: [
      /\b(specifications?|statement\s+of\s+work|scope\s+of\s+work|functional\s+requirements|requirements\s+document|technical\s+requirements|design\s+document)\b/i,
    ],
    why: "Acceptance, warranty and payment all turn on whether the software does what was agreed, and the specifications are where that is written down. An agreement to build 'the application' with no description of it leaves every later dispute without a measure.",
    fix: "Attach or reference written specifications — a statement of work or requirements document — and say how they are changed.",
  },
  {
    id: "SDA-002",
    name: "Acceptance testing, and what happens if the client says nothing",
    cite: practice("software-acceptance", "a test period, a way to reject, and deemed acceptance"),
    pat: [
      /\b(acceptance\s+(test\w*|criteria|period|procedures?)|accept\s+or\s+reject|deemed\s+(to\s+(be|have\s+been)\s+)?accepted|deemed\s+acceptance|(test|review|evaluation)\s+period)\b/i,
    ],
    why: "Without an acceptance procedure there is no moment at which the work is finished: the developer cannot tell when the final payment is due or when the warranty starts, and the client has no agreed way to reject software that does not work.",
    fix: "Add an acceptance clause: how long the client has to test each deliverable, how it rejects one and what the developer must then do, and that a deliverable is deemed accepted if the client does not respond in that time.",
  },
  {
    id: "SDA-003",
    name: "Payment schedule tied to the work",
    cite: practice("software-payment-schedule", "milestones, or rates and an invoicing period"),
    pat: [
      /\bmilestones?\b|\btime[-\s]and[-\s]materials\b|\b(hourly|daily)\s+rates?\b|\bpayment\s+schedule\b|\bfixed\s+(fee|price)\b/i,
    ],
    why: "A development fee is either earned in stages against delivered work or billed for time. An agreement that states a total and neither a schedule nor a rate leaves open when any of it is due and what is owed if the project stops halfway.",
    fix: "State how the fee is earned: milestone payments tied to named deliverables and their acceptance, or hourly rates with an invoicing period and any cap.",
  },
  {
    id: "SDA-004",
    name: "An assignment of the software, not only a work-for-hire statement",
    cite: v4Cite({
      id: "copyright-17-usc-101-work-made-for-hire",
      source:
        "17 U.S.C. § 101 (definition of “work made for hire” — a commissioned work qualifies only within nine listed categories, which do not name computer programs)",
      source_url: "https://www.copyright.gov/title17/92chap1.html",
      retrieved_at: "2026-10-10T00:00:00Z",
    }),
    pat: [
      /\b(assigns?|transfers?|conveys?)\b[^.]{0,200}?\b(right|title|interest|copyrights?|intellectual\s+property|ownership)\b/i,
      /\b(developer|contractor|consultant|vendor)\s+(retains?|(?:shall|will|must)\s+retain|owns?|(?:shall|will|must)\s+own)\b[\s\S]{0,300}?\bgrants?\b[^.]{0,160}?\blicen[sc]e\b/i,
    ],
    why: "A statement that commissioned software is a work made for hire usually does not make the client its owner. For an independent developer the statute limits work made for hire to nine listed kinds of work, and software is not among them, so unless the software fits another category the copyright stays with the developer until it is assigned in a signed writing. An agreement with no ownership term at all has the same result.",
    fix: "Add a present assignment: to the extent the software is not a work made for hire, the developer hereby assigns to the client all right, title and interest in it. If the developer is to keep ownership instead, say so and state the license the client receives.",
  },
  {
    id: "SDA-005",
    name: "Developer's pre-existing materials",
    cite: practice("software-pre-existing-materials", "tools and code the developer brings"),
    pat: [
      /\b(pre-?existing|background|prior)\s+(materials?|ip|intellectual\s+property|technology|works?|code|software|tools?|inventions?)\b|\bdeveloper\s+(tools|materials|technology)\b/i,
    ],
    why: "Every developer builds with libraries, frameworks and code written before the project. If the agreement assigns 'the software' and does not carve those out, the developer has either given away its toolkit or the client has received less than it reads; if it carves them out without a license, the client cannot run what it paid for.",
    fix: "Identify the developer's pre-existing materials, state that the developer keeps them, and grant the client a perpetual license to use them as part of the delivered software.",
  },
  {
    id: "SDA-006",
    name: "Open-source and third-party components",
    cite: practice(
      "software-open-source",
      "what the software is built on, and under which licenses",
    ),
    pat: [
      /\bopen[-\s]source\b|\bthird[-\s]party\s+(software|code|components?|librar(y|ies)|materials)\b|\bcopyleft\b|\bGPL\b/i,
    ],
    why: "Delivered software almost always includes open-source components, and some of their licenses require the client to publish its own source code when it distributes the software. The client cannot manage that risk if the agreement does not require the developer to say what was used.",
    fix: "Require the developer to list the open-source and third-party components in each deliverable with their licenses, and to get the client's written approval before using any component whose license would require disclosure of the client's source code.",
  },
]);

export const SOFTWARE_DEVELOPMENT_RULES: readonly Rule[] = SOFTWARE_DEVELOPMENT;

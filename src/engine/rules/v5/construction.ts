/**
 * v5 sub-domain M′ — US design services and lien notices
 * (spec-v45.md §6.M). Rule ids continue the CON namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { expressDenial, practice, standardForm, stateLaw } from "./_helpers.js";

const C = "construction";

const DESIGN_BUILD = pack("design-build-agreement", C, [
  {
    id: "CON-101",
    name: "Single point of responsibility recital",
    cite: standardForm(
      "DBIA",
      "Design-Build Institute of America standard form contract documents",
      "https://dbia.org/contract-documents/",
    ),
    pat: [
      /(single\s+point\s+of\s+responsibility|design-?builder\s+(shall\s+be\s+)?(solely\s+)?responsible\s+for\s+both)/i,
      /(design\s+and\s+construction|both\s+the\s+design\s+and\s+the\s+work)/i,
    ],
    why: "The whole point of design-build is that the owner has one counterparty for design and construction, which eliminates the Spearin gap between defective plans and defective work. If the agreement does not say so, the design-builder will argue the owner's program was the design.",
    fix: "Recite that the design-builder is solely responsible for both the design and the construction of the project and for their coordination.",
    sev: "critical",
  },
  {
    id: "CON-102",
    name: "Owner's program and basis-of-design documents",
    cite: standardForm(
      "DBIA",
      "Design-Build Institute of America — owner's program and criteria documents",
      "https://dbia.org/contract-documents/",
    ),
    pat: [
      /(owner'?s?\s+program|owner'?s?\s+criteria|basis\s+of\s+design)/i,
      /(attached|exhibit|incorporated|performance\s+(criteria|specification))/i,
    ],
    why: "Everything the owner did not put in the program is a change order. The line between prescriptive criteria (which the owner warrants under Spearin) and performance criteria (which the design-builder owns) is the contract's central risk allocation.",
    fix: "Attach the owner's program and basis-of-design documents, and state which criteria are prescriptive and which are performance-based.",
    sev: "critical",
  },
  {
    id: "CON-103",
    name: "Design standard of care versus performance warranty",
    cite: practice(
      "design-standard",
      "professional standard of care versus warranty in design-build",
    ),
    pat: [
      /standard\s+of\s+care/i,
      /(warrant|guarantee|fit\s+for\s+(its\s+)?intended\s+(use|purpose)|professional\s+(services|skill))/i,
    ],
    why: "Professional liability policies exclude warranty obligations. A design-builder that warrants a performance outcome may find the design portion of a claim uninsured, which helps nobody.",
    fix: "State the professional standard of care for design services and keep any performance guarantee separate and insurable, or confirm the coverage consequence deliberately.",
  },
  {
    id: "CON-104",
    name: "Pricing model and contingency",
    cite: practice("gmp-contingency", "GMP and contingency mechanics in design-build"),
    pat: [
      /(guaranteed\s+maximum\s+price|gmp|lump\s+sum|cost\s+of\s+the\s+work)/i,
      /(contingency|savings|shared\s+savings|allowance)/i,
    ],
    why: "Design-build GMPs are set before the design is complete, so the contingency is doing real work. Who controls it, what it may be spent on, and who keeps the savings is a frequent late dispute.",
    fix: "State the pricing model, the contingency amount and the conditions on its use, the approval required to draw on it, and the savings split at completion.",
  },
  {
    id: "CON-105",
    name: "Design review and owner approval rights",
    cite: practice("design-review", "owner design review in design-build agreements"),
    pat: [
      /(design\s+review|submittal|review\s+of\s+the\s+(design|documents))/i,
      /(approv|comment|shall\s+not\s+relieve|within\s+\d+\s+days)/i,
    ],
    why: "Owner review has to be real enough to catch problems but must not shift design responsibility back to the owner. The no-relief clause is what preserves the single point of responsibility.",
    fix: "Set review periods with deemed-approval consequences, and state that the owner's review or approval does not relieve the design-builder of responsibility for the design.",
  },
  {
    id: "CON-106",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Insurance including professional liability",
    cite: practice("db-insurance", "professional liability insurance in design-build"),
    pat: [
      /insur(e|ance)/i,
      /(professional\s+liability|errors\s+and\s+omissions|e&o|contractors?\s+professional|builder'?s\s+risk)/i,
    ],
    why: "A CGL policy excludes professional services. A design-builder carrying only CGL and builder's risk has no coverage for the design half of its own single-point obligation.",
    fix: "Require contractor's professional liability or design-build professional coverage at stated limits with a stated extended reporting period, in addition to CGL, builder's risk, and umbrella.",
    denied: expressDenial(String.raw`professional\s+liability\s+insurance`),
    sev: "critical",
  },
]);

const ARCHITECT = pack("architect-agreement", C, [
  {
    id: "CON-107",
    name: "Basic services by phase and additional services",
    cite: standardForm(
      "AIA Document B101",
      "Standard Form of Agreement Between Owner and Architect",
      "https://www.aiacontracts.com/",
    ),
    pat: [
      /(schematic\s+design|design\s+development|construction\s+documents|bidding)/i,
      /(additional\s+services|basic\s+services|scope\s+of\s+services)/i,
    ],
    why: "B101 splits services into five phases plus construction administration, with everything else as compensable additional services. Owners are routinely surprised by what falls outside basic services.",
    fix: "Enumerate the basic services by phase and list the additional services with their compensation basis and the notice required before performing them.",
  },
  {
    id: "CON-108",
    name: "Standard of care with no warranty or guarantee",
    cite: standardForm(
      "AIA Document B101",
      "professional standard of care",
      "https://www.aiacontracts.com/",
    ),
    pat: [
      /standard\s+of\s+care/i,
      /(professional\s+skill\s+and\s+judgment|reasonably\s+prudent|no\s+(warrant|guarantee)|does\s+not\s+warrant)/i,
    ],
    why: "An architect who warrants a result rather than promising professional care assumes an uninsurable obligation. Owners sometimes insert warranty language without realizing it strips the E&O coverage they are relying on.",
    fix: "State the professional standard of care and confirm that no warranty or guarantee of the work or the outcome is made, express or implied.",
    sev: "critical",
  },
  {
    id: "CON-109",
    name: "Instruments of service license and termination effect",
    cite: standardForm(
      "AIA Document B101",
      "copyrights and licenses in instruments of service",
      "https://www.aiacontracts.com/",
    ),
    pat: [
      /instruments\s+of\s+service/i,
      /(license|copyright|terminat|nonexclusive\s+license|shall\s+not\s+use)/i,
    ],
    why: "Under the AIA form the architect retains copyright and the owner gets a license conditioned on payment, which terminates if the architect's services are terminated for the owner's breach. An owner that plans to use the drawings elsewhere needs a different bargain.",
    fix: "State who owns the instruments of service, the scope of the owner's license, whether it survives termination, and the indemnity for use without the architect involved.",
    sev: "critical",
  },
  {
    id: "CON-110",
    name: "Construction-phase duties and site visits",
    cite: standardForm(
      "AIA Document B101",
      "construction phase — administration of the contract",
      "https://www.aiacontracts.com/",
    ),
    pat: [
      /(construction\s+(phase|administration)|site\s+visits?)/i,
      /(not\s+(required\s+)?to\s+(make\s+exhaustive|be\s+continuously\s+present)|means\s+and\s+methods|general\s+conformance)/i,
    ],
    why: "The architect's site visits are for general conformance, not inspection, and the contractor owns means and methods. Blurring the line converts an architect into a guarantor of the contractor's work.",
    fix: "State the frequency and purpose of site visits, disclaim continuous on-site inspection and responsibility for means and methods, and describe the certification of payment applications.",
  },
  {
    id: "CON-111",
    name: "Compensation, reimbursables, and phase caps",
    cite: standardForm(
      "AIA Document B101",
      "compensation and reimbursable expenses",
      "https://www.aiacontracts.com/",
    ),
    pat: [
      /(compensation|fee)/i,
      /(percentage\s+of\s+the\s+cost\s+of\s+the\s+work|stipulated\s+sum|hourly|reimbursable\s+expenses|not\s+to\s+exceed)/i,
    ],
    why: "A fee as a percentage of the cost of the work moves with scope, which is either the right alignment or an unbudgeted escalation depending on which side you are on.",
    fix: "State the compensation basis, the phase allocation, the reimbursable categories and multiplier, and any not-to-exceed limits.",
  },
  {
    id: "CON-112",
    name: "Professional liability insurance limits",
    cite: practice(
      "architect-insurance",
      "professional liability insurance in owner-architect agreements",
    ),
    pat: [
      /insur(e|ance)/i,
      /(professional\s+liability|errors\s+and\s+omissions|per\s+claim|aggregate|\$\d)/i,
    ],
    why: "The architect's E&O policy is usually the owner's only real recovery source for a design defect, and it is claims-made — so the limits and the tail matter as much as the limit itself.",
    fix: "State the required professional liability limits per claim and in the aggregate, the deductible, and the period the coverage must be maintained after substantial completion.",
  },
]);

const PRELIEN = pack("preliminary-lien-notice", C, [
  {
    id: "CON-113",
    name: "Claimant, hiring party, and owner identified",
    cite: stateLaw(
      "preliminary-notice",
      "statutory preliminary notice contents under state mechanic's lien acts",
      "https://www.law.cornell.edu/wex/mechanic_s_lien",
    ),
    pat: [
      /(claimant|the\s+undersigned|person\s+furnishing)/i,
      /(owner|reputed\s+owner|original\s+contractor|the\s+person\s+(who|with\s+whom))/i,
    ],
    why: "Preliminary notices are strictly construed. Failing to name the owner, the hiring party, and the claimant in the form the statute prescribes forfeits lien rights entirely, regardless of the merits.",
    fix: "Name the claimant, the party that hired the claimant, the owner or reputed owner, and the original contractor, with addresses, in the statutory form.",
    sev: "critical",
  },
  {
    id: "CON-114",
    name: "Property description sufficient to identify",
    cite: stateLaw(
      "lien-property-description",
      "property description requirements in preliminary and lien notices",
      "https://www.law.cornell.edu/wex/mechanic_s_lien",
    ),
    pat: [
      /(description\s+of\s+the\s+(site|property|project)|legal\s+description|job\s+(site|address))/i,
      /(address|lot|parcel|sufficient\s+for\s+identification)/i,
    ],
    why: "Most statutes require a description sufficient for identification, and a project address alone is sometimes held insufficient where multiple parcels are involved.",
    fix: "Give the project address and a legal description or parcel number sufficient to identify the property.",
    sev: "critical",
  },
  {
    id: "CON-115",
    name: "Labor or materials furnished and estimated value",
    cite: stateLaw(
      "lien-notice-contents",
      "the description of labor, services, or materials and the estimated price required in preliminary notices",
      "https://www.law.cornell.edu/wex/mechanic_s_lien",
    ),
    pat: [
      /(labor|services|materials|equipment)\s+(furnished|provided|supplied)/i,
      /(estimated\s+(total\s+)?(price|value|amount)|general\s+description|\$)/i,
    ],
    why: "The estimated price puts the owner on notice of the exposure and, in some states, caps the eventual lien. A notice omitting it is defective on its face.",
    fix: "Describe the labor, services, equipment, or materials furnished, and state the estimated total price.",
  },
  {
    id: "CON-116",
    name: "Statutory warning language",
    cite: stateLaw(
      "lien-warning",
      "the statutory warning to the owner required verbatim in preliminary notices",
      "https://www.law.cornell.edu/wex/mechanic_s_lien",
    ),
    pat: [
      /(notice\s+to\s+(property\s+)?owner|you\s+are\s+hereby\s+notified|important\s+notice)/i,
      /(mechanic'?s\s+lien|may\s+be\s+placed\s+against\s+your\s+property|even\s+(if|though)\s+you\s+have\s+paid)/i,
    ],
    why: "Several states require a bold or capitalized warning in prescribed words. Paraphrasing the statutory text invalidates the notice in those states.",
    fix: "Reproduce the state's warning language verbatim, in the typeface, size, and emphasis the statute prescribes.",
    sev: "critical",
  },
  {
    id: "CON-117",
    name: "Service method and deadline recital",
    cite: stateLaw(
      "lien-notice-service",
      "service method and deadline requirements for preliminary notices",
      "https://www.law.cornell.edu/wex/mechanic_s_lien",
    ),
    pat: [
      /(serv(e|ed|ice)|mail(ed)?|deliver)/i,
      /(certified\s+mail|return\s+receipt|within\s+\d+\s+days|20\s+days|proof\s+of\s+service)/i,
    ],
    why: "Deadlines run from first furnishing (20 days in California, other periods elsewhere) and late notice limits the lien to work performed in the lookback window. The service method is equally prescribed.",
    fix: "State the date of first furnishing, serve by the statutory method (usually certified or registered mail with return receipt), and retain the proof of service.",
    sev: "critical",
  },
]);

export const V5_CONSTRUCTION_RULES: readonly Rule[] = [...DESIGN_BUILD, ...ARCHITECT, ...PRELIEN];

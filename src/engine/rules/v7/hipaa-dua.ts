/**
 * v7 — the HIPAA limited-data-set data use agreement (spec-v49.md §3).
 *
 * A covered entity may disclose a limited data set only under a data use
 * agreement, and 45 C.F.R. § 164.514(e)(4)(ii) lists what that agreement must
 * contain: (A) the permitted uses, (B) who may use or receive the data, and
 * (C)(1)–(5) five commitments by the recipient. One check per item. Read at
 * ecfr.gov on 2026-10-10.
 *
 * Presence only. Nothing here decides whether the data set is in fact a
 * limited data set under (e)(2), or whether the stated purpose is in fact
 * research, public health or health care operations.
 */

import type { Rule } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { pack } from "../v5/_pack.js";
import { v4Cite } from "../v5/_helpers.js";

/** One item of the required contents, cited to its own subparagraph. */
function item(sub: string, label: string): SourceCitation {
  return v4Cite({
    id: `cfr-45-164-514-e-4-ii-${sub.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `45 C.F.R. § 164.514(e)(4)(ii)(${sub}) — ${label}`,
    source_url: "https://www.ecfr.gov/current/title-45/section-164.514",
    retrieved_at: "2026-10-10T00:00:00Z",
  });
}

/** What the agreement calls the data: the limited data set, or the information in it. */
const DATA = String.raw`(?:limited\s+data\s+set|data\s+set|information|data|\bLDS\b|\bPHI\b)`;

const HIPAA_DUA = pack("hipaa-data-use-agreement", "privacy", [
  {
    id: "DUA-001",
    name: "Permitted uses, within research, public health or health care operations",
    cite: item("A", "permitted uses and disclosures, consistent with paragraph (e)(3)"),
    all: true,
    pat: [
      /\b(may|shall|will|must|permitted\s+to|authori[sz]ed\s+to)\s+(only\s+|solely\s+)?(use|disclose)\b|\bpermitted\s+uses?\b/i,
      /\b(research|public\s+health|health\s+care\s+operations|healthcare\s+operations)\b/i,
    ],
    why: "A limited data set may be used or disclosed only for research, public health or health care operations, and the agreement must state the uses it permits. An agreement that permits use for an unnamed purpose does not give the covered entity the assurance the rule requires before it discloses.",
    fix: "State the uses and disclosures the recipient is permitted to make, and that they are for research, public health or health care operations. The agreement may not authorize a use the covered entity itself could not make.",
    sev: "critical",
  },
  {
    id: "DUA-002",
    name: "Who may use or receive the limited data set",
    cite: item("B", "who is permitted to use or receive the limited data set"),
    pat: [
      new RegExp(
        String.raw`\b(who|persons?|individuals?|personnel|employees|investigators?|researchers?|staff|members|team)\b[^.]{0,160}?\b(permitted|authori[sz]ed|allowed|may)\b[^.]{0,80}?\b(use|receive|access)\b`,
        "i",
      ),
      new RegExp(
        String.raw`\b(use|receive|access)\b[^.]{0,120}?${DATA}[^.]{0,120}?\b(limited\s+to|only\s+by|solely\s+by|restricted\s+to)\b`,
        "i",
      ),
      /\b(authori[sz]ed|permitted)\s+(users?|recipients?|persons?|personnel)\b/i,
    ],
    why: "The agreement must establish who is permitted to use or receive the limited data set. Naming the recipient institution is not the same as naming who within it — or which of its collaborators — may see the data.",
    fix: "Name the persons or classes of persons permitted to use or receive the limited data set, such as the principal investigator and the study staff under that person's supervision.",
    sev: "critical",
  },
  {
    id: "DUA-003",
    name: "No use or disclosure beyond the agreement, except as required by law",
    cite: item(
      "C)(1",
      "no use or further disclosure other than as permitted or as otherwise required by law",
    ),
    pat: [
      /\b(not|no)\b[^.]{0,60}?\b(use|disclose)\b[^.]{0,160}?\b(other\s+than|except)\b[^.]{0,120}?\b(permitted|provided|allowed|authori[sz]ed|required\s+by\s+law)\b/i,
      /\b(use|disclose)\b[^.]{0,120}?\bonly\b[^.]{0,120}?\b(as\s+)?(permitted|provided|required\s+by\s+law)\b/i,
    ],
    why: "The recipient must agree not to use or further disclose the information other than as the agreement permits or as otherwise required by law. A statement of what is permitted, with no promise to stop there, leaves that commitment out.",
    fix: "Add the recipient's agreement not to use or further disclose the limited data set other than as permitted by the agreement or as otherwise required by law.",
    sev: "critical",
  },
  {
    id: "DUA-004",
    name: "Appropriate safeguards",
    cite: item("C)(2", "appropriate safeguards to prevent use or disclosure not provided for"),
    pat: [
      /\b(appropriate|reasonable|administrative,?\s+(physical,?\s+)?(and\s+)?technical)\s+safeguards\b|\bsafeguards?\s+to\s+(prevent|protect)\b/i,
    ],
    why: "The recipient must agree to use appropriate safeguards to prevent use or disclosure of the information other than as the agreement provides.",
    fix: "Add the recipient's agreement to use appropriate safeguards to prevent any use or disclosure of the limited data set that the agreement does not provide for.",
    sev: "critical",
  },
  {
    id: "DUA-005",
    name: "Report of any use or disclosure the agreement does not provide for",
    cite: item("C)(3", "report to the covered entity any use or disclosure not provided for"),
    pat: [
      /\b(report|notify)\b[^.]{0,200}?\b(use|disclosure)\b[^.]{0,160}?\b(not\s+(provided|permitted|authori[sz]ed|allowed)|unauthori[sz]ed|in\s+(violation|breach)|becomes?\s+aware)\b/i,
      /\b(unauthori[sz]ed|impermissible)\s+(use|disclosure)\b[^.]{0,200}?\b(report|notify)\b/i,
    ],
    why: "The recipient must agree to report to the covered entity any use or disclosure not provided for by the agreement of which it becomes aware. The covered entity's own duty to act on a pattern of breach depends on hearing of one.",
    fix: "Add the recipient's agreement to report to the covered entity any use or disclosure of the limited data set not provided for by the agreement of which the recipient becomes aware.",
    sev: "critical",
  },
  {
    id: "DUA-006",
    ver: "1.1.0",
    name: "Agents held to the same restrictions",
    cite: item("C)(4", "agents agree to the same restrictions and conditions"),
    pat: [
      /\b(agents?|sub-?contractors?)\b[^.]{0,240}?\b(same|equivalent|no\s+less\s+(restrictive|protective))\b[^.]{0,80}?\b(restrictions?|conditions?|terms|obligations|requirements)\b/i,
    ],
    why: "The recipient must ensure that any agent to whom it provides the limited data set agrees to the same restrictions and conditions that apply to the recipient. Without that, the data leaves the agreement the first time it is handed to a contractor or collaborator.",
    fix: "Add the recipient's agreement to ensure that any agents to whom it provides the limited data set agree to the same restrictions and conditions that apply to the recipient.",
    sev: "critical",
  },
  {
    id: "DUA-007",
    name: "No identifying the information or contacting the individuals",
    cite: item("C)(5", "not identify the information or contact the individuals"),
    all: true,
    pat: [
      /\b(not|no|never|nor)\b[^.]{0,80}?\b(re-?identif\w+|identify)\b|\bno\s+re-?identification\b/i,
      /\b(not|no|never|nor|or)\b[^.]{0,80}?\bcontact\w*\b[^.]{0,60}?\b(individuals?|patients?|subjects?|persons?)\b/i,
    ],
    why: "The recipient must agree not to identify the information and not to contact the individuals. A limited data set still carries dates, city, state and zip code, so the promise not to re-identify is what stands between it and identifiable health information.",
    fix: "Add the recipient's agreement not to identify the information and not to contact the individuals the information is about.",
    sev: "critical",
  },
]);

export const HIPAA_DUA_RULES: readonly Rule[] = HIPAA_DUA;

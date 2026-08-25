/**
 * Shared helpers for the v5 US-catalog rulesets (spec-v45.md).
 *
 * v5 does not introduce a new rule *shape*. It reuses the three v4
 * builders — clause-presence, language-quality, and compound-presence —
 * unchanged, and adds only what a hundred new **US** document families
 * need that v4 did not: a set of citation factories for the American
 * authorities those families actually turn on (the UCC as enacted by the
 * states, Title 26, the FTC's trade regulation rules, FRCP/FRAP, the
 * ABA Model Rules, the state uniform acts, and the agency rulebooks that
 * govern lending, health care, insurance, and construction).
 *
 * Every v5 rule is gated by `applies_to_playbooks` to v5 playbook ids
 * only, so adding this pack cannot change the `result_hash` of any
 * document that matched a pre-v5 family. That is the same additivity
 * contract `docs/verticals.md` states for every pack, and
 * `src/verticals/registry.test.ts` proves it.
 *
 * Rule-id ranges are disjoint from every shipped v4 range: v4 stops at
 * or below `-080` in each of the sixteen sub-domain prefixes (and at
 * `EST-304` for the estate-check deepening), so v5 starts at `-101`
 * everywhere and at `EST-401` for trust/estate.
 */

import { v4Cite } from "../v4/_helpers.js";
import type { SourceCitation } from "../../../dkb/types.js";

export {
  buildV4PresenceRule as presenceRule,
  buildV4LanguageRule as languageRule,
  buildV4CompoundRule as compoundRule,
  expressDenial,
  fullText,
  docTop,
  v4Cite,
  type V4PresenceSpec as PresenceSpec,
  type V4LanguageSpec as LanguageSpec,
  type V4CompoundSpec as CompoundSpec,
} from "../v4/_helpers.js";

/** Slugify a citation label into a stable, lowercase DKB id fragment. */
function slug(text: string): string {
  return text
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

/** A section of the United States Code. */
export function usc(title: string, section: string, label: string): SourceCitation {
  return v4Cite({
    id: `usc-${slug(title)}-${slug(section)}`,
    source: `${title} U.S.C. § ${section} — ${label}`,
    source_url: `https://www.law.cornell.edu/uscode/text/${title}/${section.split("(")[0]}`,
  });
}

/** A part or section of the Code of Federal Regulations. */
export function cfr(title: string, part: string, label: string): SourceCitation {
  return v4Cite({
    id: `cfr-${slug(title)}-${slug(part)}`,
    source: `${title} C.F.R. § ${part} — ${label}`,
    source_url: `https://www.ecfr.gov/current/title-${title}`,
  });
}

/**
 * A Uniform Commercial Code article/section. The UCC is not federal law:
 * it is a uniform act enacted, with variations, by each state, so the
 * citation names the uniform text and says so.
 */
export function ucc(section: string, label: string): SourceCitation {
  return v4Cite({
    id: `ucc-${slug(section)}`,
    source: `U.C.C. § ${section} — ${label} (uniform text; enacted with state variations)`,
    source_url: `https://www.law.cornell.edu/ucc/${section.split("-")[0]?.replace(/\D/g, "") ?? "1"}`,
    license: "Uniform Law Commission / ALI uniform text (citation only)",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** A Uniform Law Commission uniform or model act. */
export function uniformAct(name: string, label: string): SourceCitation {
  return v4Cite({
    id: `ula-${slug(name)}`,
    source: `${name} — ${label} (uniform act; enacted with state variations)`,
    source_url: "https://www.uniformlaws.org/acts",
    license: "Uniform Law Commission uniform text (citation only)",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** A Federal Rule of Civil Procedure. */
export function frcp(rule: string, label: string): SourceCitation {
  return v4Cite({
    id: `frcp-${slug(rule)}`,
    source: `Fed. R. Civ. P. ${rule} — ${label}`,
    source_url: `https://www.law.cornell.edu/rules/frcp/rule_${rule.split("(")[0]}`,
  });
}

/** A Federal Rule of Evidence. */
export function fre(rule: string, label: string): SourceCitation {
  return v4Cite({
    id: `fre-${slug(rule)}`,
    source: `Fed. R. Evid. ${rule} — ${label}`,
    source_url: `https://www.law.cornell.edu/rules/fre/rule_${rule.split("(")[0]}`,
  });
}

/**
 * An ABA Model Rule of Professional Conduct. The Model Rules are not law
 * anywhere: each state adopts its own version, so the citation says so
 * and the rule text never asserts that a jurisdiction's rule matches.
 */
export function modelRule(rule: string, label: string): SourceCitation {
  return v4Cite({
    id: `aba-mrpc-${slug(rule)}`,
    source: `ABA Model Rule of Professional Conduct ${rule} — ${label} (model text; each state adopts its own version)`,
    source_url:
      "https://www.americanbar.org/groups/professional_responsibility/publications/model_rules_of_professional_conduct/",
    license: "ABA Model Rules (citation only — copying restricted)",
    license_url: "https://www.americanbar.org/",
  });
}

/** An FTC trade regulation rule, guide, or enforcement policy statement. */
export function ftc(name: string, label: string): SourceCitation {
  return v4Cite({
    id: `ftc-${slug(name)}`,
    source: `FTC — ${name}: ${label}`,
    source_url: "https://www.ftc.gov/legal-library/browse/rules",
  });
}

/** An IRS Code section, regulation, revenue ruling, or notice. */
export function irs(ref: string, label: string): SourceCitation {
  return v4Cite({
    id: `irs-${slug(ref)}`,
    source: `${ref} — ${label}`,
    source_url: "https://www.irs.gov/",
  });
}

/** A named federal agency rulebook, handbook, or program requirement. */
export function agency(name: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `agency-${slug(name)}`,
    source: `${name} — ${label}`,
    source_url: url,
  });
}

/**
 * A body of state law that every US state has in some form, cited
 * generically because the operative text differs state to state. Always
 * phrase `label` so the reader knows the specific state's statute
 * governs, not this citation.
 */
export function stateLaw(topic: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `state-${slug(topic)}`,
    source: `State ${topic} statutes — ${label} (varies by state; the enacting state's text governs)`,
    source_url: url,
    license: "State statutory law (citation only)",
    license_url: url,
  });
}

/**
 * An industry standard form or trade-association baseline (AIA, NVCA,
 * ISDA, LSTA, ACORD, AAA/JAMS). These are copyrighted forms: cited as a
 * drafting baseline, never reproduced.
 */
export function standardForm(name: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `form-${slug(name)}`,
    source: `${name} — ${label}`,
    source_url: url,
    license: "Industry standard form (citation only — copying restricted)",
    license_url: url,
  });
}

/**
 * Common professional practice with no single citable authority — the
 * honest label for a check grounded in how the document is customarily
 * drafted rather than in a rule that compels the clause.
 */
export function practice(topic: string, label: string): SourceCitation {
  return v4Cite({
    id: `practice-${slug(topic)}`,
    source: `Customary US drafting practice — ${label} (no single controlling authority)`,
    source_url: "https://www.law.cornell.edu/wex",
    license: "Practice note (no statutory authority asserted)",
    license_url: "https://www.law.cornell.edu/wex",
  });
}

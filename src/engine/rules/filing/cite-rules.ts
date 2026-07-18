/**
 * CITE-### — authority-citation lint (add-authority-citation-lint).
 *
 * Deterministic citation hygiene for litigation briefs: well-formedness,
 * dangling short forms, and table-of-authorities reconciliation. Gated to the
 * filing family (`applies_to_playbooks: FILING_PLAYBOOK_IDS`) and active on any
 * filing brief — unlike the FILE format rules, citation linting does not need a
 * court profile.
 *
 * Honesty posture (rendered via the filing scope-of-review, and stated in every
 * finding): the pack checks citation FORMAT and INTERNAL CONSISTENCY only. It
 * never checks that a cited case exists, is accurately quoted, or is still good
 * law — that requires a database the no-server posture excludes, and remains
 * the filer's duty. TOA reconciliation is by authority, not page number (the
 * flattened tree carries no page boundaries).
 */

import type { DocPosition } from "../../../extract/types.js";
import type { Finding, Rule, RuleContext } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { forEachParagraph, posInParagraph } from "../../../extract/walk.js";
import { extractCitations, type ParsedCitation } from "../../../extract/citations.js";
import { INDIGO_BOOK_SOURCE } from "../../../extract/citation-grammar.js";
import { detectFilingBlocks } from "../../../filing/detect.js";
import { FILING_PLAYBOOK_IDS } from "./rules.js";

const GATE = Array.from(FILING_PLAYBOOK_IDS);

/** The Indigo Book grammar source as a report citation. */
const INDIGO_CITE: SourceCitation = {
  id: `citation-manual:${INDIGO_BOOK_SOURCE.cite}`,
  source: INDIGO_BOOK_SOURCE.cite,
  source_url: INDIGO_BOOK_SOURCE.url,
  retrieved_at: INDIGO_BOOK_SOURCE.retrieved_at,
  license: "CC0 1.0 (public domain)",
  license_url: "https://creativecommons.org/publicdomain/zero/1.0/",
};

/** FRAP 28(a)(3) — the table-of-authorities requirement, for CITE-004. */
const FRAP_28A3: SourceCitation = {
  id: "court-rule:Fed. R. App. P. 28(a)(3)",
  source: "Fed. R. App. P. 28(a)(3)",
  source_url: "https://www.law.cornell.edu/rules/frap/rule_28",
  retrieved_at: "2026-07-15",
  license: "Public rule text (U.S. government / court work)",
  license_url: "https://www.usa.gov/government-works",
};

type Located = { c: ParsedCitation; sectionId: string; pos: DocPosition; flatStart: number };

/** Walk the document in order, extracting every citation with its position. */
function analyze(ctx: RuleContext): { located: Located[]; toaSectionId?: string } {
  const located: Located[] = [];
  forEachParagraph(ctx.tree, (p) => {
    for (const c of extractCitations(p.text)) {
      const pos = posInParagraph(p, c.start, c.end);
      located.push({ c, sectionId: p.section.id, pos, flatStart: pos.start });
    }
  });
  located.sort((a, b) => a.flatStart - b.flatStart);
  const toa = detectFilingBlocks(ctx.tree).find((b) => b.block === "table-of-authorities");
  return { located, toaSectionId: toa?.section_id };
}

function cite(
  rule: Rule,
  args: {
    title: string;
    description: string;
    explanation: string;
    recommendation?: string;
    position: DocPosition;
    citations: SourceCitation[];
  },
): Finding {
  return makeFinding({
    rule,
    severity: "warning",
    title: args.title,
    description: args.description,
    excerptText: "",
    explanation: args.explanation,
    recommendation: args.recommendation,
    position: args.position,
    source_citations: args.citations,
  });
}

const NON_VERIFICATION =
  "This is a format/consistency check only. Vaulytica does not verify that any cited authority exists, is quoted accurately, or is still good law — that remains the filer's responsibility.";

const topPos = (ctx: RuleContext): DocPosition => ({
  section_id: ctx.tree.sections[0]?.id ?? "",
  start: 0,
  end: 0,
});

/** First name token of a "X v. Y" or supra reference, lowercased. */
function firstParty(refersTo: string | undefined): string | undefined {
  if (!refersTo) return undefined;
  const first = refersTo.split(/\s+v\.\s+|,|\s/)[0];
  return first ? first.toLowerCase() : undefined;
}

// CITE-001 — Malformed citation (matches a citation shape but violates the grammar).
export const CITE_001: Rule = {
  id: "CITE-001",
  version: "1.0.0",
  name: "Malformed citation",
  category: "filing",
  default_severity: "warning",
  description:
    "Flags text that matches a case-citation shape (volume reporter page) but whose reporter abbreviation is not in the Indigo Book reporter table, or which is missing a page.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const { located } = analyze(ctx);
    const bad = located.filter((l) => l.c.kind === "case" && l.c.well_formed === false);
    if (bad.length === 0) return null;
    const examples = [...new Set(bad.map((l) => `"${l.c.raw.trim()}"`))].slice(0, 5).join(", ");
    return cite(CITE_001, {
      title: `${bad.length} malformed citation${bad.length === 1 ? "" : "s"}`,
      description: `${bad.length} citation-shaped reference${bad.length === 1 ? " uses" : "s use"} an unrecognized reporter abbreviation or lack${bad.length === 1 ? "s" : ""} a page: ${examples}.`,
      explanation: `Checked against the Indigo Book reporter table. ${NON_VERIFICATION}`,
      recommendation: "Confirm the reporter abbreviation and page against The Indigo Book 2.0.",
      position: bad[0]!.pos,
      citations: [INDIGO_CITE],
    });
  },
};

// CITE-002 — Orphaned `id.` (no citation precedes it in the same section).
export const CITE_002: Rule = {
  id: "CITE-002",
  version: "1.0.0",
  name: "Orphaned id.",
  category: "filing",
  default_severity: "warning",
  description:
    "Flags an `id.` short form with no full or short citation preceding it within the same section (scope boundary).",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const { located } = analyze(ctx);
    const orphans: Located[] = [];
    for (let i = 0; i < located.length; i++) {
      const l = located[i]!;
      if (l.c.kind !== "id") continue;
      // A prior citation (not itself an `id.`) earlier in the SAME section.
      const hasAntecedent = located
        .slice(0, i)
        .some((p) => p.sectionId === l.sectionId && p.c.kind !== "id");
      if (!hasAntecedent) orphans.push(l);
    }
    if (orphans.length === 0) return null;
    return cite(CITE_002, {
      title: `${orphans.length} orphaned "id." reference${orphans.length === 1 ? "" : "s"}`,
      description: `${orphans.length} "id." short form${orphans.length === 1 ? "" : "s"} have no citation preceding them in their section, so the authority they refer to is ambiguous.`,
      explanation: `An "id." must follow an immediately-preceding citation. ${NON_VERIFICATION}`,
      recommendation: "Replace the orphaned id. with the full citation it refers to.",
      position: orphans[0]!.pos,
      citations: [INDIGO_CITE],
    });
  },
};

// CITE-003 — Dangling supra / short form (refers to an authority never cited in full).
export const CITE_003: Rule = {
  id: "CITE-003",
  version: "1.0.0",
  name: "Dangling supra / short form",
  category: "filing",
  default_severity: "warning",
  description:
    "Flags a `supra` or case short form that refers to an authority never introduced by a full citation earlier in the document.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const { located } = analyze(ctx);
    // An authority is "introduced" by a short-case name that has a full case
    // citation within 60 flat chars after it ("Name v. Name, Vol Rep Page").
    const introduced = new Map<string, number>(); // firstParty -> flatStart of intro
    for (const l of located) {
      if (l.c.kind !== "short-case") continue;
      const followed = located.some(
        (o) =>
          o.c.kind === "case" &&
          o.flatStart >= l.flatStart &&
          o.flatStart - (l.flatStart + l.c.raw.length) <= 60,
      );
      const key = firstParty(l.c.refers_to);
      if (followed && key && !introduced.has(key)) introduced.set(key, l.flatStart);
    }
    const dangling: Located[] = [];
    for (const l of located) {
      const key = firstParty(l.c.refers_to);
      if (!key) continue;
      if (l.c.kind === "supra") {
        const intro = introduced.get(key);
        if (intro === undefined || intro > l.flatStart) dangling.push(l);
      } else if (l.c.kind === "short-case") {
        // A short-case that is NOT itself an introduction and was never introduced.
        const isIntro = introduced.get(key) === l.flatStart;
        if (!isIntro && !introduced.has(key)) dangling.push(l);
      }
    }
    if (dangling.length === 0) return null;
    const examples = dangling
      .slice(0, 5)
      .map((l) => `"${l.c.raw.trim()}"`)
      .join(", ");
    return cite(CITE_003, {
      title: `${dangling.length} dangling short-form reference${dangling.length === 1 ? "" : "s"}`,
      description: `${dangling.length} short-form reference${dangling.length === 1 ? " points" : "s point"} to an authority never cited in full earlier: ${examples}.`,
      explanation: `A "supra" or case short form must follow a full citation of the same authority. ${NON_VERIFICATION}`,
      recommendation:
        "Add a full citation for the authority before its first short-form reference.",
      position: dangling[0]!.pos,
      citations: [INDIGO_CITE],
    });
  },
};

// CITE-004 — Table-of-authorities reconciliation (both directions).
export const CITE_004: Rule = {
  id: "CITE-004",
  version: "1.0.0",
  name: "Table of authorities reconciliation",
  category: "filing",
  default_severity: "warning",
  description:
    "Reconciles the authorities named in the table of authorities against those cited in the body, in both directions. Reconciliation is by authority, not page number.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const { located, toaSectionId } = analyze(ctx);
    if (!toaSectionId) return null; // no TOA to reconcile (FILE-006 flags absence)
    const keyOf = (c: ParsedCitation): string | undefined => {
      if (c.kind === "case" && c.reporter && c.volume && c.page)
        return `${c.volume} ${c.reporter} ${c.page}`.toLowerCase();
      if (c.kind === "short-case") return firstParty(c.refers_to);
      if (c.kind === "statute" || c.kind === "rule") return c.raw.trim().toLowerCase();
      return undefined;
    };
    const toaKeys = new Set<string>();
    const bodyKeys = new Set<string>();
    for (const l of located) {
      const k = keyOf(l.c);
      if (!k) continue;
      if (l.sectionId === toaSectionId) toaKeys.add(k);
      else bodyKeys.add(k);
    }
    // Single-section ingest (plain text / paste) puts the TOA and the body
    // in ONE section, so every citation lands in the TOA bucket and the
    // rule could never pass — a structural 100% false accusation (audit).
    // With no citations outside the TOA's section, reconciliation is
    // meaningless, not a violation: refuse.
    if (bodyKeys.size === 0) return null;
    const bodyNotInToa = [...bodyKeys].filter((k) => !toaKeys.has(k));
    const toaNotInBody = [...toaKeys].filter((k) => !bodyKeys.has(k));
    if (bodyNotInToa.length === 0 && toaNotInBody.length === 0) return null;
    const parts: string[] = [];
    if (bodyNotInToa.length > 0)
      parts.push(`${bodyNotInToa.length} cited in the body but absent from the table`);
    if (toaNotInBody.length > 0)
      parts.push(`${toaNotInBody.length} listed in the table but not found in the body`);
    return cite(CITE_004, {
      title: "Table of authorities does not reconcile with the body",
      description: `${parts.join("; ")}. FRAP 28(a)(3) requires the table to list the authorities cited, with body references.`,
      explanation: `Reconciliation is by authority (volume-reporter-page or party name), not by page number — the flattened text carries no page boundaries. ${NON_VERIFICATION}`,
      recommendation: "Reconcile the table of authorities with the citations in the body.",
      position: topPos(ctx),
      citations: [FRAP_28A3, INDIGO_CITE],
    });
  },
};

// CITE-005 — Inconsistent short forms for the same authority.
export const CITE_005: Rule = {
  id: "CITE-005",
  version: "1.0.0",
  name: "Inconsistent short forms",
  category: "filing",
  default_severity: "warning",
  description:
    "Flags a single authority (introduced as `A v. B`) that is later short-cited by both party names, which reads as two different authorities.",
  dkb_citations: [],
  applies_to_playbooks: GATE,
  check(ctx: RuleContext): Finding | null {
    const { located } = analyze(ctx);
    // Lead parties of every introduced authority: a later "Wade, supra"
    // presumptively refers to *Wade v. Hunt* when that case was introduced
    // too — not an inconsistent short form of *Roe v. Wade* (audit).
    const introducedLeads = new Set<string>();
    for (const l of located) {
      if (l.c.kind !== "short-case" || !l.c.refers_to) continue;
      const m = /^([A-Za-z]+)\s+v\.\s+/.exec(l.c.refers_to);
      if (m) introducedLeads.add(m[1]!.toLowerCase());
    }
    const inconsistent: string[] = [];
    for (const l of located) {
      if (l.c.kind !== "short-case" || !l.c.refers_to) continue;
      const m = /^([A-Za-z]+)\s+v\.\s+([A-Za-z]+)/.exec(l.c.refers_to);
      if (!m) continue;
      const a = m[1]!.toLowerCase();
      const b = m[2]!.toLowerCase();
      if (introducedLeads.has(b)) continue; // b is another authority's lead party
      // Later supra/short references by first party token.
      const later = located.filter((o) => o.flatStart > l.flatStart);
      const usesA = later.some((o) => firstParty(o.c.refers_to) === a);
      const usesB = later.some((o) => firstParty(o.c.refers_to) === b);
      if (usesA && usesB) inconsistent.push(`${m[1]} v. ${m[2]}`);
    }
    if (inconsistent.length === 0) return null;
    const uniq = [...new Set(inconsistent)];
    return cite(CITE_005, {
      title: `Inconsistent short form${uniq.length === 1 ? "" : "s"} for ${uniq.length} authorit${uniq.length === 1 ? "y" : "ies"}`,
      description: `${uniq
        .slice(0, 5)
        .map((s) => `"${s}"`)
        .join(
          ", ",
        )} ${uniq.length === 1 ? "is" : "are"} short-cited by both party names, which reads as two different authorities.`,
      explanation: `Use one consistent short form per authority. ${NON_VERIFICATION}`,
      recommendation:
        "Pick one short form (usually the first-named party) and use it consistently.",
      position: topPos(ctx),
      citations: [INDIGO_CITE],
    });
  },
};

export const CITE_RULES: readonly Rule[] = [CITE_001, CITE_002, CITE_003, CITE_004, CITE_005];

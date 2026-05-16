/**
 * v4 cross-document rule set (spec-v4.md §10, Step 43).
 *
 * Seven new rule families that join the seven v3 CC-NNN rules on the
 * existing consistency engine at `src/engine/consistency/`. Each rule
 * is a pure function over the bundle of parsed documents and emits
 * findings that cite every contributing document with the conflicting
 * text from each — the same {@link ConsistencyFinding} shape v3 ships.
 *
 * Coverage (spec §10):
 *
 *   CROSS-PARTY-001       Inconsistent party name across documents
 *   CROSS-JURIS-001       Governing-law inconsistency across 3+ docs
 *   CROSS-DEFTERM-001     Defined term with different definitions
 *   CROSS-DATE-001        Effective-date chronology impossible
 *   CROSS-AMOUNT-001      Aggregate liability cap mismatch
 *   CROSS-MISSING-001     Referenced companion document absent from bundle
 *   CROSS-PRECEDENCE-001  Order-of-precedence contradicted across documents
 *
 * The v3 CC-NNN rules continue to ship; CROSS-NNN rules either cover a
 * different surface (CROSS-PARTY / DEFTERM / DATE / AMOUNT / MISSING)
 * or fire at a different granularity than the v3 analogue (CROSS-JURIS
 * fires only when 3+ docs are in the bundle; CROSS-PRECEDENCE fires
 * only when two documents both claim controlling status).
 */

import type { ConsistencyRule, ConsistencyFinding, DocKind } from "../../types.js";
import { findByKind, kindOf, fullText } from "../../_helpers.js";
import { makeConsistencyFinding, textExcerpt } from "../_finding.js";
import {
  effectiveDateOf,
  findDefinedTermMismatches,
  findPartyNameMismatches,
  firstLiabilityCap,
} from "./_helpers.js";
import { forEachParagraph } from "../../../../extract/walk.js";

const V4_VERSION = "1.0.0";

/* -------------------- CROSS-PARTY-001 ----------------------------- */

export const CROSS_PARTY_001: ConsistencyRule = {
  id: "CROSS-PARTY-001",
  version: V4_VERSION,
  name: "Inconsistent party name across documents",
  category: "consistency",
  default_severity: "info",
  description:
    "Two documents reference what appears to be the same party under slightly different legal names (e.g., 'Acme Corp.' vs 'Acme, Inc.'). Same entity in counterparty-speak; lenders, IP licensors, and tax authorities sometimes care.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const out: ConsistencyFinding[] = [];
    const seen = new Set<string>();
    for (let i = 0; i < ctx.documents.length; i++) {
      for (let j = i + 1; j < ctx.documents.length; j++) {
        const a = ctx.documents[i]!;
        const b = ctx.documents[j]!;
        for (const m of findPartyNameMismatches(a, b)) {
          const key = `${m.canonical}|${m.a.name}|${m.b.name}|${a.doc_id}|${b.doc_id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push(
            makeConsistencyFinding({
              rule: CROSS_PARTY_001,
              title: `Party "${m.a.name}" / "${m.b.name}" appears to be the same entity under different legal names`,
              description: `Document "${a.doc_id}" names "${m.a.name}"; document "${b.doc_id}" names "${m.b.name}". They normalize to "${m.canonical}".`,
              explanation:
                "Cross-document party-name drift creates downstream chain-of-title risk. Banks, IP licensors, and state tax authorities take the legal name as it appears in the executed copy. Confirm both documents name the same legal entity, or update one.",
              recommendation:
                "Pick one canonical legal name (the one on file with the Secretary of State of the formation jurisdiction is the safest default) and amend the other document to match.",
              excerpts: [
                textExcerpt(a, m.a.name, m.a.positions[0]?.start ?? 0, m.a.positions[0]?.end ?? m.a.name.length),
                textExcerpt(b, m.b.name, m.b.positions[0]?.start ?? 0, m.b.positions[0]?.end ?? m.b.name.length),
              ],
            }),
          );
        }
      }
    }
    return out;
  },
};

/* -------------------- CROSS-JURIS-001 ----------------------------- */

export const CROSS_JURIS_001: ConsistencyRule = {
  id: "CROSS-JURIS-001",
  version: V4_VERSION,
  name: "Governing law inconsistent across the transaction bundle (3+ documents)",
  category: "consistency",
  default_severity: "warning",
  description:
    "When three or more documents are loaded together and the governing-law clauses disagree, the order-of-precedence among them must explicitly state which one controls. v3's CC-005 covers any-pair governing-law misalignment; CROSS-JURIS-001 fires at the bundle level when the bundle is large enough that the conflict requires a coordinated fix.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 3) return [];
    const laws = new Map<string, Array<{ doc_id: string; source_file_name: string; raw: string; start: number; end: number }>>();
    for (const doc of ctx.documents) {
      for (const j of doc.extracted.jurisdictions) {
        if (j.clause_kind !== "governing-law") continue;
        const key = canonicalLaw(j.raw_text);
        const list = laws.get(key) ?? [];
        list.push({
          doc_id: doc.doc_id,
          source_file_name: doc.source_file_name,
          raw: j.raw_text,
          start: j.position.start,
          end: j.position.end,
        });
        laws.set(key, list);
      }
    }
    if (laws.size < 2) return [];
    const keys = [...laws.keys()].sort();
    const excerpts = keys.slice(0, 4).flatMap((k) => {
      const entry = laws.get(k)![0]!;
      return [
        {
          doc_id: entry.doc_id,
          source_file_name: entry.source_file_name,
          text: entry.raw,
          start_offset: entry.start,
          end_offset: entry.end,
        },
      ];
    });
    return [
      makeConsistencyFinding({
        rule: CROSS_JURIS_001,
        title: `${ctx.documents.length}-document bundle spans ${laws.size} different governing-law clauses`,
        description: `Documents in this bundle pick: ${keys.join(", ")}. A 3+ document bundle with two or more governing laws requires an explicit precedence statement.`,
        explanation:
          "Multi-document transactions (MSA + DPA + BAA, or merger + ancillary agreements) need a single forum-selection story for the whole bundle to be litigated coherently. The order-of-precedence clause should name which document's governing-law selection controls the rest.",
        recommendation:
          "Pick one governing law for the operative document (typically the MSA or the Master Agreement), add a recital explaining any deliberate divergence in the ancillary documents, and confirm the order-of-precedence clause carves the divergence out explicitly.",
        excerpts,
      }),
    ];
  },
};

/* -------------------- CROSS-DEFTERM-001 --------------------------- */

export const CROSS_DEFTERM_001: ConsistencyRule = {
  id: "CROSS-DEFTERM-001",
  version: V4_VERSION,
  name: "Defined term carries different definitions across documents",
  category: "consistency",
  default_severity: "warning",
  description:
    "A defined term (e.g., 'Customer Data') is defined narrowly in one document and broadly in another. The looser definition controls in practice because every operative clause in either document reads back to its own definitions section — and a counterparty will pick the definition that suits its position.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const out: ConsistencyFinding[] = [];
    const seen = new Set<string>();
    for (let i = 0; i < ctx.documents.length; i++) {
      for (let j = i + 1; j < ctx.documents.length; j++) {
        const a = ctx.documents[i]!;
        const b = ctx.documents[j]!;
        for (const m of findDefinedTermMismatches(a, b)) {
          const key = `${m.term}|${a.doc_id}|${b.doc_id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push(
            makeConsistencyFinding({
              rule: CROSS_DEFTERM_001,
              title: `"${m.term}" is defined differently in "${a.doc_id}" and "${b.doc_id}"`,
              description: `Document "${a.doc_id}" defines "${m.term}" as: "${truncate(m.a.definition, 200)}". Document "${b.doc_id}" defines it as: "${truncate(m.b.definition, 200)}".`,
              explanation:
                "Cross-document defined-term drift is the single most-litigated source of contract ambiguity. The party with the more favorable definition will read every operative clause back to its own document; resolving it after dispute costs orders of magnitude more than resolving it during drafting.",
              recommendation:
                "Pick one canonical definition (typically the operative document's), then either remove the redundant definition from the other document or replace it with a back-reference (\"Capitalized terms not defined herein have the meanings given in [Operative Agreement]\").",
              excerpts: [
                textExcerpt(a, m.a.definition, m.a.start, m.a.end),
                textExcerpt(b, m.b.definition, m.b.start, m.b.end),
              ],
            }),
          );
        }
      }
    }
    return out;
  },
};

/* -------------------- CROSS-DATE-001 ------------------------------ */

export const CROSS_DATE_001: ConsistencyRule = {
  id: "CROSS-DATE-001",
  version: V4_VERSION,
  name: "Referenced effective date post-dates the referring document",
  category: "consistency",
  default_severity: "warning",
  description:
    "Document A references document B's effective date (or vice versa), but the referenced date falls after the referring document's own effective date. Either the document is back-dated or the cross-reference is stale.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const out: ConsistencyFinding[] = [];
    for (let i = 0; i < ctx.documents.length; i++) {
      for (let j = 0; j < ctx.documents.length; j++) {
        if (i === j) continue;
        const a = ctx.documents[i]!;
        const b = ctx.documents[j]!;
        const dateA = effectiveDateOf(a);
        const dateB = effectiveDateOf(b);
        if (!dateA || !dateB) continue;
        if (dateA >= dateB) continue;
        // Does A reference B explicitly?
        const aText = fullText(a);
        const bKindLabel = kindLabel(kindOf(b));
        const refersToB = bKindLabel ? new RegExp(`\\b${bKindLabel}\\b`, "i").test(aText) : false;
        if (!refersToB) continue;
        out.push(
          makeConsistencyFinding({
            rule: CROSS_DATE_001,
            title: `"${a.doc_id}" (effective ${dateA}) references "${b.doc_id}" (effective ${dateB}) — chronology impossible`,
            description: `${a.doc_id} is dated ${dateA} and references the ${bKindLabel}, but the ${bKindLabel} is itself dated ${dateB}.`,
            explanation:
              "A reference to a later document implies either back-dating or a misaligned cross-reference. Either case is interpretation-bait under contra proferentem and most state evidence rules.",
            recommendation:
              "Confirm both documents' effective dates and either re-execute the earlier one with the matching reference removed, or align the dates with an explicit recital.",
            excerpts: [
              {
                doc_id: a.doc_id,
                source_file_name: a.source_file_name,
                text: `Effective date: ${dateA}`,
                start_offset: 0,
                end_offset: dateA.length,
              },
              {
                doc_id: b.doc_id,
                source_file_name: b.source_file_name,
                text: `Effective date: ${dateB}`,
                start_offset: 0,
                end_offset: dateB.length,
              },
            ],
          }),
        );
      }
    }
    return out;
  },
};

/* -------------------- CROSS-AMOUNT-001 ---------------------------- */

export const CROSS_AMOUNT_001: ConsistencyRule = {
  id: "CROSS-AMOUNT-001",
  version: V4_VERSION,
  name: "Aggregate liability cap mismatch across documents",
  category: "consistency",
  default_severity: "warning",
  description:
    "Two documents in the bundle state different aggregate-liability caps. The lower cap controls in practice for any conduct that touches both documents; if the higher cap was the intent, the carve-out must be stated explicitly.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const caps = ctx.documents
      .map((d) => ({ doc: d, cap: firstLiabilityCap(d) }))
      .filter((x): x is { doc: typeof x.doc; cap: NonNullable<typeof x.cap> } => x.cap !== null);
    if (caps.length < 2) return [];
    // Find the lowest and highest capped docs; flag if they differ.
    let lo = caps[0]!;
    let hi = caps[0]!;
    for (const c of caps) {
      if (c.cap.amount_usd < lo.cap.amount_usd) lo = c;
      if (c.cap.amount_usd > hi.cap.amount_usd) hi = c;
    }
    if (lo.cap.amount_usd === hi.cap.amount_usd) return [];
    return [
      makeConsistencyFinding({
        rule: CROSS_AMOUNT_001,
        title: `Aggregate liability caps differ: $${lo.cap.amount_usd.toLocaleString()} in "${lo.doc.doc_id}" vs $${hi.cap.amount_usd.toLocaleString()} in "${hi.doc.doc_id}"`,
        description: `"${lo.doc.doc_id}" caps liability at $${lo.cap.amount_usd.toLocaleString()}; "${hi.doc.doc_id}" caps it at $${hi.cap.amount_usd.toLocaleString()}. The lower cap will control for any liability that touches both documents.`,
        explanation:
          "Cap mismatch is one of the most common multi-document drafting errors. Operatively the lower cap wins; a party that wanted the higher cap to control for one stream of conduct must carve it out explicitly in the document the conduct comes under.",
        recommendation:
          "Reconcile the caps to a single number, or add a carve-out clause naming which conduct gets which cap with a clear precedence rule.",
        excerpts: [
          textExcerpt(lo.doc, lo.cap.raw_text, lo.cap.start, lo.cap.end),
          textExcerpt(hi.doc, hi.cap.raw_text, hi.cap.start, hi.cap.end),
        ],
      }),
    ];
  },
};

/* -------------------- CROSS-MISSING-001 --------------------------- */

const COMPANION_REFERENCE_PATTERNS: Array<{ kind: DocKind; pattern: RegExp; label: string }> = [
  { kind: "dpa", pattern: /\b(data\s+processing\s+(?:agreement|addendum))\b/i, label: "DPA / Data Processing Agreement" },
  { kind: "baa", pattern: /\b(business\s+associate\s+agreement)\b/i, label: "BAA / Business Associate Agreement" },
  { kind: "sow", pattern: /\b(statement\s+of\s+work)\b/i, label: "SOW / Statement of Work" },
];

export const CROSS_MISSING_001: ConsistencyRule = {
  id: "CROSS-MISSING-001",
  version: V4_VERSION,
  name: "Referenced companion document absent from the bundle",
  category: "consistency",
  default_severity: "warning",
  description:
    "An operative document references a companion document by family name (e.g., 'DPA attached as Schedule B', 'as set forth in the Business Associate Agreement') but no document of that family is present in the bundle.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 1) return [];
    const out: ConsistencyFinding[] = [];
    const presentKinds = new Set<DocKind>(ctx.documents.map(kindOf));
    for (const doc of ctx.documents) {
      for (const ref of COMPANION_REFERENCE_PATTERNS) {
        // Skip when the referencing doc *is* the companion family.
        if (kindOf(doc) === ref.kind) continue;
        if (presentKinds.has(ref.kind)) continue;
        // Find the paragraph that names the companion document.
        type ParaHit = { text: string; section_id?: string; start: number; end: number };
        const slot: { value: ParaHit | null } = { value: null };
        forEachParagraph(doc.tree, (p) => {
          if (slot.value) return;
          if (ref.pattern.test(p.text)) {
            slot.value = { text: p.text, section_id: p.section.id || undefined, start: p.start, end: p.end };
          }
        });
        if (!slot.value) continue;
        const found: ParaHit = slot.value;
        out.push(
          makeConsistencyFinding({
            rule: CROSS_MISSING_001,
            title: `"${doc.doc_id}" references the ${ref.label} but no ${ref.label} is in the bundle`,
            description: `${doc.doc_id} mentions the ${ref.label} but the bundle only contains: ${[...presentKinds].join(", ")}. The cross-reference is unverifiable on this bundle.`,
            explanation:
              "Operative cross-references that the linter cannot resolve are a flag the reviewing counsel needs. Either the companion document is missing from the package, or the reference is a leftover from a template that should have been removed.",
            recommendation:
              "Either add the referenced ${ref.label} to the bundle or strike the reference if no companion document was intended.".replace("${ref.label}", ref.label),
            excerpts: [
              {
                doc_id: doc.doc_id,
                source_file_name: doc.source_file_name,
                text: truncate(found.text, 480),
                section_id: found.section_id,
                start_offset: found.start,
                end_offset: found.end,
              },
            ],
          }),
        );
      }
    }
    return out;
  },
};

/* -------------------- CROSS-PRECEDENCE-001 ------------------------ */

export const CROSS_PRECEDENCE_001: ConsistencyRule = {
  id: "CROSS-PRECEDENCE-001",
  version: V4_VERSION,
  name: "Order-of-precedence contradicted across documents",
  category: "consistency",
  default_severity: "warning",
  description:
    "Two documents in the bundle each claim to control in the event of conflict (e.g., MSA says 'MSA controls'; SOW says 'SOW controls'). One must win at execution time and the documents need to agree which one.",
  requires: [],
  check(ctx): ConsistencyFinding[] {
    if (ctx.documents.length < 2) return [];
    const claimants: Array<{
      doc_id: string;
      source_file_name: string;
      excerpt: string;
      section_id?: string;
      start: number;
      end: number;
    }> = [];
    for (const doc of ctx.documents) {
      const text = fullText(doc);
      // Find the "this Agreement / MSA / SOW / Annex controls" claim.
      const m = text.match(
        /\b(this\s+(?:agreement|msa|master\s+services?\s+agreement|sow|statement\s+of\s+work|annex|exhibit|schedule)|the\s+(?:msa|master\s+services?\s+agreement|sow|statement\s+of\s+work))\s+(?:shall\s+)?(?:controls?|govern[s]?|prevails?|takes?\s+precedence)\b/i,
      );
      if (!m) continue;
      // Locate the paragraph for the excerpt.
      const start = text.indexOf(m[0]);
      const end = start + m[0].length;
      // Walk paragraphs to find the one that contains the match for section_id.
      type ParaHit = { text: string; section_id?: string; start: number; end: number };
      const slot: { value: ParaHit | null } = { value: null };
      forEachParagraph(doc.tree, (p) => {
        if (slot.value) return;
        if (p.text.includes(m[0])) {
          slot.value = { text: p.text, section_id: p.section.id || undefined, start: p.start, end: p.end };
        }
      });
      const para = slot.value;
      claimants.push({
        doc_id: doc.doc_id,
        source_file_name: doc.source_file_name,
        excerpt: para ? para.text : m[0],
        section_id: para?.section_id,
        start: para?.start ?? start,
        end: para?.end ?? end,
      });
    }
    if (claimants.length < 2) return [];
    // Two-claimant clash is enough; pick the lexicographically first pair
    // for a single deterministic finding.
    claimants.sort((a, b) => (a.doc_id < b.doc_id ? -1 : a.doc_id > b.doc_id ? 1 : 0));
    const a = claimants[0]!;
    const b = claimants[1]!;
    return [
      makeConsistencyFinding({
        rule: CROSS_PRECEDENCE_001,
        title: `Both "${a.doc_id}" and "${b.doc_id}" claim controlling status`,
        description: `${a.doc_id} states its own controlling status; ${b.doc_id} states its own controlling status. The bundle is internally inconsistent.`,
        explanation:
          "Each document was probably drafted in isolation; a precedence clause that names the other document is the standard fix. Without one, a court applies state-default precedence rules, which favor the more recent or more specific document depending on jurisdiction.",
        recommendation:
          "Add a single explicit order-of-precedence statement to the operative document (typically the MSA) naming which document controls in conflicts, and strike the contradictory claim from the other document.",
        excerpts: [
          {
            doc_id: a.doc_id,
            source_file_name: a.source_file_name,
            text: truncate(a.excerpt, 320),
            section_id: a.section_id,
            start_offset: a.start,
            end_offset: a.end,
          },
          {
            doc_id: b.doc_id,
            source_file_name: b.source_file_name,
            text: truncate(b.excerpt, 320),
            section_id: b.section_id,
            start_offset: b.start,
            end_offset: b.end,
          },
        ],
      }),
    ];
  },
};

/* -------------------- Internal helpers ---------------------------- */

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}

function canonicalLaw(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/\b(governed|construed|in\s+accordance\s+with|the\s+laws?\s+of|state\s+of|commonwealth\s+of|by)\b/g, " ")
    .replace(/[^a-z]+/g, " ")
    .trim();
}

function kindLabel(kind: DocKind): string | null {
  switch (kind) {
    case "msa":
      return "Master Services Agreement";
    case "baa":
      return "Business Associate Agreement";
    case "dpa":
      return "Data Processing Agreement";
    case "sow":
      return "Statement of Work";
    case "nda":
      return "Non-Disclosure Agreement";
    case "other":
      return null;
  }
}

/* -------------------- Registry ----------------------------------- */

export const V4_CROSS_RULES: ConsistencyRule[] = [
  CROSS_PARTY_001,
  CROSS_JURIS_001,
  CROSS_DEFTERM_001,
  CROSS_DATE_001,
  CROSS_AMOUNT_001,
  CROSS_MISSING_001,
  CROSS_PRECEDENCE_001,
];

// Suppress the "unused" warning on `findByKind` — kept imported because
// the v4 helpers re-export it conceptually for any future v4 rules.
void findByKind;

import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";
import type { Party } from "../../../extract/types.js";

/**
 * STRUCT-017 — Signature-block completeness (spec-v9 Thrust B, §17–§18).
 *
 * `STRUCT-003` answers "is there a signature block?" — a yes/no.
 * `STRUCT-017` goes one layer deeper, to the failure that actually kills a
 * closing: a multi-party agreement where a named, declared party has **no
 * line to sign**. It reconciles the contracting parties the extractor
 * already pulls (preamble entities + defined roles) against the names and
 * roles that appear in the document's signature region, and reports every
 * declared party with no corresponding signature presence.
 *
 * Deliberately conservative — it fires only when *all* of these hold, so a
 * noisy extraction never manufactures a false closing blocker:
 *   1. there are ≥ 2 declared contracting parties (an entity-typed or
 *      role-defined party — not an incidental capitalized name);
 *   2. the signature region carries a real signature signal (a `By:` /
 *      `Name:` / `Signature` token), so we know a block exists at all (a
 *      document with no block is STRUCT-003's job, not this rule's);
 *   3. at least one declared party DOES appear in the signature region
 *      (the block is reconcilable); and
 *   4. at least one declared party does NOT.
 *
 * Internal reconciliation only (corollary 2): it reports the gap, never
 * that the document is "not validly executed."
 */

const EXHIBIT_HEADING = /\b(?:exhibit|schedule|attachment|appendix|annex|annexure)\b/i;
// A real signature line carries a labeled, colon-terminated field
// ("By:", "Name:", "Title:", "Signature:"). The colon is REQUIRED — without
// it the bare word "by" in prose ("retained by Seller") would masquerade as a
// signature block and manufacture a false closing blocker.
const SIG_SIGNAL = /\b(?:By|Name|Title|Signature|Signed|Authorized\s+Signatory)\s*:/i;

/** Max length of a paragraph treated as a short "label line" above a By: line. */
const LABEL_LINE_MAX = 60;

export const rule: Rule = {
  id: "STRUCT-017",
  version: "1.0.0",
  name: "Signature-block completeness",
  category: "structural",
  default_severity: "warning",
  description:
    "Reconciles the declared contracting parties against the signature region and reports any named party with no signature line — an execution-readiness gap, internal-consistency only.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // A defined term occasionally slips into the party set when the
    // preamble extractor mistakes a capitalized phrase + a word that opens
    // with an entity token ("Confidential Information includes…" → entity
    // "inc") for an entity. A genuine signing entity is not a defined term,
    // so drop any principal whose name matches one — it keeps a spurious
    // "party" from manufacturing a missing-signature finding.
    const definedTerms = new Set(
      ctx.extracted.definitions.entries.map((e) => normalizeName(e.term)),
    );
    const principals = ctx.extracted.parties.filter(
      (p) => isDeclaredParty(p) && !definedTerms.has(normalizeName(p.name)),
    );
    if (principals.length < 2) return null;

    // Collect paragraphs (skipping exhibits — a signature block does not
    // live inside an attached exhibit).
    type P = { text: string; sectionId: string; start: number };
    const paragraphs: P[] = [];
    const exhibitSectionIds = new Set<string>();
    forEachSection(ctx.tree, (s) => {
      if (EXHIBIT_HEADING.test(s.heading)) exhibitSectionIds.add(s.id);
    });
    forEachParagraph(ctx.tree, (p) => {
      if (exhibitSectionIds.has(p.section.id)) return;
      paragraphs.push({ text: p.text, sectionId: p.section.id, start: p.start });
    });
    if (paragraphs.length === 0) return null;

    // The NARROW signature block: every paragraph that carries a labeled,
    // colon-terminated signature field, PLUS the paragraph directly above it
    // (the "ACME CORP." / "PROVIDER:" label line that sits over a "By:"
    // line). Restricting to this block — not the document tail — is what
    // separates "this party has no signature line" from "this party's role
    // is merely mentioned in an operative clause near the end."
    const blockParas = new Map<number, P>();
    for (let i = 0; i < paragraphs.length; i++) {
      if (SIG_SIGNAL.test(paragraphs[i]!.text)) {
        // Only fold in the preceding paragraph when it is SHORT and
        // label-like (e.g. "PROVIDER:" / "ACME CORP., a Delaware
        // corporation") — never a full operative or preamble paragraph,
        // which would drag every party name into the block and defeat the
        // reconciliation.
        const above = i > 0 ? paragraphs[i - 1]! : undefined;
        if (above && above.text.trim().length <= LABEL_LINE_MAX) {
          blockParas.set(above.start, above);
        }
        blockParas.set(paragraphs[i]!.start, paragraphs[i]!);
      }
    }
    if (blockParas.size === 0) return null;
    const block = [...blockParas.values()].sort((a, b) => a.start - b.start);
    const blockLower = block.map((p) => p.text).join("\n").toLowerCase();

    const present = (party: Party): boolean => {
      for (const surface of surfacesOf(party)) {
        if (surface.length < 3) continue;
        const re = new RegExp(`\\b${escapeRegExp(surface.toLowerCase())}\\b`);
        if (re.test(blockLower)) return true;
      }
      return false;
    };

    const signed = principals.filter(present);
    const unsigned = principals.filter((p) => !present(p));
    // Fire only when the block clearly labels at least TWO declared parties
    // (so it is unambiguously a multi-party, party-labeled signature block —
    // the spec's canonical "four-party agreement with three signature lines")
    // AND a further declared party has no attributable line. A generic stub
    // ("Signed by: ____") or a block naming ≤ 1 party stays silent —
    // reconciliation is not reliably possible there, so the rule does not
    // manufacture a finding (it errs toward precision, per §18).
    if (signed.length < 2 || unsigned.length === 0) return null;

    const names = unsigned.map((p) => p.name).join(", ");
    const anchor = block[block.length - 1]!;
    return makeFinding({
      rule,
      title: `Declared part${unsigned.length === 1 ? "y" : "ies"} with no signature line: ${unsigned.length}`,
      description: `The document declares ${principals.length} contracting parties and the signature block names ${signed.length} of them; ${names} ${unsigned.length === 1 ? "has" : "have"} no attributable signature line.`,
      excerptText: anchor.text.slice(0, 160),
      explanation:
        "Every party bound by the agreement needs a line to sign. The signature block here is party-labeled but a declared party has no line attributable to it — a closing blocker, since the agreement cannot be fully executed until each named party has a place to sign. This reconciles the parties against the signature block; it does not assert the document is or is not validly executed (a jurisdiction-specific legal judgment).",
      recommendation: `Add a signature line (By / Name / Title / Date) for ${names}, or confirm the party is intentionally a non-signatory (e.g., a named beneficiary). Reconcile every preamble party to a signature line before closing.`,
      position: { section_id: anchor.sectionId, start: anchor.start, end: anchor.start + anchor.text.length },
      source_citations: [],
    });
  },
};

/** A corporate suffix at the END of the entity's own name. */
const CORP_SUFFIX =
  /\b(?:Corp|Corporation|Inc|LLC|L\.L\.C\.|Ltd|Limited|Co|Company|GmbH|AG|PLC|LP|LLP|PLLC|Trust)\.?,?$/i;

/**
 * A declared contracting party: an entity whose own NAME ends in a corporate
 * suffix (Acme Corp, Globex Inc., Initech LLC). The name-suffix test is the
 * decisive precision gate: the preamble extractor occasionally fabricates an
 * entity-typed "party" by matching a sub-word entity token (a phrase followed
 * by "…**inc**ludes" / "…**ag**ainst" yields entity "inc"/"ag"), but those
 * phantoms ("Business Purpose", "SOW") do not end in a corporate suffix,
 * whereas a real signing entity does. Requiring the suffix keeps the
 * reconciliation to entities that genuinely sign — precision over recall
 * (§18), so a non-corporate signatory (an individual, a trust by trustee) is
 * simply not reconciled rather than falsely flagged.
 */
function isDeclaredParty(p: Party): boolean {
  return Boolean(p.entity_type) && CORP_SUFFIX.test(p.name.trim());
}

/** Surface forms to look for in the signature region: name, role, aliases, d/b/a. */
function surfacesOf(p: Party): string[] {
  const out = new Set<string>();
  out.add(p.name);
  if (p.role) out.add(p.role);
  if (p.dba) out.add(p.dba);
  for (const a of p.aliases ?? []) out.add(a);
  return [...out].filter(Boolean);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Normalize a name/term for comparison: trim trailing punctuation, lowercase. */
function normalizeName(s: string): string {
  return s.trim().replace(/[.,;:]+$/, "").toLowerCase();
}

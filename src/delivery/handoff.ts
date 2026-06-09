/**
 * The HANDOFF-* finding family (spec-v9 Thrust A). Pure functions from
 * {@link ContainerFacts} to {@link HandoffFinding}s. Every finding is
 * presence-only and self-citing: it reports what is *in* the container and
 * where, never what the fact legally *means* (§3 corollary 2), and never
 * reports its silence as a clean bill (§3 corollary 3).
 *
 *   HANDOFF-001  tracked changes present        (critical)
 *   HANDOFF-002  comments present               (critical)
 *   HANDOFF-003  hidden / non-printing content  (warning)
 *   HANDOFF-004  authoring metadata present     (info → warning → critical)
 *   HANDOFF-005  sensitive-data patterns         (warning → critical)
 */

import type { ContainerFacts, HandoffFinding, MetadataFact } from "./types.js";

/** Metadata fields whose value can leak a prior client or the real drafter. */
const IDENTITY_FIELDS = new Set(["company", "manager", "template", "creator", "lastModifiedBy"]);

/**
 * The subset that names an *organization* (§12). Only these are cross-matter-
 * checked against the party set: a `Company`/`Manager`/`Template`-path naming
 * an entity absent from the parties is a likely prior-client leak. A bare
 * person name (`creator`/`lastModifiedBy`) is a metadata fact, not an entity
 * mismatch, so it is never elevated to critical on its own.
 */
const ENTITY_FIELDS = new Set(["company", "manager", "template"]);

/**
 * Derive the handoff findings. `parties` is the engine-extracted party set
 * (preamble + defined roles); when supplied, a metadata identity field naming
 * an entity absent from it is flagged as a likely cross-matter leak (§12).
 */
export function deriveHandoffFindings(
  facts: ContainerFacts,
  parties: readonly string[] = [],
): HandoffFinding[] {
  const findings: HandoffFinding[] = [];

  if (facts.revisions.length > 0) {
    findings.push({
      rule_id: "HANDOFF-001",
      severity: "critical",
      title: "Tracked changes are still present",
      description: `${facts.revisions.length} tracked-change revision${plural(facts.revisions.length)} remain in the document's container.`,
      count: facts.revisions.length,
      evidence: facts.revisions.slice(0, 20).map((r) => {
        const who = r.author ? ` by ${r.author}` : "";
        const what = r.excerpt ? `: “${r.excerpt}”` : "";
        return `${r.kind}${who}${what}`;
      }),
    });
  }

  if (facts.comments.length > 0) {
    findings.push({
      rule_id: "HANDOFF-002",
      severity: "critical",
      title: "Comments are still present",
      description: `${facts.comments.length} comment${plural(facts.comments.length)} remain in the document's container.`,
      count: facts.comments.length,
      evidence: facts.comments.slice(0, 20).map((c) => {
        const who = c.author ? `${c.author}` : "unattributed";
        const what = c.excerpt ? `: “${c.excerpt}”` : "";
        return `${who}${what}`;
      }),
    });
  }

  if (facts.hidden.length > 0) {
    findings.push({
      rule_id: "HANDOFF-003",
      severity: "warning",
      title: "Hidden or non-printing content is recoverable",
      description: `${facts.hidden.length} span${plural(facts.hidden.length)} present in the bytes but absent from the rendered text — a recipient's tooling can recover them.`,
      count: facts.hidden.length,
      evidence: facts.hidden.slice(0, 20).map((h) => {
        const what = h.excerpt ? `: “${h.excerpt}”` : "";
        return `${h.kind}${what}`;
      }),
    });
  }

  if (facts.metadata.length > 0) {
    const crossMatter = facts.metadata.filter((mf) => isCrossMatter(mf, parties));
    const severity = crossMatter.length > 0 ? "critical" : metadataSeverity(facts.metadata);
    const leakNote =
      crossMatter.length > 0
        ? ` ${crossMatter.length} identity field${plural(crossMatter.length)} name an entity not among the document's parties (a likely cross-matter leak).`
        : "";
    findings.push({
      rule_id: "HANDOFF-004",
      severity,
      title: "Authoring metadata is present",
      description: `${facts.metadata.length} authoring-metadata field${plural(facts.metadata.length)} are embedded in the container.${leakNote}`,
      count: facts.metadata.length,
      evidence: facts.metadata.slice(0, 30).map((mf) => {
        const flag = isCrossMatter(mf, parties) ? " ⚠ not a named party" : "";
        return `${mf.field}: ${mf.value}${flag}`;
      }),
    });
  }

  if (facts.sensitive.length > 0) {
    const hasHigh = facts.sensitive.some((s) => s.confidence === "high");
    findings.push({
      rule_id: "HANDOFF-005",
      severity: hasHigh ? "critical" : "warning",
      title: "Sensitive-data patterns are present",
      description: `${facts.sensitive.length} span${plural(facts.sensitive.length)} match sensitive-data formats that are routinely redacted before disclosure.`,
      count: facts.sensitive.length,
      evidence: facts.sensitive.slice(0, 30).map(
        (s) => `${s.type} (${s.confidence} confidence): ${s.masked}`,
      ),
    });
  }

  return findings;
}

function isCrossMatter(mf: MetadataFact, parties: readonly string[]): boolean {
  if (!ENTITY_FIELDS.has(mf.field)) return false;
  // Dates and pure timestamps are never an entity name.
  const value = normalizeEntity(mf.value);
  if (value.length < 3) return false;
  // A field that is a bare person name (creator/lastModifiedBy) is a leak only
  // when a party list exists to compare against; with no parties we cannot
  // adjudicate, so we do not over-claim.
  if (parties.length === 0) return false;
  for (const p of parties) {
    const np = normalizeEntity(p);
    if (np.length === 0) continue;
    if (np.includes(value) || value.includes(np)) return false;
  }
  return true;
}

/** Normalize an entity name for cross-matter comparison: lowercase, strip suffixes/punct. */
function normalizeEntity(name: string): string {
  return name
    .toLowerCase()
    .replace(/\b(?:inc|llc|llp|ltd|corp|co|lp|plc|gmbh|company|incorporated|limited)\b\.?/g, "")
    .replace(/[^a-z0-9]+/g, "")
    .trim();
}

function metadataSeverity(metadata: MetadataFact[]): HandoffFinding["severity"] {
  return metadata.some((mf) => IDENTITY_FIELDS.has(mf.field)) ? "warning" : "info";
}

function plural(n: number): string {
  return n === 1 ? "" : "s";
}

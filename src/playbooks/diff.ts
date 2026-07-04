/**
 * Custom-playbook structural diff (spec-v8 §23, Step 144).
 *
 * `diffPlaybooks(a, b)` is a deterministic structural diff of two custom
 * playbooks (the v6 bring-your-own format): which built-in rules were
 * selected/deselected, which severity overrides changed, which thresholds
 * and required clauses moved, and which custom rules were added, removed,
 * or edited — rendered as JSON or Markdown. It gives custom-playbook
 * authors version control for their team standard: "what changed between
 * `team-standard-v1.json` and `v2.json`" becomes a reviewable summary
 * before adoption.
 *
 * Pure JSON diff — deterministic (sorted keys, stable ordering), no clock,
 * no network, no posture cost. Reads two `CustomPlaybook`s; mutates
 * neither.
 */

import type {
  CustomPlaybook,
  CustomPlaybookRuleOverride,
  CustomPredicate,
  CustomRule,
  NegotiationPosition,
} from "./custom-playbook.js";

export type FieldChange = { field: string; from: unknown; to: unknown };

export type OverrideChange = {
  rule_id: string;
  from?: CustomPlaybookRuleOverride;
  to?: CustomPlaybookRuleOverride;
};

export type CustomRuleChange = {
  id: string;
  /** Top-level fields that differ between the two versions. */
  fields: string[];
};

export type PlaybookDiff = {
  from: { id: string; name: string; catalog_version: string };
  to: { id: string; name: string; catalog_version: string };
  /** Top-level metadata fields whose value changed. */
  metadata: FieldChange[];
  rule_selection: {
    include: { added: string[]; removed: string[] };
    exclude: { added: string[]; removed: string[] };
  };
  rule_overrides: {
    added: OverrideChange[];
    removed: OverrideChange[];
    changed: OverrideChange[];
  };
  thresholds: {
    added: Array<{ key: string; value: number }>;
    removed: Array<{ key: string; value: number }>;
    changed: Array<{ key: string; from: number; to: number }>;
  };
  required_clauses: {
    added: Array<{ category: string; severity: string }>;
    removed: Array<{ category: string; severity: string }>;
    changed: Array<{ category: string; from: string; to: string }>;
  };
  custom_rules: {
    added: string[];
    removed: string[];
    changed: CustomRuleChange[];
  };
  /**
   * Negotiation-position (walk-away ladder) drift — the field the entire
   * posture/coherence family polices. Added at fix-playbook-diff-
   * completeness: two playbooks differing only in an acceptable floor
   * used to diff as "No structural differences" and exit 0.
   */
  negotiation_positions: {
    added: string[];
    removed: string[];
    changed: PositionChange[];
  };
  /** True when the two playbooks are structurally identical. */
  identical: boolean;
};

export type PositionChange = {
  dimension: string;
  /** Attorney-terms summaries, one per changed aspect of the position. */
  changes: string[];
};

/**
 * Attorney-terms description of a rung change: a numeric threshold whose
 * metric/comparator held still renders as a moved floor ("acceptable floor
 * for Liability cap moved 6 → 4"); anything else states the tier changed.
 */
function describePredicateChange(
  dimension: string,
  tier: "ideal" | "acceptable",
  from: CustomPredicate,
  to: CustomPredicate,
): string {
  const label = tier === "acceptable" ? "acceptable floor" : "ideal position";
  if (
    from.kind === "numeric_threshold" &&
    to.kind === "numeric_threshold" &&
    from.metric === to.metric &&
    from.comparator === to.comparator
  ) {
    return `${label} for ${dimension} moved ${from.value} → ${to.value}`;
  }
  return `${label} for ${dimension} changed (${JSON.stringify(from)} → ${JSON.stringify(to)})`;
}

function diffNegotiationPositions(
  a: NegotiationPosition[] = [],
  b: NegotiationPosition[] = [],
): PlaybookDiff["negotiation_positions"] {
  const aMap = new Map(a.map((p) => [p.dimension, p]));
  const bMap = new Map(b.map((p) => [p.dimension, p]));
  const added = [...bMap.keys()].filter((d) => !aMap.has(d)).sort();
  const removed = [...aMap.keys()].filter((d) => !bMap.has(d)).sort();
  const changed: PositionChange[] = [];
  for (const [dimension, pa] of aMap) {
    const pb = bMap.get(dimension);
    if (!pb) continue;
    const changes: string[] = [];
    for (const tier of ["ideal", "acceptable"] as const) {
      if (JSON.stringify(pa[tier]) !== JSON.stringify(pb[tier])) {
        changes.push(describePredicateChange(dimension, tier, pa[tier], pb[tier]));
      }
    }
    if (JSON.stringify(pa.guidance ?? null) !== JSON.stringify(pb.guidance ?? null)) {
      changes.push(`negotiation guidance for ${dimension} changed`);
    }
    if (changes.length > 0) changed.push({ dimension, changes });
  }
  changed.sort((x, y) => (x.dimension < y.dimension ? -1 : x.dimension > y.dimension ? 1 : 0));
  return { added, removed, changed };
}

function setDiff(a: string[], b: string[]): { added: string[]; removed: string[] } {
  const sa = new Set(a);
  const sb = new Set(b);
  return {
    added: b.filter((x) => !sa.has(x)).sort(),
    removed: a.filter((x) => !sb.has(x)).sort(),
  };
}

const META_FIELDS = ["name", "description", "mode", "catalog_version"] as const;

function diffOverrides(
  a: Record<string, CustomPlaybookRuleOverride> = {},
  b: Record<string, CustomPlaybookRuleOverride> = {},
): PlaybookDiff["rule_overrides"] {
  const added: OverrideChange[] = [];
  const removed: OverrideChange[] = [];
  const changed: OverrideChange[] = [];
  const ids = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  for (const rule_id of ids) {
    const from = a[rule_id];
    const to = b[rule_id];
    if (from && !to) removed.push({ rule_id, from });
    else if (!from && to) added.push({ rule_id, to });
    else if (from && to && (from.severity !== to.severity || from.skip !== to.skip)) {
      changed.push({ rule_id, from, to });
    }
  }
  return { added, removed, changed };
}

function diffThresholds(
  a: Record<string, number> = {},
  b: Record<string, number> = {},
): PlaybookDiff["thresholds"] {
  const added: Array<{ key: string; value: number }> = [];
  const removed: Array<{ key: string; value: number }> = [];
  const changed: Array<{ key: string; from: number; to: number }> = [];
  for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
    const from = a[key];
    const to = b[key];
    if (from === undefined && to !== undefined) added.push({ key, value: to });
    else if (from !== undefined && to === undefined) removed.push({ key, value: from });
    else if (from !== undefined && to !== undefined && from !== to) changed.push({ key, from, to });
  }
  return { added, removed, changed };
}

function diffRequiredClauses(
  a: CustomPlaybook["required_clauses"] = [],
  b: CustomPlaybook["required_clauses"] = [],
): PlaybookDiff["required_clauses"] {
  const ma = new Map(a.map((c) => [c.category, c.severity]));
  const mb = new Map(b.map((c) => [c.category, c.severity]));
  const added: Array<{ category: string; severity: string }> = [];
  const removed: Array<{ category: string; severity: string }> = [];
  const changed: Array<{ category: string; from: string; to: string }> = [];
  for (const category of [...new Set([...ma.keys(), ...mb.keys()])].sort()) {
    const from = ma.get(category);
    const to = mb.get(category);
    if (from === undefined && to !== undefined) added.push({ category, severity: to });
    else if (from !== undefined && to === undefined) removed.push({ category, severity: from });
    else if (from !== undefined && to !== undefined && from !== to)
      changed.push({ category, from, to });
  }
  return { added, removed, changed };
}

const CUSTOM_RULE_FIELDS: Array<keyof CustomRule> = [
  "title",
  "description",
  "severity",
  "assert",
  "citation",
];

function diffCustomRules(a: CustomRule[] = [], b: CustomRule[] = []): PlaybookDiff["custom_rules"] {
  const ma = new Map(a.map((r) => [r.id, r]));
  const mb = new Map(b.map((r) => [r.id, r]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: CustomRuleChange[] = [];
  for (const id of [...new Set([...ma.keys(), ...mb.keys()])].sort()) {
    const from = ma.get(id);
    const to = mb.get(id);
    if (!from && to) added.push(id);
    else if (from && !to) removed.push(id);
    else if (from && to) {
      const fields = CUSTOM_RULE_FIELDS.filter(
        (f) => JSON.stringify(from[f]) !== JSON.stringify(to[f]),
      ).map(String);
      if (fields.length > 0) changed.push({ id, fields });
    }
  }
  return { added, removed, changed };
}

export function diffPlaybooks(a: CustomPlaybook, b: CustomPlaybook): PlaybookDiff {
  const metadata: FieldChange[] = [];
  for (const field of META_FIELDS) {
    if (a[field] !== b[field]) metadata.push({ field, from: a[field], to: b[field] });
  }

  const rule_selection = {
    include: setDiff(a.rule_selection?.include ?? [], b.rule_selection?.include ?? []),
    exclude: setDiff(a.rule_selection?.exclude ?? [], b.rule_selection?.exclude ?? []),
  };
  const rule_overrides = diffOverrides(a.rule_overrides, b.rule_overrides);
  const thresholds = diffThresholds(a.thresholds, b.thresholds);
  const required_clauses = diffRequiredClauses(a.required_clauses, b.required_clauses);
  const custom_rules = diffCustomRules(a.custom_rules, b.custom_rules);
  const negotiation_positions = diffNegotiationPositions(
    a.negotiation_positions,
    b.negotiation_positions,
  );

  const identical =
    metadata.length === 0 &&
    rule_selection.include.added.length === 0 &&
    rule_selection.include.removed.length === 0 &&
    rule_selection.exclude.added.length === 0 &&
    rule_selection.exclude.removed.length === 0 &&
    rule_overrides.added.length === 0 &&
    rule_overrides.removed.length === 0 &&
    rule_overrides.changed.length === 0 &&
    thresholds.added.length === 0 &&
    thresholds.removed.length === 0 &&
    thresholds.changed.length === 0 &&
    required_clauses.added.length === 0 &&
    required_clauses.removed.length === 0 &&
    required_clauses.changed.length === 0 &&
    custom_rules.added.length === 0 &&
    custom_rules.removed.length === 0 &&
    custom_rules.changed.length === 0 &&
    negotiation_positions.added.length === 0 &&
    negotiation_positions.removed.length === 0 &&
    negotiation_positions.changed.length === 0;

  return {
    from: { id: a.id, name: a.name, catalog_version: a.catalog_version },
    to: { id: b.id, name: b.name, catalog_version: b.catalog_version },
    metadata,
    rule_selection,
    rule_overrides,
    thresholds,
    required_clauses,
    custom_rules,
    negotiation_positions,
    identical,
  };
}

function bullets(label: string, items: string[]): string[] {
  if (items.length === 0) return [];
  return [`- **${label}:** ${items.join(", ")}`];
}

/** Render a {@link PlaybookDiff} as a reviewable Markdown summary. */
export function diffPlaybooksMarkdown(a: CustomPlaybook, b: CustomPlaybook): string {
  const d = diffPlaybooks(a, b);
  const lines: string[] = [];
  lines.push(`# Playbook diff: ${d.from.id} → ${d.to.id}`);
  lines.push("");
  lines.push(`**From:** ${d.from.name} (catalog ${d.from.catalog_version})`);
  lines.push(`**To:** ${d.to.name} (catalog ${d.to.catalog_version})`);
  lines.push("");

  if (d.identical) {
    lines.push("_No structural differences._");
    lines.push("");
    return lines.join("\n");
  }

  if (d.metadata.length > 0) {
    lines.push("## Metadata");
    for (const m of d.metadata)
      lines.push(`- **${m.field}:** \`${String(m.from)}\` → \`${String(m.to)}\``);
    lines.push("");
  }

  const selLines = [
    ...bullets(
      "Rules included",
      d.rule_selection.include.added.map((x) => `+${x}`),
    ),
    ...bullets(
      "Rules un-included",
      d.rule_selection.include.removed.map((x) => `-${x}`),
    ),
    ...bullets(
      "Rules excluded",
      d.rule_selection.exclude.added.map((x) => `+${x}`),
    ),
    ...bullets(
      "Rules un-excluded",
      d.rule_selection.exclude.removed.map((x) => `-${x}`),
    ),
  ];
  if (selLines.length > 0) {
    lines.push("## Built-in rule selection");
    lines.push(...selLines);
    lines.push("");
  }

  const ro = d.rule_overrides;
  if (ro.added.length || ro.removed.length || ro.changed.length) {
    lines.push("## Severity / skip overrides");
    for (const o of ro.added) lines.push(`- **${o.rule_id}:** added ${JSON.stringify(o.to)}`);
    for (const o of ro.removed) lines.push(`- **${o.rule_id}:** removed`);
    for (const o of ro.changed)
      lines.push(`- **${o.rule_id}:** ${JSON.stringify(o.from)} → ${JSON.stringify(o.to)}`);
    lines.push("");
  }

  const th = d.thresholds;
  if (th.added.length || th.removed.length || th.changed.length) {
    lines.push("## Thresholds");
    for (const t of th.added) lines.push(`- **${t.key}:** added \`${t.value}\``);
    for (const t of th.removed) lines.push(`- **${t.key}:** removed (was \`${t.value}\`)`);
    for (const t of th.changed) lines.push(`- **${t.key}:** \`${t.from}\` → \`${t.to}\``);
    lines.push("");
  }

  const rc = d.required_clauses;
  if (rc.added.length || rc.removed.length || rc.changed.length) {
    lines.push("## Required clauses");
    for (const c of rc.added) lines.push(`- **${c.category}:** added (${c.severity})`);
    for (const c of rc.removed) lines.push(`- **${c.category}:** removed`);
    for (const c of rc.changed) lines.push(`- **${c.category}:** severity ${c.from} → ${c.to}`);
    lines.push("");
  }

  const cr = d.custom_rules;
  if (cr.added.length || cr.removed.length || cr.changed.length) {
    lines.push("## Custom rules");
    lines.push(...bullets("Added", cr.added));
    lines.push(...bullets("Removed", cr.removed));
    for (const c of cr.changed) lines.push(`- **${c.id}:** changed (${c.fields.join(", ")})`);
    lines.push("");
  }

  const np = d.negotiation_positions;
  if (np.added.length || np.removed.length || np.changed.length) {
    lines.push("## Negotiation positions");
    lines.push(...bullets("Added", np.added));
    lines.push(...bullets("Removed", np.removed));
    for (const c of np.changed) for (const summary of c.changes) lines.push(`- ${summary}`);
    lines.push("");
  }

  return lines.join("\n");
}

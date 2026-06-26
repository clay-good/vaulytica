/**
 * v9 Thrust B — Readiness consolidation & the Closing Checklist
 * (spec-v9 §23–§24, Steps 158–159).
 *
 * A single ordered readiness surface that composes the execution-readiness
 * findings the engine already produced — unfilled placeholders
 * (`STRUCT-011`/`STRUCT-013`), the missing signature block (`STRUCT-003`),
 * and the v9 reconciliations (`STRUCT-017` signature completeness,
 * `STRUCT-018` attachment completeness, `STRUCT-019` recited formalities) —
 * plus the handoff items that make a draft not send-ready (`HANDOFF-001`
 * tracked changes, `HANDOFF-002` comments). It is a re-projection of findings
 * the report already carries, so it introduces no new correctness risk and no
 * `result_hash` moves; the checklist is a render-side artifact.
 *
 * Presence-only (the v5/v9 honesty contract): the checklist reports the
 * readiness items left to resolve. It never asserts the document IS "ready to
 * sign" or "validly executed" — those are legal conclusions (Part XVI). An
 * empty checklist means "no readiness item was detected," not "ready."
 */

import type { EngineRun, Finding } from "../engine/finding.js";

/** The readiness category a checklist item belongs to. */
export type ChecklistCategory = "signature" | "attachment" | "formality" | "blank" | "handoff";

export type ChecklistItem = {
  category: ChecklistCategory;
  /** Source rule id (a STRUCT- or HANDOFF- rule). */
  rule_id: string;
  /** One-line, checkable label. */
  label: string;
  /** Section the item sits in, when known. */
  section?: string;
};

export type ClosingChecklist = {
  items: ChecklistItem[];
  /** Count of readiness items left to resolve. */
  open_count: number;
};

/** Engine rules that bear on execution readiness, in checklist order. */
const READINESS_RULES: Record<string, { category: ChecklistCategory; order: number }> = {
  "STRUCT-003": { category: "signature", order: 0 },
  "STRUCT-017": { category: "signature", order: 1 },
  "STRUCT-018": { category: "attachment", order: 2 },
  "STRUCT-019": { category: "formality", order: 3 },
  "STRUCT-011": { category: "blank", order: 4 },
  "STRUCT-013": { category: "blank", order: 5 },
};

/** A handoff finding shape (mirrors `src/delivery/types.ts` HandoffFinding). */
export type ChecklistHandoff = {
  rule_id: string;
  title: string;
  count: number;
};

const HANDOFF_ORDER: Record<string, number> = {
  "HANDOFF-001": 6,
  "HANDOFF-002": 7,
};

/**
 * Build the consolidated closing checklist from a completed run and, when the
 * delivery scan ran, the send-readiness handoff findings (tracked changes,
 * comments). Deterministic and pure: same inputs → byte-identical checklist.
 */
export function buildClosingChecklist(
  run: EngineRun,
  handoff: readonly ChecklistHandoff[] = [],
): ClosingChecklist {
  const items: Array<ChecklistItem & { _order: number; _pos: number }> = [];

  for (const f of run.findings) {
    const spec = READINESS_RULES[f.rule_id];
    if (!spec) continue;
    items.push({
      category: spec.category,
      rule_id: f.rule_id,
      label: labelFor(f),
      ...(f.excerpt.section_id ? { section: f.excerpt.section_id } : {}),
      _order: spec.order,
      _pos: f.document_position,
    });
  }

  for (const h of handoff) {
    const order = HANDOFF_ORDER[h.rule_id];
    if (order === undefined || h.count === 0) continue;
    items.push({
      category: "handoff",
      rule_id: h.rule_id,
      label: handoffLabel(h),
      _order: order,
      _pos: 0,
    });
  }

  // Deterministic order: by readiness category order, then document position,
  // then rule id.
  items.sort(
    (a, b) => a._order - b._order || a._pos - b._pos || a.rule_id.localeCompare(b.rule_id, "en"),
  );

  const clean: ChecklistItem[] = items.map(({ _order, _pos, ...rest }) => {
    void _order;
    void _pos;
    return rest;
  });
  return { items: clean, open_count: clean.length };
}

function labelFor(f: Finding): string {
  // The finding titles are already one-line and checkable; reuse them.
  return f.title;
}

function handoffLabel(h: ChecklistHandoff): string {
  if (h.rule_id === "HANDOFF-001") {
    return `${h.count} tracked change${h.count === 1 ? "" : "s"} still in the document — not send-ready`;
  }
  if (h.rule_id === "HANDOFF-002") {
    return `${h.count} comment${h.count === 1 ? "" : "s"} still in the document — not send-ready`;
  }
  return h.title;
}

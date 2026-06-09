/**
 * The Delivery report aggregate (spec-v9 §15, Step 153). Composes the
 * container facts and the HANDOFF-* findings into one artifact with its own
 * `delivery_hash` — deterministic over the original bytes, **additive to and
 * namespaced apart from** the engine `result_hash`, so no existing golden
 * re-baselines (the v8 Step-146 "field outside the run" precedent).
 *
 * The summary line is the one-glance verdict for the complete-state header,
 * and it obeys the presence-only contract: it states what was found, never
 * "clean" / "safe to send".
 */

import type { ContainerFacts, DeliveryReport, HandoffFinding } from "./types.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";

/** Build the Delivery report. The hash covers the canonical facts + findings. */
export async function buildDeliveryReport(
  facts: ContainerFacts,
  findings: HandoffFinding[],
): Promise<DeliveryReport> {
  const canonical = stableStringify({ facts, findings });
  const delivery_hash = await sha256Hex(canonical);
  return {
    source: facts.source,
    inspectable: facts.inspectable,
    note: facts.note,
    findings,
    summary: summarize(facts, findings),
    delivery_hash,
  };
}

/**
 * One-line, presence-only summary. When the container could not be inspected
 * (pasted text, image-only, malformed), the line says exactly that — it never
 * asserts cleanliness for content it could not read (§3 corollary 3).
 */
function summarize(facts: ContainerFacts, findings: HandoffFinding[]): string {
  if (!facts.inspectable && findings.length === 0) {
    return `Delivery: ${facts.note ?? "no container to inspect"} — pre-disclosure scan could not run.`;
  }
  if (findings.length === 0) {
    return "Delivery: the pre-disclosure scan surfaced no tracked changes, comments, hidden content, metadata, or sensitive-data patterns it can match. This is not a guarantee the document is clean.";
  }
  const parts: string[] = [];
  for (const f of findings) {
    parts.push(`${f.count} ${labelFor(f)}`);
  }
  return `Delivery: ${parts.join(", ")} — review before sending.`;
}

function labelFor(f: HandoffFinding): string {
  switch (f.rule_id) {
    case "HANDOFF-001":
      return f.count === 1 ? "tracked change" : "tracked changes";
    case "HANDOFF-002":
      return f.count === 1 ? "comment" : "comments";
    case "HANDOFF-003":
      return f.count === 1 ? "hidden span" : "hidden spans";
    case "HANDOFF-004":
      return f.count === 1 ? "metadata field" : "metadata fields";
    case "HANDOFF-005":
      return f.count === 1 ? "sensitive-data span" : "sensitive-data spans";
    default:
      return "item";
  }
}

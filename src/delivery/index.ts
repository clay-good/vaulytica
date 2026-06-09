/**
 * Delivery layer barrel (spec-v9 Thrust A — "Clean to Send"). The
 * pre-disclosure scan: a deterministic, private read over a document's
 * original container bytes that recovers the revision, comment,
 * hidden-content, metadata, and sensitive-data facts the normalizing ingest
 * discards, and surfaces them as a {@link DeliveryReport}.
 *
 * The whole surface is additive: a text-only or metadata-clean document yields
 * an empty report, so the engine `result_hash` never moves.
 */

export type {
  ContainerSource,
  ContainerFacts,
  RevisionFact,
  CommentFact,
  HiddenFact,
  MetadataFact,
  SensitiveFact,
  HandoffSeverity,
  HandoffFinding,
  DeliveryReport,
} from "./types.js";

export { readContainer } from "./container.js";
export { scanSensitive } from "./sensitive.js";
export { deriveHandoffFindings } from "./handoff.js";
export { buildDeliveryReport } from "./report.js";
export { maskDigits, maskEmail, luhnValid, ssnStructurallyValid } from "./mask.js";

import type { ContainerSource, DeliveryReport } from "./types.js";
import { readContainer } from "./container.js";
import { deriveHandoffFindings } from "./handoff.js";
import { buildDeliveryReport } from "./report.js";

/**
 * Top-level entry point: read the container, derive the handoff findings, and
 * build the Delivery report. `text` is the already-flattened document text the
 * engine read; `parties` (optional) is the engine-extracted party set, used to
 * flag cross-matter metadata leaks (§12). Never throws — a malformed container
 * yields an honest, presence-only report.
 */
export async function scanDelivery(input: {
  bytes: ArrayBuffer;
  source: ContainerSource;
  text: string;
  parties?: readonly string[];
}): Promise<DeliveryReport> {
  const facts = readContainer(input.bytes, input.source, input.text);
  const findings = deriveHandoffFindings(facts, input.parties ?? []);
  return buildDeliveryReport(facts, findings);
}

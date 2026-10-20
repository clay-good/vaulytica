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
import { readBoxesOverText } from "./pdf-paint.js";
import { deriveHandoffFindings } from "./handoff.js";
import { buildDeliveryReport } from "./report.js";
import { SEC_EXHIBIT_FAMILIES } from "./sec-exhibit.js";

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
  /** The type the document routed to; an SEC-exhibit type brings HANDOFF-008 into scope. */
  playbookId?: string;
  /** `--sec-exhibit`: the user asserts the document is an SEC exhibit. */
  secExhibit?: boolean;
}): Promise<DeliveryReport> {
  const facts = readContainer(input.bytes, input.source, input.text);
  // A filled box over text needs the PDF's drawing operations, which only
  // pdf.js reads; the rest of the container read is synchronous byte work.
  // Added only when something is found, so no other report's hash moves.
  if (input.source === "pdf" && facts.inspectable) {
    const painted = await readBoxesOverText(input.bytes);
    if (painted.facts.length > 0) {
      facts.redactions = [...(facts.redactions ?? []), ...painted.facts];
    }
    const unchecked = painted.unopened
      ? "Filled boxes over text were not checked: the drawing reader could not open the file."
      : painted.uninspectable.length > 0
        ? `Filled boxes over text were not checked on ${painted.uninspectable.join(", ")}.`
        : undefined;
    if (unchecked) facts.note = `${facts.note ?? ""} ${unchecked}`.trim();
  }
  const secExhibit =
    input.secExhibit === true ||
    (input.playbookId !== undefined && SEC_EXHIBIT_FAMILIES.has(input.playbookId));
  const findings = deriveHandoffFindings(facts, input.parties ?? [], {
    text: input.text,
    secExhibit,
  });
  return buildDeliveryReport(facts, findings);
}

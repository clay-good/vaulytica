/**
 * Which kind of JSON is this — named in the words a caller would recognise.
 *
 * 🚨 **This tool writes four kinds of JSON and eight of its commands read
 * one.** So every command has three neighbouring wrong turns, and each one's
 * wrong turn is another command's happy path. Left unnamed, each produced a
 * true and useless shape dump:
 *
 *     ✗ invalid playbook:
 *       a: (root): Unrecognized keys: "schema", "coherence_hash", "ladder_hash", …
 *       a: catalog_version: Invalid input: expected string, received undefined
 *
 *     ✗ round 1: schema must be one of "vaulytica.posture-coherence.v1", … (got undefined)
 *
 *     vaulytica: Cannot read properties of undefined (reading 'findings')
 *
 * `cli-diff-wrong-input.test.ts` named this defect for `diff` and fixed it for
 * ONE of the three shapes — an analysis report. A certificate or a coherence
 * artifact still got the shape dump. This is the single owner that ends it:
 * one recogniser, four kinds, and every reader asks it before printing a
 * schema list.
 *
 * 🚨 Returns `null` for JSON this tool did not write. There is no name to give
 * then, and the schema errors ARE the most useful answer — replacing them
 * would be a loss.
 */
export type JsonKind = "report" | "certificate" | "playbook" | "coherence";

/** How each kind is named in an error a user reads. */
const NAME: Record<JsonKind, string> = {
  report: "an analysis report",
  certificate: "a verification certificate",
  playbook: "a custom playbook",
  coherence: "a posture-coherence artifact",
};

/** The command that writes each kind, for "pass this instead". */
export const WRITTEN_BY: Record<JsonKind, string> = {
  report: "vaulytica analyze <docs> --format json",
  certificate: "vaulytica analyze <docs> --certificate",
  playbook: "a custom playbook file you author (the JSON you pass to --playbook-file)",
  coherence:
    "vaulytica analyze <docs> --playbook-file <playbook.json> --posture --emit-coherence <path>",
};

/**
 * The command that READS each kind — so a message can point a misplaced file at
 * the command it belongs to, not only say what this one wanted.
 */
export const READ_BY: Record<JsonKind, string> = {
  report: "vaulytica verify <report.json> <original>",
  certificate: "vaulytica verify <certificate.json> <original>",
  playbook: "vaulytica diff <a.json> <b.json>",
  coherence: "vaulytica coherence-trend <r1.coherence.json> <r2.coherence.json>",
};

/** The kind of JSON in `text`, or `null` when it is not one this tool writes. */
export function jsonKindOf(text: string): JsonKind | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const schema = typeof o.schema === "string" ? o.schema : "";
  if (schema === "vaulytica.verification-certificate.v1") return "certificate";
  if (schema.startsWith("vaulytica.posture-coherence.")) return "coherence";
  // A report is the pair of envelopes; `run` alone is not distinctive enough.
  if ("run" in o && "ingest" in o) return "report";
  if ("rules" in o || "catalog_version" in o || "rule_overrides" in o) return "playbook";
  return null;
}

/**
 * The name of the kind in `text` when it is NOT the kind this command wants —
 * or `null` when there is nothing useful to say, which is when the file is the
 * expected kind (and failed for some other reason) or is not one of ours.
 */
export function wrongKindOfJson(text: string, expected: JsonKind): string | null {
  const kind = jsonKindOf(text);
  return kind === null || kind === expected ? null : NAME[kind];
}

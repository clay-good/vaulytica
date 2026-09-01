/**
 * The jurisdiction overlays reach the CLI's JSON report.
 *
 * `buildJsonReport` builds `jurisdiction_overlays` (spec-v6 Part VI §21) from
 * the governing-law clauses in its `extracted` argument, and the CLI passed
 * `undefined` for that argument — so the field could never appear in a CLI
 * report, for any document, on any playbook with an overlay family.
 *
 * The document below is the one that found it: a standalone non-compete that
 * runs five years, nationwide, for any competitor, and chooses California law.
 * Cal. Bus. & Prof. Code § 16600 voids it outright, and since 2024 § 16600.5
 * makes attempting to enforce it an independent violation. The tool knows
 * this — the overlay catalog carries it, the selector resolves it, and the
 * Word report prints it. The one surface a script or a CI job can read
 * reported thirteen findings and did not mention California.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runAnalyze } from "../../tools/cli/run.js";

const tmp = mkdtempSync(join(tmpdir(), "vaul-overlay-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const DOC = join(tmp, "non-competition-agreement.txt");
writeFileSync(
  DOC,
  [
    "NON-COMPETITION AGREEMENT",
    "",
    "Desmond Vaillancourt agrees that for five years after leaving Halcyon Analytics, Inc. he will not work for any competitor anywhere in the United States.",
    "",
    "This applies to any business that competes with the Company in any way.",
    "",
    "California law governs.",
    "",
  ].join("\n"),
  "utf8",
);

async function analyzeJson(): Promise<Record<string, unknown>> {
  const out: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    await runAnalyze([DOC, "--format", "json"]);
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
  const text = out.join("");
  const start = text.indexOf("{");
  return JSON.parse(text.slice(start)) as Record<string, unknown>;
}

describe("CLI json report — jurisdiction overlays", () => {
  it("names the governing-law state's non-compete posture", async () => {
    const payload = await analyzeJson();
    const overlays = payload.jurisdiction_overlays as
      | {
          family: string;
          matched: Array<{ jurisdiction: string; posture: string; headline: string }>;
          detected_states: string[];
        }
      | undefined;
    expect(overlays, "jurisdiction_overlays absent from the CLI json report").toBeDefined();
    expect(overlays!.family).toBe("employment");
    expect(overlays!.detected_states).toContain("us-ca");
    const ca = overlays!.matched.find((m) => m.jurisdiction === "us-ca");
    expect(ca, "no California overlay matched").toBeDefined();
    expect(ca!.posture).toBe("prohibited");
  }, 60_000);
});

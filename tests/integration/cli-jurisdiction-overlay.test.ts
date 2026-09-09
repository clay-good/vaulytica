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

async function analyzeRaw(format: string): Promise<string> {
  const out: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    await runAnalyze([DOC, "--format", format]);
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
  return out.join("");
}

async function analyzeJson(): Promise<Record<string, unknown>> {
  const text = await analyzeRaw("json");
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

/**
 * And the same question one surface over: SARIF is what the Action uploads and
 * what a code-scanning dashboard reads, and it carried **no overlay at all**
 * until 9.628.0 — the identical silence this file was written about, on the
 * surface a CI job actually consumes.
 */
describe("CLI sarif — jurisdiction overlays", () => {
  it("carries the state-law overlay as a note-level result", async () => {
    const text = await analyzeRaw("sarif");
    const sarif = JSON.parse(text.slice(text.indexOf("{"))) as {
      runs: Array<{
        results: Array<{ ruleId: string; level: string; message: { text: string } }>;
        tool: { driver: { rules: Array<{ id: string }> } };
      }>;
    };
    const notes = sarif.runs[0]!.results.filter(
      (r) => r.ruleId === "VAULYTICA-JURISDICTION-OVERLAY",
    );
    expect(notes.length, "the CI surface carried no overlay").toBeGreaterThan(0);
    expect(notes[0]!.level, "an overlay is a caveat to read, not a violation").toBe("note");
    expect(notes[0]!.message.text).toContain("California");
    // The descriptor is registered alongside it, so a consumer can resolve it.
    expect(
      sarif.runs[0]!.tool.driver.rules.some((r) => r.id === "VAULYTICA-JURISDICTION-OVERLAY"),
    ).toBe(true);
  }, 60_000);
});

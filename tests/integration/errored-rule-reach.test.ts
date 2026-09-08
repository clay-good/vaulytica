/**
 * A rule that CRASHED is not a rule that passed.
 *
 * The engine swallows a throwing rule and records it as silence — correct for a
 * pure-rule contract, and one bad rule must not take down the run. What is not
 * correct is leaving it unsaid: "this check crashed" and "this check passed"
 * are not the same sentence to a lawyer relying on the review, and the notice
 * spells out the consequence — *"this document was NOT checked against them.
 * Treat the corresponding area as unreviewed."*
 *
 * `ExecutionLogEntry.errored` was added precisely to break that conflation.
 * `erroredRuleNotice` was written to state it. And it reached the **Word
 * reports only**: the print-clean HTML, the JSON, SARIF (what a CI job gates
 * on) and the browser tab all showed a clean run with a hole in it.
 *
 * Both halves, and the second is the one that matters:
 *   1. Reach — each surface says it when a rule threw.
 *   2. Anti-vacuity — **none** of them says anything when none did, which is
 *      the overwhelmingly common path and must render byte-unchanged.
 */

import { describe, expect, it } from "vitest";
import { unzipSync, strFromU8 } from "fflate";

import type { EngineRun, ExecutionLogEntry } from "../../src/engine/finding.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildSarif } from "../../src/report/sarif.js";
import { buildDocxReport } from "../../src/report/docx.js";
import { erroredRuleNotice } from "../../src/report/execution-log.js";
import type { IngestResult } from "../../src/ingest/types.js";

function logEntry(rule_id: string, errored?: true): ExecutionLogEntry {
  return {
    rule_id,
    rule_version: "1.0.0",
    ran: true,
    fired: false,
    elapsed_ms: 0,
    ...(errored ? { errored } : {}),
  };
}

function run(withError: boolean): EngineRun {
  return {
    findings: [],
    execution_log: [logEntry("OK-001"), logEntry("BOOM-002", withError ? true : undefined)],
    version: "9.9.9",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda-deep",
    source_file: { name: "nda.docx", sha256: "a".repeat(64), size_bytes: 10 },
    executed_at: "",
    result_hash: "c".repeat(64),
  } as unknown as EngineRun;
}

const ingest: IngestResult = {
  source: "docx",
  word_count: 10,
  page_count: 1,
  language: "en",
  sha256: "a".repeat(64),
  warnings: [],
  tree: { sections: [] },
} as unknown as IngestResult;

const NOTICE_FRAGMENT = "Treat the corresponding area as unreviewed";

describe("a crashed rule is reported on every surface", () => {
  it("the sentence itself names the rule and the consequence", () => {
    const notice = erroredRuleNotice(run(true).execution_log)!;
    expect(notice).toContain("BOOM-002");
    expect(notice).not.toContain("OK-001");
    expect(notice).toContain(NOTICE_FRAGMENT);
    // Anti-vacuity at the source: nothing to say when nothing threw.
    expect(erroredRuleNotice(run(false).execution_log)).toBeUndefined();
  });

  it("JSON emits it as a field, not just as flags a consumer must derive", async () => {
    const withErr = JSON.parse(await buildJsonReport(run(true), ingest).text());
    expect(withErr.rules_errored_notice).toContain("BOOM-002");
    const clean = JSON.parse(await buildJsonReport(run(false), ingest).text());
    expect("rules_errored_notice" in clean).toBe(false);
  });

  it("HTML prints it above the findings", () => {
    const dkb = loadStarterDkbSync();
    expect(buildHtmlReport(run(true), ingest, dkb)).toContain(NOTICE_FRAGMENT);
    expect(buildHtmlReport(run(false), ingest, dkb)).not.toContain(NOTICE_FRAGMENT);
  });

  it("SARIF carries it as a WARNING, not a note — it is a hole in the analysis", () => {
    const log = buildSarif(run(true), undefined, undefined, ingest);
    const hit = log.runs[0]!.results.filter((r) => r.ruleId === "VAULYTICA-RULE-ERRORED");
    expect(hit).toHaveLength(1);
    expect(hit[0]!.level).toBe("warning");
    expect(hit[0]!.message.text).toContain("BOOM-002");
    expect(hit[0]!.partialFingerprints["vaulyticaErroredRules/v1"]).toBe("BOOM-002");
    const rules = log.runs[0]!.tool.driver.rules;
    expect(rules[hit[0]!.ruleIndex!]!.id).toBe("VAULYTICA-RULE-ERRORED");

    const clean = buildSarif(run(false), undefined, undefined, ingest);
    expect(clean.runs[0]!.results.some((r) => r.ruleId === "VAULYTICA-RULE-ERRORED")).toBe(false);
  });

  it("the DOCX still says it (the one surface that always did)", async () => {
    const dkb = loadStarterDkbSync();
    const xml = async (withError: boolean): Promise<string> => {
      const blob = await buildDocxReport(run(withError), ingest, dkb, {
        id: "mutual-nda-deep",
        name: "Mutual NDA",
      } as never);
      return strFromU8(unzipSync(new Uint8Array(await blob.arrayBuffer()))["word/document.xml"]!);
    };
    expect(await xml(true)).toContain("BOOM-002");
    expect(await xml(false)).not.toContain(NOTICE_FRAGMENT);
  }, 120_000);
});

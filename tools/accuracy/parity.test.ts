/**
 * Node↔browser pipeline parity (spec-v7 Part XII / Step 120).
 *
 * Two pipelines compose the same `src/` functions: the browser pipeline
 * (`src/ui/pipeline.ts`, via `runReport`) and the Node accuracy harness
 * (`tools/accuracy/pipeline.ts`, via `runDocument`). They are *intended*
 * to be identical — a measured accuracy number must describe shipped
 * behavior. This test makes that executable: a shared document, driven
 * through both, must produce a byte-identical `EngineRun` (same
 * `result_hash`, same findings, same execution_log, same playbook).
 *
 * Both paths consume the same `ingestPaste` tree, the same DKB, and the
 * same `selectMatchCandidates` → `matchPlaybook` selection, so any
 * divergence localizes to the engine invocation itself — the exact
 * failure v5 is built to prevent.
 */

import { describe, expect, it } from "vitest";

import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { matchPlaybook } from "../../src/playbooks/index.js";
import { selectMatchCandidates } from "../../src/ui/playbook-candidates.js";
import { runReport, type PreparedDocument } from "../../src/ui/pipeline.js";
import type { DocumentTree, Section } from "../../src/ingest/types.js";

import { loadAccuracyDeps, runDocument } from "./pipeline.js";

/** Mirror both pipelines' body-text construction: every run's text, space-joined. */
function bodyTextOf(tree: DocumentTree): string {
  const parts: string[] = [];
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(s.children);
    }
  };
  walk(tree.sections);
  return parts.join(" ");
}

const FIXTURES: Array<{ name: string; text: string }> = [
  {
    name: "mutual-nda.txt",
    text: [
      "Mutual Non-Disclosure Agreement",
      "",
      'This Mutual Non-Disclosure Agreement is between Acme Corp., a Delaware corporation ("Disclosing Party"), and Globex Industries, Inc., a New York corporation ("Receiving Party"), effective 2026-01-01.',
      "",
      '"Confidential Information" means any non-public information disclosed by either party.',
      "",
      "Each party shall protect the Confidential Information for a period of three (3) years. This Agreement shall be governed by the laws of the State of Delaware.",
    ].join("\n"),
  },
  {
    name: "services-agreement.txt",
    text: [
      "Master Services Agreement",
      "",
      "This Master Services Agreement is between Acme Corp. and Globex Industries, Inc., effective 2026-02-01.",
      "",
      "Provider shall deliver the Services within thirty (30) days after the Effective Date. The aggregate liability of each party shall not exceed $1,000,000.",
      "",
      "Either party may terminate this Agreement for convenience upon sixty (60) days notice. Governed by the laws of the State of New York.",
    ].join("\n"),
  },
];

describe("Node↔browser pipeline parity (spec-v7 Step 120)", () => {
  for (const fx of FIXTURES) {
    it(`produces a byte-identical EngineRun through both pipelines: ${fx.name}`, async () => {
      const deps = await loadAccuracyDeps();

      // Accuracy harness path (Node).
      const acc = await runDocument(fx.text, fx.name, undefined, deps);

      // Browser path (runReport), driven from the SAME ingestPaste tree and
      // the SAME shared selection functions, with source_file constructed
      // identically to the accuracy harness so result_hash is comparable.
      const ingest = await ingestPaste(fx.text);
      const extracted = extractAll(ingest.tree, {
        classifier: { vocab: { vocab: {} }, patterns: deps.dkb.classifier.patterns },
      });
      const title = ingest.tree.sections[0]?.heading ?? fx.name;
      const body = bodyTextOf(ingest.tree);
      const candidates = selectMatchCandidates(deps.launchPlaybooks, deps.extendedPlaybooks, {
        title,
        body,
        classified: extracted.classified,
        extracted,
      });
      const match = matchPlaybook(extracted, extracted.classified, candidates, {
        title,
        body_text: body,
      });
      const playbook =
        candidates.find((p) => p.id === match.playbook_id) ?? deps.launchPlaybooks[0]!;
      const prepared: PreparedDocument = {
        ingest,
        extracted,
        body_text: body,
        dkb: deps.dkb,
        playbook,
        // Identical to runDocument's source_file construction: the UTF-8
        // byte length of the input, the same basis the browser stamps.
        source_file: {
          name: fx.name,
          sha256: ingest.sha256,
          size_bytes: Buffer.byteLength(fx.text),
        },
        match: {
          playbook_id: match.playbook_id,
          confidence: match.confidence,
          reasoning: match.reasoning,
        },
        secondary_playbooks: [],
      };
      const ui = await runReport(prepared);

      // Same playbook selected, byte-identical hash, identical substantive run.
      expect(ui.run.playbook_id).toBe(acc.run.playbook_id);
      expect(ui.run.result_hash).toBe(acc.run.result_hash);
      expect(ui.run.findings).toEqual(acc.run.findings);
      expect(ui.run.execution_log.map((e) => [e.rule_id, e.fired])).toEqual(
        acc.run.execution_log.map((e) => [e.rule_id, e.fired]),
      );

      // v8 Steps 141–142 — the browser pipeline emits the SARIF + standalone
      // HTML reach formats alongside the Word/JSON/fix-list downloads, so the
      // complete-state can offer them. Confirm they are produced and non-empty.
      expect(ui.sarif_blob.type).toBe("application/sarif+json");
      expect(ui.sarif_blob.size).toBeGreaterThan(0);
      expect(ui.html_blob.type).toBe("text/html");
      const html = await ui.html_blob.text();
      expect(html.startsWith("<!doctype html>")).toBe(true);
      expect(html).not.toContain("<script");
    });
  }
});

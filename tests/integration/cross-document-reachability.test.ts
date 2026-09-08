/**
 * Every cross-document rule can still RUN.
 *
 * The consistency runner skips a rule whose `requires` are not satisfied by the
 * bundle — it records `ran: false, "skipped (requires not satisfied)"` and
 * moves on. That is correct behaviour and it is also a silent failure mode: a
 * rule gated on a {@link DocKind} that gets renamed, or on a playbook id that
 * moves, stops running everywhere and reports exactly what a rule that ran and
 * found nothing reports. `kindOf` has been edited more than once — a
 * `privacy_policy` kind was added for CC-008/CC-009 — and nothing asserted that
 * the existing gates still matched anything afterwards.
 *
 * So: assemble every specimen as one bundle and require that **all 22 rules
 * execute**. This is deliberately not a findings assertion — a directory is not
 * a bundle, and the conflicts such a set produces are true and meaningless. The
 * question is only "could this check run at all", the cross-document form of
 * `boilerplate-satisfaction`'s "can this check fail?".
 *
 * Measured 2026-09-08 over the 312 specimens: **0 skipped**, 14 rules fired,
 * 8 ran silent. The eight are not a defect — those conflicts do not occur in
 * this corpus — but they are the ones a `requires` regression would hide
 * behind, which is why the assertion is on `ran`, not on findings.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { runConsistency } from "../../src/engine/consistency/runner.js";
import { ALL_CONSISTENCY_RULES } from "../../src/engine/consistency/rules/index.js";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { selectMatchCandidates } from "../../src/ui/playbook-candidates.js";
import { flattenText } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

describe("the cross-document engine's rules are all reachable", () => {
  it("every rule executes against the specimen corpus as one bundle", async () => {
    const deps = await loadAccuracyDeps();
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(files.length, "the specimen corpus").toBeGreaterThan(250);

    const documents = [];
    for (const f of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, f), "utf8"));
      const extracted = extractAll(ingest.tree, {
        classifier: { vocab: { vocab: {} }, patterns: deps.dkb.classifier.patterns },
      });
      const signals = {
        title: titleCorpus(ingest.tree, f),
        body: flattenText(ingest.tree),
        classified: extracted.classified,
        extracted,
      };
      const candidates = selectMatchCandidates(
        deps.launchPlaybooks,
        deps.extendedPlaybooks,
        signals,
      );
      const match = matchPlaybook(extracted, extracted.classified, candidates, {
        title: signals.title,
        body_text: signals.body,
      });
      documents.push({
        doc_id: f,
        source_file_name: f,
        playbook_id: match.playbook_id,
        tree: ingest.tree,
        extracted,
      });
    }

    const run = await runConsistency({
      rules: ALL_CONSISTENCY_RULES,
      documents,
      dkb: deps.dkb,
    });

    // Guard the probe: an execution log shorter than the rule set would make
    // the assertion below pass by not looking.
    expect(run.execution_log).toHaveLength(ALL_CONSISTENCY_RULES.length);

    const skipped = run.execution_log.filter((e) => !e.ran).map((e) => e.rule_id);
    expect(
      skipped,
      `these cross-document rules could not run against ANY of ${files.length} documents — ` +
        `their \`requires\` no longer match a kind the corpus produces:\n  ${skipped.join("\n  ")}`,
    ).toEqual([]);

    // And the corpus does exercise a real share of them, so "all ran" is not
    // the vacuous result of a bundle nothing applies to.
    const fired = run.execution_log.filter((e) => e.findings_count > 0);
    expect(fired.length, "rules that actually produced a finding").toBeGreaterThan(8);
  }, 300_000);
});

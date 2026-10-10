/**
 * One round of the drafting loop, compactly (spec-v51 §3).
 *
 * `compare` has always known which findings a revision resolved and which it
 * introduced — in 41 KB of JSON, with only the introduced ones named in its
 * Markdown. An agent or a person revising a draft asks three questions: what
 * did my change fix, what did it cause, and what did it remove. This is the
 * answer to those, in the words {@link isActionable} defines:
 *
 *  - `fixed`              actionable findings that no longer fire
 *  - `introduced`         findings the revision caused
 *  - `remaining`          actionable findings still firing, located in the revision
 *  - `no_longer_present`  observations that disappeared — which is what
 *                         happens when a clause is DELETED, so they are kept
 *                         apart from `fixed`
 *  - `removed`            clauses removed and the net word change
 *
 * The tool never says a draft is good. It says which named checks no longer
 * fire, and shows when a round's progress came from deleting.
 */

import { isActionable, type Finding, type Severity } from "../../src/engine/finding.js";
import { truncate } from "../../src/engine/text.js";
import { LOOP_CLEAN_STATEMENT, nonAdviceStatement } from "../../src/report/disclaimers.js";
import type { FileComparison } from "./api.js";

export type LoopFinding = {
  rule_id: string;
  severity: Severity;
  title: string;
  /** Where it is in the REVISED draft (introduced and remaining only). */
  section_label?: string;
  start_offset?: number;
  end_offset?: number;
  recommendation?: string;
};

export type ComparisonBrief = {
  comparison_hash: string;
  base: { name: string; type: string; result_hash: string };
  revised: { name: string; type: string; result_hash: string; sha256: string };
  /** Set when the revision was held to the base draft's document type. */
  pinned_type?: string;
  fixed: LoopFinding[];
  introduced: Array<LoopFinding & { actionable: boolean }>;
  remaining: LoopFinding[];
  no_longer_present: LoopFinding[];
  /** Observations in both drafts: facts about the document, nothing to do. */
  observations_unchanged: number;
  clauses: {
    rewritten: number;
    added: number;
    removed: number;
    renumbered: number;
    unchanged: number;
  };
  removed: { clauses: number; words_net: number; note?: string };
  /** Present only when nothing actionable is left. Says what that means. */
  clean?: string;
  caveats: { dkb_mismatch?: string; comparison: string; not_legal_advice: string };
};

/** One printable line: a title can interpolate document text. */
function line(text: string, max = 200): string {
  // eslint-disable-next-line no-control-regex
  return truncate(text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").trim(), max);
}

const named = (f: Finding): LoopFinding => ({
  rule_id: f.rule_id,
  severity: f.severity,
  title: line(f.title),
});

const located = (f: Finding): LoopFinding => ({
  ...named(f),
  ...(f.excerpt.section_label ? { section_label: line(f.excerpt.section_label, 80) } : {}),
  start_offset: f.excerpt.start_offset,
  end_offset: f.excerpt.end_offset,
  ...(f.recommendation ? { recommendation: f.recommendation } : {}),
});

export function buildComparisonBrief(c: FileComparison): ComparisonBrief {
  const { comparison: cmp, clause_diff: diff } = c;
  const { resolved, introduced, unchanged } = cmp.delta;
  const remaining = unchanged.filter((u) => isActionable(u.finding));
  const wordsNet = c.revised.ingest.word_count - c.base.ingest.word_count;
  const observationsGone = resolved.filter((f) => !isActionable(f));
  const fixed = resolved.filter(isActionable);
  // A round whose checks cleared while clauses went missing is said plainly.
  const byRemoval = diff.removed.length > 0 && (fixed.length > 0 || observationsGone.length > 0);
  return {
    comparison_hash: cmp.result_hash,
    base: {
      name: line(cmp.base.name),
      type: cmp.base.playbook_id,
      result_hash: cmp.base.result_hash,
    },
    revised: {
      name: line(cmp.revised.name),
      type: cmp.revised.playbook_id,
      result_hash: cmp.revised.result_hash,
      sha256: c.revised.run.source_file.sha256,
    },
    ...(c.pinned_type ? { pinned_type: c.pinned_type } : {}),
    fixed: fixed.map(named),
    introduced: introduced.map((f) => ({ ...located(f), actionable: isActionable(f) })),
    remaining: remaining.map((u) => located(u.finding)),
    no_longer_present: observationsGone.map(named),
    observations_unchanged: unchanged.length - remaining.length,
    clauses: {
      rewritten: diff.changed.length,
      added: diff.added.length,
      removed: diff.removed.length,
      renumbered: diff.renumbered.length,
      unchanged: diff.unchanged_count,
    },
    removed: {
      clauses: diff.removed.length,
      words_net: wordsNet,
      ...(byRemoval
        ? {
            note: `This round removed ${diff.removed.length} clause${diff.removed.length === 1 ? "" : "s"} (${wordsNet >= 0 ? "+" : "−"}${Math.abs(wordsNet)} words net). A check that stops firing because its clause was deleted is not a fix.`,
          }
        : {}),
    },
    ...(remaining.length === 0 && introduced.every((f) => !isActionable(f))
      ? { clean: LOOP_CLEAN_STATEMENT }
      : {}),
    caveats: {
      ...(cmp.dkb_mismatch
        ? {
            dkb_mismatch: "The two drafts were analyzed against different knowledge-base versions.",
          }
        : {}),
      comparison:
        "Findings are matched by rule. `fixed` means a named check no longer fires; it does not mean the clause is right.",
      not_legal_advice: nonAdviceStatement("comparison"),
    },
  };
}

/** The same round as Markdown sections, for `compare --format markdown`. */
export function comparisonBriefMarkdown(b: ComparisonBrief): string {
  const out: string[] = [];
  const list = (heading: string, items: readonly LoopFinding[], note?: string): void => {
    out.push(`### ${heading} (${items.length})`);
    out.push("");
    if (note) out.push(note, "");
    if (items.length === 0) out.push("_None._");
    for (const f of items) {
      const where = f.section_label ? ` — ${f.section_label}` : "";
      out.push(`- **[${f.severity.toUpperCase()}] ${f.rule_id}** — ${f.title}${where}`);
    }
    out.push("");
  };
  out.push("## This round");
  out.push("");
  list("Fixed", b.fixed, "Actionable findings that no longer fire.");
  list("Introduced", b.introduced, "Findings the revision caused.");
  list("Remaining", b.remaining, "Actionable findings still firing in the revised draft.");
  list(
    "No longer present",
    b.no_longer_present,
    "Observations that disappeared. They disappear when a clause is deleted, so they are not counted as fixed.",
  );
  if (b.removed.note) out.push(`> ${b.removed.note}`, "");
  if (b.clean) out.push(`> ${b.clean}`, "");
  return out.join("\n");
}

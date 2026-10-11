/**
 * Scoreboard assembly + reproducible hash + markdown render (spec-v5 §10, Step 71).
 *
 * Turns the per-(doc × playbook) graded results into the published artifact:
 * headline precision/recall/F1 (macro + micro), per-rule breakdown, the
 * worst-offenders and unmeasured-rule sections, the κ summary, and the
 * version stamps `(corpus, dkb, engine)` that make every number reproducible.
 *
 * `scoreboardHash` is `SHA-256(canonical(artifact-without-hash))`, computed
 * with the same canonicalization discipline as the engine's `result_hash`
 * (sorted keys, no wall-clock) — two engineers on the same `(corpus, commit)`
 * get byte-identical scoreboards.
 */

import { createHash } from "node:crypto";
import { stableStringify } from "../../src/engine/index.js";
import {
  computeScoreboard,
  worstByPrecision,
  worstByRecall,
  type GradedDocument,
  type RuleMetric,
  type Counts,
} from "./metrics.js";
import { cohensKappa, type KappaResult, type VerdictPair } from "./kappa.js";
import { measureRouting, ROUTING_OUTCOMES, type RoutingMeasure } from "./routing.js";

export type ScoreboardArtifact = {
  schema_version: 1;
  corpus_version: string;
  dkb_version: string;
  engine_version: string;
  /** Catalog size the run reflects, so "measured N of M rules" is checkable. */
  catalog: { rules: number; playbooks: number };
  doc_counts: { real_graded_pairs: number; bootstrap_pairs: number };
  /** Overall inter-annotator agreement over the κ-input annotations. */
  kappa: KappaResult;
  headline: {
    micro: { precision: number | null; recall: number | null; f1: number | null };
    macro: { precision: number | null; recall: number | null; f1: number | null };
  };
  totals: Counts;
  per_rule: RuleMetric[];
  worst_precision: RuleMetric[];
  worst_recall: RuleMetric[];
  unmeasured_rule_ids: string[];
  /**
   * Routing on public filings (spec-v53 §8): of the exhibits sampled, how many
   * the tool recognized for what their own titles say they are. Present with
   * its caveats even when the sample is empty.
   */
  routing: RoutingMeasure;
  /** Honest status: empty (no real docs), thin (<floor), or populated. */
  corpus_status: "empty" | "thin" | "populated";
  notes: string[];
  /** SHA-256 over the canonical artifact with this field blanked. */
  scoreboard_hash: string;
};

export type AssembleInput = {
  corpus_version: string;
  dkb_version: string;
  engine_version: string;
  catalog: { rules: number; playbooks: number };
  graded: ReadonlyArray<GradedDocument>;
  /** Paired annotator verdicts feeding the overall κ (spec-v5 §5). */
  kappa_pairs: ReadonlyArray<VerdictPair>;
  /** The routing sample's measure; omitted, an empty sample over no catalog. */
  routing?: RoutingMeasure;
  /** Real graded pairs below this count → corpus_status "thin"; 0 → "empty". */
  thin_floor?: number;
  worst_n?: number;
};

export function assembleScoreboard(input: AssembleInput): ScoreboardArtifact {
  const board = computeScoreboard(input.graded);
  const kappa = cohensKappa(input.kappa_pairs);
  const worstN = input.worst_n ?? 20;
  const thinFloor = input.thin_floor ?? 1;

  const realPairs = board.graded_pairs;
  const corpus_status: ScoreboardArtifact["corpus_status"] =
    realPairs === 0 ? "empty" : realPairs < thinFloor ? "thin" : "populated";

  const notes: string[] = [];
  if (corpus_status === "empty") {
    notes.push(
      "No real annotated documents yet. The accuracy harness is verified by unit tests; " +
        "the ground-truth corpus (spec-v5 Step 68) and attorney annotations (Step 70) are " +
        "human-gated and pending. No headline precision/recall number is published until real " +
        "documents land — by design, this is the dishonesty v5 exists to break.",
    );
  }
  if (board.bootstrap_pairs > 0) {
    notes.push(
      `${board.bootstrap_pairs} bootstrap placeholder pair(s) were excluded from every count ` +
        "(maintainer-authored, not real-world samples).",
    );
  }
  if (board.unmeasured_rule_ids.length > 0) {
    notes.push(
      `${board.unmeasured_rule_ids.length} rule(s) had no κ-confident grading document and are ` +
        "excluded from the headline (reported as unmeasured).",
    );
  }

  const artifact: ScoreboardArtifact = {
    schema_version: 1,
    corpus_version: input.corpus_version,
    dkb_version: input.dkb_version,
    engine_version: input.engine_version,
    catalog: input.catalog,
    doc_counts: { real_graded_pairs: realPairs, bootstrap_pairs: board.bootstrap_pairs },
    kappa,
    headline: board.averages,
    totals: board.totals,
    per_rule: board.per_rule,
    worst_precision: worstByPrecision(board, worstN),
    worst_recall: worstByRecall(board, worstN),
    unmeasured_rule_ids: board.unmeasured_rule_ids,
    routing: input.routing ?? measureRouting([], [], []),
    corpus_status,
    notes,
    scoreboard_hash: "",
  };

  artifact.scoreboard_hash = scoreboardHash(artifact);
  return artifact;
}

/** SHA-256 over the canonical artifact with `scoreboard_hash` blanked. */
export function scoreboardHash(artifact: ScoreboardArtifact): string {
  const canonical = stableStringify({ ...artifact, scoreboard_hash: "" });
  return createHash("sha256").update(canonical).digest("hex");
}

function pct(x: number | null): string {
  return x === null ? "—" : `${(x * 100).toFixed(1)}%`;
}

/** Human-readable SCOREBOARD.md (spec-v5 §10). Deterministic. */
export function renderScoreboardMarkdown(a: ScoreboardArtifact): string {
  const lines: string[] = [];
  lines.push("# Vaulytica accuracy scoreboard");
  lines.push("");
  lines.push(
    "> Generated by `npm run accuracy` from `tools/accuracy/`. Do not edit by hand. " +
      "Reproducible: same `(corpus, dkb, engine)` → identical `scoreboard_hash`.",
  );
  lines.push("");
  lines.push(
    `- **Corpus:** \`${a.corpus_version}\` · **DKB:** \`${a.dkb_version}\` · **Engine:** \`${a.engine_version}\``,
  );
  lines.push(`- **Status:** ${a.corpus_status}`);
  lines.push(
    `- **Real graded pairs:** ${a.doc_counts.real_graded_pairs} · **Bootstrap (excluded):** ${a.doc_counts.bootstrap_pairs}`,
  );
  lines.push(`- **Catalog:** ${a.catalog.rules} rules · ${a.catalog.playbooks} playbooks`);
  lines.push(
    `- **Inter-annotator κ:** ${a.kappa.n === 0 ? "—" : a.kappa.kappa.toFixed(3)} (${a.kappa.interpretation}, n=${a.kappa.n})`,
  );
  lines.push(`- **Scoreboard hash:** \`${a.scoreboard_hash}\``);
  lines.push("");
  lines.push("## Headline");
  lines.push("");
  lines.push("| Average | Precision | Recall | F1 |");
  lines.push("|---|---|---|---|");
  lines.push(
    `| Micro | ${pct(a.headline.micro.precision)} | ${pct(a.headline.micro.recall)} | ${pct(a.headline.micro.f1)} |`,
  );
  lines.push(
    `| Macro | ${pct(a.headline.macro.precision)} | ${pct(a.headline.macro.recall)} | ${pct(a.headline.macro.f1)} |`,
  );
  lines.push("");

  if (a.notes.length > 0) {
    lines.push("## Notes");
    lines.push("");
    for (const n of a.notes) lines.push(`- ${n}`);
    lines.push("");
  }

  if (a.per_rule.length > 0) {
    lines.push("## Per-rule (sorted worst-F1 first)");
    lines.push("");
    lines.push("| Rule | TP | FP | FN | TN | Precision | Recall | F1 | Docs | Conf |");
    lines.push("|---|--:|--:|--:|--:|--:|--:|--:|--:|---|");
    const sorted = [...a.per_rule].sort((x, y) => (x.f1 ?? 1) - (y.f1 ?? 1));
    for (const r of sorted) {
      lines.push(
        `| ${r.rule_id} | ${r.tp} | ${r.fp} | ${r.fn} | ${r.tn} | ${pct(r.precision)} | ${pct(r.recall)} | ${pct(r.f1)} | ${r.graded_docs} | ${r.low_confidence ? "low" : "ok"} |`,
      );
    }
    lines.push("");
  }

  lines.push("## Routing on public filings");
  lines.push("");
  const r = a.routing;
  lines.push(
    r.n === 0
      ? "No exhibits sampled yet. The sample is selected by rule from EDGAR material-contract exhibits, and its size is the owner's decision (spec-v53 §8). No routing number is published until it exists."
      : `Of ${r.n} EDGAR exhibits, where the tool sent each, against the type its own title names. No exhibit text is held: each record is an accession number, a URL, a date, a hash, a title, a label and a route.`,
  );
  lines.push("");
  lines.push("| Outcome | Exhibits | Share |");
  lines.push("|---|--:|--:|");
  const OUTCOME_LABEL = {
    exact: "The type its title names",
    acceptable: "Another type accepted for that title",
    wrong: "A different type",
    fallback: "No type matched",
    no_family: "The catalog has no type for this title",
  } as const;
  for (const o of ROUTING_OUTCOMES) {
    lines.push(`| ${OUTCOME_LABEL[o]} | ${r.counts[o]} | ${pct(r.shares[o])} |`);
  }
  lines.push("");
  for (const c of r.caveats) lines.push(`- ${c}`);
  lines.push("");
  if (r.per_family.length > 0) {
    lines.push("| Type | Exhibits | Exact | Acceptable | Wrong | Fallback |");
    lines.push("|---|--:|--:|--:|--:|--:|");
    for (const f of r.per_family) {
      lines.push(
        `| ${f.family} | ${f.n} | ${f.counts.exact} | ${f.counts.acceptable} | ${f.counts.wrong} | ${f.counts.fallback} |`,
      );
    }
    lines.push("");
  }

  lines.push("## Worst offenders");
  lines.push("");
  lines.push(
    `- **Lowest precision:** ${a.worst_precision.map((r) => r.rule_id).join(", ") || "—"}`,
  );
  lines.push(`- **Lowest recall:** ${a.worst_recall.map((r) => r.rule_id).join(", ") || "—"}`);
  lines.push("");
  lines.push("## Unmeasured rules");
  lines.push("");
  lines.push(
    a.unmeasured_rule_ids.length === 0
      ? "None — every graded rule had at least one κ-confident document."
      : `${a.unmeasured_rule_ids.length}: ${a.unmeasured_rule_ids.join(", ")}`,
  );
  lines.push("");
  return lines.join("\n");
}

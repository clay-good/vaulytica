/**
 * Vaulytica headless CLI (spec-v8 Thrust C, Steps 143–145).
 *
 *   tsx tools/cli/run.ts analyze <path|glob|dir> \
 *       [--playbook <id>] [--format json,sarif,html,md,csv] \
 *       [--out <dir>] [--fail-on critical|warning|info] \
 *       [--court <frap-default|ca9-appellate|cal-rules-8.204> [--reply]] \
 *       [--playbook-file <path> --posture [--fail-on-divergence]] \
 *       [--baseline <bundle> | --baseline-coherence <coherence.json>] \
 *       [--emit-coherence <path>] [--fail-on-coherence-regression]
 *
 * `--court` selects a court profile and runs the filing-format-lint pack
 * (FILE-001..008) against its limits, but only when the document matches a
 * filing playbook (appellate-brief / trial-motion / petition); without it the
 * pack is dormant. `--reply` applies the profile's reply-brief limits.
 *
 * `--deadline-profile <frcp-6|cal-ccp-12>` (+ optional `--service-method
 * <electronic|mail|clerk|other-consented|personal>`) resolves the
 * critical-dates register's business-day/court-day and calendar-day offsets
 * under the selected rule (FRCP 6 / CCP 12): court-day counting for "business
 * days", and FRCP 6(a) roll-forward + 6(d) service for "days". Without it the
 * register — and every existing hash — is unchanged.
 *
 * `analyze <dir|.zip> --production-qa` runs production QA over a document
 * production set (not per-document analysis): Bates sequence + privilege-log
 * (the single `.csv` member) reconciliation and a pre-production HANDOFF sweep,
 * emitting a JSON report with its own `production_qa_hash`.
 * `--fail-on-production-gap` exits non-zero (2) when a Bates gap is found, for a
 * CI check before a production goes out.
 *
 * `--regime <ccpa,gdpr,gdpr-13,gdpr-14>` (comma-separated; `gdpr` = both
 * articles) runs the privacy-notice content checks (PNOT presence rules) for
 * the asserted regime(s) when the document matches a privacy-notice playbook;
 * dormant with none asserted. The asserted regimes are stamped into the run and
 * a per-regime coverage table (found / not detected) is added to the JSON.
 *
 * `--estate-checks` runs the estate deepening rules (EST-1xx recital presence,
 * EST-2xx residuary share arithmetic, EST-3xx fiduciary/survivorship) when the
 * document is a will, revocable trust, or codicil. Assertion-gated: without the
 * flag the pack is dormant and existing will/trust hashes are unchanged. It
 * checks recitals, not valid execution.
 *
 * spec-v15: an emitted coherence artifact is pinned to the playbook ladder its
 * rungs were computed against; `--baseline-coherence` refuses to diff it against
 * a round computed on a different ladder (a cross-ladder compare is meaningless).
 *   tsx tools/cli/run.ts diff <a.json> <b.json> [--format markdown|json] [--exit-code]
 *   tsx tools/cli/run.ts compare <base> <revised> [--fail-on <sev>] [--fail-on-regression] [--format json|markdown]
 *   tsx tools/cli/run.ts compare-coherence <base.coherence.json> <revised.coherence.json> [--format markdown|json] [--fail-on-coherence-regression]
 *   tsx tools/cli/run.ts coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coherence-regression]
 *   tsx tools/cli/run.ts coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-fracture]
 *   tsx tools/cli/run.ts coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-regression-or-fracture]
 *   tsx tools/cli/run.ts coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-exposure]
 *   tsx tools/cli/run.ts coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-open-exposure]
 *   tsx tools/cli/run.ts coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-widening-exposure]
 *   tsx tools/cli/run.ts coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-recurring-exposure]
 *   tsx tools/cli/run.ts coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-volatile-exposure]
 *   tsx tools/cli/run.ts coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-synchronized-exposure]
 *   tsx tools/cli/run.ts coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-unsettled-exposure]
 *   tsx tools/cli/run.ts verify <report.json> <original> [--playbook <id>] [--dkb <dir>]
 *
 * One dispatcher over the reach commands: `analyze` runs the engine headless
 * (CI gate), `diff` compares two custom playbooks (Step 144), `compare`
 * version-compares two documents + emits the clause redline (a CI redline
 * gate), `compare-coherence` diffs two saved coherence artifacts with no
 * documents on either side (spec-v16), `coherence-trend` walks N ≥ 2 saved
 * coherence artifacts and reports the per-front binding-floor trajectory across
 * the whole negotiation (spec-v17), `coherence-shift-trend` walks the same N
 * artifacts and reports the per-front fracture/reconcile trajectory (spec-v18),
 * `coherence-arc` joins those two trajectories into the v13 per-front combined
 * view over N rounds with one combined gate (spec-v19), `coherence-exposure`
 * reads the same N artifacts on the orthogonal *level* axis — the worst binding
 * floor each front reached across the deal, gating on a front that ever fell
 * below the acceptable floor (spec-v20), `coherence-persistence` reads the same N
 * artifacts on the orthogonal *duration* axis — how long each front sat below the
 * floor and whether it is *still* below floor, gating only on a front open now
 * (spec-v21), `coherence-breadth` reads the same N artifacts on the transpose
 * *per-round* axis — how many fronts sat below the floor in each round, the deal's
 * worst round, and whether the package's exposure broadened first→latest, gating on
 * a widening deal (spec-v22), `coherence-recurrence` reads the same N artifacts on
 * the orthogonal *episode-count* axis — how many *separate* times each front fell
 * below the floor (one steady descent vs a recover-then-relapse), gating on a front
 * that recovered and relapsed (spec-v23), `coherence-volatility` reads the same N
 * artifacts on the orthogonal *crossing-count* axis — how many times each front's
 * standing flipped across the floor (falls and recoveries alike), gating on a front
 * whose standing reversed across the floor (spec-v24), `coherence-synchrony` reads
 * the same N artifacts on the per-round transpose of that crossing axis — how many
 * fronts crossed the floor *together* in each round-transition, the deal's peak step,
 * gating on a synchronized step where two or more fronts crossed at once
 * (spec-v25), `coherence-settling` reads the same N artifacts on the orthogonal
 * *time-of-last-movement* axis — the latest round-transition any front crossed the
 * floor, the quiet tail of steady rounds after it, and whether the final transition
 * still crossed, gating on a deal that never settled before the close (spec-v26),
 * `coherence-onset` reads the mirror *time-of-first-movement* axis — the earliest
 * round-transition any front crossed the floor, the clean lead-in of steady rounds
 * before it, and whether the first transition crossed, gating on a deal that
 * degraded from the opening (spec-v27), `coherence-latency` reads the same N
 * artifacts on the orthogonal *recovery-latency* axis — per front, how many rounds
 * its standing sat below the floor between a fall and the recovery that closes it, the
 * deal's slowest recovery, and whether any fall went unrecovered, gating on a front
 * that fell and never came back (spec-v28), `coherence-concurrency` reads the
 * direction-resolved split of v25's per-step crossing axis — per step, how many fronts
 * *fell* below the floor vs. *recovered*, the deal's peak fall step, gating on a
 * concerted fall where two or more fronts fell together (spec-v29), `coherence-relapse`
 * reads the mirror of v28's recovery-latency axis — per front, how many rounds its
 * standing held *above* the floor between a recovery and the next fall that undoes it,
 * the deal's quickest relapse, gating on a recovery undone at the very next round
 * (spec-v30), `coherence-tenure` reads the orthogonal *occupancy* axis — per front, what
 * share of the rounds that stated it sat below the floor, the deal's heaviest such share,
 * gating on a front below floor for a strict majority of its stated rounds (spec-v31),
 * `coherence-affinity` reads the orthogonal *pairwise* axis — per pair of fronts, how
 * reliably the two fell below the floor *together* across the deal, the deal's tightest
 * such pairing, gating on a pair that fell together more often than apart (spec-v32),
 * `coherence-recovery-affinity` reads the mirror of that pairwise axis on the *recovery*
 * direction — per pair of fronts, how reliably the two *recovered* together across the deal,
 * the deal's tightest such pairing, gating on a pair restored together more often than apart
 * (spec-v33), `coherence-opposition` reads the off-diagonal completion of those two pairwise
 * axes — per pair of fronts, how often the two crossed the floor the same step in *opposite*
 * directions (one fell as the other recovered), a see-saw the counterparty trades one against
 * the other, gating on a pair that counter-moved more often than it aligned (spec-v34),
 * `coherence-precedence` reads the family's first *directional* pairwise axis — per pair of fronts,
 * when the two both cross the floor (in any direction), whether one consistently crosses *first*
 * (a lead-lag pairing whose leader is an early-warning indicator for the follower), gating on a
 * front that crossed first for a strict majority of the comparisons (spec-v35),
 * `coherence-concession` reads the family's first *direction-resolved* precedence — restricted to
 * *falls* only, per pair of fronts, which front *concedes* (falls below floor) first (a pair can
 * lead v35 because one front *recovers* first; this isolates the concession order), gating on a
 * front that conceded first for a strict majority of the comparisons (spec-v36),
 * `coherence-recovery-order` reads the recovery mirror of that direction-resolved precedence —
 * restricted to *recoveries* only, per pair of fronts, which front climbs back above the floor *first*
 * (and so which recovers *last*, the laggard left exposed longest), gating on a front recovered first
 * for a strict majority of the comparisons — and so a consistent laggard (spec-v37),
 * `coherence-weak-front` reads the family's first *per-front* synthesis — the join of v36 and v37, per
 * front, whether it both *concedes* first (a v36 first-conceder) *and* *recovers* last (a v37
 * last-recoverer), gating on a single front that is the weak side of *both* orderings — the deal's
 * persistent weak point (spec-v38),
 * `coherence-cadence` reads the *churn* mirror of v31's dwell — per front, the *rate* at which it flips
 * across the floor (`crossings` out of its `transitions`), gating on a front that crossed for a strict
 * majority of its transitions: an oscillating front that flips sides more often than it holds one
 * (spec-v39),
 * `coherence-duration` reads the *duration-magnitude* of v28's recovery episodes — per front, the
 * *mean* rounds its binding floor sat below the floor across its recovered exposures, gating on a
 * front whose recovered exposures *typically* span at least two rounds: a chronic lingerer the single
 * worst episode cannot name (spec-v40),
 * `coherence-durability` reads the above-floor mirror of v40 — the *durability-magnitude* of v30's
 * relapse intervals — per front, the *mean* clean rounds its binding floor held above the floor across
 * its relapsed recoveries, gating on a front whose relapsed recoveries *typically* hold fewer than two
 * clean rounds: a chronically fragile front whose fix usually does not survive a single round, strictly
 * stronger evidence than v30's single-fast-relapse gate (spec-v41),
 * `coherence-chain` reads the *transitive closure* of v35's pairwise lead-lag relation — composing
 * the strict-majority `leading` edges into a directed graph, naming the deal's *headwater* (the
 * greatest-reach source front, the one to watch first across a whole cascade), and gating on a
 * directed *cycle* (Cap leads Term leads Indemnity leads Cap — three clean pairwise leads that
 * cannot be globally ranked, an intransitivity no pairwise read can see) (spec-v42),
 * `coherence-recovery-chain` reads the *transitive closure* of v37's pairwise recovery-order
 * relation — the recovery mirror of v42 — composing the strict-majority `first_recoverer →
 * last_recoverer` edges into a directed graph, naming the deal's *tailwater* (the front the
 * counterparty restores last across a whole cascade, left exposed below the floor longest), and
 * gating on a directed *cycle* (Cap recovers before Term before Indemnity before Cap — three clean
 * pairwise orders that cannot be globally ranked) (spec-v43),
 * `coherence-matrix` emits the raw *per-front × per-round* floor-state grid every other axis
 * collapses — a posture *heatmap* (each cell `below` / `above` / `unstated`) plus the per-round
 * column summaries — gating on a *blackout* round in which every stated front sits below the floor
 * at once, the deal's worst cross-section, the one whole-grid verdict no reduction poses (spec-v44) — and
 * `verify` re-derives a saved report's `result_hash` (Step 145).
 * The DKB ships with the tool — it opens no socket. The engine is the SAME engine
 * the tab runs (parity-proven), so a number on a CI dashboard describes
 * shipped behavior. Build/CI-only; never imported by `src/`.
 */

import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, basename, extname, resolve } from "node:path";

import { analyzeFile, loadAccuracyDeps, runProductionQa, type AnalyzeResult } from "./api.js";
import { COURT_PROFILE_IDS, getCourtProfile } from "../../src/filing/court-profile.js";
import type { CourtProfile } from "../../src/filing/court-profile.js";
import type { BriefKind } from "../../src/filing/run-options.js";
import { DEADLINE_PROFILE_IDS, getDeadlineProfile } from "../../src/deadlines/profile.js";
import { SERVICE_METHODS } from "../../src/deadlines/profile.js";
import type { DeadlineResolution } from "../../src/report/critical-dates.js";
import { REGIME_IDS } from "../../src/privacy/regime-data.js";
import type { RegimeId } from "../../src/privacy/regime-data.js";

/** Values the `--regime` flag accepts (`gdpr` expands to both articles). */
const REGIME_FLAG_VALUES = ["ccpa", "gdpr", "gdpr-13", "gdpr-14"] as const;
import { runDiff } from "./diff.js";
import { runCompare } from "./compare.js";
import { runCompareCoherence } from "./compare-coherence.js";
import { runCoherenceTrend } from "./coherence-trend.js";
import { runPostureReview } from "./posture-review.js";
import { runCoherenceShiftTrend } from "./coherence-shift-trend.js";
import { runCoherenceArc } from "./coherence-arc.js";
import { runCoherenceExposure } from "./coherence-exposure.js";
import { runCoherencePersistence } from "./coherence-persistence.js";
import { runCoherenceBreadth } from "./coherence-breadth.js";
import { runCoherenceRecurrence } from "./coherence-recurrence.js";
import { runCoherenceVolatility } from "./coherence-volatility.js";
import { runCoherenceSynchrony } from "./coherence-synchrony.js";
import { runCoherenceSettling } from "./coherence-settling.js";
import { runCoherenceOnset } from "./coherence-onset.js";
import { runCoherenceLatency } from "./coherence-latency.js";
import { runCoherenceConcurrency } from "./coherence-concurrency.js";
import { runCoherenceRelapse } from "./coherence-relapse.js";
import { runCoherenceTenure } from "./coherence-tenure.js";
import { runCoherenceAffinity } from "./coherence-affinity.js";
import { runCoherenceRecoveryAffinity } from "./coherence-recovery-affinity.js";
import { runCoherenceOpposition } from "./coherence-opposition.js";
import { runCoherencePrecedence } from "./coherence-precedence.js";
import { runCoherenceConcession } from "./coherence-concession.js";
import { runCoherenceRecoveryOrder } from "./coherence-recovery-order.js";
import { runCoherenceWeakFront } from "./coherence-weak-front.js";
import { runCoherenceCadence } from "./coherence-cadence.js";
import { runCoherenceDuration } from "./coherence-duration.js";
import { runCoherenceDurability } from "./coherence-durability.js";
import { runCoherenceChain } from "./coherence-chain.js";
import { runCoherenceRecoveryChain } from "./coherence-recovery-chain.js";
import { runCoherenceMatrix } from "./coherence-matrix.js";
import { verifyReproducibilityFromFile, explainReproResult, type SavedReport } from "./verify.js";
import type { Severity } from "../../src/engine/index.js";
import { extractAll } from "../../src/extract/index.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildSarifJson } from "../../src/report/sarif.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildFixListMarkdown, buildFixListCsv } from "../../src/report/exports.js";
import { dkbCurrency } from "../../src/report/citations.js";
import { buildReviewedDocx } from "../../src/report/docx-comments.js";
import {
  buildCertificateDocx,
  buildCertificateJson,
  verifyCertificateHash,
  CERTIFICATE_SCHEMA,
  type VerificationCertificate,
} from "../../src/report/certificate.js";
import { buildDefinitionsReport, buildDefinitionsMarkdown } from "../../src/report/definitions.js";
import { parseCustomPlaybookJson } from "../../src/playbooks/custom-playbook.js";
import { ladderHash } from "../../src/playbooks/custom-interpreter.js";
import {
  bundlePostureCoherence,
  hasDivergence,
  buildPostureCoherenceJson,
  parsePostureCoherenceJson,
  type CoherenceInput,
  type PostureCoherence,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherence,
  coherenceRegressed,
  renderCoherenceMovementSummary,
} from "../../src/report/coherence-movement.js";

const SUPPORTED_EXT = new Set([".txt", ".md", ".markdown", ".text", ".docx", ".pdf"]);
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
type Format = "json" | "sarif" | "html" | "md" | "csv" | "docx-comments";
/**
 * Formats a machine consumes (`jq`, SARIF uploaders, spreadsheets). Stream
 * contract (fix-cli-json-purity): when any of these is selected, stdout
 * carries ONLY the serialized artifact — every human summary/progress line
 * goes to stderr, so `analyze x.docx --format json | jq .` just works.
 */
const MACHINE_FORMATS: ReadonlySet<Format> = new Set(["json", "sarif", "csv"]);
const VALID_FORMATS = ["json", "sarif", "html", "md", "csv", "docx-comments"] as const;
const FORMAT_EXT: Record<Format, string> = {
  json: ".json",
  sarif: ".sarif.json",
  html: ".html",
  md: ".fixlist.md",
  csv: ".fixlist.csv",
  "docx-comments": ".reviewed.docx",
};

type Args = {
  target: string;
  playbook?: string;
  formats: Format[];
  out?: string;
  failOn?: Severity;
  /** spec-v9 Thrust A — run the pre-disclosure ("Clean to Send") scan. */
  delivery?: boolean;
  /** spec-v9 Thrust C — compute the critical-dates register. */
  criticalDates?: boolean;
  /** spec-v9 Thrust B — build the closing checklist. */
  checklist?: boolean;
  /** spec-v10 Thrust B — path to a custom playbook whose positions drive `--posture`. */
  playbookFile?: string;
  /** spec-v10 Thrust B — evaluate the custom playbook's negotiation posture. */
  posture?: boolean;
  /** spec-v12 Thrust A — exit non-zero when a posture front diverges across the bundle. */
  failOnDivergence?: boolean;
  /** spec-v13 Thrust A — a baseline bundle (path|glob|dir) to diff the coherence against. */
  baseline?: string;
  /** spec-v13 Thrust A — exit non-zero when the bundle's binding floor regressed vs. the baseline. */
  failOnCoherenceRegression?: boolean;
  /** spec-v14 Thrust B — write this round's cross-document coherence to a portable artifact. */
  emitCoherence?: string;
  /** spec-v14 Thrust B — diff against a saved coherence artifact instead of re-analyzing a baseline bundle. */
  baselineCoherence?: string;
  /** Explicit DKB artifact directory; default resolves the latest `dkb/dist/` version (browser parity). */
  dkb?: string;
  /** Ingest the target(s) as UTF-8 text regardless of extension (never .docx/.pdf). */
  asText?: boolean;
  /** Write the verification certificate (<name>.certificate.{docx,json}) alongside the report. */
  certificate?: boolean;
  /** Add the definitions report to the JSON output and the md summary. */
  definitions?: boolean;
  /** add-filing-format-lint — the court profile id whose limits the FILE pack applies. */
  court?: string;
  /** add-filing-format-lint — treat the document as a reply brief (reply limits). */
  reply?: boolean;
  /** add-deadline-computation — the deadline profile id for critical-dates resolution. */
  deadlineProfile?: string;
  /** add-deadline-computation — the service method for the FRCP 6(d) / CCP 1013 add-on. */
  serviceMethod?: string;
  /** add-production-qa-pack — run production QA over a directory/.zip production set. */
  productionQa?: boolean;
  /** add-production-qa-pack — exit non-zero when a Bates sequence gap is found. */
  failOnProductionGap?: boolean;
  /** add-privacy-notice-pack — asserted privacy regimes for the PNOT pack. */
  regimes?: string[];
  /** add-estate-planning-pack — assert the estate-checks pack on wills/trusts/codicils. */
  estateChecks?: boolean;
};

/** Build the filing activation from parsed args, or undefined when no `--court`. */
function filingOptionFrom(
  args: Args,
): { profile: CourtProfile; brief_kind: BriefKind } | undefined {
  if (!args.court) return undefined;
  const profile = getCourtProfile(args.court);
  if (!profile) return undefined; // already validated in parseArgs; defensive
  return { profile, brief_kind: args.reply ? "reply" : "principal" };
}

/** Build the deadline resolution from parsed args, or undefined when no profile. */
function deadlineOptionFrom(args: Args): DeadlineResolution | undefined {
  if (!args.deadlineProfile) return undefined;
  const profile = getDeadlineProfile(args.deadlineProfile);
  if (!profile) return undefined; // validated in parseArgs; defensive
  return {
    profile,
    ...(args.serviceMethod ? { service_method: args.serviceMethod as never } : {}),
  };
}

function parseArgs(argv: string[]): Args {
  // argv: [target, ...flags] (the "analyze" command word is already stripped)
  const target = argv[0];
  if (!target || target.startsWith("--")) throw new Error("missing <path|glob|dir> argument");
  const args: Args = { target, formats: ["json"] };
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const val = argv[i + 1];
    switch (flag) {
      case "--playbook":
        args.playbook = val;
        i++;
        break;
      case "--format": {
        // Empty / unknown / duplicate values are usage errors, never a
        // silent no-op (fix-cli-output-completeness).
        const values = (val ?? "")
          .split(",")
          .map((f) => f.trim())
          .filter(Boolean);
        if (values.length === 0) {
          throw new Error(`--format requires a value: ${VALID_FORMATS.join(", ")}`);
        }
        for (const v of values) {
          if (!(VALID_FORMATS as readonly string[]).includes(v)) {
            throw new Error(`unknown --format "${v}" (valid: ${VALID_FORMATS.join(", ")})`);
          }
        }
        if (new Set(values).size !== values.length) {
          throw new Error(`duplicate --format value in "${val}"`);
        }
        args.formats = values as Format[];
        i++;
        break;
      }
      case "--out":
        args.out = val;
        i++;
        break;
      case "--fail-on":
        args.failOn = val as Severity;
        i++;
        break;
      case "--delivery":
        args.delivery = true;
        break;
      case "--critical-dates":
        args.criticalDates = true;
        break;
      case "--checklist":
        args.checklist = true;
        break;
      case "--playbook-file":
        args.playbookFile = val;
        i++;
        break;
      case "--posture":
        args.posture = true;
        break;
      case "--fail-on-divergence":
        args.failOnDivergence = true;
        break;
      case "--baseline":
        args.baseline = val;
        i++;
        break;
      case "--fail-on-coherence-regression":
        args.failOnCoherenceRegression = true;
        break;
      case "--emit-coherence":
        args.emitCoherence = val;
        i++;
        break;
      case "--baseline-coherence":
        args.baselineCoherence = val;
        i++;
        break;
      case "--dkb":
        args.dkb = val;
        i++;
        break;
      case "--as-text":
        args.asText = true;
        break;
      case "--certificate":
        args.certificate = true;
        break;
      case "--definitions":
        args.definitions = true;
        break;
      case "--court":
        if (!val || val.startsWith("--")) {
          throw new Error(`--court requires a profile id (one of: ${COURT_PROFILE_IDS.join(", ")})`);
        }
        if (!COURT_PROFILE_IDS.includes(val)) {
          throw new Error(`unknown --court profile "${val}" (valid: ${COURT_PROFILE_IDS.join(", ")})`);
        }
        args.court = val;
        i++;
        break;
      case "--reply":
        args.reply = true;
        break;
      case "--deadline-profile":
        if (!val || val.startsWith("--")) {
          throw new Error(
            `--deadline-profile requires a profile id (one of: ${DEADLINE_PROFILE_IDS.join(", ")})`,
          );
        }
        if (!DEADLINE_PROFILE_IDS.includes(val)) {
          throw new Error(
            `unknown --deadline-profile "${val}" (valid: ${DEADLINE_PROFILE_IDS.join(", ")})`,
          );
        }
        args.deadlineProfile = val;
        i++;
        break;
      case "--service-method":
        if (!val || val.startsWith("--")) {
          throw new Error(`--service-method requires a value (${SERVICE_METHODS.join(", ")})`);
        }
        if (!(SERVICE_METHODS as readonly string[]).includes(val)) {
          throw new Error(`unknown --service-method "${val}" (valid: ${SERVICE_METHODS.join(", ")})`);
        }
        args.serviceMethod = val;
        i++;
        break;
      case "--regime": {
        if (!val || val.startsWith("--")) {
          throw new Error(`--regime requires a value (${REGIME_FLAG_VALUES.join(", ")})`);
        }
        const requested = val
          .split(",")
          .map((r) => r.trim().toLowerCase())
          .filter(Boolean);
        const resolved: string[] = [];
        for (const r of requested) {
          if (r === "gdpr") {
            resolved.push("gdpr-13", "gdpr-14");
          } else if ((REGIME_IDS as readonly string[]).includes(r)) {
            resolved.push(r);
          } else {
            throw new Error(`unknown --regime "${r}" (valid: ${REGIME_FLAG_VALUES.join(", ")})`);
          }
        }
        args.regimes = [...new Set(resolved)];
        i++;
        break;
      }
      case "--estate-checks":
        args.estateChecks = true;
        break;
      case "--production-qa":
        args.productionQa = true;
        break;
      case "--fail-on-production-gap":
        args.failOnProductionGap = true;
        break;
      default:
        throw new Error(`unknown flag "${flag}"`);
    }
  }
  return args;
}

/** Recursively collect supported files under a directory. */
async function walkDir(dir: string): Promise<string[]> {
  const out: string[] = [];
  // Code-unit ordering (not `localeCompare`, which depends on the host
  // locale/ICU and would make a directory analysis non-reproducible across
  // machines) — and identical to the glob branch's bare `.sort()`, so
  // `analyze dir/` and `analyze 'dir/*.ext'` ingest files in the same order.
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walkDir(full)));
    else if (SUPPORTED_EXT.has(extname(entry.name).toLowerCase())) out.push(full);
  }
  return out;
}

/**
 * Split a `dir/pattern` glob into its directory and basename pattern. A glob
 * with no slash (e.g. `*.docx`) resolves against the current directory — the
 * previous `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`)
 * for that case, so a bare glob silently matched nothing.
 */
export function splitGlob(target: string): { dir: string; pattern: string } {
  const slash = target.lastIndexOf("/");
  return slash >= 0
    ? { dir: target.slice(0, slash) || "/", pattern: target.slice(slash + 1) }
    : { dir: ".", pattern: target };
}

/** Compile a single-segment glob pattern (`*` wildcard) to an anchored RegExp. */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + escaped + "$");
}

/** Resolve the target into a deterministic, sorted list of input files. */
export async function resolveInputs(
  target: string,
  opts: { asText?: boolean } = {},
): Promise<string[]> {
  const st = await stat(target).catch(() => null);
  if (st?.isDirectory()) return walkDir(target);
  if (st?.isFile()) {
    // A directly named file honors the same allowlist directory and glob
    // resolution apply (fix-cli-input-type-honesty): an unknown extension
    // used to fall through to a silent UTF-8 decode and a full,
    // confidently wrong findings report. `--as-text` is the explicit
    // opt-in for extensionless / unconventionally named text files.
    if (!opts.asText && !SUPPORTED_EXT.has(extname(target).toLowerCase())) {
      throw new Error(
        `unsupported input type: ${target} (supported: ` +
          `${[...SUPPORTED_EXT].sort().join(", ")}; pass --as-text to ingest as UTF-8 text)`,
      );
    }
    return [target];
  }
  // Treat as a simple `dir/*.ext` glob (one wildcard segment).
  if (target.includes("*")) {
    const { dir, pattern } = splitGlob(target);
    const re = globToRegExp(pattern);
    const names = await readdir(dir).catch(() => [] as string[]);
    return names
      .filter((n) => re.test(n))
      .filter((n) => opts.asText || SUPPORTED_EXT.has(extname(n).toLowerCase()))
      .sort()
      .map((n) => join(dir, n));
  }
  throw new Error(`no such file or directory: ${target}`);
}

async function renderFormat(
  fmt: Exclude<Format, "docx-comments">,
  r: AnalyzeResult,
  dkb: Dkb,
  definitions?: import("../../src/report/definitions.js").DefinitionsReport,
): Promise<string> {
  // Deterministic citation-currency reference — the DKB's own build date.
  const currency = dkbCurrency(dkb.manifest);
  // The v9 "Last Look" surfaces, populated only when the matching flag ran
  // (--delivery / --critical-dates / --checklist). Threaded into every format.
  const v9surfaces = {
    delivery: r.delivery,
    criticalDates: r.critical_dates,
    closingChecklist: r.closing_checklist,
  };
  switch (fmt) {
    case "json":
      return buildJsonReport(
        r.run,
        r.ingest,
        undefined,
        undefined,
        undefined,
        r.delivery,
        r.critical_dates,
        r.closing_checklist,
        r.negotiation_posture,
        currency,
        definitions,
      ).text();
    case "sarif":
      return buildSarifJson(r.run, v9surfaces, currency);
    case "html":
      return buildHtmlReport(r.run, r.ingest, dkb, undefined, v9surfaces);
    case "md": {
      const md = buildFixListMarkdown(r.run, undefined, currency);
      return definitions ? `${md}\n${buildDefinitionsMarkdown(definitions)}` : md;
    }
    case "csv":
      return buildFixListCsv(r.run, currency);
  }
}

type Dkb = Awaited<ReturnType<typeof loadAccuracyDeps>>["dkb"];

/**
 * Portable document identifier for coherence/posture artifacts
 * (fix-verify-receipt-depth): the basename, so an artifact hashes
 * identically no matter which machine or directory the bundle was
 * verified from — and never leaks the author's local paths. Collision
 * rule: when two inputs in the bundle share a basename, both keep their
 * as-given path (normalized to forward slashes), which must differ.
 */
export function documentLabel(file: string, all: readonly string[]): string {
  const base = basename(file);
  const collides = all.some((f) => f !== file && basename(f) === base);
  return collides ? file.split("\\").join("/") : base;
}

function worstSeverity(r: AnalyzeResult): Severity | null {
  let worst: Severity | null = null;
  for (const f of r.run.findings) {
    if (worst === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

export async function runAnalyze(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  // Stream contract: with a machine format active, human lines → stderr.
  const machine = args.formats.some((f) => MACHINE_FORMATS.has(f));
  const human = (s: string): void => {
    (machine ? process.stderr : process.stdout).write(s);
  };

  // add-production-qa-pack — a distinct mode over a production SET (a directory
  // or .zip), not per-document analysis: Bates + privilege-log reconciliation
  // and a pre-production sweep. Handled here before the document flow.
  if (args.productionQa) {
    const report = await runProductionQa(args.target);
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    const gapCount = report.findings.filter(
      (f) => f.code === "PROD-001" || f.code === "PROD-011",
    ).length;
    process.stderr.write(
      `Production QA: ${report.member_count} members, ${report.findings.length} finding(s)` +
        `${report.log_present ? ", privilege log reconciled" : ", no privilege log"}.\n`,
    );
    if (args.failOnProductionGap && gapCount > 0) {
      process.stderr.write(`--fail-on-production-gap: ${gapCount} Bates gap finding(s).\n`);
      process.exitCode = 2;
    }
    return;
  }

  const deps = await loadAccuracyDeps({ dkbDir: args.dkb });

  // spec-v10 Thrust B — load + validate a custom playbook file (its
  // `negotiation_positions` drive `--posture`). A malformed playbook is a hard
  // error with the validator's messages, never a silent no-op.
  let customPlaybook: import("../../src/playbooks/custom-playbook.js").CustomPlaybook | undefined;
  if (args.playbookFile) {
    const text = await readFile(args.playbookFile, "utf8").catch(() => null);
    if (text === null) {
      process.stderr.write(`cannot read playbook file: ${args.playbookFile}\n`);
      process.exitCode = 1;
      return;
    }
    const parsed = parseCustomPlaybookJson(text);
    if (!parsed.ok) {
      process.stderr.write(
        `invalid playbook ${args.playbookFile}:\n  ${parsed.errors.join("\n  ")}\n`,
      );
      process.exitCode = 1;
      return;
    }
    customPlaybook = parsed.playbook;
    if (args.posture && !customPlaybook.negotiation_positions?.length) {
      process.stderr.write(`--posture: ${args.playbookFile} defines no negotiation_positions.\n`);
    }
  }
  if (args.posture && !args.playbookFile) {
    process.stderr.write("--posture requires --playbook-file <path>\n");
    process.exitCode = 1;
    return;
  }
  if (args.failOnDivergence && !args.posture) {
    process.stderr.write("--fail-on-divergence requires --posture\n");
    process.exitCode = 1;
    return;
  }
  if (args.baseline && !args.posture) {
    process.stderr.write("--baseline requires --posture\n");
    process.exitCode = 1;
    return;
  }
  // spec-v14 — a saved coherence baseline is an alternative source for the same
  // diff; it requires --posture (this round must produce a coherence) and is
  // mutually exclusive with re-analyzing a baseline bundle.
  if (args.baselineCoherence && !args.posture) {
    process.stderr.write("--baseline-coherence requires --posture\n");
    process.exitCode = 1;
    return;
  }
  if (args.baseline && args.baselineCoherence) {
    process.stderr.write("--baseline and --baseline-coherence are mutually exclusive\n");
    process.exitCode = 1;
    return;
  }
  if (args.failOnCoherenceRegression && !args.baseline && !args.baselineCoherence) {
    process.stderr.write(
      "--fail-on-coherence-regression requires --baseline or --baseline-coherence\n",
    );
    process.exitCode = 1;
    return;
  }
  if (args.emitCoherence && !args.posture) {
    process.stderr.write("--emit-coherence requires --posture\n");
    process.exitCode = 1;
    return;
  }

  const inputs = await resolveInputs(args.target, { asText: args.asText });
  // Delivery completeness (fix-cli-output-completeness): every rendered
  // artifact must have a destination. Multi-format or multi-input runs
  // used to render everything and silently drop it (summary line, exit 0)
  // whenever --out was absent.
  if (!args.out && (args.formats.length > 1 || inputs.length > 1)) {
    throw new Error(
      `multiple formats/inputs require --out <dir> — ` +
        `${inputs.length} input(s) × ${args.formats.length} format(s) would render with nowhere to go`,
    );
  }
  if (!args.out && args.certificate) {
    throw new Error("--certificate writes binary .docx output and requires --out <dir>");
  }
  if (!args.out && args.formats.includes("docx-comments")) {
    throw new Error(
      "--format docx-comments produces a binary .docx and requires --out <dir> (never stdout)",
    );
  }
  if (args.formats.includes("docx-comments")) {
    const nonDocx = inputs.filter((f) => extname(f).toLowerCase() !== ".docx");
    if (nonDocx.length > 0) {
      throw new Error(
        `--format docx-comments annotates a copy of the uploaded DOCX and only applies to .docx inputs; not: ${nonDocx.join(", ")}`,
      );
    }
  }
  if (inputs.length === 0) {
    process.stderr.write(`no analyzable files matched: ${args.target}\n`);
    process.exitCode = 1;
    return;
  }

  let breached = false;
  // spec-v12 Thrust A — collect each document's posture so that, after the
  // bundle is analyzed, we can report how each negotiation front sits *across*
  // the documents (the cross-document axis of the v10 posture).
  const postures: CoherenceInput[] = [];
  const filing = filingOptionFrom(args);
  const deadline = deadlineOptionFrom(args);
  for (const file of inputs) {
    const r = await analyzeFile(file, {
      playbookId: args.playbook,
      deps,
      asText: args.asText,
      delivery: args.delivery,
      criticalDates: args.criticalDates,
      checklist: args.checklist,
      customPlaybook,
      posture: args.posture,
      filing,
      deadline,
      regimes: args.regimes as RegimeId[] | undefined,
      estateChecks: args.estateChecks,
    });

    const counts = { critical: 0, warning: 0, info: 0 };
    for (const f of r.run.findings) counts[f.severity]++;
    human(`${file}  [${r.playbook_id}]  ${counts.critical}C ${counts.warning}W ${counts.info}I\n`);
    if (r.delivery) human(`  ${r.delivery.summary}\n`);
    if (r.critical_dates) {
      human(
        `  Critical dates: ${r.critical_dates.resolved_count} computed, ${r.critical_dates.unresolved_count} to verify manually.\n`,
      );
    }
    if (r.closing_checklist) {
      human(
        `  Closing checklist: ${r.closing_checklist.open_count} readiness item(s) to resolve.\n`,
      );
    }
    if (r.negotiation_posture) {
      const c = r.negotiation_posture.counts;
      human(
        `  Negotiation posture: ${c.ideal} ideal, ${c.acceptable} acceptable, ${c.below_acceptable} below floor, ${c.unevaluable} not stated.\n`,
      );
      postures.push({ document: documentLabel(file, inputs), posture: r.negotiation_posture });
    }

    // add-defined-terms-report — projection over a classifier-free
    // re-extract (definitions don't need the classifier), outside the run.
    const definitions = args.definitions
      ? await buildDefinitionsReport(extractAll(r.ingest.tree))
      : undefined;

    for (const fmt of args.formats) {
      if (fmt === "docx-comments") {
        // Binary reviewed copy: the uploaded container plus anchored Word
        // comments (add-word-comment-export). Validated above: .docx input
        // and --out are both guaranteed here.
        const originalBytes = await readFile(file);
        const reviewed = buildReviewedDocx(
          originalBytes.buffer.slice(
            originalBytes.byteOffset,
            originalBytes.byteOffset + originalBytes.byteLength,
          ) as ArrayBuffer,
          r.run,
        );
        await mkdir(args.out!, { recursive: true });
        const outName = basename(file, extname(file)) + FORMAT_EXT[fmt];
        await writeFile(join(args.out!, outName), reviewed.bytes);
        human(
          `  Reviewed copy: ${reviewed.anchored} comment(s) anchored` +
            `${reviewed.unanchored > 0 ? `, ${reviewed.unanchored} collected at document start` : ""} → ${outName}\n`,
        );
        continue;
      }
      const content = await renderFormat(fmt, r, deps.dkb, definitions);
      if (args.out) {
        await mkdir(args.out, { recursive: true });
        const outName = basename(file, extname(file)) + FORMAT_EXT[fmt];
        await writeFile(join(args.out, outName), content);
      } else {
        // By construction single input × single format (validated above),
        // so stdout is a complete delivery target — never render-and-drop.
        process.stdout.write(content + "\n");
      }
    }

    if (args.certificate) {
      // Verification certificate (add-court-certification-receipt): the
      // one-page compliance artifact + tamper-evident JSON companion.
      await mkdir(args.out!, { recursive: true });
      const stem = basename(file, extname(file));
      const certJson = await buildCertificateJson(r.run);
      await writeFile(join(args.out!, `${stem}.certificate.json`), certJson);
      const certDocx = await buildCertificateDocx(r.run);
      await writeFile(
        join(args.out!, `${stem}.certificate.docx`),
        new Uint8Array(await certDocx.arrayBuffer()),
      );
      human(`  Verification certificate → ${stem}.certificate.{docx,json}\n`);
    }

    if (args.failOn) {
      const worst = worstSeverity(r);
      if (worst !== null && SEVERITY_RANK[worst] <= SEVERITY_RANK[args.failOn]) breached = true;
    }
  }

  // spec-v12 Thrust A — cross-document posture coherence. Only meaningful for a
  // bundle (≥2 documents) classified against the same playbook ladder: it shows,
  // per front, whether the documents agree on the rung or one undercuts the
  // position, and surfaces the bundle's binding floor.
  let diverged = false;
  let coherence: PostureCoherence | null = null;
  if (args.posture && postures.length >= 2) {
    coherence = await bundlePostureCoherence(postures);
    human(renderCoherenceSummary(coherence));
    diverged = hasDivergence(coherence);
  }

  // spec-v14 Thrust B — emit this round's coherence as a portable, hash-verified
  // baseline artifact, so a later round can gate against it (--baseline-coherence)
  // without re-checking-out this round's documents. Off by default; additive.
  if (args.emitCoherence) {
    if (!coherence) {
      process.stderr.write(
        `\n--emit-coherence: no cross-document coherence to write (need ≥2 documents with a posture).\n`,
      );
    } else {
      // spec-v15 — pin the ladder the rungs were computed against so a consuming
      // round can refuse a cross-ladder diff. The ladder is always available here
      // (--emit-coherence requires --posture requires --playbook-file).
      const ladder = customPlaybook ? await ladderHash(customPlaybook) : null;
      await writeFile(args.emitCoherence, buildPostureCoherenceJson(coherence, ladder));
      human(`\nwrote coherence artifact → ${resolve(args.emitCoherence)}\n`);
    }
  }

  // spec-v13 Thrust A — cross-document posture movement. Given a baseline bundle
  // (a prior round of the same deal, classified against the SAME playbook), diff
  // the two coherences front-by-front: how did each binding floor move, and did
  // any front fracture or reconcile? Matched by dimension, so the baseline may
  // carry different filenames or a different document count. spec-v14 adds a
  // second baseline source: a saved coherence artifact, verified on load.
  let regressed = false;
  if (coherence && (args.baseline || args.baselineCoherence)) {
    let baselineCoherence: PostureCoherence | null;
    if (args.baselineCoherence) {
      const text = await readFile(args.baselineCoherence, "utf8").catch(() => null);
      if (text === null) {
        process.stderr.write(`\n--baseline-coherence: cannot read ${args.baselineCoherence}\n`);
        process.exitCode = 1;
        return;
      }
      const parsed = await parsePostureCoherenceJson(text);
      if (!parsed.ok) {
        process.stderr.write(
          `\n--baseline-coherence: invalid artifact ${args.baselineCoherence}:\n  ${parsed.errors.join("\n  ")}\n`,
        );
        process.exitCode = 1;
        return;
      }
      // spec-v15 — cross-ladder guard. A v2 artifact pins the ladder its rungs
      // sit on; refuse to diff it against a round computed on a different ladder
      // (comparing floors from two ladders is nonsense). A v1 artifact carries no
      // pin: fall back to v14's caller-owns-it contract with a clear note.
      if (parsed.ladderHash !== null) {
        const thisLadder = customPlaybook ? await ladderHash(customPlaybook) : null;
        if (thisLadder !== parsed.ladderHash) {
          process.stderr.write(
            `\n--baseline-coherence: ladder mismatch — the artifact was computed against a different playbook ladder ` +
              `(artifact ${parsed.ladderHash.slice(0, 12)}…, this round ${(thisLadder ?? "none").slice(0, 12)}…). ` +
              `Comparing binding floors across different ladders is meaningless; use the same --playbook-file for both rounds.\n`,
          );
          process.exitCode = 1;
          return;
        }
      } else {
        process.stderr.write(
          `\nnote: ${args.baselineCoherence} is an unpinned (v1) coherence artifact — cross-ladder verification unavailable; ` +
            `ensure both rounds used the same --playbook-file (spec-v15 pins this automatically for newly emitted artifacts).\n`,
        );
      }
      baselineCoherence = parsed.coherence;
    } else {
      baselineCoherence = await collectBaselineCoherence(args.baseline!, {
        deps,
        playbookId: args.playbook,
        customPlaybook,
      });
      if (!baselineCoherence) {
        process.stderr.write(
          `\n--baseline: ${args.baseline} yielded no cross-document coherence (need ≥2 documents with a posture).\n`,
        );
        process.exitCode = 1;
        return;
      }
    }
    const movement = await compareCoherence(baselineCoherence, coherence);
    human(renderCoherenceMovementSummary(movement));
    regressed = coherenceRegressed(movement);
  }

  if (args.out)
    human(
      `\nwrote ${args.formats.join(", ")} for ${inputs.length} file(s) → ${resolve(args.out)}\n`,
    );
  if (breached) {
    process.stderr.write(`\n✗ findings breached --fail-on ${args.failOn}\n`);
    process.exitCode = 2;
  }
  if (args.failOnDivergence && diverged) {
    process.stderr.write("\n✗ posture diverges across the bundle (--fail-on-divergence)\n");
    process.exitCode = 2;
  }
  if (args.failOnCoherenceRegression && regressed) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed vs. the baseline (--fail-on-coherence-regression)\n",
    );
    process.exitCode = 2;
  }
}

/**
 * Analyze a baseline bundle quietly (no per-file lines, no format output) and
 * return its cross-document coherence — the prior round to diff the current
 * bundle against (spec-v13). Returns `null` when fewer than two documents carry
 * a posture (nothing cross-document to compare). Every document is classified
 * against the SAME custom playbook the primary bundle used, so the two
 * coherences sit on one ladder.
 */
async function collectBaselineCoherence(
  target: string,
  opts: {
    deps: Awaited<ReturnType<typeof loadAccuracyDeps>>;
    playbookId?: string;
    customPlaybook?: import("../../src/playbooks/custom-playbook.js").CustomPlaybook;
  },
): Promise<PostureCoherence | null> {
  const inputs = await resolveInputs(target);
  const postures: CoherenceInput[] = [];
  for (const file of inputs) {
    const r = await analyzeFile(file, {
      playbookId: opts.playbookId,
      deps: opts.deps,
      customPlaybook: opts.customPlaybook,
      posture: true,
    });
    if (r.negotiation_posture)
      postures.push({ document: documentLabel(file, inputs), posture: r.negotiation_posture });
  }
  return postures.length >= 2 ? bundlePostureCoherence(postures) : null;
}

// `renderCoherenceMovementSummary` moved to `src/report/coherence-movement.ts`
// (beside its JSON sibling) in spec-v16 so both the `analyze --baseline*` path
// and the document-free `compare-coherence` command share one renderer; re-export
// it here so existing importers (and the test suite) keep their `./run.js` import.
export { renderCoherenceMovementSummary };

/**
 * Render the cross-document posture coherence (spec-v12) as human-readable
 * lines: the per-kind counts, then one line per divergent front naming the
 * binding floor and the document carrying it — the front a deal team most needs
 * to reconcile across a package.
 */
export function renderCoherenceSummary(coherence: PostureCoherence): string {
  const c = coherence.counts;
  const lines = [
    "\nCross-document posture coherence:",
    `  ${c.aligned} aligned, ${c.divergent} divergent, ${c.single} stated by one, ${c.unstated} unstated.`,
  ];
  for (const d of coherence.dimensions) {
    if (d.coherence !== "divergent") continue;
    const spread = d.tiers
      .filter((t) => t.tier !== "unevaluable")
      .map((t) => `${t.document}=${t.tier}`)
      .join(", ");
    lines.push(
      `  ⚠ ${d.dimension}: divergent (${spread}); binding floor ${d.weakest_tier} in ${d.weakest_documents.join(", ")}.`,
    );
  }
  lines.push(`  coherence_hash: ${coherence.coherence_hash}`);
  return lines.join("\n") + "\n";
}

async function runVerify(argv: string[]): Promise<void> {
  // Sequential parse so a `--playbook <id>` placed *before* the positionals
  // does not leak its value into the positional list (a filter-by-prefix
  // approach would mis-assign the report path).
  const positional: string[] = [];
  let playbookId: string | undefined;
  let dkbDir: string | undefined;
  let asText = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--playbook") {
      playbookId = argv[++i];
    } else if (argv[i] === "--dkb") {
      dkbDir = argv[++i];
    } else if (argv[i] === "--as-text") {
      asText = true;
    } else if (argv[i]!.startsWith("--")) {
      throw new Error(`unknown flag "${argv[i]}"`);
    } else {
      positional.push(argv[i]!);
    }
  }
  const [reportPath, originalPath] = positional;
  if (!reportPath || !originalPath) {
    throw new Error(
      "usage: verify <report.json> <original> [--playbook <id>] [--dkb <dir>] [--as-text]",
    );
  }
  const parsed = JSON.parse(await readFile(reportPath, "utf8")) as Record<string, unknown>;
  // A verification certificate is an alternative provenance source
  // (add-court-certification-receipt): same fields as the report block,
  // hash-verified before use so a doctored certificate is a hard error.
  let saved: SavedReport;
  if (parsed.schema === CERTIFICATE_SCHEMA) {
    const cert = parsed as unknown as VerificationCertificate;
    if (!(await verifyCertificateHash(cert))) {
      throw new Error(
        "certificate_hash mismatch — the certificate was edited after it was produced",
      );
    }
    saved = {
      run: {
        version: cert.tool.engine_version,
        dkb_version: cert.tool.dkb_version,
        playbook_id: cert.playbook_id,
        source_file: { name: cert.input.name, sha256: cert.input.sha256 },
        result_hash: cert.result_hash,
      },
      provenance: {
        engine_version: cert.tool.engine_version,
        dkb_version: cert.tool.dkb_version,
      },
    };
  } else {
    saved = parsed as unknown as SavedReport;
  }
  // The override is passed as an option, never written into `saved` — the
  // body-integrity check must see the report exactly as it was produced.
  const result = await verifyReproducibilityFromFile(saved, originalPath, {
    dkbDir,
    asText,
    playbookId,
  });
  process.stdout.write(explainReproResult(result) + "\n");
  if (result.body_tampered) process.exitCode = 4;
  else if (!result.reproduced) process.exitCode = 3;
}

const USAGE = `vaulytica — deterministic legal-document linter (headless)

Commands:
  analyze <path|glob|dir> [--playbook <id>] [--format json,sarif,html,md,csv,docx-comments]
                          [--out <dir>] [--fail-on critical|warning|info]
                          [--delivery] [--critical-dates] [--checklist]
                          [--playbook-file <path>] [--posture]
                          [--fail-on-divergence] [--dkb <dir>] [--as-text] [--certificate]
                          [--definitions]
                          [--baseline <path|glob|dir> | --baseline-coherence <coherence.json>]
                          [--emit-coherence <path>] [--fail-on-coherence-regression]
  diff    <a.json> <b.json> [--format markdown|json] [--exit-code]
  compare <base> <revised> [--playbook <id>] [--playbook-file <path>] [--posture]
                          [--format json|markdown]
                          [--fail-on critical|warning|info] [--fail-on-regression]
                          [--confirm-pairing] [--dkb <dir>]
  compare-coherence <base.coherence.json> <revised.coherence.json>
                          [--format markdown|json] [--fail-on-coherence-regression]
  posture-review <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json]
      One attorney-facing view over a round archive: position drift, exposure
      map, and weakest front — each naming the command to drill into.
  coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-coherence-regression]
  coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-fracture]
  coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-regression-or-fracture]
  coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-exposure]
  coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-open-exposure]
  coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-widening-exposure]
  coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-recurring-exposure]
  coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-volatile-exposure]
  coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-synchronized-exposure]
  coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-unsettled-exposure]
  coherence-onset <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-early-onset-exposure]
  coherence-latency <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-unrecovered-exposure]
  coherence-concurrency <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-concerted-fall]
  coherence-relapse <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-immediate-relapse]
  coherence-tenure <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-majority-below]
  coherence-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-coupled-fronts]
  coherence-recovery-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-coupled-recoveries]
  coherence-opposition <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-opposed-fronts]
  coherence-precedence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-leading-front]
  coherence-concession <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-leading-concession]
  coherence-recovery-order <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-lagging-recovery]
  coherence-weak-front <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-persistent-weak-front]
  coherence-cadence <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-oscillating-front]
  coherence-duration <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-lingering-exposure]
  coherence-durability <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-fragile-recovery]
  coherence-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-lead-cycle]
  coherence-recovery-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-recovery-cycle]
  coherence-matrix <r1.coherence.json> <r2.coherence.json> [<r3…> …]
                          [--format markdown|json] [--fail-on-blackout-round]
  verify  <report.json|certificate.json> <original> [--playbook <id>] [--dkb <dir>] [--as-text]

Output delivery: one input × one format streams the artifact to stdout;
any multi-format or multi-input run requires --out <dir> — rendered
output is never silently dropped.

Input types: a directly named file must carry a supported extension
(.txt, .md, .markdown, .text, .docx, .pdf) — an unknown extension is a
hard error, never a silent UTF-8 decode. \`--as-text\` explicitly opts a
text file with an unconventional (or no) extension into UTF-8 ingestion;
it never applies to .docx/.pdf.

Stream contract: with a machine-readable format (json, sarif, csv), stdout
carries exactly one serialized artifact — summaries, notes, and progress
lines go to stderr, so \`analyze x.docx --format json | jq .\` just works.
Human formats (md, default summaries) keep stdout. Exit codes are unchanged.
`;

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "analyze":
      return runAnalyze(rest);
    case "diff":
      return runDiff(rest);
    case "compare":
      return runCompare(rest);
    case "compare-coherence":
      return runCompareCoherence(rest);
    case "posture-review":
      return runPostureReview(rest);
    case "coherence-trend":
      return runCoherenceTrend(rest);
    case "coherence-shift-trend":
      return runCoherenceShiftTrend(rest);
    case "coherence-arc":
      return runCoherenceArc(rest);
    case "coherence-exposure":
      return runCoherenceExposure(rest);
    case "coherence-persistence":
      return runCoherencePersistence(rest);
    case "coherence-breadth":
      return runCoherenceBreadth(rest);
    case "coherence-recurrence":
      return runCoherenceRecurrence(rest);
    case "coherence-volatility":
      return runCoherenceVolatility(rest);
    case "coherence-synchrony":
      return runCoherenceSynchrony(rest);
    case "coherence-settling":
      return runCoherenceSettling(rest);
    case "coherence-onset":
      return runCoherenceOnset(rest);
    case "coherence-latency":
      return runCoherenceLatency(rest);
    case "coherence-concurrency":
      return runCoherenceConcurrency(rest);
    case "coherence-relapse":
      return runCoherenceRelapse(rest);
    case "coherence-tenure":
      return runCoherenceTenure(rest);
    case "coherence-affinity":
      return runCoherenceAffinity(rest);
    case "coherence-recovery-affinity":
      return runCoherenceRecoveryAffinity(rest);
    case "coherence-opposition":
      return runCoherenceOpposition(rest);
    case "coherence-precedence":
      return runCoherencePrecedence(rest);
    case "coherence-concession":
      return runCoherenceConcession(rest);
    case "coherence-recovery-order":
      return runCoherenceRecoveryOrder(rest);
    case "coherence-weak-front":
      return runCoherenceWeakFront(rest);
    case "coherence-cadence":
      return runCoherenceCadence(rest);
    case "coherence-duration":
      return runCoherenceDuration(rest);
    case "coherence-durability":
      return runCoherenceDurability(rest);
    case "coherence-chain":
      return runCoherenceChain(rest);
    case "coherence-recovery-chain":
      return runCoherenceRecoveryChain(rest);
    case "coherence-matrix":
      return runCoherenceMatrix(rest);
    case "verify":
      return runVerify(rest);
    case undefined:
    case "--help":
    case "-h":
    case "help":
      process.stdout.write(USAGE);
      return;
    default:
      throw new Error(
        `unknown command "${command}" (expected: analyze | diff | compare | compare-coherence | coherence-trend | coherence-shift-trend | coherence-arc | coherence-exposure | coherence-persistence | coherence-breadth | coherence-recurrence | coherence-volatility | coherence-synchrony | coherence-settling | coherence-onset | coherence-latency | coherence-concurrency | coherence-relapse | coherence-tenure | coherence-affinity | coherence-recovery-affinity | coherence-opposition | coherence-precedence | coherence-concession | coherence-recovery-order | coherence-weak-front | coherence-cadence | coherence-duration | coherence-durability | coherence-chain | coherence-recovery-chain | coherence-matrix | verify)`,
      );
  }
}

// Run as a CLI only when invoked directly, not when imported by a test
// (importing for the unit tests must not trigger the dispatcher).
if (process.argv[1] && /run\.ts$/.test(process.argv[1])) {
  void main().catch((err) => {
    process.stderr.write(`vaulytica: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}

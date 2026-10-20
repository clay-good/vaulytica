/**
 * The artifacts an analysis renders to, as pure functions (spec-v48 §4).
 *
 * The format tables and the renderers lived inside `run.ts` beside argv
 * parsing, stdout writes and exit codes, so nothing but the `analyze` command
 * could produce an artifact. Here they take an {@link AnalyzeResult} and return
 * text or bytes: the CLI writes what they return, and `exportArtifacts` in
 * `api.ts` does the same for a caller with no terminal. One renderer per
 * format is what makes "exported bytes equal `--out`" true by construction.
 *
 * Writes nothing, reads no argv, sets no exit code.
 */

import "./no-localstorage.js";

import type { AnalyzeResult } from "./api.js";
import type { AccuracyDeps } from "../accuracy/pipeline.js";
import type { ConsistencyRun } from "../../src/engine/consistency/types.js";

import { buildBriefJson } from "./brief.js";
import { buildReviewedDocx } from "../../src/report/docx-comments.js";
import { buildDocxReport } from "../../src/report/docx.js";
import { buildV3ReportInputs, hasV3Sections } from "../../src/report/v3/inputs.js";
import { extractAll } from "../../src/extract/index.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildSarif, sarifConformanceViolations } from "../../src/report/sarif.js";
import { buildHtmlReport } from "../../src/report/html.js";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildClosingChecklistMarkdown,
  buildClosingChecklistCsv,
  buildCriticalDatesMarkdown,
  buildCriticalDatesIcs,
  buildObligationsCsv,
  buildDeadlinesIcs,
  buildNegotiationPostureMarkdown,
  buildNegotiationPostureCsv,
} from "../../src/report/exports.js";
import { buildNegotiationSheet } from "../../src/report/negotiation-sheet.js";
import { dkbCurrency } from "../../src/report/citations.js";
import { buildDefinitionsMarkdown, buildDefinitionsCsv } from "../../src/report/definitions.js";
import {
  buildDocumentAbstract,
  buildInventory,
  buildInventoryCsv,
  buildInventoryJson,
} from "../../src/report/abstract.js";

export type Format =
  | "json"
  | "sarif"
  | "html"
  | "md"
  | "csv"
  | "docx"
  | "docx-comments"
  | "bundle-json"
  | "bundle-docx"
  | "bundle-zip"
  | "checklist-md"
  | "checklist-csv"
  | "dates-md"
  | "dates-ics"
  | "obligations-csv"
  | "deadlines-ics"
  | "posture-md"
  | "posture-csv"
  | "posture-sheet"
  | "definitions-csv"
  | "brief-json"
  | "triage-md"
  | "triage-json"
  | "abstract-json"
  | "abstract-csv"
  | "inventory-csv"
  | "inventory-json";
/**
 * Formats a machine consumes (`jq`, SARIF uploaders, spreadsheets). Stream
 * contract (fix-cli-json-purity): when any of these is selected, stdout
 * carries ONLY the serialized artifact — every human summary/progress line
 * goes to stderr, so `analyze x.docx --format json | jq .` just works.
 */
/**
 * The five formats that never reach stdout: two are binary `.docx`, and the
 * three bundle artifacts write ONE file for the whole run, so there is no
 * single-input case where stdout is a complete delivery target. Each is
 * rejected with its own message when `--out` is missing; this set is what
 * {@link MACHINE_FORMATS} subtracts, so the two lists cannot drift.
 */
export const OUT_ONLY_FORMATS: ReadonlySet<Format> = new Set([
  "docx",
  "docx-comments",
  "bundle-json",
  "bundle-docx",
  "bundle-zip",
]);
export const VALID_FORMATS = [
  "json",
  "sarif",
  "html",
  "md",
  "csv",
  // The full attorney-facing report, the artifact this tool's whole output is
  // shaped around — and until 9.570.0 the ONE the headless surface could not
  // produce. `docx-comments` is a different thing: a byte-copy of the caller's
  // own .docx with anchored Word comments. This is the REPORT.
  "docx",
  "docx-comments",
  // The three CONSOLIDATED artifacts: one report for the whole deal room, not
  // one per file. The browser has built them on every multi-document drop since
  // v4; the CLI ran the cross-document rules (9.535.0) and still could not write
  // the report they belong in. Each needs --consistency, because a directory is
  // not a bundle.
  "bundle-json",
  "bundle-docx",
  "bundle-zip",
  // The four artifacts the browser has always offered and the headless surface
  // could not produce at all: the closing checklist (v9 Ready to Sign) and the
  // critical-dates register (v9 Tracked to Its Dates), each in the two forms a
  // person actually uses. Every builder is a pure function that already shipped
  // and was already tested; only the caller was missing. `md`/`csv` are the FIX
  // LIST, so these carry their surface name rather than overloading those.
  "checklist-md",
  "checklist-csv",
  "dates-md",
  "dates-ics",
  // The v6 findings-to-action exports and the v10 negotiation deliverables. Same
  // story as the four above: pure builders, shipped and tested, never called by
  // anything in tools/. `deadlines-ics` is the v6 calendar built from the
  // document's own obligation deadlines; `dates-ics` is the v9 DERIVED register
  // (anchor plus-or-minus N). Both are real and they are not the same artifact.
  "obligations-csv",
  "deadlines-ics",
  "posture-md",
  "posture-csv",
  "posture-sheet",
  // The definitions report already reaches JSON and the `md` summary through
  // `--definitions`; its CSV had no caller.
  "definitions-csv",
  // The compact projection (spec-v50 §4): the same analysis in a few KB, for a
  // script or an agent. A VIEW — `verify` and the certificate need `json`.
  "brief-json",
  // Folder triage (spec-v52): ONE page for the whole run — which documents
  // need a person first, and what to open to check the tool's work.
  "triage-md",
  "triage-json",
  // The abstract (add-contract-abstract-inventory): one row of facts per
  // document — type, parties, effective date, renewal, law, forum, cap — each
  // with the section it was read from. Per document, and as ONE inventory
  // for the whole run.
  "abstract-json",
  "abstract-csv",
  "inventory-csv",
  "inventory-json",
] as const;
/**
 * Every format a PROGRAM parses — JSON, SARIF, CSV, iCalendar — and therefore
 * every format that must OWN stdout, with human summary and progress lines
 * going to stderr instead.
 *
 * 🚨 This used to be the literal `["json", "sarif", "csv"]`, written when those
 * were the only three. **Six more machine-parsed formats shipped since and none
 * of them joined**, so the stream contract this file's own docstring states was
 * false for all of them: `analyze x.docx --format obligations-csv > o.csv`
 * wrote
 *
 * ```
 * x.docx  [msa-deep]  1C 2W 1I
 *   Critical dates: 0 computed, 1 to verify manually.
 * obligor,modal,action,...
 * ```
 *
 * — a CSV whose header row is the third line, which a spreadsheet reads as
 * data under a two-column header. `--format dates-ics` was worse: two lines
 * before `BEGIN:VCALENDAR` make a file no calendar application will open.
 *
 * Derived from the artifact's own EXTENSION rather than listed, so a format
 * added tomorrow is covered the day it is added. The defect was not a wrong
 * list — it was a list that had to be remembered.
 *
 * Markdown and HTML formats are deliberately NOT here. They are read by a
 * person, the summary line is context rather than corruption, and
 * `--format md`'s stdout summary is pinned by its own test as intended
 * behaviour.
 */
export const MACHINE_EXTENSIONS = [".json", ".csv", ".ics"];

export const FORMAT_EXT: Record<Format, string> = {
  json: ".json",
  sarif: ".sarif.json",
  html: ".html",
  md: ".fixlist.md",
  csv: ".fixlist.csv",
  docx: ".report.docx",
  // These three are named for the BUNDLE, not for a document, so the stem is
  // supplied by the writer rather than a source filename.
  "bundle-json": ".json",
  "bundle-docx": ".docx",
  "bundle-zip": ".zip",
  "docx-comments": ".reviewed.docx",
  "checklist-md": ".checklist.md",
  "checklist-csv": ".checklist.csv",
  "dates-md": ".dates.md",
  "dates-ics": ".dates.ics",
  "obligations-csv": ".obligations.csv",
  "deadlines-ics": ".deadlines.ics",
  "posture-md": ".posture.md",
  "posture-csv": ".posture.csv",
  "posture-sheet": ".negotiation-sheet.html",
  "definitions-csv": ".definitions.csv",
  // Not `.json`: it would collide with the full report under --out.
  "brief-json": ".brief.json",
  // Named for the run, not for a document: written as TRIAGE.md / TRIAGE.json.
  "triage-md": ".md",
  "triage-json": ".json",
  "abstract-json": ".abstract.json",
  "abstract-csv": ".abstract.csv",
  // Named for the run: written as INVENTORY.csv / INVENTORY.json.
  "inventory-csv": ".csv",
  "inventory-json": ".json",
};

/**
 * Formats that are ONE artifact for the whole run, however many inputs it had.
 * Unlike the bundle formats they can stream to stdout: a folder page is the
 * answer a bare `analyze <dir>` never had.
 */
export const WHOLE_RUN_FORMATS: ReadonlySet<Format> = new Set([
  "triage-md",
  "triage-json",
  "inventory-csv",
  "inventory-json",
]);

/** The abstract of one analyzed document, as the CLI and the inventory both build it. */
export function abstractOf(file: string, r: AnalyzeResult) {
  return buildDocumentAbstract({
    file,
    tree: r.ingest.tree,
    run: r.run,
    playbookName: r.playbook.name,
  });
}

export const MACHINE_FORMATS: ReadonlySet<Format> = new Set(
  VALID_FORMATS.filter(
    (f) => !OUT_ONLY_FORMATS.has(f) && MACHINE_EXTENSIONS.some((e) => FORMAT_EXT[f].endsWith(e)),
  ),
);

/**
 * The JSON report with the configuration block appended after every key the
 * builder wrote. Re-serialized with the builder's own indentation, so the rest
 * of the report is unchanged byte for byte.
 */
function withConfigBlock(json: string, config: import("./config.js").ConfigProvenance): string {
  return JSON.stringify({ ...(JSON.parse(json) as Record<string, unknown>), config }, null, 2);
}

export async function renderFormat(
  fmt: Exclude<
    Format,
    | "docx"
    | "docx-comments"
    | "bundle-json"
    | "bundle-docx"
    | "bundle-zip"
    | "triage-md"
    | "triage-json"
    | "inventory-csv"
    | "inventory-json"
  >,
  r: AnalyzeResult,
  dkb: Dkb,
  definitions?: import("../../src/report/definitions.js").DefinitionsReport,
  consistency?: ConsistencyRun,
  /**
   * The project configuration that shaped this run, when one was applied.
   * Recorded as a top-level `config` block in `json` and `brief-json`, outside
   * `run`, so `result_hash` is unchanged; absent, both render byte-identically.
   */
  config?: import("./config.js").ConfigProvenance,
): Promise<string> {
  // Deterministic citation-currency reference — the DKB's own build date.
  const currency = dkbCurrency(dkb.manifest);
  // The two honesty caveats, for the Markdown artifacts a person receives as a
  // FILE. They already reach whoever ran the command, on stderr; a colleague
  // handed `register.md` never saw that terminal. Gated on presence inside the
  // builders, so a run with neither renders byte-identically.
  const caveats = {
    warnings: r.ingest.warnings,
    classification_notice: r.run.classification_notice,
  };
  // The v9 "Last Look" surfaces, populated only when the matching flag ran
  // (--delivery / --critical-dates / --checklist). Threaded into every format.
  const v9surfaces = {
    delivery: r.delivery,
    criticalDates: r.critical_dates,
    closingChecklist: r.closing_checklist,
    // The matched family's normal pairings. Absent here until 9.515.0, so the
    // headless DOCX/HTML/SARIF carried a section the browser's did.
    relatedDocuments: r.related_documents.length > 0 ? r.related_documents : undefined,
    // How many clearly-present families the cap left UNSCANNED. The terminal
    // has said this since the count existed; the FILES the terminal writes did
    // not, so a report read by anyone but the person at the keyboard showed a
    // truncated list as a complete one.
    secondaryFamiliesOmitted: r.secondary_families_present - r.secondary_families.length,
  };
  switch (fmt) {
    case "json":
      return buildJsonReport(
        r.run,
        r.ingest,
        undefined,
        // The OTHER families the document clearly contains
        // (fix-headless-secondary-families). Until 9.508.0 the headless path
        // did not RUN these at all, so this argument had nothing to pass —
        // 238 of 312 specimens produce secondary findings the browser showed
        // and a CI pipeline never saw. Outside `run`, so `result_hash` and
        // every `--fail-on` gate are unchanged.
        r.secondary_families.length > 0 ? r.secondary_families : undefined,
        // The jurisdiction overlays (spec-v6 Part VI §21) are built from the
        // governing-law clauses in `extracted`, and this argument was
        // `undefined` — so `jurisdiction_overlays` could never appear in a CLI
        // report, for any document. A standalone California non-compete
        // reported thirteen findings and said nothing about California, where
        // Bus. & Prof. Code § 16600 voids the covenant outright and § 16600.5
        // makes attempting to enforce it an independent violation. The overlay
        // catalog knows this, the selector resolves it, and the DOCX report
        // prints it; the one surface a script can read did not. Re-extracted
        // here rather than threaded through `AnalyzeResult`, matching the
        // `--critical-dates` and `--posture` paths above: the overlay is not
        // part of `run.result_hash`, so this cannot change what a run verifies
        // to.
        extractAll(r.ingest.tree),
        r.delivery,
        r.critical_dates,
        r.closing_checklist,
        r.negotiation_posture,
        currency,
        definitions,
        r.related_documents.length > 0 ? r.related_documents : undefined,
        v9surfaces.secondaryFamiliesOmitted,
      )
        .text()
        .then((json) => (config ? withConfigBlock(json, config) : json));
    case "sarif": {
      // The cross-document run rides in only when the caller asserted a bundle
      // (--consistency); each conflict lands in the SARIF of the document its
      // first excerpt names, so it appears exactly once across the set.
      //
      // The overlays are re-extracted here for the same reason the JSON and
      // HTML paths do it, and to close the same gap one surface over: SARIF is
      // the artifact the Action uploads, and it carried no state-law overlay at
      // all — a California non-compete annotated its findings and said nothing
      // about § 16600. Outside `run`, so `result_hash` is unchanged.
      //
      // 🥇 `sarifConformanceViolations` says in its own docstring that it is
      // "exposed (not test-only) so a caller writing SARIF — e.g. the CLI —
      // can self-check its output before handing it to a downstream tool". It
      // had no caller anywhere: not the CLI it names, and it had never been run
      // over the corpus. That matters here more than anywhere, because SARIF is
      // the artifact the Action uploads by default and a malformed log does not
      // fail loudly — GitHub Code Scanning drops the results and reports
      // nothing, which reads as a clean scan.
      //
      // A warning, not a gate. The artifact still goes to stdout: a downstream
      // tool refusing it is a better outcome than this tool deciding on the
      // user's behalf that they get nothing.
      const log = buildSarif(
        r.run,
        v9surfaces,
        currency,
        r.ingest,
        consistency,
        extractAll(r.ingest.tree),
      );
      const violations = sarifConformanceViolations(log);
      if (violations.length > 0) {
        process.stderr.write(
          `vaulytica: warning: this SARIF log does not conform to the structural rules ` +
            `GitHub Code Scanning enforces, and an uploader may silently drop its results:\n`,
        );
        for (const v of violations.slice(0, 10)) process.stderr.write(`  - ${v}\n`);
        if (violations.length > 10) {
          process.stderr.write(`  … and ${violations.length - 10} more\n`);
        }
      }
      return JSON.stringify(log, null, 2);
    }
    case "html":
      return buildHtmlReport(
        r.run,
        r.ingest,
        dkb,
        undefined,
        v9surfaces,
        undefined,
        r.secondary_families.length > 0 ? r.secondary_families : undefined,
        consistency,
        // Same re-extraction the JSON path does, and for the same reason: the
        // overlays and the obligations ledger are built from `extracted`, which
        // is not part of `run.result_hash`, so this cannot change what a run
        // verifies to.
        extractAll(r.ingest.tree),
      );
    case "md": {
      const md = buildFixListMarkdown(r.run, undefined, currency, r.ingest);
      return definitions ? `${md}\n${buildDefinitionsMarkdown(definitions)}` : md;
    }
    case "csv":
      return buildFixListCsv(r.run, currency);
    // The asserted surfaces. `renderFormat` is only reached for these once the
    // flag has been validated AND the surface came back non-empty (the caller
    // warns and skips otherwise), so the non-null assertions hold.
    case "checklist-md":
      return buildClosingChecklistMarkdown(r.closing_checklist!, caveats);
    case "checklist-csv":
      return buildClosingChecklistCsv(r.closing_checklist!);
    case "dates-md":
      return buildCriticalDatesMarkdown(r.critical_dates!, caveats);
    case "dates-ics":
      return buildCriticalDatesIcs(r.critical_dates!);
    case "obligations-csv":
      return buildObligationsCsv(extractAll(r.ingest.tree), r.ingest.tree);
    case "deadlines-ics":
      return buildDeadlinesIcs(extractAll(r.ingest.tree), r.ingest.tree);
    case "posture-md":
      return buildNegotiationPostureMarkdown(r.negotiation_posture!, caveats);
    case "posture-csv":
      return buildNegotiationPostureCsv(r.negotiation_posture!);
    case "posture-sheet":
      return buildNegotiationSheet(r.negotiation_posture!, r.playbook_id, caveats);
    case "definitions-csv":
      return buildDefinitionsCsv(definitions!);
    case "brief-json":
      return buildBriefJson(r, config ? { config } : {});
    case "abstract-json":
    case "abstract-csv": {
      const inventory = await buildInventory([await abstractOf(r.run.source_file.name, r)]);
      return fmt === "abstract-csv" ? buildInventoryCsv(inventory) : buildInventoryJson(inventory);
    }
  }
}

export { buildInventory, buildInventoryCsv, buildInventoryJson };

export type Dkb = AccuracyDeps["dkb"];

/**
 * The full attorney-facing report, as bytes. The builder the browser calls,
 * with the v9 surfaces, the secondary families and the v3 sections (transfers
 * §56, subprocessors §57, insurance §58 — passed only when the document
 * carries that language). `consistency` is a bundle's cross-document run; the
 * report's §59 appendix renders from it.
 */
export async function renderDocxReport(
  r: AnalyzeResult,
  dkb: Dkb,
  consistency?: ConsistencyRun,
): Promise<Uint8Array> {
  const extracted = extractAll(r.ingest.tree);
  const v3Inputs = buildV3ReportInputs(r.ingest.tree, {
    parties: extracted.parties,
    dkb_build_date: dkb.manifest.built_at,
    consistency,
  });
  const blob = await buildDocxReport(
    r.run,
    r.ingest,
    dkb,
    r.playbook,
    hasV3Sections(v3Inputs) ? v3Inputs : undefined,
    extracted,
    r.secondary_families.length > 0 ? r.secondary_families : undefined,
    {
      delivery: r.delivery,
      criticalDates: r.critical_dates,
      closingChecklist: r.closing_checklist,
      relatedDocuments: r.related_documents.length > 0 ? r.related_documents : undefined,
      secondaryFamiliesOmitted: r.secondary_families_present - r.secondary_families.length,
    },
    r.negotiation_posture!,
  );
  return new Uint8Array(await blob.arrayBuffer());
}

/**
 * The reviewed copy: the caller's own `.docx`, byte for byte, with anchored
 * Word comments (add-word-comment-export).
 */
export function renderReviewedDocx(
  original: Uint8Array,
  r: AnalyzeResult,
): ReturnType<typeof buildReviewedDocx> {
  return buildReviewedDocx(
    original.buffer.slice(
      original.byteOffset,
      original.byteOffset + original.byteLength,
    ) as ArrayBuffer,
    r.run,
    { warnings: r.ingest.warnings, classification_notice: r.run.classification_notice },
  );
}

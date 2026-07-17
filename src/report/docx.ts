/**
 * DOCX report builder (spec §22, build step 9).
 *
 * Produces the deterministic Word document described in §22:
 *
 *   Page 1   — Cover (title, filename, dates, fingerprint, versions,
 *              playbook, determinism statement, mint wordmark)
 *   Page 2   — Executive summary
 *   Page 3+  — Findings, Critical → Warning → Info
 *   Page N+  — Obligations Ledger (table)
 *   Page N+  — Extracted Data Appendix (compact tables)
 *   Page N+  — Audit Trail (rules executed + bibliography)
 *   Final    — Disclaimer block (determinism / privacy / non-advice)
 *
 * Visual contract: US Letter (12240 × 15840 DXA), 1-inch margins
 * (1440 DXA), Arial 11pt body (size 22 in half-points), Arial bold
 * for headings, mint accent (`#00A883`) used sparingly on section
 * headings and the closing wordmark. The doc is intended to read
 * well in both light and dark Word/Pages/Docs themes.
 */

import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  PageBreak,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  type IParagraphOptions,
  type IRunOptions,
} from "docx";

import type { ClassificationNotice, EngineRun, Finding } from "../engine/finding.js";
import type { DKB } from "../dkb/types.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { scopeForPlaybook } from "../verticals/registry.js";
import { buildReviewCoverage, reviewCoverageSentence } from "./review-coverage.js";
import type { ExtractedData } from "../extract/types.js";
import type { ReportSecondaryFamily } from "./json.js";
import type { V9Surfaces } from "./v9-surfaces.js";
import type { DeliveryReport } from "../delivery/types.js";
import type { ClosingChecklist, ChecklistCategory } from "./closing-checklist.js";
import type { CriticalDatesRegister, CriticalDateKind } from "./critical-dates.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";
import { buildBibliography, citationIndex, type BibliographyEntry } from "./bibliography.js";
import {
  formatCitation,
  formatBibliographyEntry,
  breakLongTokens,
  dkbCurrency,
} from "./citations.js";
import { modelClauseForRule, MODEL_CLAUSE_COVERAGE } from "../dkb/model-clauses.js";
import { selectStateOverlays, type StateOverlayResult } from "../dkb/state-overlays.js";
import type { V3ReportInputs } from "./v3/types.js";
import {
  renderComplianceMatrix,
  renderTransfersSummary,
  renderSubprocessorPage,
  renderInsurancePage,
  renderConsistencyAppendix,
  renderCitationIndex,
  buildV3Footer,
} from "./v3/index.js";

const MINT = "00A883";
const DEFAULT_FONT = "Arial";
const BODY_SIZE = 22; // half-points = 11pt

const DETERMINISM_STATEMENT =
  "This report was produced by a deterministic process. Given the same input file, the same Vaulytica engine version, and the same Deterministic Knowledge Base version listed above, the rules in this report will produce an identical report on any machine, at any time. The fingerprint of the input file is recorded above for verification. No part of this analysis was performed by a language model or any other non-deterministic system. The complete list of rules executed, including those that produced no findings, is included in the Audit Trail section so that the scope of the analysis is fully transparent.";

const PRIVACY_STATEMENT =
  "This analysis was performed entirely inside the user's web browser. No portion of the input document was transmitted to any server. Vaulytica is a static web page hosted on Cloudflare Pages; the page has no backend, no database, no analytics, and no telemetry. The developer of Vaulytica has no record of this analysis, no ability to recover it, and no way to identify the user who performed it. The user's network logs at the time of analysis can independently confirm this.";

const NON_ADVICE_STATEMENT =
  "Vaulytica is a software tool, not a lawyer. This report is a checklist of mechanical findings produced by a deterministic rule engine against a contract you provided. It is not legal advice, and using Vaulytica does not create an attorney-client relationship with anyone. The findings may be incorrect, incomplete, or inapplicable to your situation. The decision to act on any finding, or not, is yours and your counsel's. If something in this report matters to a transaction or a dispute, consult a licensed attorney in the relevant jurisdiction.";

void ImageRun; // reserved for future image embedding; keep the import surface stable

export async function buildDocxReport(
  run: EngineRun,
  ingest: IngestResult,
  dkb: DKB,
  playbook: Playbook,
  v3?: V3ReportInputs,
  extracted?: ExtractedData,
  secondaryFamilies?: ReadonlyArray<ReportSecondaryFamily>,
  v9?: V9Surfaces,
  negotiationPosture?: NegotiationPosture,
): Promise<Blob> {
  const bibliography = buildBibliography(run.findings, dkb);
  const children: (Paragraph | Table)[] = [
    ...renderCover(run, ingest, playbook),
    // Unmatched-document banner + scope-of-review, both above the findings so
    // a reader sees the honesty caveat before any finding.
    ...renderClassificationNotice(run.classification_notice),
    ...renderScopeOfReview(run.playbook_id),
    ...renderExecutiveSummary(run, playbook),
    // v3 §54 — compliance matrix sits between the executive summary and
    // the findings list. Conditional on `v3.matrix` being present.
    ...(v3?.matrix ? renderComplianceMatrix(v3.matrix) : []),
    ...renderFindingsSection("Critical Findings", "critical", run.findings, bibliography),
    ...renderFindingsSection("Warnings", "warning", run.findings, bibliography),
    ...renderFindingsSection("Informational", "info", run.findings, bibliography),
    // spec-v9 "Last Look" surfaces — render-side, outside result_hash. Each
    // renderer returns [] when its surface is absent/empty, so a v8-era
    // document produces a byte-identical report.
    ...renderDeliverySection(v9?.delivery),
    ...renderClosingChecklistSection(v9?.closingChecklist),
    ...renderCriticalDatesSection(v9?.criticalDates),
    // spec-v10 Thrust A — tiered negotiation posture (custom playbook only).
    ...renderNegotiationPostureSection(negotiationPosture),
    // spec-v6 multi-family activation — additional families the document
    // also contains, scanned with their own rule sets and quarantined here
    // so the primary report above stays clean.
    ...renderSecondaryFamiliesSection(secondaryFamilies),
    // v3 §§56–58 — conditional summary pages. Each renderer returns [] when
    // the corresponding input is absent, so the page only appears when
    // relevant.
    ...(v3?.transfers ? renderTransfersSummary(v3.transfers) : []),
    ...(v3?.subprocessor ? renderSubprocessorPage(v3.subprocessor) : []),
    ...(v3?.insurance ? renderInsurancePage(v3.insurance) : []),
    ...renderObligationsLedger(run, extracted),
    // spec-v6 Part VI §21 — jurisdiction overlays. State-law deltas for the
    // detected governing-law state(s), surfaced as an advisory reference layer
    // (not EngineRun findings, so result_hash is unchanged). Empty for
    // families with no overlay catalog or when no covered state is detected.
    ...renderJurisdictionOverlaysSection(
      extracted ? selectStateOverlays(run.playbook_id, extracted.jurisdictions) : undefined,
    ),
    ...renderExtractedAppendix(run, extracted),
    ...renderAuditTrail(run, playbook, bibliography, dkbCurrency(dkb.manifest)),
    // v3 §59 — two-document consistency appendix.
    ...(v3?.consistency ? renderConsistencyAppendix(v3.consistency) : []),
    // v3 §55 — citation depth verification appendix.
    ...renderCitationIndex(bibliography, run.dkb_version, v3?.dkb_build_date),
    // add-attorney-review-ledger — honest "N of M findings cite an
    // attorney-reviewed rule", a projection of run.findings (not in the hash).
    ...renderReviewCoverageSection(run),
    ...renderDisclaimer(),
  ];

  const v3Footer = buildV3Footer({
    engine_version: run.version,
    dkb_version: run.dkb_version,
    result_hash: run.result_hash,
    dkb_build_date: v3?.dkb_build_date,
  });

  const doc = new Document({
    creator: "Vaulytica",
    title: "Vaulytica Report",
    description: "Deterministic contract review",
    styles: {
      default: {
        document: {
          run: { font: DEFAULT_FONT, size: BODY_SIZE },
        },
      },
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 12240, height: 15840 },
            margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
          },
        },
        footers: { default: v3Footer },
        children,
      },
    ],
  });

  const blob = await Packer.toBlob(doc);
  // `Packer.toBlob` returns a Blob with no explicit type on some `docx`
  // versions, which causes macOS to treat the download as an
  // unrecognized binary. Re-wrap with the canonical Office MIME so the
  // file picks up the right Finder icon and opens in Word.
  if (blob.type === "") {
    return new Blob([blob], {
      type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    });
  }
  return blob;
}

// ---------------------------------------------------------------------------
// Cover

function renderCover(run: EngineRun, ingest: IngestResult, playbook: Playbook): Paragraph[] {
  const confidence = run.playbook_match_confidence ?? null;
  const isoDate = run.executed_at || new Date(0).toISOString();
  const humanDate = formatHumanDate(isoDate);

  // Asserted opt-in packs, recorded on the cover so the receipt shows what the
  // user turned on (each rides inside the hashed run).
  const asserted: Paragraph[] = [];
  if (run.filing_profile) {
    asserted.push(
      coverField(
        "Court profile",
        `${run.filing_profile.id} (${run.filing_profile.brief_kind} brief) — asserted by the user`,
      ),
    );
  }
  if (run.asserted_regimes && run.asserted_regimes.length > 0) {
    asserted.push(
      coverField("Privacy regimes", `${run.asserted_regimes.join(", ")} — asserted by the user`),
    );
  }
  if (run.estate_checks_asserted) {
    asserted.push(coverField("Estate checks", "asserted by the user (--estate-checks)"));
  }

  return [
    para({
      text: "Vaulytica Report",
      heading: HeadingLevel.TITLE,
      color: MINT,
      alignment: AlignmentType.CENTER,
    }),
    spacer(),
    coverField("Input file", ingest_filename(ingest, run)),
    coverField("Analysis date", `${isoDate}  (${humanDate})`),
    coverField("File SHA-256", run.source_file.sha256),
    coverField("Engine version", run.version),
    coverField("DKB version", run.dkb_version),
    coverField(
      "Playbook",
      `${playbook.name} (${playbook.id} v${playbook.version})${
        confidence !== null ? ` — match confidence ${confidence}` : ""
      }${
        playbook.deprecated === true
          ? playbook.superseded_by
            ? ` — legacy; superseded by ${playbook.superseded_by}`
            : " — legacy"
          : ""
      }`,
    ),
    ...asserted,
    spacer(),
    para({ text: DETERMINISM_STATEMENT, italics: true }),
    spacer(2),
    para({ text: "Vaulytica", color: MINT, bold: true, alignment: AlignmentType.CENTER }),
    pageBreak(),
  ];
}

function coverField(label: string, value: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true, font: DEFAULT_FONT, size: BODY_SIZE }),
      new TextRun({ text: value, font: DEFAULT_FONT, size: BODY_SIZE }),
    ],
  });
}

function ingest_filename(ingest: IngestResult, run: EngineRun): string {
  return run.source_file.name || `(${ingest.source} input, ${ingest.word_count} words)`;
}

// ---------------------------------------------------------------------------
// Executive summary

function renderExecutiveSummary(run: EngineRun, playbook: Playbook): Paragraph[] {
  const counts = countFindings(run.findings);
  const summary = `This report was generated against the ${playbook.name} playbook. It contains ${plural(counts.critical, "critical finding")}, ${plural(counts.warning, "warning")}, and ${plural(counts.info, "informational item")}; review the critical section first.`;
  return [h1("Executive Summary"), para({ text: summary }), pageBreak()];
}

// ---------------------------------------------------------------------------
// Findings

function renderFindingsSection(
  heading: string,
  severity: "critical" | "warning" | "info",
  findings: Finding[],
  bibliography: BibliographyEntry[],
): (Paragraph | Table)[] {
  const filtered = findings.filter((f) => f.severity === severity);
  const out: (Paragraph | Table)[] = [h1(heading)];
  if (filtered.length === 0) {
    out.push(para({ text: `No ${severity} findings.`, italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const f of filtered) {
    out.push(...renderFinding(f, bibliography));
  }
  out.push(pageBreak());
  return out;
}

function renderFinding(f: Finding, bibliography: BibliographyEntry[]): Paragraph[] {
  const badgeColor = severityColor(f.severity);
  const citationNumbers = f.source_citations
    .map((c) => citationIndex(bibliography, c.id))
    .filter((n): n is number => typeof n === "number");

  return [
    para({ text: f.title, bold: true, size: 26 }),
    para({
      text: `[${f.severity.toUpperCase()}] ${f.description}`,
      color: badgeColor,
      bold: true,
    }),
    para({
      text: `Excerpt (${f.excerpt.section_id ?? "doc"} @ ${f.excerpt.start_offset}–${f.excerpt.end_offset}): "${truncate(f.excerpt.text, 480)}"`,
      italics: true,
    }),
    para({ text: f.explanation }),
    ...(f.recommendation
      ? [para({ text: `Recommendation: ${f.recommendation}`, bold: true })]
      : []),
    ...(citationNumbers.length > 0
      ? [para({ text: `Sources: ${citationNumbers.map((n) => `[${n}]`).join(" ")}` })]
      : []),
    ...renderModelClauseReference(f),
    spacer(),
  ];
}

/**
 * "Reference model clause" section (spec-v6 Part IV §15). For findings whose
 * rule has an associated public model clause, surface the attributed public
 * reference — what good looks like — never a generated redline. Returns []
 * for rules without a reference, so coverage is honest.
 */
function renderModelClauseReference(f: Finding): Paragraph[] {
  const mc = modelClauseForRule(f.rule_id);
  if (!mc) return [];
  return [
    para({ text: "Reference model clause", bold: true, color: MINT }),
    para({ text: `${mc.title} — ${mc.source_catalog}`, bold: true }),
    para({ text: mc.summary }),
    para({
      text: `Reference only — Vaulytica does not draft. Source: ${formatCitation(mc.source)}${
        mc.source.attribution ? ` (${mc.source.attribution})` : ""
      } [license: ${mc.source.license}]`,
      italics: true,
    }),
  ];
}

// ---------------------------------------------------------------------------
// Obligations Ledger

function renderObligationsLedger(run: EngineRun, extracted?: ExtractedData): (Paragraph | Table)[] {
  // Preferred path: render the full obligor / action / trigger ledger
  // from ExtractedData when the caller threaded it through. Falls back
  // to the finding-derived two-column table when not provided
  // (preserves legacy reports that don't have extract data on hand).
  if (extracted && extracted.obligations.length > 0) {
    const ledger = new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Obligor", "Modal", "Action", "Trigger / Qualifier"]),
        ...extracted.obligations.map((o) =>
          bodyRow([
            o.obligor,
            o.modal,
            truncate(o.action, 160),
            [o.trigger, o.qualifier].filter(Boolean).join(" — ") || "—",
          ]),
        ),
      ],
    });
    return [
      h1("Obligations Ledger"),
      para({
        text: `${extracted.obligations.length} obligation${extracted.obligations.length === 1 ? "" : "s"} extracted from the document.`,
      }),
      ledger,
      pageBreak(),
    ];
  }

  const rows: Finding[][] = [[]];
  for (const f of run.findings) {
    if (!isObligationRelevant(f)) continue;
    rows[0]!.push(f);
  }
  if (rows[0]!.length === 0) {
    return [
      h1("Obligations Ledger"),
      para({ text: "No obligations extracted from findings." }),
      pageBreak(),
    ];
  }
  const table = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      headerRow(["Source", "Severity", "Obligation"]),
      ...rows[0]!.map((f) =>
        bodyRow([
          f.excerpt.section_id ?? "doc",
          f.severity.toUpperCase(),
          truncate(f.description, 200),
        ]),
      ),
    ],
  });
  return [h1("Obligations Ledger"), table, pageBreak()];
}

function isObligationRelevant(f: Finding): boolean {
  return /^(OBLI|RISK|TERM|PERS|FIN)-\d{3}$/.test(f.rule_id);
}

// ---------------------------------------------------------------------------
// Additional checks from other detected families (spec-v6 multi-family
// activation). The primary report above covers the matched playbook; this
// section surfaces every *other* family the document clearly contains, each
// scanned with its own rule set, so a present family is never silently
// skipped. Each family is clearly labeled and kept separate from the primary
// findings, including families that ran clean (which is itself reassuring).

function renderSecondaryFamiliesSection(
  secondary: ReadonlyArray<ReportSecondaryFamily> | undefined,
): (Paragraph | Table)[] {
  if (!secondary || secondary.length === 0) return [];
  const out: (Paragraph | Table)[] = [
    h1("Additional Checks From Other Detected Families"),
    para({
      text: "Beyond the primary playbook, this document also contains content from the families below. Each was scanned with its own rule set. These checks are kept separate from the primary findings above.",
      italics: true,
    }),
  ];
  for (const fam of secondary) {
    const c = fam.counts;
    out.push(
      para({
        text: `${fam.playbook_name} (${fam.playbook_id}) — ${c.critical} critical, ${c.warning} warnings, ${c.info} informational`,
        bold: true,
      }),
    );
    if (fam.findings.length === 0) {
      out.push(
        para({ text: "No findings — this family's requirements appear to be met.", italics: true }),
      );
      continue;
    }
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Severity", "Rule", "Finding", "Section"]),
          ...fam.findings.map((f) =>
            bodyRow([
              f.severity.toUpperCase(),
              f.rule_id,
              truncate(f.description, 200),
              f.excerpt.section_id ?? "doc",
            ]),
          ),
        ],
      }),
    );
  }
  out.push(pageBreak());
  return out;
}

// ---------------------------------------------------------------------------
// spec-v9 "Last Look" surfaces (Thrusts A/B/C) — render-side, outside result_hash

/** "Clean to send" — the delivery / HANDOFF-* pre-disclosure section (Thrust A). */
function renderDeliverySection(delivery: DeliveryReport | undefined): (Paragraph | Table)[] {
  if (!delivery || delivery.findings.length === 0) return [];
  const out: (Paragraph | Table)[] = [
    h1("Clean to Send — Pre-Disclosure Scan"),
    para({ text: delivery.summary, italics: true }),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Severity", "Check", "What was found", "Count"]),
        ...delivery.findings.map((f) =>
          bodyRow([
            f.severity.toUpperCase(),
            f.rule_id,
            truncate(f.description, 240),
            String(f.count),
          ]),
        ),
      ],
    }),
    para({
      text: "Vaulytica reports what it found in the original file and where — it never removes it (that is your edit in Word) and never certifies the document clean.",
      italics: true,
      size: 18,
    }),
  ];
  out.push(pageBreak());
  return out;
}

const CHECKLIST_CAT_LABEL: Record<ChecklistCategory, string> = {
  signature: "Signatures",
  attachment: "Attachments",
  formality: "Execution formalities",
  blank: "Unfilled content",
  handoff: "Pre-send cleanup",
};

/** "Ready to sign" — the consolidated closing checklist (Thrust B). */
function renderClosingChecklistSection(
  checklist: ClosingChecklist | undefined,
): (Paragraph | Table)[] {
  if (!checklist || checklist.items.length === 0) return [];
  const out: (Paragraph | Table)[] = [
    h1("Ready to Sign — Closing Checklist"),
    para({
      text: `${checklist.open_count} readiness item${
        checklist.open_count === 1 ? "" : "s"
      } to resolve before closing. A deterministic projection of the findings; it does not certify the document is ready to sign or validly executed.`,
      italics: true,
    }),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Category", "Rule", "Item", "Section"]),
        ...checklist.items.map((i) =>
          bodyRow([
            CHECKLIST_CAT_LABEL[i.category],
            i.rule_id,
            truncate(i.label, 240),
            i.section ?? "—",
          ]),
        ),
      ],
    }),
  ];
  out.push(pageBreak());
  return out;
}

const CRITICAL_DATE_KIND_LABEL: Record<CriticalDateKind, string> = {
  "auto-renewal-notice": "Auto-renewal notice",
  "cure-window": "Cure window",
  "opt-out-window": "Opt-out / termination",
  "survival-end": "Survival end",
  "notice-period": "Notice deadline",
};

/**
 * Unmatched-document banner. Rendered only when the run carries a
 * classification notice (generic fallback), above every finding so the caveat
 * is unmissable. The text comes from the hashed run, not this renderer.
 */
function renderClassificationNotice(
  notice: ClassificationNotice | undefined,
): (Paragraph | Table)[] {
  if (!notice) return [];
  return [h1("Document Type Not Recognized"), para({ text: notice.message, italics: true })];
}

/**
 * Scope-of-review block for the active regulated pack: what it checked and
 * what it did not. Presence-only — it never states the document is compliant
 * or clean, only what the listed checks looked for.
 */
function renderScopeOfReview(playbookId: string): (Paragraph | Table)[] {
  const scope = scopeForPlaybook(playbookId);
  if (!scope) return [];
  const out: (Paragraph | Table)[] = [
    h1(`Scope of Review — ${scope.pack}`),
    para({
      text: "This report reflects only the checks listed below. Where a check found nothing, that means the reviewed language was present, not that the document is compliant or complete.",
      italics: true,
    }),
    h3("Reviewed for"),
  ];
  for (const item of scope.reviewed_for) out.push(para({ text: `• ${item}` }));
  out.push(h3("Not reviewed for"));
  for (const item of scope.not_reviewed_for) out.push(para({ text: `• ${item}` }));
  return out;
}

/** "Your calendar, computed" — the critical-dates register (Thrust C). */
function renderCriticalDatesSection(
  register: CriticalDatesRegister | undefined,
): (Paragraph | Table)[] {
  if (!register || register.register.length === 0) return [];
  const out: (Paragraph | Table)[] = [
    h1("Critical Dates — Computed From the Document"),
    para({
      text: `${register.resolved_count} computed, ${register.unresolved_count} to verify manually. Each date is calendar arithmetic over the document's own terms — not a determination that a deadline is met, missed, or binding.`,
      italics: true,
    }),
    ...(register.register.find((r) => r.deadline_profile_id)
      ? [
          para({
            text: `Business-day and roll-forward deadlines were computed under ${register.register.find((r) => r.deadline_profile_id)!.deadline_profile_id} as asserted by the user; the filer's own count governs for any certification.`,
            italics: true,
          }),
        ]
      : []),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Date", "Type", "Responsible", "Section", "Trigger"]),
        ...register.register.map((r) =>
          bodyRow([
            r.resolved
              ? r.window
                ? `${r.window[0]} – ${r.window[1]}`
                : (r.computed_date ?? "—")
              : "Verify manually",
            CRITICAL_DATE_KIND_LABEL[r.kind],
            r.responsible || "—",
            r.section ?? "—",
            truncate(r.trigger, 200),
          ]),
        ),
      ],
    }),
  ];
  // add-deadline-computation (DDL follow-up) — drafting notes, present only when
  // a deadline profile was asserted.
  if (register.deadline_notes && register.deadline_notes.length > 0) {
    out.push(h3("Drafting notes"));
    for (const n of register.deadline_notes) {
      out.push(para({ text: `${n.code} — ${n.title}. ${n.detail}`, italics: true }));
    }
  }
  out.push(pageBreak());
  return out;
}

const NEGOTIATION_TIER_LABEL: Record<NegotiationTier, string> = {
  ideal: "Ideal",
  acceptable: "Acceptable",
  "below-acceptable": "Below floor — escalate",
  unevaluable: "Not stated — verify",
};

/** "Negotiation posture" — the tiered ideal/acceptable ladder per dimension (Thrust A). */
function renderNegotiationPostureSection(
  posture: NegotiationPosture | undefined,
): (Paragraph | Table)[] {
  if (!posture || posture.positions.length === 0) return [];
  const c = posture.counts;
  const out: (Paragraph | Table)[] = [
    h1("Negotiation Posture"),
    para({
      text: `Where this draft sits on your team's ladder: ${c.ideal} ideal · ${c.acceptable} acceptable · ${c.below_acceptable} below floor · ${c.unevaluable} not stated. Advisory posture computed deterministically from your playbook's positions — it does not render a legal conclusion.`,
      italics: true,
    }),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Dimension", "Tier", "What we found / guidance", "Section"]),
        ...posture.positions.map((p) =>
          bodyRow([
            p.dimension,
            NEGOTIATION_TIER_LABEL[p.tier],
            truncate(p.detail ?? p.reason ?? p.guidance ?? "—", 280),
            p.section_id ?? "—",
          ]),
        ),
      ],
    }),
  ];
  out.push(pageBreak());
  return out;
}

// ---------------------------------------------------------------------------
// Jurisdiction Overlays (spec-v6 Part VI §21, Step 101)

function postureLabel(posture: StateOverlayResult["matched"][number]["posture"]): string {
  switch (posture) {
    case "prohibited":
      return "Prohibited";
    case "restricted":
      return "Restricted";
    case "permitted":
      return "Permitted";
    case "informational":
      return "Reference";
  }
}

function renderJurisdictionOverlaysSection(
  overlays: StateOverlayResult | undefined,
): (Paragraph | Table)[] {
  // Honest scope: nothing to show when the family has no overlay catalog or
  // when the document named no covered governing-law state. We do not invent
  // a section in that case.
  if (!overlays || (overlays.matched.length === 0 && overlays.detected_states.length === 0)) {
    return [];
  }
  const topic = overlays.matched[0]?.topic ?? overlays.family;
  const out: (Paragraph | Table)[] = [
    h1("Jurisdiction Overlays"),
    para({
      text: `State law on ${topic} varies sharply. Vaulytica's overlay catalog covers ${plural(
        overlays.states_in_catalog,
        "state",
      )} for the ${overlays.family} family. The entries below match the governing-law state(s) this document names. These are a citable reference layer, not findings — they do not change the report's result hash.`,
      italics: true,
    }),
  ];

  if (overlays.matched.length > 0) {
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["State", "Status", "Summary", "Authority"]),
          ...overlays.matched.map((o) =>
            bodyRow([
              o.state_name,
              `${postureLabel(o.posture)} — ${o.headline}`,
              truncate(o.summary, 320),
              o.citation.source,
            ]),
          ),
        ],
      }),
    );
    for (const o of overlays.matched) {
      out.push(
        para({
          text: `${o.state_name}: ${o.headline}`,
          bold: true,
          color: severityColor(o.severity),
        }),
        para({ text: o.recommendation }),
        para({
          text: `Authority: ${o.citation.source} — ${o.citation.source_url}`,
          italics: true,
          size: 18,
        }),
        spacer(),
      );
    }
  }

  if (overlays.uncovered_states.length > 0) {
    out.push(
      para({
        text: `No overlay on file for: ${overlays.uncovered_states
          .map((s) => s.replace(/^us-/, "").toUpperCase())
          .join(", ")}. This is an honest coverage gap — not a clean pass. Verify ${topic} for ${
          overlays.uncovered_states.length === 1 ? "that state" : "those states"
        } manually.`,
        italics: true,
      }),
    );
  }
  out.push(pageBreak());
  return out;
}

// ---------------------------------------------------------------------------
// Extracted Data Appendix

function renderExtractedAppendix(run: EngineRun, extracted?: ExtractedData): (Paragraph | Table)[] {
  // Preferred path: surface parties / dates / amounts / definitions /
  // jurisdictions tables from ExtractedData (spec.md §22, Step 9
  // follow-up). Falls back to the counts-only summary when extracted
  // data isn't threaded (preserves legacy callers).
  const counts = countFindings(run.findings);
  const out: (Paragraph | Table)[] = [
    h1("Extracted Data Appendix"),
    para({ text: "Summary of finding counts:" }),
    new Table({
      width: { size: 50, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Severity", "Count"]),
        bodyRow(["Critical", String(counts.critical)]),
        bodyRow(["Warning", String(counts.warning)]),
        bodyRow(["Informational", String(counts.info)]),
      ],
    }),
  ];

  if (!extracted) {
    out.push(pageBreak());
    return out;
  }

  if (extracted.parties.length > 0) {
    out.push(spacer(), h2("Parties"));
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Name", "Role", "Entity type", "Formation jurisdiction"]),
          ...extracted.parties.map((p) =>
            bodyRow([
              p.name,
              p.role ?? "—",
              p.entity_type ?? "—",
              p.jurisdiction_of_formation ?? "—",
            ]),
          ),
        ],
      }),
    );
  }

  if (extracted.dates.length > 0) {
    out.push(spacer(), h2("Dates"));
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Raw text", "Type", "ISO", "Anchor / offset"]),
          ...extracted.dates.map((d) => {
            const anchor =
              d.anchor && typeof d.offset_days === "number"
                ? `${d.anchor} ${d.offset_days >= 0 ? "+" : ""}${d.offset_days}d`
                : (d.anchor ?? "—");
            return bodyRow([truncate(d.raw_text, 80), d.type, d.iso ?? "—", anchor]);
          }),
        ],
      }),
    );
  }

  if (extracted.amounts.length > 0) {
    out.push(spacer(), h2("Amounts"));
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Raw text", "Currency", "Amount", "Word form"]),
          ...extracted.amounts.map((a) =>
            bodyRow([truncate(a.raw_text, 80), a.currency, a.amount, a.word_form ? "yes" : "no"]),
          ),
        ],
      }),
    );
  }

  if (extracted.definitions.entries.length > 0) {
    out.push(spacer(), h2("Defined terms"));
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Term", "Definition", "Used"]),
          ...extracted.definitions.entries.map((e) =>
            bodyRow([e.term, truncate(e.definition, 200), String(e.used_at.length)]),
          ),
        ],
      }),
    );
    if (extracted.definitions.unused_terms.length > 0) {
      out.push(
        para({
          text: `Unused defined terms: ${extracted.definitions.unused_terms.join(", ")}`,
        }),
      );
    }
  }

  if (extracted.jurisdictions.length > 0) {
    out.push(spacer(), h2("Jurisdictions"));
    out.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Clause kind", "Raw text", "Normalized id"]),
          ...extracted.jurisdictions.map((j) =>
            bodyRow([j.clause_kind, truncate(j.raw_text, 100), j.jurisdiction_id ?? "—"]),
          ),
        ],
      }),
    );
  }

  out.push(pageBreak());
  return out;
}

// ---------------------------------------------------------------------------
// Audit Trail

function renderAuditTrail(
  run: EngineRun,
  playbook: Playbook,
  bibliography: BibliographyEntry[],
  currency?: import("./citations.js").CitationCurrency,
): (Paragraph | Table)[] {
  const matched = run.playbook_match_reasoning
    ? `auto-selected (${run.playbook_match_reasoning})`
    : "selected by caller";
  // spec-v6 §15 — honest model-clause coverage. Count distinct fired rules
  // in this report that carry a public model-clause reference.
  const referencedInReport = new Set(
    run.findings.map((f) => f.rule_id).filter((id) => modelClauseForRule(id)),
  ).size;
  return [
    h1("Audit Trail"),
    para({ text: `Engine version: ${run.version}` }),
    para({ text: `DKB version: ${run.dkb_version}` }),
    para({
      text: `Playbook: ${playbook.name} — ${playbook.id} v${playbook.version} — ${matched}${
        playbook.deprecated === true
          ? playbook.superseded_by
            ? ` — legacy; superseded by ${playbook.superseded_by}`
            : " — legacy"
          : ""
      }`,
    }),
    para({ text: `File fingerprint: ${run.source_file.sha256}` }),
    para({ text: `Result hash: ${run.result_hash}` }),
    para({ text: `Executed at: ${run.executed_at || "(omitted from hash)"}` }),
    para({
      text: `Model-clause references: this report references ${referencedInReport} public model clause${
        referencedInReport === 1 ? "" : "s"
      }. Vaulytica's catalog carries model-clause references for ${MODEL_CLAUSE_COVERAGE.rules_with_reference} rules across ${MODEL_CLAUSE_COVERAGE.model_clauses} public model clauses.`,
    }),
    spacer(),
    h2("Rules executed"),
    ...run.execution_log.map((e) =>
      para({
        text: `${e.rule_id} v${e.rule_version} — ${e.fired ? "fired" : "silent"}${e.fired && e.finding_id ? ` → ${e.finding_id}` : ""} (${formatElapsed(e.elapsed_ms)} ms)`,
      }),
    ),
    spacer(),
    h2("Bibliography"),
    ...(bibliography.length === 0
      ? [para({ text: "No DKB sources were referenced by any finding in this report." })]
      : bibliography.map((b) =>
          wrappingPara({ text: formatBibliographyEntry(b.index, b.source, currency) }),
        )),
    pageBreak(),
  ];
}

// ---------------------------------------------------------------------------
// Attorney-review coverage block (add-attorney-review-ledger)

function renderReviewCoverageSection(run: EngineRun): Paragraph[] {
  const coverage = buildReviewCoverage(run.findings);
  if (coverage.total === 0) return [];
  return [h2("Attorney review coverage"), para({ text: reviewCoverageSentence(coverage) })];
}

// Disclaimer block

function renderDisclaimer(): Paragraph[] {
  return [
    h1("Disclaimer"),
    h3("Determinism"),
    para({ text: DETERMINISM_STATEMENT }),
    spacer(),
    h3("Privacy"),
    para({ text: PRIVACY_STATEMENT }),
    spacer(),
    h3("Not legal advice"),
    para({ text: NON_ADVICE_STATEMENT }),
  ];
}

// ---------------------------------------------------------------------------
// Primitives

type ParaOpts = {
  text: string;
  bold?: boolean;
  italics?: boolean;
  color?: string;
  size?: number;
  heading?: IParagraphOptions["heading"];
  alignment?: IParagraphOptions["alignment"];
};

function para(opts: ParaOpts): Paragraph {
  const runOpts: IRunOptions = {
    text: opts.text,
    bold: opts.bold,
    italics: opts.italics,
    color: opts.color,
    font: DEFAULT_FONT,
    size: opts.size ?? BODY_SIZE,
  };
  return new Paragraph({
    heading: opts.heading,
    alignment: opts.alignment,
    children: [new TextRun(runOpts)],
  });
}

/**
 * A paragraph whose long unbroken tokens (citation URLs) are split into
 * adjacent runs so Word can wrap them at the page margin rather than let
 * the line overflow (spec-v8 §18). The concatenated run text equals
 * `text` exactly, so the citation is never truncated.
 */
function wrappingPara(opts: ParaOpts): Paragraph {
  const base = {
    bold: opts.bold,
    italics: opts.italics,
    color: opts.color,
    font: DEFAULT_FONT,
    size: opts.size ?? BODY_SIZE,
  };
  return new Paragraph({
    heading: opts.heading,
    alignment: opts.alignment,
    children: breakLongTokens(opts.text).map((seg) => new TextRun({ ...base, text: seg })),
  });
}

function h1(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_1, color: MINT, bold: true, size: 32 });
}

function h2(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_2, color: MINT, bold: true, size: 28 });
}

function h3(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_3, bold: true, size: 24 });
}

function spacer(count = 1): Paragraph {
  void count;
  return new Paragraph({ children: [new TextRun({ text: "" })] });
}

function pageBreak(): Paragraph {
  return new Paragraph({ children: [new PageBreak()] });
}

function headerRow(cells: string[]): TableRow {
  return new TableRow({
    children: cells.map(
      (text) =>
        new TableCell({
          shading: { type: ShadingType.CLEAR, fill: MINT, color: "auto" },
          children: [
            new Paragraph({
              children: [
                new TextRun({
                  text,
                  bold: true,
                  color: "FFFFFF",
                  font: DEFAULT_FONT,
                  size: BODY_SIZE,
                }),
              ],
            }),
          ],
        }),
    ),
  });
}

function bodyRow(cells: string[]): TableRow {
  return new TableRow({
    children: cells.map(
      (text) =>
        new TableCell({
          borders: {
            top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            left: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            right: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
          },
          children: [
            new Paragraph({
              children: [new TextRun({ text, font: DEFAULT_FONT, size: BODY_SIZE })],
            }),
          ],
        }),
    ),
  });
}

function severityColor(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical":
      return "B00020";
    case "warning":
      return "A86700";
    case "info":
      return "555555";
  }
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

function countFindings(findings: Finding[]): Record<"critical" | "warning" | "info", number> {
  const out = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function formatElapsed(ms: number): string {
  // Stable rounding to 3 decimals; the execution log values are
  // performance.now() deltas and would otherwise vary at the
  // microsecond level across runs.
  return (Math.round(ms * 1000) / 1000).toFixed(3);
}

function formatHumanDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toUTCString();
}

export { formatCitation };

/**
 * The results page (add-results-page).
 *
 * The single-document result used to be a severity count, a stack of panels
 * and a row of downloads: the findings themselves were only in the Word
 * report. This module turns a run into the page a reader acts on — "N things
 * to raise before you sign", one row per item that opens to the evidence, the
 * reason and the rule's suggested change, and the document's key terms.
 *
 * Two halves. {@link buildResultsModel} is a pure projection of data the
 * exports already read (the run, the abstract, the delivery scan); it runs in
 * the lazy pipeline chunk. {@link resultsPageHtml} and {@link wireResultsPage}
 * render it; every string is escaped and every link is checked, because a
 * finding quotes the user's document.
 *
 * Render-side only: nothing here enters `result_hash`, and nothing here writes
 * contract language. "Suggested change" is the rule's own recommendation,
 * verbatim.
 */

import { isActionable } from "../engine/finding.js";
import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import { hasQuotedExcerpt } from "../report/clause-evidence.js";
import { LOOP_CLEAN_STATEMENT } from "../report/disclaimers.js";
import type { AbstractCell, DocumentAbstract } from "../report/abstract.js";
import type { Party } from "../extract/types.js";
import type { DocumentTree } from "../ingest/types.js";

/** One delivery (HANDOFF-*) item, as the complete state already carries it. */
export type ResultsDeliveryItem = {
  rule_id: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: ReadonlyArray<string>;
};

export type ResultsRow = {
  rule_id: string;
  severity: Severity;
  title: string;
  /** The section heading the finding sits under, when the document has one. */
  section?: string;
  /** Verbatim document text — only when the finding pinned a real span. */
  quote?: string;
  /** The finding's placeholder ("(clause absent from the document)") when it pinned none. */
  absent?: string;
  why?: string;
  /** The rule's recommendation, verbatim. */
  suggested?: string;
  sources: ReadonlyArray<{ name: string; url: string }>;
  /** Delivery items: what the scan found in the file. */
  evidence?: ReadonlyArray<string>;
  /** The report page for this finding; absent for a custom-playbook finding. */
  report_url?: string;
};

export type KeyTerm = { label: string; value?: string; section?: string };

export type ResultsModel = {
  type_label: string;
  headline: string;
  /** Present only when there is nothing to raise. */
  clean_statement?: string;
  /** Critical and warning delivery items: "Before you send this file". */
  delivery_rows: ResultsRow[];
  /** Every actionable finding, in report order. */
  todo_rows: ResultsRow[];
  /** Findings without a recommendation, and info-level delivery items. */
  observations: ResultsRow[];
  key_terms: KeyTerm[];
};

/** Plain words for a severity — what the reader should do, not the engine's bucket. */
export const SEVERITY_LABEL: Readonly<Record<Severity, string>> = {
  critical: "Fix before signing",
  warning: "Worth raising",
  info: "Optional",
};

function findingRow(f: Finding, reportUrl: (f: Finding) => string | null): ResultsRow {
  const quoted = hasQuotedExcerpt(f);
  const absent = f.excerpt.text.trim();
  const url = reportUrl(f);
  return {
    rule_id: f.rule_id,
    severity: f.severity,
    title: f.title,
    ...(f.excerpt.section_label ? { section: f.excerpt.section_label } : {}),
    ...(quoted ? { quote: f.excerpt.text } : absent ? { absent } : {}),
    ...(f.explanation.trim() ? { why: f.explanation } : {}),
    ...(f.recommendation?.trim() ? { suggested: f.recommendation } : {}),
    sources: f.source_citations.map((c) => ({ name: c.source, url: c.source_url })),
    ...(url ? { report_url: url } : {}),
  };
}

function deliveryRow(d: ResultsDeliveryItem): ResultsRow {
  return {
    rule_id: d.rule_id,
    severity: d.severity,
    title: d.title,
    ...(d.description.trim() ? { why: d.description } : {}),
    sources: [],
    evidence: d.evidence,
  };
}

/** "Northgate Instrument Company (Ohio)"; the role only when it says something the name does not. */
function partyText(p: DocumentAbstract["parties"][number]): string {
  const role = p.role && !p.name.toLowerCase().includes(p.role.toLowerCase()) ? p.role : undefined;
  return [p.name, role ? `as ${role}` : "", p.formation ? `(${p.formation})` : ""]
    .filter(Boolean)
    .join(" ");
}

function cellTerm(label: string, cell: AbstractCell | undefined): KeyTerm {
  return { label, ...(cell?.value ? { value: cell.value } : {}), ...sectionOf(cell?.section) };
}

function sectionOf(section: string | undefined): { section?: string } {
  return section ? { section } : {};
}

/**
 * The key terms, from the abstract. A blank stays blank. A name read only from
 * a "By:" / "Name:" line is a signer, not a party: the extractor keeps signers
 * as parties on purpose (a document with no preamble names its parties only
 * there), so the page sorts them by where they were read, never by whether a
 * role was found — 74 of 363 specimens name a real party with no role.
 */
export function keyTermsOf(
  abstract: DocumentAbstract,
  isSigner: (name: string) => boolean,
): KeyTerm[] {
  const parties = abstract.parties.filter((p) => !isSigner(p.name));
  const signers = abstract.parties.filter((p) => isSigner(p.name));
  const terms: KeyTerm[] = [
    {
      label: "Parties",
      ...(parties.length > 0 ? { value: parties.map(partyText).join(" · ") } : {}),
    },
  ];
  if (signers.length > 0) {
    terms.push({ label: "Signed by", value: signers.map((p) => p.name).join(" · ") });
  }
  terms.push(
    cellTerm("Effective date", abstract.effective_date),
    cellTerm("Governing law", abstract.governing_law),
    cellTerm("Forum", abstract.forum),
    cellTerm("Liability cap", abstract.liability_cap),
    cellTerm("Renewal", abstract.renewal),
    cellTerm("Assignment", abstract.assignment),
  );
  return terms;
}

function headlineFor(count: number): string {
  if (count === 0) return "Nothing to raise";
  return `${count} ${count === 1 ? "thing" : "things"} to raise before you sign`;
}

/** The page, as data. Pure. */
export function buildResultsModel(input: {
  run: Pick<EngineRun, "findings">;
  abstract: DocumentAbstract;
  delivery?: ReadonlyArray<ResultsDeliveryItem>;
  isSigner: (name: string) => boolean;
  reportUrl: (f: Finding) => string | null;
}): ResultsModel {
  const { run, abstract } = input;
  const delivery = input.delivery ?? [];
  const delivery_rows = delivery.filter((d) => d.severity !== "info").map(deliveryRow);
  const todo_rows = run.findings
    .filter((f) => isActionable(f))
    .map((f) => findingRow(f, input.reportUrl));
  const observations = [
    ...run.findings.filter((f) => !isActionable(f)).map((f) => findingRow(f, input.reportUrl)),
    ...delivery.filter((d) => d.severity === "info").map(deliveryRow),
  ];
  const count = delivery_rows.length + todo_rows.length;
  return {
    type_label: abstract.document_type_label,
    headline: headlineFor(count),
    ...(count === 0 ? { clean_statement: LOOP_CLEAN_STATEMENT } : {}),
    delivery_rows,
    todo_rows,
    observations,
    key_terms: keyTermsOf(abstract, input.isSigner),
  };
}

/**
 * A signature-block line: "By: …", "Name: …", or a signature table's
 * "Name | …" cell — the same markers the party extractor reads signers from.
 */
const SIGNATURE_NAME_LINE = /^\s*(?:By|Name)\s*[:|]/i;

/**
 * Whether a party name was read ONLY from signature-block lines. Those are the
 * people who signed; the page lists them as "Signed by" rather than as parties.
 * A name that also appears anywhere else (the preamble, a notice block) stays a
 * party.
 */
export function signerTest(
  tree: DocumentTree,
  parties: ReadonlyArray<Party>,
): (name: string) => boolean {
  const text = new Map<string, string>();
  const walk = (sections: DocumentTree["sections"]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) text.set(p.id, p.runs.map((r) => r.text).join(""));
      walk(s.children);
    }
  };
  walk(tree.sections);
  const signers = new Set<string>();
  for (const party of parties) {
    const lines = party.positions.map((pos) =>
      pos.paragraph_id ? text.get(pos.paragraph_id) : undefined,
    );
    if (lines.length > 0 && lines.every((l) => l !== undefined && SIGNATURE_NAME_LINE.test(l))) {
      signers.add(party.name);
    }
  }
  return (name) => signers.has(name);
}

// ---------------------------------------------------------------------------
// Rendering

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Only web links and the site's own report page are ever made clickable. */
function safeHref(url: string): string | null {
  return /^https?:\/\//i.test(url) || /^\/(?!\/)/.test(url) ? url : null;
}

/** The text "Copy suggested change" puts on the clipboard. */
export function copyText(row: ResultsRow): string {
  return `${row.suggested ?? ""}\n(${row.title} · Vaulytica rule ${row.rule_id})`;
}

function rowHtml(row: ResultsRow, id: string): string {
  const parts: string[] = [];
  if (row.quote !== undefined) {
    parts.push(`<blockquote class="result-quote">“${esc(row.quote)}”</blockquote>`);
    if (row.section) parts.push(`<p class="result-quote-at">${esc(row.section)}</p>`);
  } else if (row.absent !== undefined) {
    parts.push(
      `<p class="result-absent"><span class="result-k">Not in the document:</span> ${esc(row.absent)}</p>`,
    );
  }
  if (row.evidence && row.evidence.length > 0) {
    parts.push(
      `<ul class="result-evidence">${row.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`,
    );
  }
  if (row.why) parts.push(`<p><span class="result-k">Why:</span> ${esc(row.why)}</p>`);
  if (row.suggested) {
    parts.push(`<p><span class="result-k">Suggested change:</span> ${esc(row.suggested)}</p>`);
  }
  const sources = row.sources
    .map((s) => {
      const href = safeHref(s.url);
      return href
        ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(s.name)}</a>`
        : esc(s.name);
    })
    .concat(`<span class="result-rule">${esc(row.rule_id)}</span>`);
  parts.push(
    `<p class="result-source"><span class="result-k">Source:</span> ${sources.join(" · ")}</p>`,
  );
  const actions: string[] = [];
  if (row.suggested) {
    actions.push(
      `<button type="button" class="btn-link result-copy" data-role="copy-suggested" data-copy="${esc(copyText(row))}">Copy suggested change</button>`,
    );
  }
  const report = row.report_url ? safeHref(row.report_url) : null;
  if (report) {
    actions.push(
      `<a class="result-report" href="${esc(report)}" target="_blank" rel="noopener">Not a problem? Tell us</a>`,
    );
  }
  if (actions.length > 0) parts.push(`<div class="result-actions">${actions.join("")}</div>`);
  parts.push(`<p class="result-copy-status" data-role="copy-status" aria-live="polite"></p>`);

  return (
    `<li class="result-row result-row--${row.severity}">` +
    `<button type="button" class="result-row__toggle" aria-expanded="false" aria-controls="${id}" data-role="result-row">` +
    `<span class="result-row__sev">${esc(SEVERITY_LABEL[row.severity])}</span>` +
    `<span class="result-row__title">${esc(row.title)}</span>` +
    (row.section ? `<span class="result-row__section">${esc(row.section)}</span>` : "") +
    `</button>` +
    `<div class="result-row__detail" id="${id}" data-role="result-detail" hidden>${parts.join("")}</div>` +
    `</li>`
  );
}

/** A list of rows, each with a stable id `<prefix>-<index>`. */
export function rowsHtml(rows: ReadonlyArray<ResultsRow>, prefix: string, role: string): string {
  return `<ul class="results-list" data-role="${role}">${rows
    .map((r, i) => rowHtml(r, `${prefix}-${i}`))
    .join("")}</ul>`;
}

/** The top of the page: type, headline, the to-do list, and the key terms. */
export function resultsPageHtml(model: ResultsModel): string {
  const out: string[] = [];
  out.push(`<p class="results-type" data-role="results-type">${esc(model.type_label)}</p>`);
  out.push(`<h2 class="results-headline" data-role="results-headline">${esc(model.headline)}</h2>`);
  if (model.clean_statement) {
    out.push(
      `<p class="results-clean" data-role="results-clean">${esc(model.clean_statement)}</p>`,
    );
  }
  if (model.delivery_rows.length > 0) {
    out.push(`<h3 class="results-group">Before you send this file</h3>`);
    out.push(rowsHtml(model.delivery_rows, "rp-send", "results-delivery"));
  }
  if (model.todo_rows.length > 0) {
    if (model.delivery_rows.length > 0) out.push(`<h3 class="results-group">In the document</h3>`);
    out.push(rowsHtml(model.todo_rows, "rp-todo", "results-todo"));
  }
  out.push(`<h3 class="results-group">Key terms</h3>`);
  out.push(
    `<dl class="key-terms" data-role="key-terms">${model.key_terms
      .map(
        (t) =>
          `<div class="key-term"><dt>${esc(t.label)}</dt><dd>` +
          (t.value !== undefined
            ? `<span class="key-term__value">${esc(t.value)}</span>`
            : `<span class="key-term__value key-term__value--none">Not found in the text</span>`) +
          (t.section ? `<span class="key-term__section">${esc(t.section)}</span>` : "") +
          `</dd></div>`,
      )
      .join("")}</dl>`,
  );
  return out.join("");
}

/**
 * The page as the tab mounts it: rendered here, in the lazy pipeline chunk, so
 * the eager entry carries only the few lines that make it clickable
 * (`results-wire.ts`).
 */
export type RenderedResults = {
  model: ResultsModel;
  page_html: string;
  /** The "Also noted" rows; empty when there are none. */
  noted_html: string;
  noted_count: number;
};

export function renderResults(model: ResultsModel): RenderedResults {
  return {
    model,
    page_html: resultsPageHtml(model),
    noted_html:
      model.observations.length > 0
        ? rowsHtml(model.observations, "rp-noted", "results-noted")
        : "",
    noted_count: model.observations.length,
  };
}

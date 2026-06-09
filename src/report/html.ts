/**
 * Standalone single-file HTML report (spec-v8 §21, Step 142).
 *
 * A self-contained `.html` report — all CSS inlined, no external resource,
 * no `<script>` — that renders the full report (cover proof fields,
 * severity-grouped findings, inline citations + bibliography, verbatim
 * posture block) and prints cleanly to PDF from any browser. It is the
 * universal, archivable, emailable counterpart to the DOCX: plain text a
 * user can diff in version control, paste into an email, or print without
 * Word.
 *
 * Determinism: fixed, font-agnostic CSS; no timestamps in the body beyond
 * the run's recorded `executed_at` (which the DOCX also shows); same
 * content as `docx.ts`, an HTML renderer instead of the OOXML writer.
 * Citable: renders the full Thrust-B citation with wrapped URLs
 * (`overflow-wrap: anywhere`) and the §17 freshness signal. In-tab /
 * offline — it ships no network reference. Render-side — zero
 * `result_hash` churn.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { DKB, SourceCitation } from "../dkb/types.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { buildBibliography, citationIndex } from "./bibliography.js";
import { formatBibliographyEntry, freshnessSignal } from "./citations.js";
import { buildClauseEvidence } from "./clause-evidence.js";

const SEVERITY_ORDER: Severity[] = ["critical", "warning", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical Findings",
  warning: "Warnings",
  info: "Informational",
};

const DETERMINISM_STATEMENT =
  "This report was produced by a deterministic process. Given the same input file, the same Vaulytica engine version, and the same Deterministic Knowledge Base version listed above, the rules in this report will produce an identical report on any machine, at any time. The fingerprint of the input file is recorded above for verification. No part of this analysis was performed by a language model or any other non-deterministic system. The complete list of rules executed, including those that produced no findings, is included in the Audit Trail section so that the scope of the analysis is fully transparent.";

const PRIVACY_STATEMENT =
  "This analysis was performed entirely inside the user's web browser. No portion of the input document was transmitted to any server. Vaulytica is a static web page hosted on Cloudflare Pages; the page has no backend, no database, no analytics, and no telemetry. The developer of Vaulytica has no record of this analysis, no ability to recover it, and no way to identify the user who performed it. The user's network logs at the time of analysis can independently confirm this.";

const NON_ADVICE_STATEMENT =
  "Vaulytica is a software tool, not a lawyer. This report is a checklist of mechanical findings produced by a deterministic rule engine against a contract you provided. It is not legal advice, and using Vaulytica does not create an attorney-client relationship with anyone. The findings may be incorrect, incomplete, or inapplicable to your situation. The decision to act on any finding, or not, is yours and your counsel's. If something in this report matters to a transaction or a dispute, consult a licensed attorney in the relevant jurisdiction.";

/** Escape text for safe inclusion in HTML element content / attributes. */
function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Return `url` only if it is a safe http(s) web address, else `null`. The
 * standalone HTML report is designed to be emailed/shared, so a citation URL
 * with a `javascript:` or `data:` scheme — which a malicious custom playbook
 * could supply — must never become an active `<a href>`. The schema already
 * rejects such URLs at load (defense in depth); this guarantees the rendered
 * artifact is safe even for a citation that bypassed validation.
 */
function safeHref(url: string): string | null {
  try {
    const protocol = new URL(url).protocol;
    return protocol === "https:" || protocol === "http:" ? url : null;
  } catch {
    return null;
  }
}

// Fixed, font-agnostic, print-clean CSS. `overflow-wrap: anywhere` on the
// citation URL is the HTML half of the §18 always-wrap contract.
const STYLE = `
  :root { --mint: #00a883; --crit: #b00020; --warn: #a86700; --info: #555; }
  * { box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; color: #1a1a1a; line-height: 1.5;
    max-width: 52rem; margin: 0 auto; padding: 1.25rem; }
  h1, h2, h3 { color: var(--mint); line-height: 1.25; }
  h1 { font-size: 1.6rem; border-bottom: 2px solid var(--mint); padding-bottom: .3rem; }
  h2 { font-size: 1.25rem; margin-top: 2rem; }
  h3 { font-size: 1.05rem; color: #1a1a1a; margin-bottom: .25rem; }
  .proof { background: #f6f8f7; border: 1px solid #dde3e1; border-radius: 6px;
    padding: .75rem 1rem; margin: 1rem 0; }
  .proof dt { font-weight: bold; }
  .proof dd { margin: 0 0 .5rem 0; font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: .85rem; overflow-wrap: anywhere; }
  .finding { border-left: 4px solid #ccc; padding: .25rem 0 .75rem 1rem; margin: 1rem 0; }
  .finding.critical { border-left-color: var(--crit); }
  .finding.warning { border-left-color: var(--warn); }
  .finding.info { border-left-color: var(--info); }
  .sev { font-size: .7rem; font-weight: bold; text-transform: uppercase;
    letter-spacing: .05em; padding: .1rem .4rem; border-radius: 3px; color: #fff; }
  .sev.critical { background: var(--crit); }
  .sev.warning { background: var(--warn); }
  .sev.info { background: var(--info); }
  .ruleid { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .8rem; color: #666; }
  .cite, .cite a { overflow-wrap: anywhere; word-break: break-word; }
  .cite { font-size: .85rem; color: #333; margin-top: .4rem; }
  .fresh { color: #777; font-size: .8rem; }
  ol.biblio { padding-left: 1.4rem; }
  ol.biblio li { overflow-wrap: anywhere; margin-bottom: .4rem; font-size: .85rem; }
  .posture p { font-size: .85rem; color: #333; }
  @media print { body { max-width: none; } a { color: inherit; text-decoration: underline; } }
  @media (max-width: 32rem) { body { padding: .75rem; } h1 { font-size: 1.35rem; } }
`;

function renderCitation(c: SourceCitation): string {
  const url = c.source_url?.trim();
  const fresh = freshnessSignal(c);
  const freshPart = fresh ? ` <span class="fresh">(${esc(fresh)})</span>` : "";
  if (url) {
    const href = safeHref(url);
    // Safe scheme → clickable link. Unsafe scheme → render the source + the
    // URL as inert escaped text, so the citation stays visible/verifiable but
    // can never execute when the shared report is opened.
    return href
      ? `<div class="cite">Authority: <a href="${esc(href)}">${esc(c.source)}</a>${freshPart}</div>`
      : `<div class="cite">Authority: ${esc(c.source)} (${esc(url)})${freshPart}</div>`;
  }
  // URL-less custom-playbook rule (spec-v8 §14): render cleanly, honestly
  // distinguished, never a dangling segment.
  return `<div class="cite">Authority: ${esc(c.source)} <span class="fresh">(cited — ${esc(c.license || "team policy")})</span></div>`;
}

function renderFinding(f: Finding, bibliography: ReturnType<typeof buildBibliography>): string {
  const refs = f.source_citations
    .map((c) => citationIndex(bibliography, c.id))
    .filter((n): n is number => n !== undefined)
    .map((n) => `[${n}]`)
    .join(" ");
  const parts: string[] = [];
  parts.push(`<div class="finding ${f.severity}">`);
  parts.push(
    `<h3><span class="sev ${f.severity}">${f.severity}</span> ${esc(f.title)} ${refs ? `<span class="ruleid">${refs}</span>` : ""}</h3>`,
  );
  parts.push(`<div class="ruleid">${esc(f.rule_id)} v${esc(f.rule_version)}${f.excerpt.section_id ? ` · §${esc(f.excerpt.section_id)}` : ""}</div>`);
  if (f.explanation) parts.push(`<p>${esc(f.explanation)}</p>`);
  if (f.recommendation) parts.push(`<p><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>`);
  for (const c of f.source_citations) parts.push(renderCitation(c));
  parts.push("</div>");
  return parts.join("\n");
}

export function buildHtmlReport(
  run: EngineRun,
  ingest: IngestResult,
  dkb: DKB,
  playbook?: Playbook,
): string {
  const bibliography = buildBibliography(run.findings, dkb);
  const counts = { critical: 0, warning: 0, info: 0 } as Record<Severity, number>;
  for (const f of run.findings) counts[f.severity]++;

  const body: string[] = [];
  body.push(`<h1>Vaulytica Report — ${esc(run.source_file.name)}</h1>`);

  // Cover proof fields (mirrors the DOCX cover).
  body.push('<dl class="proof">');
  body.push(`<dt>Playbook</dt><dd>${esc(run.playbook_id)}${playbook?.deprecated ? " (legacy)" : ""}</dd>`);
  body.push(`<dt>DKB version</dt><dd>${esc(run.dkb_version)}</dd>`);
  body.push(`<dt>Engine version</dt><dd>${esc(run.version)}</dd>`);
  body.push(
    `<dt>Document</dt><dd>${esc(ingest.source)} · ${ingest.word_count} words${ingest.page_count ? ` · ${ingest.page_count} pages` : ""}</dd>`,
  );
  body.push(`<dt>File fingerprint (SHA-256)</dt><dd>${esc(run.source_file.sha256)}</dd>`);
  body.push(`<dt>Result hash</dt><dd>${esc(run.result_hash)}</dd>`);
  body.push(`<dt>Executed at</dt><dd>${esc(run.executed_at || "(omitted from hash)")}</dd>`);
  body.push(
    `<dt>Findings</dt><dd>${counts.critical} critical · ${counts.warning} warning · ${counts.info} info (${run.findings.length} total)</dd>`,
  );
  body.push("</dl>");

  // Findings, grouped by severity.
  for (const sev of SEVERITY_ORDER) {
    const group = run.findings.filter((f) => f.severity === sev);
    body.push(`<h2>${SEVERITY_LABEL[sev]} (${group.length})</h2>`);
    if (group.length === 0) {
      body.push("<p><em>None.</em></p>");
      continue;
    }
    for (const f of group) body.push(renderFinding(f, bibliography));
  }

  // Bibliography.
  body.push("<h2>Bibliography</h2>");
  if (bibliography.length === 0) {
    body.push("<p>No DKB sources were referenced by any finding in this report.</p>");
  } else {
    body.push('<ol class="biblio">');
    for (const b of bibliography) {
      const url = b.source.source_url?.trim();
      // Strip the leading "[N] " — the <ol> supplies the number.
      const text = formatBibliographyEntry(b.index, b.source).replace(/^\[\d+\]\s*/, "");
      // Escape the whole line, then turn the (escaped) URL into a link so a
      // reader can click through and the URL still wraps (.biblio li has
      // overflow-wrap). Never truncated — the full entry is rendered.
      const escaped = esc(text);
      // Only an http(s) URL becomes a link; an unsafe scheme stays inert
      // escaped text (it is already part of `escaped`), so a shared report
      // can never carry an active javascript:/data: link.
      const href = url ? safeHref(url) : null;
      const li = href ? escaped.replace(esc(href), `<a href="${esc(href)}">${esc(href)}</a>`) : escaped;
      body.push(`<li>${li}</li>`);
    }
    body.push("</ol>");
  }

  // Clause-evidence coverage (spec-v8 §25) — how defensible the findings are.
  const evidence = buildClauseEvidence(run);
  if (evidence.total > 0) {
    body.push("<h2>Clause-evidence coverage</h2>");
    body.push(
      `<p>${evidence.quoted} of ${evidence.total} findings (${Math.round(evidence.coverage_ratio * 100)}%) pin a verbatim quoted clause span; ${evidence.bare} rest on a bare structural/pattern match. Quoted findings are quickest to confirm.</p>`,
    );
  }

  // Posture block (verbatim, same statements as the DOCX disclaimer).
  body.push('<div class="posture">');
  body.push("<h2>Disclaimer</h2>");
  body.push("<h3>Determinism</h3>");
  body.push(`<p>${esc(DETERMINISM_STATEMENT)}</p>`);
  body.push("<h3>Privacy</h3>");
  body.push(`<p>${esc(PRIVACY_STATEMENT)}</p>`);
  body.push("<h3>Not legal advice</h3>");
  body.push(`<p>${esc(NON_ADVICE_STATEMENT)}</p>`);
  body.push("</div>");

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>Vaulytica Report — ${esc(run.source_file.name)}</title>`,
    `<style>${STYLE}</style>`,
    "</head>",
    "<body>",
    body.join("\n"),
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

export function htmlReportBlob(
  run: EngineRun,
  ingest: IngestResult,
  dkb: DKB,
  playbook?: Playbook,
): Blob {
  return new Blob([buildHtmlReport(run, ingest, dkb, playbook)], { type: "text/html" });
}

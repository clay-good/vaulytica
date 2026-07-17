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
import { scopeForPlaybook } from "../verticals/registry.js";
import type { DKB, SourceCitation } from "../dkb/types.js";
import { isHttpUrl } from "../dkb/url-safety.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { buildBibliography, citationIndex } from "./bibliography.js";
import {
  currencyLabel,
  dkbCurrency,
  formatBibliographyEntry,
  freshnessSignal,
  type CitationCurrency,
} from "./citations.js";
import { buildClauseEvidence } from "./clause-evidence.js";
import { buildReviewCoverage, reviewCoverageSentence, tierBadgeLabel } from "./review-coverage.js";
import type { V9Surfaces } from "./v9-surfaces.js";
import type { DeliveryReport } from "../delivery/types.js";
import type { ClosingChecklist, ChecklistCategory } from "./closing-checklist.js";
import type { CriticalDatesRegister, CriticalDateKind } from "./critical-dates.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

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
 * rejects such URLs at load (input boundary); this guarantees the rendered
 * artifact is safe even for a citation that bypassed validation.
 */
function safeHref(url: string): string | null {
  return isHttpUrl(url) ? url : null;
}

// Fixed, font-agnostic, print-clean CSS. `overflow-wrap: anywhere` on the
// citation URL is the HTML half of the §18 always-wrap contract.
const STYLE = `
  :root { --mint: #00a883; --crit: #b00020; --warn: #a86700; --info: #555; }
  * { box-sizing: border-box; }
  /* overflow-wrap is inherited, so setting it on body makes every text node in
     the report — headings (the filename in the <h1>), finding titles, rule ids,
     SHA-256 proof values, citation URLs — break a long unbreakable token rather
     than push the page past a phone viewport. No horizontal scroll, anywhere. */
  body { font-family: Arial, Helvetica, sans-serif; color: #1a1a1a; line-height: 1.5;
    max-width: 52rem; margin: 0 auto; padding: 1.25rem; overflow-wrap: anywhere; }
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
  .tier-badge { display: inline-block; margin-top: .25rem; padding: .1rem .4rem; border-radius: 3px;
    font-size: .7rem; font-weight: bold; background: #1f6feb; color: #fff; }
  .cite, .cite a { overflow-wrap: anywhere; word-break: break-word; }
  .cite { font-size: .85rem; color: #333; margin-top: .4rem; }
  /* #6b6b6b ≈ 5.0:1 on white — clears WCAG 2 AA (4.5:1) for this small,
     muted freshness label; #777 was 4.47:1 and failed by a hair. */
  .fresh { color: #6b6b6b; font-size: .8rem; }
  ol.biblio { padding-left: 1.4rem; }
  ol.biblio li { overflow-wrap: anywhere; margin-bottom: .4rem; font-size: .85rem; }
  .posture p { font-size: .85rem; color: #333; }
  /* v9 "Last Look" surfaces — each a bordered card list, mobile-safe (every
     cell wraps, no fixed widths, no horizontal scroll). */
  .v9-note { font-size: .8rem; color: #555; font-style: italic; margin: .25rem 0 .75rem; }
  ul.v9-list { list-style: none; padding: 0; margin: .5rem 0; }
  ul.v9-list li { border: 1px solid #dde3e1; border-left-width: 4px; border-radius: 6px;
    padding: .5rem .7rem; margin-bottom: .5rem; overflow-wrap: anywhere; }
  ul.v9-list li.crit { border-left-color: var(--crit); }
  ul.v9-list li.warn { border-left-color: var(--warn); }
  ul.v9-list li.info { border-left-color: var(--info); }
  ul.v9-list li.ok { border-left-color: var(--mint); }
  .v9-head { font-weight: bold; }
  .v9-sub { font-size: .82rem; color: #555; margin-top: .15rem; }
  .v9-evi { font-size: .82rem; color: #444; margin: .1rem 0 0; padding-left: 1.1rem; }
  .v9-date { font-family: ui-monospace, Menlo, Consolas, monospace; font-weight: bold; }
  @media print { body { max-width: none; } a { color: inherit; text-decoration: underline; } }
  @media (max-width: 32rem) { body { padding: .75rem; } h1 { font-size: 1.35rem; } }
`;

function renderCitation(c: SourceCitation, currency?: CitationCurrency): string {
  const url = c.source_url?.trim();
  const fresh = freshnessSignal(c);
  // Currency label (fix-legal-authority-currency): deterministic — anchored
  // to the DKB's own built_at, never the wall clock.
  const stale = currencyLabel(c, currency);
  const freshPart =
    (fresh ? ` <span class="fresh">(${esc(fresh)})</span>` : "") +
    (stale ? ` <span class="fresh">⚠ ${esc(stale)}</span>` : "");
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

function renderFinding(
  f: Finding,
  bibliography: ReturnType<typeof buildBibliography>,
  currency?: CitationCurrency,
): string {
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
  parts.push(
    `<div class="ruleid">${esc(f.rule_id)} v${esc(f.rule_version)}${f.excerpt.section_id ? ` · §${esc(f.excerpt.section_id)}` : ""}</div>`,
  );
  // add-attorney-review-ledger — the tier badge, only on a finding whose rule
  // an attorney signed (dormant until the ledger is signed; never fabricated).
  if (f.tier) parts.push(`<div class="tier-badge">${esc(tierBadgeLabel(f.tier))}</div>`);
  if (f.explanation) parts.push(`<p>${esc(f.explanation)}</p>`);
  if (f.recommendation)
    parts.push(`<p><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>`);
  for (const c of f.source_citations) parts.push(renderCitation(c, currency));
  parts.push("</div>");
  return parts.join("\n");
}

const SEV_CLASS: Record<string, string> = { critical: "crit", warning: "warn", info: "info" };

/** "Clean to send" — the delivery / HANDOFF-* pre-disclosure section (Thrust A). */
function renderDeliverySection(delivery: DeliveryReport): string[] {
  if (delivery.findings.length === 0) return [];
  const out: string[] = ["<h2>Clean to send — pre-disclosure scan</h2>"];
  out.push(`<p class="v9-note">${esc(delivery.summary)}</p>`);
  out.push('<ul class="v9-list">');
  for (const f of delivery.findings) {
    const evi = f.evidence
      .slice(0, 6)
      .map((e) => `<div class="v9-evi">${esc(e)}</div>`)
      .join("");
    const more = f.count > 6 ? `<div class="v9-evi">…and ${f.count - 6} more</div>` : "";
    out.push(
      `<li class="${SEV_CLASS[f.severity] ?? "info"}"><div class="v9-head"><span class="ruleid">${esc(f.rule_id)}</span> ${esc(f.title)}</div><div class="v9-sub">${esc(f.description)}</div>${evi}${more}</li>`,
    );
  }
  out.push("</ul>");
  out.push(
    '<p class="v9-note">Vaulytica reports what it found in the original file and where — it never removes it (that is your edit in Word) and never certifies the document clean.</p>',
  );
  return out;
}

const CHECKLIST_CAT_LABEL: Record<ChecklistCategory, string> = {
  signature: "Signatures",
  attachment: "Attachments",
  formality: "Execution formalities",
  blank: "Unfilled content",
  handoff: "Pre-send cleanup",
};
const CHECKLIST_CAT_ORDER: ChecklistCategory[] = [
  "signature",
  "attachment",
  "formality",
  "blank",
  "handoff",
];

/** "Ready to sign" — the consolidated closing checklist (Thrust B). */
function renderClosingChecklistSection(checklist: ClosingChecklist): string[] {
  if (checklist.items.length === 0) return [];
  const out: string[] = ["<h2>Ready to sign — closing checklist</h2>"];
  out.push(
    `<p class="v9-note">${checklist.open_count} readiness item${checklist.open_count === 1 ? "" : "s"} to resolve. A projection of the findings — it does not certify the document is ready to sign or validly executed.</p>`,
  );
  for (const cat of CHECKLIST_CAT_ORDER) {
    const group = checklist.items.filter((i) => i.category === cat);
    if (group.length === 0) continue;
    out.push(`<h3>${esc(CHECKLIST_CAT_LABEL[cat])} (${group.length})</h3>`);
    out.push('<ul class="v9-list">');
    for (const i of group) {
      const where = i.section ? ` <span class="ruleid">§${esc(i.section)}</span>` : "";
      out.push(
        `<li class="warn"><span class="ruleid">${esc(i.rule_id)}</span> ${esc(i.label)}${where}</li>`,
      );
    }
    out.push("</ul>");
  }
  return out;
}

const CRITICAL_DATE_KIND_LABEL: Record<CriticalDateKind, string> = {
  "auto-renewal-notice": "Auto-renewal notice",
  "cure-window": "Cure window",
  "opt-out-window": "Opt-out / termination",
  "survival-end": "Survival end",
  "notice-period": "Notice deadline",
};

/** "Your calendar, computed" — the critical-dates register (Thrust C). */
function renderCriticalDatesSection(register: CriticalDatesRegister): string[] {
  if (register.register.length === 0) return [];
  const out: string[] = ["<h2>Critical dates — computed from the document</h2>"];
  out.push(
    `<p class="v9-note">${register.resolved_count} computed · ${register.unresolved_count} to verify manually. Each date is calendar arithmetic over the document's own terms; never a determination that a deadline is met, missed, or binding.</p>`,
  );
  out.push('<ul class="v9-list">');
  for (const r of register.register) {
    const label = CRITICAL_DATE_KIND_LABEL[r.kind] ?? "Deadline";
    const date = r.resolved
      ? r.window
        ? `${esc(r.window[0])} – ${esc(r.window[1])}`
        : esc(r.computed_date ?? "")
      : "Verify manually";
    const meta: string[] = [];
    if (r.anchor) meta.push(`anchor: ${esc(r.anchor)}`);
    if (r.responsible) meta.push(`responsible: ${esc(r.responsible)}`);
    if (r.section) meta.push(`§${esc(r.section)}`);
    const reason = !r.resolved && r.reason ? `<div class="v9-evi">${esc(r.reason)}</div>` : "";
    out.push(
      `<li class="${r.resolved ? "ok" : "warn"}"><div class="v9-head"><span class="v9-date">${date}</span> · <span class="ruleid">${esc(r.rule_id)}</span> ${esc(label)}</div><div class="v9-sub">${esc(r.trigger)}</div>${meta.length ? `<div class="v9-sub">${meta.join(" · ")}</div>` : ""}${reason}</li>`,
    );
  }
  out.push("</ul>");
  return out;
}

const NEGOTIATION_TIER: Record<NegotiationTier, { label: string; cls: string }> = {
  ideal: { label: "Ideal", cls: "ok" },
  acceptable: { label: "Acceptable", cls: "info" },
  "below-acceptable": { label: "Below floor — escalate", cls: "crit" },
  unevaluable: { label: "Not stated — verify", cls: "warn" },
};

/** "Negotiation posture" — the tiered ideal/acceptable ladder per dimension (spec-v10 Thrust A). */
function renderNegotiationPostureSection(posture: NegotiationPosture): string[] {
  if (posture.positions.length === 0) return [];
  const c = posture.counts;
  const out: string[] = ["<h2>Negotiation posture</h2>"];
  out.push(
    `<p class="v9-note">${c.ideal} ideal · ${c.acceptable} acceptable · ${c.below_acceptable} below floor · ${c.unevaluable} not stated. Advisory posture computed deterministically from your playbook's positions — it does not render a legal conclusion.</p>`,
  );
  out.push('<ul class="v9-list">');
  for (const p of posture.positions) {
    const tier = NEGOTIATION_TIER[p.tier];
    const detail = p.detail ?? p.reason ?? "";
    const guide = p.guidance ? `<div class="v9-evi">Guidance: ${esc(p.guidance)}</div>` : "";
    const where = p.section_id ? ` <span class="ruleid">§${esc(p.section_id)}</span>` : "";
    out.push(
      `<li class="${tier.cls}"><div class="v9-head">${esc(p.dimension)} — <strong>${esc(tier.label)}</strong>${where}</div>${detail ? `<div class="v9-sub">${esc(detail)}</div>` : ""}${guide}</li>`,
    );
  }
  out.push("</ul>");
  return out;
}

export function buildHtmlReport(
  run: EngineRun,
  ingest: IngestResult,
  dkb: DKB,
  playbook?: Playbook,
  v9?: V9Surfaces,
  negotiationPosture?: NegotiationPosture,
): string {
  const bibliography = buildBibliography(run.findings, dkb);
  const currency = dkbCurrency(dkb.manifest);
  const counts = { critical: 0, warning: 0, info: 0 } as Record<Severity, number>;
  for (const f of run.findings) counts[f.severity]++;

  const body: string[] = [];
  body.push(`<h1>Vaulytica Report — ${esc(run.source_file.name)}</h1>`);

  // Cover proof fields (mirrors the DOCX cover).
  body.push('<dl class="proof">');
  body.push(
    `<dt>Playbook</dt><dd>${esc(run.playbook_id)}${playbook?.deprecated ? " (legacy)" : ""}</dd>`,
  );
  body.push(`<dt>DKB version</dt><dd>${esc(run.dkb_version)}</dd>`);
  body.push(`<dt>Engine version</dt><dd>${esc(run.version)}</dd>`);
  body.push(
    `<dt>Document</dt><dd>${esc(ingest.source)} · ${ingest.word_count} words${ingest.page_count ? ` · ${ingest.page_count} pages` : ""}</dd>`,
  );
  body.push(`<dt>File fingerprint (SHA-256)</dt><dd>${esc(run.source_file.sha256)}</dd>`);
  if (run.filing_profile) {
    body.push(
      `<dt>Court profile</dt><dd>${esc(run.filing_profile.id)} (${esc(run.filing_profile.brief_kind)} brief) — asserted by the user</dd>`,
    );
  }
  if (run.asserted_regimes && run.asserted_regimes.length > 0) {
    body.push(
      `<dt>Privacy regimes</dt><dd>${esc(run.asserted_regimes.join(", "))} — asserted by the user</dd>`,
    );
  }
  if (run.estate_checks_asserted) {
    body.push("<dt>Estate checks</dt><dd>asserted by the user (--estate-checks)</dd>");
  }
  body.push(`<dt>Result hash</dt><dd>${esc(run.result_hash)}</dd>`);
  body.push(`<dt>Executed at</dt><dd>${esc(run.executed_at || "(omitted from hash)")}</dd>`);
  body.push(
    `<dt>Findings</dt><dd>${counts.critical} critical · ${counts.warning} warning · ${counts.info} info (${run.findings.length} total)</dd>`,
  );
  body.push("</dl>");

  // Unmatched-document banner + scope-of-review, above the findings (mirrors
  // the DOCX order). Each emits nothing when not applicable.
  if (run.classification_notice) {
    body.push('<div class="classification-notice">');
    body.push("<h2>Document Type Not Recognized</h2>");
    body.push(`<p>${esc(run.classification_notice.message)}</p>`);
    body.push("</div>");
  }
  const scope = scopeForPlaybook(run.playbook_id);
  if (scope) {
    body.push('<div class="scope-of-review">');
    body.push(`<h2>Scope of Review — ${esc(scope.pack)}</h2>`);
    body.push(
      '<p class="v9-note">This report reflects only the checks listed below. Where a check found nothing, that means the reviewed language was present, not that the document is compliant or complete.</p>',
    );
    body.push("<h3>Reviewed for</h3><ul>");
    for (const item of scope.reviewed_for) body.push(`<li>${esc(item)}</li>`);
    body.push("</ul><h3>Not reviewed for</h3><ul>");
    for (const item of scope.not_reviewed_for) body.push(`<li>${esc(item)}</li>`);
    body.push("</ul></div>");
  }

  // Findings, grouped by severity.
  for (const sev of SEVERITY_ORDER) {
    const group = run.findings.filter((f) => f.severity === sev);
    body.push(`<h2>${SEVERITY_LABEL[sev]} (${group.length})</h2>`);
    if (group.length === 0) {
      body.push("<p><em>None.</em></p>");
      continue;
    }
    for (const f of group) body.push(renderFinding(f, bibliography, currency));
  }

  // v9 "Last Look" surfaces — render-side, outside `result_hash`. Each is
  // omitted when empty, so a document with none yields the v8 report byte-for-byte.
  if (v9?.delivery) body.push(...renderDeliverySection(v9.delivery));
  if (v9?.closingChecklist) body.push(...renderClosingChecklistSection(v9.closingChecklist));
  if (v9?.criticalDates) body.push(...renderCriticalDatesSection(v9.criticalDates));
  // spec-v10 Thrust A — tiered negotiation posture (custom playbook only).
  if (negotiationPosture) body.push(...renderNegotiationPostureSection(negotiationPosture));

  // Bibliography.
  body.push("<h2>Bibliography</h2>");
  if (bibliography.length === 0) {
    body.push("<p>No DKB sources were referenced by any finding in this report.</p>");
  } else {
    body.push('<ol class="biblio">');
    for (const b of bibliography) {
      const url = b.source.source_url?.trim();
      // Strip the leading "[N] " — the <ol> supplies the number.
      const text = formatBibliographyEntry(b.index, b.source, currency).replace(/^\[\d+\]\s*/, "");
      // Escape the whole line, then turn the (escaped) URL into a link so a
      // reader can click through and the URL still wraps (.biblio li has
      // overflow-wrap). Never truncated — the full entry is rendered.
      const escaped = esc(text);
      // Only an http(s) URL becomes a link; an unsafe scheme stays inert
      // escaped text (it is already part of `escaped`), so a shared report
      // can never carry an active javascript:/data: link.
      const href = url ? safeHref(url) : null;
      // Use a replacer *function*, not a string: a string replacement makes
      // `$&`/`$1`/`` $` ``/`$'` in a (user-supplied custom-playbook) citation URL
      // expand as special patterns and corrupt the rendered link. A function
      // inserts the markup verbatim.
      const li = href
        ? escaped.replace(esc(href), () => `<a href="${esc(href)}">${esc(href)}</a>`)
        : escaped;
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

  // Attorney-review coverage (add-attorney-review-ledger) — honest "N of M".
  const reviewCoverage = buildReviewCoverage(run.findings);
  if (reviewCoverage.total > 0) {
    body.push("<h2>Attorney review coverage</h2>");
    body.push(`<p>${esc(reviewCoverageSentence(reviewCoverage))}</p>`);
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
  v9?: V9Surfaces,
  negotiationPosture?: NegotiationPosture,
): Blob {
  return new Blob([buildHtmlReport(run, ingest, dkb, playbook, v9, negotiationPosture)], {
    type: "text/html",
  });
}

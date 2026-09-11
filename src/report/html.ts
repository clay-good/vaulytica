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
 * the run's recorded `executed_at` (which the DOCX also shows).
 *
 * It is NOT byte-for-byte the DOCX's content, and this comment used to say it
 * was. What both carry: the findings, the honesty caveats (input notices,
 * classification notice, scope of review), the three v9 surfaces, the
 * negotiation posture, the privacy-regime and attorney-review coverage, the
 * clause-evidence coverage, the citations and bibliography, and the disclaimer
 * — plus, since the claim was checked, the secondary-family checks, which the
 * DOCX had carried since v6 while this file omitted them entirely. A document
 * that is both an NDA and a DPA had its DPA findings in one human-readable
 * surface and not the other, and findings are the one thing a report may not
 * silently omit. The cross-document consistency appendix (spec-v3 §59) was the
 * same omission, found by the same question, and is here now too.
 *
 * What the DOCX still has and this does not, deliberately: the cover page and
 * its proof fields, the executive summary, the findings INDEX (a triage table
 * ahead of the same findings rendered below it), the extracted-data appendix,
 * and the audit trail. Those are the paginated report's navigation and
 * reference apparatus; a single scrolling page that a reader can search does
 * not need a triage table over content it already contains. If one of them is
 * ever added, add it here and to this list together.
 *
 * 🚨 **Two entries were on that list and did not belong on it**: the
 * jurisdiction overlays and the obligations ledger, both here since 9.579.0. A
 * California non-compete's Bus. & Prof. Code § 16600 overlay is the single most
 * consequential thing this tool can say about that document, and
 * `uncovered_states` is an honest coverage gap that must not read as a clean
 * pass; who owes what, by when, is likewise content. Filing content under
 * "navigation apparatus" is how a deliberate-omissions list stops being a
 * decision and becomes a place things go.
 *
 * 🚨 **And two things were on no list at all** (9.580.0), which is worse than a
 * misfiled entry — a silent omission is not a decision anyone made. Every
 * finding here rendered without its **PROOF**: the DOCX leads each one with
 * "Evidence — <section, characters N–M>" and the quoted clause, or with "Basis
 * — the document contains no matching clause; this finding is about what is
 * absent." A reader of the emailable report could not check a single finding
 * against the document and could not tell those two shapes apart. The
 * per-finding **public model clause** — what good looks like, with attribution
 * and license — was likewise in the DOCX and the JSON and not here. So were
 * the finding's own `description` (this file rendered only `explanation`, so
 * every finding opened with the reasoning for a claim the reader had not been
 * given) and the **"your playbook"** provenance marker, without which a finding
 * from a user-supplied standard is presented exactly like one from Vaulytica's
 * catalog.
 * Citable: renders the full Thrust-B citation with wrapped URLs
 * (`overflow-wrap: anywhere`) and the §17 freshness signal. In-tab /
 * offline — it ships no network reference. Render-side — zero
 * `result_hash` churn.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { ConsistencyRun } from "../engine/consistency/types.js";
import { scopeForPlaybook } from "../verticals/registry.js";
import { buildRegimeCoverage } from "../privacy/coverage.js";
import { estateFormalitiesForState } from "../dkb/estate-formalities.js";
import type { RegimeId } from "../privacy/regime-data.js";
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
import { buildReviewCoverage, reviewCoverageSentence, tierBadgeLabel } from "./review-coverage.js";
import { erroredRuleNotice } from "./execution-log.js";
import { buildClauseEvidence, clauseEvidenceSentence } from "./clause-evidence.js";
import { selectStateOverlays, type StateOverlayResult } from "../dkb/state-overlays.js";
import { modelClauseForRule } from "../dkb/model-clauses.js";
import type { ExtractedData } from "../extract/types.js";
import { ENGAGEMENT_SCOPE } from "./engagement-scope.js";
import type { V9Surfaces } from "./v9-surfaces.js";
import type { ReportSecondaryFamily } from "./json.js";
import { cappedFamiliesNotice } from "../engine/secondary-family-notice.js";
import { truncate } from "./v3/_dx.js";
import type { DeliveryReport } from "../delivery/types.js";
import type { ClosingChecklist, ChecklistCategory } from "./closing-checklist.js";
import type { CriticalDatesRegister, CriticalDateKind } from "./critical-dates.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";
import { nonAdviceStatement, privacyStatement } from "./disclaimers.js";

const SEVERITY_ORDER: Severity[] = ["critical", "warning", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical Findings",
  warning: "Warnings",
  info: "Informational",
};

const DETERMINISM_STATEMENT =
  "This report was produced by a deterministic process. Given the same input file, the same Vaulytica engine version, and the same Deterministic Knowledge Base version listed above, the rules in this report will produce an identical report on any machine, at any time. The fingerprint of the input file is recorded above for verification. No part of this analysis was performed by a language model or any other non-deterministic system. The complete list of rules executed, including those that produced no findings, is included in the Audit Trail section so that the scope of the analysis is fully transparent.";

const PRIVACY_STATEMENT = privacyStatement("document");

const NON_ADVICE_STATEMENT = nonAdviceStatement("document");

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
  /* The proof block: the locator line and the clause it quotes. Bordered so a
     reader scanning a printed page can tell the document's OWN words from
     Vaulytica's, which is the whole point of showing them. */
  .proof-basis { margin: .5rem 0 .2rem; font-size: .9rem; }
  blockquote { margin: .2rem 0 .6rem; padding: .4rem .7rem; border-left: 3px solid #c9c9c9;
    background: #fafafa; white-space: pre-wrap; overflow-wrap: anywhere; }
  .model-clause { margin: .5rem 0 .2rem; padding: .4rem .7rem; border-left: 3px solid #2f8f5b;
    background: #f5faf7; }
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

/**
 * The public model clause for a finding's rule — what good looks like, with its
 * attribution and license. Returns [] for a rule with no reference, so
 * coverage stays honest.
 */
function renderModelClauseReference(f: Finding): string[] {
  const mc = modelClauseForRule(f.rule_id);
  if (!mc) return [];
  return [
    `<p class="model-clause"><strong>Reference model clause</strong><br>` +
      `<strong>${esc(mc.title)} — ${esc(mc.source_catalog)}</strong><br>` +
      `${esc(mc.summary)}</p>`,
    `<p class="v9-note">Reference only — Vaulytica does not draft. Source: ${esc(
      mc.source.source,
    )}${mc.source.attribution ? ` (${esc(mc.source.attribution)})` : ""} [license: ${esc(
      mc.source.license,
    )}]</p>`,
  ];
}

/** A finding has a span when its excerpt covers a real range of the text. */
function hasSpan(f: Finding): boolean {
  return f.excerpt.end_offset > f.excerpt.start_offset;
}

/**
 * Where a finding came from, stated precisely enough to check by hand — the
 * section plus the exact character span, grouped (`12,433`) because a person
 * reads it. A finding with no span says so rather than printing
 * `characters 0–0` and sending the reader to look for something that was never
 * there.
 */
function findingLocator(f: Finding): string {
  if (!hasSpan(f)) return "absent — nothing to quote";
  const span = `characters ${f.excerpt.start_offset.toLocaleString("en-US")}–${f.excerpt.end_offset.toLocaleString("en-US")}`;
  return f.excerpt.section_id ? `${f.excerpt.section_id}, ${span}` : span;
}

/**
 * The proof for one finding, in the two honest shapes the DOCX uses and never
 * blurs: the rule fired ON text — show that text under the range it matched at
 * — or it fired on an ABSENCE, which is said plainly rather than quoting a
 * marker string at `characters 0–0`.
 *
 * "Evidence", not "Quoted": a rule may widen its excerpt to the surrounding
 * sentence or narrow it to the matched value, so "quoted" is not true of every
 * finding and "evidence at this range" is.
 */
function renderProof(f: Finding): string[] {
  if (!hasSpan(f)) {
    return [
      '<p class="proof-basis"><strong>Basis</strong> — the document contains no matching clause; this finding is about what is absent.</p>',
    ];
  }
  return [
    `<p class="proof-basis"><strong>Evidence</strong> — ${esc(findingLocator(f))}</p>`,
    `<blockquote>${esc(truncate(f.excerpt.text, 900))}</blockquote>`,
  ];
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
  // The rule behind the finding, named so it can be looked up, re-run, or
  // disagreed with — and, for a finding from a user-supplied playbook, SAID:
  // "your standard flagged this" must never be confused with "Vaulytica's
  // catalog flagged this". The DOCX has carried that distinction since custom
  // playbooks shipped; this file rendered the rule id alone.
  parts.push(
    `<div class="ruleid">${esc(f.rule_id)} v${esc(f.rule_version)}${
      f.excerpt.section_id ? ` · §${esc(f.excerpt.section_id)}` : ""
    }${f.source === "custom-playbook" ? " · your playbook" : ""}</div>`,
  );
  // What is wrong, in the finding's own words. The DOCX renders `description`
  // AND `explanation`; this file rendered only the second, so every finding
  // here opened with the reasoning for a claim the reader had not been given.
  if (f.description) parts.push(`<p>${esc(f.description)}</p>`);
  // add-attorney-review-ledger — the tier badge, only on a finding whose rule
  // an attorney signed (dormant until the ledger is signed; never fabricated).
  if (f.tier) parts.push(`<div class="tier-badge">${esc(tierBadgeLabel(f.tier))}</div>`);
  // The PROOF — the DOCX has led every finding with this since the report was
  // made to lead with evidence, and this file rendered none of it. A reader of
  // the emailable report could not check a single finding against the document,
  // and could not tell a finding about text from a finding about an ABSENCE.
  // Worse since 9.578.0: this surface now prints "N of M findings quote the
  // exact clause text they fired on" while showing none of them.
  parts.push(...renderProof(f));
  if (f.explanation) parts.push(`<p>${esc(f.explanation)}</p>`);
  if (f.recommendation)
    parts.push(`<p><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>`);
  // "What good looks like" — the attributed public model clause, never a
  // generated redline. In the DOCX and the JSON since spec-v6 Part IV; this
  // file did not carry it, and it was not on the deliberate-omissions list
  // either, so it was a silent omission rather than a decision.
  parts.push(...renderModelClauseReference(f));
  for (const c of f.source_citations) parts.push(renderCitation(c, currency));
  parts.push("</div>");
  return parts.join("\n");
}

const SEV_CLASS: Record<string, string> = { critical: "crit", warning: "warn", info: "info" };

/**
 * The families this document ALSO contains, kept apart from the primary
 * findings — the HTML mirror of the DOCX section of the same name.
 */
/**
 * The cross-document consistency appendix — the HTML counterpart of the DOCX's
 * `renderConsistencyAppendix`. A conflict is a fact about a PAIR of documents,
 * so every finding names the documents it cites and quotes the conflicting text
 * from each; the run's own hash closes the section, as it does in the DOCX.
 *
 * A run with no conflicts still prints the section: "we checked and found
 * nothing" and "we never checked" are different statements, and only one of
 * them is what a bundle report should leave a reader with.
 */
function renderConsistencySection(consistency: ConsistencyRun | undefined): string[] {
  if (!consistency) return [];
  const out: string[] = ["<h2>Cross-document consistency</h2>"];
  out.push(
    `<p>Documents in this bundle: ${esc(
      consistency.documents.map((d) => `${d.doc_id} (${d.kind})`).join(", "),
    )}.</p>`,
  );
  if (consistency.findings.length === 0) {
    out.push("<p><em>No cross-document conflicts were detected by the consistency rules.</em></p>");
  } else {
    out.push(
      `<p>${consistency.findings.length} cross-document finding${
        consistency.findings.length === 1 ? "" : "s"
      }. Each lists the affected documents and the conflicting text from each.</p>`,
    );
    out.push(
      "<table><thead><tr><th>#</th><th>Rule</th><th>Severity</th><th>Title</th></tr></thead><tbody>",
    );
    consistency.findings.forEach((f, i) => {
      out.push(
        `<tr><td>${i + 1}</td><td>${esc(f.rule_id)}</td>` +
          `<td>${esc(f.severity.toUpperCase())}</td><td>${esc(truncate(f.title, 120))}</td></tr>`,
      );
    });
    out.push("</tbody></table>");
    for (const f of consistency.findings) {
      out.push(`<h3>${esc(f.rule_id)} — ${esc(f.title)}</h3>`);
      out.push(`<p><strong>[${esc(f.severity.toUpperCase())}]</strong> ${esc(f.description)}</p>`);
      out.push(`<p>${esc(f.explanation)}</p>`);
      if (f.recommendation) {
        out.push(`<p><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>`);
      }
      out.push("<h4>Conflicting excerpts</h4>");
      for (const e of f.excerpts) {
        out.push(
          `<blockquote>${esc(e.doc_id)} (${esc(e.source_file_name)}): ` +
            `&ldquo;${esc(truncate(e.text, 480))}&rdquo;</blockquote>`,
        );
      }
    }
  }
  out.push(`<p class="v9-note">Consistency result hash: ${esc(consistency.result_hash)}</p>`);
  return out;
}

/**
 * State-law overlays — the same content the DOCX renders, in the surface a
 * reader can email. Empty when the family has no overlay catalog or the
 * document named no covered state: we do not invent a section.
 */
function renderJurisdictionOverlaysSection(overlays: StateOverlayResult | undefined): string[] {
  if (!overlays || (overlays.matched.length === 0 && overlays.detected_states.length === 0)) {
    return [];
  }
  const topic = overlays.matched[0]?.topic ?? overlays.family;
  const out: string[] = ["<h2>Jurisdiction overlays</h2>"];
  out.push(
    `<p class="v9-note">State law on ${esc(topic)} varies sharply. Vaulytica's overlay catalog covers ${overlays.states_in_catalog} state(s) for the ${esc(
      overlays.family,
    )} family. The entries below match the governing-law state(s) this document names. These are a citable reference layer, not findings — they do not change the report's result hash.</p>`,
  );
  if (overlays.matched.length > 0) {
    out.push(
      "<table><thead><tr><th>State</th><th>Status</th><th>Summary</th><th>Authority</th></tr></thead><tbody>",
    );
    for (const o of overlays.matched) {
      out.push(
        `<tr><td>${esc(o.state_name)}</td><td>${esc(o.posture)} — ${esc(o.headline)}</td>` +
          `<td>${esc(truncate(o.summary, 320))}</td><td>${esc(o.citation.source)}</td></tr>`,
      );
    }
    out.push("</tbody></table>");
    for (const o of overlays.matched) {
      out.push(
        `<p><strong>${esc(o.state_name)}: ${esc(o.headline)}</strong></p>` +
          `<p>${esc(o.recommendation)}</p>` +
          `<p class="v9-note">Authority: ${esc(o.citation.source)} — ${esc(o.citation.source_url)}</p>`,
      );
    }
  }
  if (overlays.uncovered_states.length > 0) {
    out.push(
      `<p class="v9-note"><strong>No overlay on file for: ${esc(
        overlays.uncovered_states.map((st) => st.replace(/^us-/, "").toUpperCase()).join(", "),
      )}.</strong> This is an honest coverage gap — not a clean pass. Verify ${esc(topic)} for ${
        overlays.uncovered_states.length === 1 ? "that state" : "those states"
      } manually.</p>`,
    );
  }
  return out;
}

/** Who owes what, by when — the DOCX's ledger, in the emailable surface. */
function renderObligationsLedgerSection(extracted: ExtractedData | undefined): string[] {
  if (!extracted || extracted.obligations.length === 0) return [];
  const out: string[] = ["<h2>Obligations ledger</h2>"];
  out.push(
    `<p class="v9-note">${extracted.obligations.length} obligation${
      extracted.obligations.length === 1 ? "" : "s"
    } extracted from the document.</p>`,
  );
  out.push(
    "<table><thead><tr><th>Obligor</th><th>Modal</th><th>Action</th><th>Trigger / Qualifier</th></tr></thead><tbody>",
  );
  for (const o of extracted.obligations) {
    out.push(
      `<tr><td>${esc(o.obligor)}</td><td>${esc(o.modal)}</td>` +
        `<td>${esc(truncate(o.action, 160))}</td>` +
        `<td>${esc([o.trigger, o.qualifier].filter(Boolean).join(" — ") || "—")}</td></tr>`,
    );
  }
  out.push("</tbody></table>");
  return out;
}

function renderSecondaryFamiliesSection(
  secondary: ReadonlyArray<ReportSecondaryFamily> | undefined,
  omitted?: number,
): string[] {
  if (!secondary || secondary.length === 0) return [];
  const out: string[] = ["<h2>Additional checks from other detected families</h2>"];
  out.push(
    '<p class="v9-note">The families below were detected from this document&#39;s own VOCABULARY, not confirmed. A document can discuss another instrument&#39;s subject matter without being one — an 83(b) election letter names restricted stock and a right of first refusal, and is not a stock purchase agreement. Each family was scanned with its own rule set, and those checks assume the document IS one; where it is not, an absence reported below is a clause the document was never supposed to carry. Read this section as a prompt to confirm the family, not as a verdict. Kept separate from the primary findings above, and outside every result hash.</p>',
  );
  if (omitted && omitted > 0) {
    out.push(
      `<p class="v9-note"><strong>${esc(cappedFamiliesNotice(omitted, secondary.length))}</strong></p>`,
    );
  }
  for (const fam of secondary) {
    const c = fam.counts;
    out.push(
      `<p><strong>${esc(fam.playbook_name)} (${esc(fam.playbook_id)})</strong> — ` +
        `${c.critical} critical, ${c.warning} warnings, ${c.info} informational</p>`,
    );
    if (fam.findings.length === 0) {
      out.push("<p><em>No findings from this family's checks.</em></p>");
      continue;
    }
    out.push(
      "<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Section</th></tr></thead><tbody>",
    );
    for (const f of fam.findings) {
      out.push(
        `<tr><td>${esc(f.severity.toUpperCase())}</td><td>${esc(f.rule_id)}</td>` +
          `<td>${esc(truncate(f.description, 200))}</td>` +
          `<td>${esc(f.excerpt.section_id ?? "doc")}</td></tr>`,
      );
    }
    out.push("</tbody></table>");
  }
  return out;
}

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
  secondaryFamilies?: ReadonlyArray<ReportSecondaryFamily>,
  consistency?: ConsistencyRun,
  /**
   * The extracted data, for the two sections this file used to omit.
   *
   * Optional, so every existing caller renders exactly as it did — the two
   * sections below simply do not appear without it, the same way they do not
   * appear in the DOCX when the DOCX is called without `extracted`.
   */
  extracted?: ExtractedData,
): string {
  const bibliography = buildBibliography(run.findings, dkb);
  const currency = dkbCurrency(dkb.manifest);
  const counts = { critical: 0, warning: 0, info: 0 } as Record<Severity, number>;
  for (const f of run.findings) counts[f.severity]++;

  const body: string[] = [];
  body.push(`<h1>Vaulytica Report — ${esc(run.source_file.name)}</h1>`);
  // A rule that THREW is swallowed by the engine and reported as silence — the
  // right behaviour for a pure-rule contract, and the wrong thing to leave
  // unsaid. Until 9.577.0 only the Word report said it; the print-clean HTML a
  // reader is just as likely to be handed did not.
  const errored = erroredRuleNotice(run.execution_log);
  if (errored) body.push(`<p class="v9-note"><strong>${esc(errored)}</strong></p>`);

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
  // What the ingest could and could not read. On the cover, beside the other
  // proof fields, because it qualifies everything under it — an analysis of a
  // redline is an analysis of ONE of its two versions.
  if (ingest.warnings.length > 0) {
    body.push(
      `<dt>About this input</dt><dd><ul class="input-warnings">${ingest.warnings
        .map((w) => `<li>${esc(w)}</li>`)
        .join("")}</ul></dd>`,
    );
  }
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
    // Mirror the DOCX cover: name the verified formality posture the
    // overlay is speaking when the asserted state has a catalog node.
    const overlay = run.asserted_state ? estateFormalitiesForState(run.asserted_state) : undefined;
    body.push(
      run.asserted_state
        ? `<dt>Estate checks</dt><dd>asserted by the user (--state ${esc(run.asserted_state)})${overlay ? ` — ${esc(overlay.state_name)}: ${esc(overlay.headline)} (${esc(overlay.citation.source)})` : ""}</dd>`
        : "<dt>Estate checks</dt><dd>asserted by the user (--estate-checks)</dd>",
    );
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

  // The families the matched playbook names as its normal pairings. A
  // reference list, never a gap — a single document knows nothing about what
  // else exists, so unlike the bundle's "Companion Documents Not in This
  // Package" this asserts no absence. Omitted for the 50 families that name
  // none, so those reports are byte-unchanged.
  const related = v9?.relatedDocuments;
  if (related && related.length > 0) {
    body.push('<div class="related-documents">');
    body.push("<h2>Documents Normally Reviewed Alongside This One</h2>");
    body.push(
      '<p class="v9-note">A document of this kind is normally read together with the papers below. This is a reference list drawn from the matched playbook, not a finding: we have not seen these documents and make no claim about whether they exist, apply to you, or are missing.</p>',
    );
    body.push("<ul>");
    for (const r of related) body.push(`<li>${esc(r.name)}</li>`);
    body.push("</ul></div>");
  }

  // add-privacy-notice-pack — per-regime coverage table (found / not
  // detected), present only when the PNOT pack ran. Mirrors the Markdown and
  // DOCX exports: a projection of the fired PNOT findings, outside result_hash.
  if (run.asserted_regimes && run.asserted_regimes.length > 0) {
    const fired = new Set(
      run.findings.filter((f) => f.rule_id.startsWith("PNOT-")).map((f) => f.rule_id),
    );
    body.push('<div class="regime-coverage">');
    body.push("<h2>Privacy Regime Coverage</h2>");
    body.push(
      '<p class="v9-note">For each privacy regime asserted by the user, the enumerated notice-content items and whether each item\'s language was found. "Found" means the language was detected — never that the notice is adequate or compliant. Items not detected also appear as findings below.</p>',
    );
    for (const c of buildRegimeCoverage(run.asserted_regimes as RegimeId[], fired)) {
      body.push(`<h3>${esc(c.regime_name)} — ${c.found_count} of ${c.total} items found</h3>`);
      body.push("<ul>");
      for (const item of c.items) {
        body.push(
          `<li>${item.found ? "Found" : "Not detected"} — ${esc(item.item)} (${esc(item.rule_id)})</li>`,
        );
      }
      body.push("</ul>");
    }
    body.push("</div>");
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
  // spec-v6 multi-family activation — the families this document ALSO contains,
  // each scanned with its own rule set and quarantined here so the primary
  // report stays clean. The DOCX has carried this since v6; this file's own
  // header promises "same content as docx.ts", and a document that is both an
  // NDA and a DPA had its DPA findings in one human-readable surface and not
  // the other. Findings are the one thing a report may not silently omit.
  body.push(...renderSecondaryFamiliesSection(secondaryFamilies, v9?.secondaryFamiliesOmitted));
  // spec-v6 Part VI §21 — state-law overlays. The header below used to file
  // these under "the paginated report's navigation and reference apparatus",
  // alongside the findings index and the audit trail. They are not apparatus:
  // a California non-compete's Bus. & Prof. Code § 16600 entry is the single
  // most consequential thing this tool can say about that document, and
  // `uncovered_states` is an honest coverage gap that must not read as a clean
  // pass. Both were in the DOCX and absent from the report you can email.
  body.push(
    ...renderJurisdictionOverlaysSection(
      extracted ? selectStateOverlays(run.playbook_id, extracted.jurisdictions) : undefined,
    ),
  );
  // Same reclassification: who owes what, by when, is content.
  body.push(...renderObligationsLedgerSection(extracted));
  // spec-v3 §59 — the cross-document consistency appendix. The DOCX has
  // rendered it since v3 (`renderConsistencyAppendix`); this file did not, and
  // the omission was not on the deliberate list in the header above — so a
  // bundle's conflicts reached one human-readable surface and not the other.
  // Same defect, same file, as the secondary families directly above.
  body.push(...renderConsistencySection(consistency));

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
    // Legal basis above, textual evidence here — both or neither.
    const evidence = clauseEvidenceSentence(buildClauseEvidence(run));
    if (evidence) body.push(`<p>${esc(evidence)}</p>`);
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
  // Universal scope-of-review — limited-scope-engagement framing on every report
  // (add-attorney-review-ledger). Distinct from the per-pack "Scope of Review".
  body.push("<h3>Scope of this review</h3>");
  body.push(`<p>${esc(ENGAGEMENT_SCOPE.intro)}</p>`);
  body.push("<h4>Reviewed for</h4><ul>");
  for (const item of ENGAGEMENT_SCOPE.reviewed_for) body.push(`<li>${esc(item)}</li>`);
  body.push("</ul><h4>Not reviewed for</h4><ul>");
  for (const item of ENGAGEMENT_SCOPE.not_reviewed_for) body.push(`<li>${esc(item)}</li>`);
  body.push("</ul>");
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
  secondaryFamilies?: ReadonlyArray<ReportSecondaryFamily>,
  consistency?: ConsistencyRun,
  extracted?: ExtractedData,
): Blob {
  return new Blob(
    [
      buildHtmlReport(
        run,
        ingest,
        dkb,
        playbook,
        v9,
        negotiationPosture,
        secondaryFamilies,
        consistency,
        extracted,
      ),
    ],
    { type: "text/html" },
  );
}

/**
 * `/sample-report` — a real Vaulytica result, generated at build time.
 *
 * An attorney deciding whether to trust a tool with a client's document wants
 * to see what it produces first. The page is the results page the tab shows
 * (add-results-page) for a deliberately flawed mutual NDA from the test
 * fixtures: the same analysis, the same model and the same markup, so it can
 * never drift from the product — every build regenerates it. It is shown the
 * way it prints, every item open, because the page carries no script. The only
 * additions are a banner saying what it is, and the head tags a public page
 * needs.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { analyzeFile, loadAccuracyDeps } from "../cli/api.js";
import { abstractOf } from "../cli/artifacts.js";
import { extractAll } from "../../src/extract/index.js";
import { reportLinkForFinding } from "../../src/report/report-link.js";
import {
  buildResultsModel,
  resultsPageHtml,
  rowsHtml,
  signerTest,
  type ResultsModel,
} from "../../src/ui/results-page.js";
import { ORIGIN } from "./seo-pages.js";

/** The fixture the sample is built from, and the name it is shown under. */
export const SAMPLE_SOURCE = "tests/fixtures/contracts/bad-nda.docx";
export const SAMPLE_NAME = "sample-mutual-nda.docx";

const BANNER = `<div style="background:#161b26;border:1px solid #e3b341;border-radius:10px;padding:14px 18px;margin:0 0 24px;font:15px/1.5 ui-sans-serif,-apple-system,sans-serif;color:#c9c6bc">
<strong style="color:#f3efe4">This is a sample report.</strong> It is the page Vaulytica shows for a deliberately flawed mutual NDA from its public test fixtures, with every item opened — the same page you get for your own document. <a href="/" style="color:#e9c05a">Review your document — free →</a>
</div>`;

const HEAD = `<link rel="canonical" href="${ORIGIN}/sample-report" />
<meta name="description" content="A real Vaulytica contract review: what to raise before signing, each item with the clause, the reason, the rule's suggested change and its source. Generated from a sample NDA." />
<meta name="robots" content="index, follow" />
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />`;

/** Add the banner and head tags to a page. Pure. */
export function decorateSampleReport(html: string): string {
  if (!/<\/head>/i.test(html) || !/<body[^>]*>/i.test(html)) {
    throw new Error("sample-report: the report HTML has no <head> or <body>");
  }
  return html
    .replace(/<title>[^<]*<\/title>/i, "<title>Sample Contract Review | Vaulytica</title>")
    .replace(/<\/head>/i, `${HEAD}\n</head>`)
    .replace(/(<body[^>]*>)/i, `$1\n${BANNER}`);
}

/**
 * The page as it prints: every row open, and the controls that need a script
 * (open and close, copy) left out. The toggle stays as the row's heading.
 */
export function staticResultsHtml(model: ResultsModel): string {
  const noted =
    model.observations.length > 0
      ? `<h3 class="results-group">Also noted (${model.observations.length})</h3>` +
        rowsHtml(model.observations, "rp-noted", "results-noted")
      : "";
  return (resultsPageHtml(model) + noted)
    .replace(
      /<button type="button" class="result-row__toggle" aria-expanded="false"[^>]*>/g,
      '<div class="result-row__toggle">',
    )
    .replace(/<\/span><\/button>/g, "</span></div>")
    .replace(/ data-role="result-detail" hidden>/g, ' data-role="result-detail">')
    .replace(/<button type="button" class="btn-link result-copy"[^>]*>[^<]*<\/button>/g, "")
    .replace(/<p class="result-copy-status"[^>]*><\/p>/g, "");
}

/** The site's own stylesheet, so the sample looks exactly like the tab. */
function siteCss(root: string): string {
  const html = readFileSync(resolve(root, "site", "index.html"), "utf8");
  const m = html.match(/<style[^>]*>([\s\S]*?)<\/style>/);
  if (!m) throw new Error("sample-report: could not read the site stylesheet");
  return m[1]!;
}

/** Analyze the sample fixture and write the decorated page. */
export async function writeSampleReport(root: string, outFile: string): Promise<void> {
  const deps = await loadAccuracyDeps();
  const r = await analyzeFile(resolve(root, SAMPLE_SOURCE), {
    deps,
    sourceName: SAMPLE_NAME,
    // The tab scans every uploaded file before it is sent; so does the sample.
    delivery: true,
  });
  const model = buildResultsModel({
    run: r.run,
    abstract: await abstractOf(SAMPLE_NAME, r),
    delivery: r.delivery?.findings,
    isSigner: signerTest(r.ingest.tree, extractAll(r.ingest.tree).parties),
    reportUrl: (f) => reportLinkForFinding(r.run, f),
  });
  const page = `<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sample</title>
<style>${siteCss(root)}
.sample-body { padding: 16px; }
.sample-body > div:first-child { max-width: 760px; margin: 0 auto 24px !important; }
.sample-wrap { max-width: 760px; margin: 0 auto; padding: 0 0 48px; }
.sample-wrap .result-row__toggle { cursor: default; }
.sample-wrap .result-row__toggle::after { content: none; }
</style>
</head><body class="sample-body">
<main class="sample-wrap">
<section class="results-page" aria-label="What to raise">${staticResultsHtml(model)}</section>
</main>
</body></html>
`;
  writeFileSync(outFile, decorateSampleReport(page), "utf8");
}

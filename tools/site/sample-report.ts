/**
 * `/sample-report` — a real Vaulytica report, generated at build time.
 *
 * An attorney deciding whether to trust a tool with a client's document wants
 * to see what it produces first. The page is the unedited HTML report the
 * engine writes for a deliberately flawed mutual NDA from the test fixtures,
 * run through the same CLI a user runs, so it can never drift from the
 * product: every build regenerates it. The only additions are a banner saying
 * what it is, and the head tags a public page needs.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ORIGIN } from "./seo-pages.js";

/** The fixture the sample is built from, and the name it is shown under. */
export const SAMPLE_SOURCE = "tests/fixtures/contracts/bad-nda.docx";
export const SAMPLE_NAME = "sample-mutual-nda.docx";

const BANNER = `<div style="background:#161b26;border:1px solid #e3b341;border-radius:10px;padding:14px 18px;margin:0 0 24px;font:15px/1.5 ui-sans-serif,-apple-system,sans-serif;color:#c9c6bc">
<strong style="color:#f3efe4">This is a sample report.</strong> It is the unedited output Vaulytica produces for a deliberately flawed mutual NDA from its public test fixtures — the same report you get for your own document. <a href="/" style="color:#e9c05a">Review your document — free →</a>
</div>`;

const HEAD = `<link rel="canonical" href="${ORIGIN}/sample-report" />
<meta name="description" content="A real Vaulytica contract review report: every finding quotes the clause, names the rule, and cites its source. Generated from a sample NDA." />
<meta name="robots" content="index, follow" />
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />`;

/** Add the banner and head tags to the engine's HTML report. Pure. */
export function decorateSampleReport(html: string): string {
  if (!/<\/head>/i.test(html) || !/<body[^>]*>/i.test(html)) {
    throw new Error("sample-report: the report HTML has no <head> or <body>");
  }
  return html
    .replace(/<title>[^<]*<\/title>/i, "<title>Sample Contract Review Report | Vaulytica</title>")
    .replace(/<\/head>/i, `${HEAD}\n</head>`)
    .replace(/(<body[^>]*>)/i, `$1\n${BANNER}`);
}

/** Run the CLI on the sample fixture and write the decorated page. */
export function writeSampleReport(root: string, outFile: string): void {
  const dir = mkdtempSync(join(tmpdir(), "vaulytica-sample-"));
  try {
    const input = join(dir, SAMPLE_NAME);
    copyFileSync(resolve(root, SAMPLE_SOURCE), input);
    execFileSync(
      process.execPath,
      [resolve(root, "bin", "vaulytica.mjs"), "analyze", input, "--format", "html", "--out", dir],
      { cwd: root, stdio: "ignore" },
    );
    const html = readFileSync(join(dir, SAMPLE_NAME.replace(/\.docx$/, ".html")), "utf8");
    writeFileSync(outFile, decorateSampleReport(html), "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

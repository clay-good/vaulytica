/**
 * The one report page and the links that lead to it (spec-v53 §4, Step 330).
 *
 * What is held here is the property the design rests on: a contract cannot
 * travel with a report. Context rides in the URL fragment, which is never sent
 * to a server; it is at most a kind and five identifiers the tool chose; a
 * finding from a reader's own playbook gets no link at all; and until an
 * endpoint exists the page sends nothing.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LAUNCH_RULES, V3_RULES, V4_RULES, V5_RULES, V6_RULES } from "../../src/engine/index.js";
import type { Finding } from "../../src/engine/finding.js";
import { buildHtmlReport } from "../../src/report/html.js";
import {
  REPORT_FIELDS,
  REPORT_PAGE_URL,
  parseReportFragment,
  reportLink,
  reportLinkForFinding,
  reportLinkForRun,
  reportLinkForUnmatched,
} from "../../src/report/report-link.js";
import { renderState, select } from "../../src/ui/states.js";
import { analyzeFile, buildBrief, loadAccuracyDeps } from "../../tools/cli/api.js";
import { INSTRUCTIONS } from "../../tools/mcp/text.js";
import { renderReportPage } from "../../tools/site/seo-pages.js";
// The page's own script: a static ES module, imported here exactly as served.
// @ts-expect-error — a hand-written script with no type declarations.
import * as page from "../../site/report.js";

const ROOT = process.cwd();
const NDA = join(ROOT, "tests", "fixtures", "specimens", "mutual-nda-complete.txt");
const RUN = {
  version: "9.867.0",
  dkb_version: "v2026-10-05-local",
  playbook_id: "mutual-nda-deep",
  findings: [] as Finding[],
};
const ALL_RULES = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES];

describe("a link to the report page", () => {
  it("carries its context in the fragment only: a kind and five identifiers", () => {
    const url = new URL(
      reportLinkForFinding(RUN, { rule_id: "NDA-D-019", rule_version: "1.1.0" })!,
    );
    expect(`${url.origin}${url.pathname}`).toBe(REPORT_PAGE_URL);
    // Nothing a server would receive: no query string, no path parameter.
    expect(url.search).toBe("");
    expect(url.hash).toBe(
      "#kind=wrong-finding&rule=NDA-D-019&rv=1.1.0&engine=9.867.0&dkb=v2026-10-05-local&type=mutual-nda-deep",
    );
    expect(Object.keys(parseReportFragment(url.hash)).sort()).toEqual(
      ["dkb", "engine", "kind", "rule", "rv", "type"].sort(),
    );
    expect(REPORT_FIELDS).toHaveLength(7);
  });

  it("can name every rule and every document type in the catalog", () => {
    const types = (
      JSON.parse(readFileSync(join(ROOT, "tools/site/doc-types.json"), "utf8")) as {
        types: Array<{ id: string }>;
      }
    ).types;
    const lost: string[] = [];
    for (const r of ALL_RULES) {
      const ctx = parseReportFragment(new URL(reportLink({ rule: r.id, rv: r.version })).hash);
      if (ctx.rule !== r.id || ctx.rv !== r.version) lost.push(r.id);
    }
    for (const t of [...types.map((x) => x.id), "generic-fallback"]) {
      if (parseReportFragment(new URL(reportLink({ type: t, near: t })).hash).type !== t)
        lost.push(t);
    }
    expect(lost).toEqual([]);
    expect(ALL_RULES.length).toBeGreaterThan(1800);
  });

  it("has no room for prose: a value that is not an id is dropped, on the way out and in", () => {
    const hostile = [
      "This Agreement is governed by the laws of Delaware",
      "Acme%20Corp%20shall%20pay",
      "<script>alert(1)</script>",
      "nda.docx",
      "08fa998384229ccb461e3f3290b30a460f374f45a191fa182c62abedaf2bd93f",
      "a b",
    ];
    for (const value of hostile) {
      // Built with a hostile value: nothing is written.
      expect(reportLink({ rule: value, type: value, near: value, dkb: value })).toBe(
        REPORT_PAGE_URL,
      );
      // A hand-edited link: nothing is read, by the builder's parser or the page's.
      for (const key of ["rule", "rv", "engine", "kind"]) {
        const hash = `#${key}=${value}&excerpt=${value}&note=${value}`;
        expect(parseReportFragment(hash)).toEqual({});
        expect(page.parseFragment(hash)).toEqual({});
      }
    }
    // A document's hash is the right shape for no field at all — SHA-256,
    // SHA-1 or MD5, in either parser.
    for (const length of [64, 40, 32]) {
      const hash = `#type=${"a1".repeat(length / 2)}&near=${"a1".repeat(length / 2)}`;
      expect(parseReportFragment(hash)).toEqual({});
      expect(page.parseFragment(hash)).toEqual({});
    }
  });

  it("is not offered for a reader's own playbook", () => {
    const custom = { rule_id: "MY-001", rule_version: "1.0.0", source: "custom-playbook" as const };
    expect(reportLinkForFinding(RUN, custom)).toBeNull();
    const mixed = { ...RUN, findings: [custom as unknown as Finding] };
    // …nor for any finding of a run that used one, nor for the run itself.
    expect(reportLinkForFinding(mixed, { rule_id: "NDA-D-019", rule_version: "1.1.0" })).toBeNull();
    expect(reportLinkForRun(mixed)).toBeNull();
    expect(reportLinkForRun(RUN, { customPlaybook: true })).toBeNull();
    expect(reportLinkForUnmatched(RUN, "eula", { customPlaybook: true })).toBeNull();
    expect(reportLinkForRun(RUN)).toContain("#engine=9.867.0");
  });

  it("from an unmatched document names the closest type, and never its score", () => {
    const url = reportLinkForUnmatched(RUN, "employment-at-will-us")!;
    expect(url).toBe(
      `${REPORT_PAGE_URL}#kind=wrong-type&engine=9.867.0&dkb=v2026-10-05-local&near=employment-at-will-us`,
    );
    expect(url).not.toMatch(/0\.\d/);
    expect(reportLinkForUnmatched(RUN)).not.toContain("near=");
  });
});

describe("the report page", () => {
  const html = renderReportPage();
  const script = readFileSync(join(ROOT, "site", "report.js"), "utf8");

  it("sends nothing, and says so", () => {
    expect(html).toContain("Nothing on this page is sent anywhere.");
    expect(html).toContain("Do not paste contract text. Describe the clause in your own words.");
    // No form to submit and no button to press: there is nowhere to send to.
    expect(html).not.toMatch(/<form\b|<button\b|type="submit"/i);
    expect(html).toContain('<script type="module" src="/report.js"></script>');
    expect(html).toContain('content="noindex, follow"');
    // The script makes no network call and keeps nothing.
    expect(script).not.toMatch(
      /\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|localStorage|sessionStorage|indexedDB|document\.cookie|\.submit\s*\(/,
    );
    // It is the only script the page loads, and it shares no code with the app.
    expect(html.match(/<script\b/g)).toHaveLength(1);
    expect(script).not.toMatch(/\bimport\b[^;]*from/);
  });

  it("reads a link exactly as the builder wrote it", () => {
    const link = reportLinkForFinding(RUN, { rule_id: "PERS-008", rule_version: "1.3.0" })!;
    const hash = new URL(link).hash;
    expect(page.parseFragment(hash)).toEqual(parseReportFragment(hash));
    expect([...page.FIELDS]).toEqual([...REPORT_FIELDS]);
    for (const r of ALL_RULES.slice(0, 200)) {
      const h = new URL(reportLink({ rule: r.id, rv: r.version, type: "msa-general" })).hash;
      expect(page.parseFragment(h)).toEqual(parseReportFragment(h));
    }
  });

  it("shows the reader exactly what a report would contain", () => {
    document.body.innerHTML = html.slice(html.indexOf("<main"), html.indexOf("</main>") + 7);
    const hash = new URL(reportLinkForFinding(RUN, { rule_id: "PERS-008", rule_version: "1.3.0" })!)
      .hash;
    page.init(document, `${hash}&excerpt=SECRET-CLAUSE-TEXT`);
    const preview = (): string[] =>
      [...document.querySelectorAll("#report-preview li")].map((li) => li.textContent ?? "");
    expect(preview()).toEqual([
      "Kind of problem: wrong-finding",
      "Rule: PERS-008",
      "Rule version: 1.3.0",
      "Engine version: 9.867.0",
      "Knowledge base version: v2026-10-05-local",
      "Document type: mutual-nda-deep",
    ]);
    expect(document.body.textContent).not.toContain("SECRET-CLAUSE-TEXT");
    // The kind the link implies is selected; the reader may change it.
    const checked = document.querySelector<HTMLInputElement>('input[name="report-kind"]:checked')!;
    expect(checked.value).toBe("wrong-finding");
    // A note is shown back as typed — as text, capped — and nothing else changes.
    const note = document.querySelector<HTMLTextAreaElement>("#report-note")!;
    note.value = "<b>The cap is stated twice.</b>";
    note.dispatchEvent(new Event("input"));
    expect(preview().at(-1)).toBe("Your note: <b>The cap is stated twice.</b>");
    expect(document.querySelector("#report-preview b")).toBeNull();
    note.value = "x".repeat(400);
    note.dispatchEvent(new Event("input"));
    expect(preview().at(-1)).toBe(`Your note: ${"x".repeat(page.NOTE_MAX)}`);
    expect(note.getAttribute("maxlength")).toBe(String(page.NOTE_MAX));
  });

  it("opens from a bare address with nothing filled in", () => {
    document.body.innerHTML = html.slice(html.indexOf("<main"), html.indexOf("</main>") + 7);
    page.init(document, "");
    expect(document.querySelector('input[name="report-kind"]:checked')).toBeNull();
    expect(document.querySelector("#report-preview")!.textContent).toContain("Nothing yet");
  });
});

describe("where the link is offered", { timeout: 120_000 }, () => {
  it("once in the HTML report, in the compact report, and from the command line", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(NDA, { deps });
    const report = buildHtmlReport(r.run, r.ingest, deps.dkb);
    expect(report.split(`${REPORT_PAGE_URL}#`).length - 1).toBe(2); // the href and its text
    expect(report).toContain("Report a problem");
    expect(buildBrief(r).report_url).toBe(reportLinkForRun(r.run));
    expect(INSTRUCTIONS).toMatch(/never sends a report itself/);

    const cli = spawnSync(
      process.execPath,
      [join(ROOT, "bin", "vaulytica.mjs"), "analyze", NDA, "--format", "brief-json"],
      { encoding: "utf8", timeout: 100_000 },
    );
    expect(cli.stderr.split(REPORT_PAGE_URL)).toHaveLength(2);
  });

  it("in the Word report's audit trail, by the same builder", () => {
    const docx = readFileSync(join(ROOT, "src", "report", "docx.ts"), "utf8");
    expect(docx).toMatch(/reportLinkForRun\(run\)/);
    expect(docx.indexOf("reportLinkForRun(run)")).toBeGreaterThan(
      docx.indexOf('h1("Audit Trail")'),
    );
  });

  it("in the tab: under the result, and on the unmatched notice", () => {
    const base = {
      kind: "complete" as const,
      filename: "x.pdf",
      playbook_name: "Generic Fallback",
      counts: { critical: 0, warning: 1, info: 3 },
      docx_blob: new Blob(["docx"]),
      json_blob: new Blob(["{}"]),
      docx_filename: "x.docx",
      json_filename: "x.json",
    };
    const dz = document.createElement("div");
    renderState(dz, {
      ...base,
      report_url: reportLinkForRun(RUN)!,
      classification_notice: {
        message: "No known document family matched this document.",
        report_url: reportLinkForUnmatched(RUN, "eula")!,
      },
    });
    const result = select(dz, "report-link")!;
    expect(result.hasAttribute("hidden")).toBe(false);
    expect(result.querySelector("a")!.getAttribute("href")).toBe(reportLinkForRun(RUN));
    expect(result.querySelector("a")!.getAttribute("rel")).toBe("noopener noreferrer");
    const notice = select(dz, "classification-notice")!;
    expect(notice.textContent).toContain("What kind of document is this?");
    expect(notice.querySelector("a")!.getAttribute("href")).toContain("near=eula");

    // With a custom playbook loaded the state carries no link, and none is shown.
    const custom = document.createElement("div");
    renderState(custom, {
      ...base,
      classification_notice: { message: "No known document family matched this document." },
    });
    expect(select(custom, "report-link")!.hasAttribute("hidden")).toBe(true);
    expect(select(custom, "classification-notice")!.querySelector("a")).toBeNull();
  });
});

/**
 * Wherever a caveat's SUBJECT is rendered, the caveat must be rendered too.
 *
 * `secondary-family-cap-caveat.test.ts` proves each surface says the number
 * when it is handed one. This asks the prior question: is there a surface
 * nobody hands it to? That is how the caveat reached exactly one consumer for
 * as long as it did — every individual renderer was correct on its own terms,
 * and the SET of renderers was never enumerated.
 *
 * The bundle's consolidated DOCX was the last one: it carried the "Also
 * checked" list and the "detected, not confirmed" caveat, the bundle JSON had
 * carried the omitted count since 9.567.0, and the artifact a reviewer actually
 * reads showed a truncated list as if it were the whole set.
 *
 * A file that renders the list and says nothing about the cap fails here. Add a
 * declared exception with a reason if one is ever genuinely right.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();

/** Every non-test `.ts` under a directory, recursively, POSIX-separated. */
function sources(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : 1,
  )) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...sources(p));
    else if (e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

/**
 * A file RENDERS the list when it walks the families to produce output — the
 * heading a reader sees is the reliable tell, and it is the same phrase in
 * every surface ("Additional Checks From Other Detected Families" /
 * "additional checks from other detected families" / "Also checked").
 */
const RENDER_MARKERS = [/other detected families/i, /Also checked \(/, /Also checked: /];

/**
 * Comments are stripped before the scan.
 *
 * 🚨 Twice in this repo a source-scanning guard has been fooled by a quoted
 * phrase inside a comment, and this one was too on its first run:
 * `playbook-candidates.ts` DOCUMENTS the section it feeds ("these drive the
 * report's 'additional checks from other detected families'") without rendering
 * anything. A guard that reads comments is reading documentation, not code.
 *
 * The markers are narrowed for the same reason: a bare /Also checked/ matched
 * the empty-state copy's "drop a pair and they are also checked against each
 * other", which is about cross-document checks and not this list at all.
 */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/**
 * Import lines are stripped too, for the same reason comments are: an
 * `import { cappedFamiliesNotice }` left behind by a deleted call site is a
 * mention, not a render. (Lint would eventually flag the unused import — but a
 * guard that depends on a *different* guard firing first is not a guard.)
 */
function scannable(src: string): string {
  return stripComments(src).replace(/^import\s[\s\S]*?from\s+"[^"]+";$/gm, "");
}

/**
 * Saying the cap: the shared sentence, or the phrase every short form of it
 * carries.
 *
 * 🚨 This first accepted `secondary_families_omitted` / `secondaryFamiliesOmitted`
 * as evidence — and a file that merely DECLARES the field passes that. Proven:
 * the bundle's notice was deleted and the guard stayed green, because
 * `BundleDocument` still declares the field two hundred lines away. Evidence of
 * a caveat has to be evidence of RENDERING one. `cappedFamiliesNotice` is the
 * single owner of the long form; "NOT scanned" is the phrase the compact form
 * on the multi-document card shares with it, so the two cannot say opposite
 * things about whether anything was skipped.
 */
const STATES_CAP = [/cappedFamiliesNotice/, /NOT scanned/];

const DECLARED = new Map<string, string>();

describe("the secondary-family cap is stated by every renderer of the list", () => {
  it("derives a plausible surface (guards the derivation itself)", () => {
    const files = [...sources("src/report"), ...sources("src/ui"), ...sources("tools/cli")];
    expect(files.length).toBeGreaterThan(40);
    const renderers = files.filter((f) =>
      RENDER_MARKERS.some((re) => re.test(scannable(readFileSync(join(ROOT, f), "utf8")))),
    );
    // Four today: the report DOCX and HTML, the browser tab, and the bundle.
    // An empty set would make the assertion below vacuous.
    expect(renderers.length).toBeGreaterThanOrEqual(4);
    expect(renderers).toContain("src/report/bundle.ts");
    expect(renderers).toContain("src/ui/states.ts");
  });

  it("no renderer shows the list without saying how much of it is missing", () => {
    const files = [...sources("src/report"), ...sources("src/ui"), ...sources("tools/cli")];
    const silent: string[] = [];
    for (const f of files) {
      const src = scannable(readFileSync(join(ROOT, f), "utf8"));
      if (!RENDER_MARKERS.some((re) => re.test(src))) continue;
      if (STATES_CAP.some((re) => re.test(src))) continue;
      if (DECLARED.has(f)) continue;
      silent.push(f);
    }
    expect(
      silent,
      `these render the "also checked" list and never say the cap truncated it:\n  ${silent.join(
        "\n  ",
      )}`,
    ).toEqual([]);
  });
});

/**
 * The attorney-review caveat: "N of M findings cite a rule whose legal basis a
 * licensed attorney has signed off on" — at the current zero state, "0 of M …
 * every rule applied here is author-asserted."
 *
 * It is the most load-bearing sentence this tool emits, and it reached the DOCX
 * and HTML reports only. The BROWSER TAB — where a user drops a document and
 * reads three severity counts — said nothing. Neither did SARIF, which is what
 * a code-scanning dashboard shows a reviewer who never opens the Word file, nor
 * the consolidated bundle report a portfolio reviewer reads.
 *
 * Same rule as above, one layer out: a surface that renders FINDING COUNTS owes
 * the reader what those findings rest on.
 */
describe("the attorney-review caveat reaches every surface that reports findings", () => {
  const SURFACES = [
    "src/report/docx.ts",
    "src/report/html.ts",
    "src/report/json.ts",
    "src/report/sarif.ts",
    "src/report/bundle.ts",
    "src/ui/main.ts",
  ];

  it("each one computes or emits the coverage", () => {
    const missing = SURFACES.filter((f) => {
      const src = scannable(readFileSync(join(ROOT, f), "utf8"));
      return !/buildReviewCoverage|review_coverage|reviewCoverageSentence/.test(src);
    });
    expect(
      missing,
      `these report findings and never say what the findings rest on:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the tab renders it, not just computes it", () => {
    // `src/ui/main.ts` builds the sentence and `states.ts` is what puts it on
    // screen; a value computed and never rendered is the exact shape of the
    // defect this file exists for.
    const states = scannable(readFileSync(join(ROOT, "src/ui/states.ts"), "utf8"));
    expect(states).toMatch(/review-coverage/);
    expect(states).toMatch(/renderReviewCoverage\(/);
  });
});

/**
 * The crashed-rule notice: *"N rules could not be evaluated ... this document
 * was NOT checked against them. Treat the corresponding area as unreviewed."*
 *
 * Third instance of the same shape in this file, and the worst of the three:
 * the other two qualify a number, this one reports a HOLE. It reached the two
 * Word reports and nothing else — so a CI job gating on SARIF, a reader handed
 * the print-clean HTML, and a user watching the tab all saw a clean run.
 *
 * `errored-rule-reach.test.ts` proves each surface says it and that none says
 * it when nothing threw; this asserts the SET of surfaces, so a new one cannot
 * be added without it.
 */
describe("the crashed-rule notice reaches every surface that reports a run", () => {
  const SURFACES = [
    "src/report/docx.ts",
    "src/report/html.ts",
    "src/report/json.ts",
    "src/report/sarif.ts",
    "src/report/bundle.ts",
    "src/ui/main.ts",
  ];

  it("each one emits the notice", () => {
    const missing = SURFACES.filter(
      (f) => !/erroredRuleNotice/.test(scannable(readFileSync(join(ROOT, f), "utf8"))),
    );
    expect(
      missing,
      `these report a run and never say a rule crashed:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the tab renders it, not just computes it", () => {
    const states = scannable(readFileSync(join(ROOT, "src/ui/states.ts"), "utf8"));
    expect(states).toMatch(/rule-errored/);
    expect(states).toMatch(/renderRuleErrored\(/);
  });
});

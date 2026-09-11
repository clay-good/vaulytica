/**
 * Every surface that renders findings must also render the two caveats that
 * qualify them.
 *
 * The engine has two ways of saying "read this with care", and both are facts
 * about the ANALYSIS rather than about the contract:
 *
 *  - `run.classification_notice` — no document family matched, so only the
 *    generic lint ran, and "the findings below may be irrelevant or misleading
 *    for a document that is not a contract";
 *  - `IngestResult.warnings` — what the ingest could and could not READ: a
 *    redline taken as all-changes-accepted, a PDF that fell back to OCR,
 *    pasted text that lost its structure.
 *
 * They are the easiest thing in the tree to leave out, because a surface is
 * built to show findings and a caveat is not one. `IngestResult.warnings` was
 * composed from the beginning and read by NO consumer anywhere until session
 * 29. Session 30 found both missing from the bundle CARD. Session 32 found
 * them missing from three more: the CLI terminal — where a bread recipe
 * printed `[generic-fallback]  1C 2W 1I` and nothing else — the bundle DOCX's
 * per-document subsection, and (as a roll-up) the SARIF.
 *
 * So this is a reach test, not a rendering test. It asserts only that each
 * surface READS both fields; what it does with them is that surface's business
 * and its own tests' subject. A new render surface must join this list, which
 * is the point: the list is where the omission becomes visible.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Every module that turns a run into something a person or a pipeline reads. */
const FINDING_SURFACES: ReadonlyArray<[file: string, what: string]> = [
  ["src/report/json.ts", "the JSON report"],
  ["src/report/docx.ts", "the DOCX report"],
  ["src/report/html.ts", "the standalone HTML report"],
  ["src/report/sarif.ts", "the SARIF (CI) surface"],
  ["src/report/bundle.ts", "the bundle report"],
  ["src/report/exports.ts", "the Markdown fix list"],
  ["tools/cli/run.ts", "the CLI's terminal output"],
  ["src/ui/states.ts", "the in-tab result states"],
  // 🚨 Joined in 9.706.0, having rendered findings since the feature shipped
  // without either caveat. It is a byte-copy of the CLIENT'S OWN CONTRACT with
  // review comments inserted, and its comments quote Chancery practice and the
  // Restatement — the surface most likely to be forwarded to someone who did
  // not run the tool, and the only one that said nothing about what it is.
  // The docstring above says a new render surface must join this list; this
  // one never did, which is exactly how it was missed.
  ["src/report/docx-comments.ts", "the anchored-comments reviewed DOCX"],
];

/**
 * The reach test above is at FILE granularity, and `src/report/exports.ts`
 * builds seven artifacts. It passed because the fix list read both fields
 * while the register, the closing checklist and the negotiation posture — each
 * separately obtainable as its own file — did not. A guard satisfied by one
 * artifact inside a file says nothing about the other six.
 *
 * So this one is at BUILDER granularity: every Markdown artifact a person can
 * receive as a file must take an `ArtifactCaveats` and render it. A `.csv` or
 * an `.ics` is deliberately out — there is no honest place for prose in either,
 * and the caveat reaches whoever ran the command on stderr.
 */
describe("every prose artifact accepts the caveats", () => {
  /** Builder → the file it is declared in. Markdown and HTML alike. */
  const PROSE_BUILDERS: Record<string, string> = {
    buildFixListMarkdown: "src/report/exports.ts",
    buildCriticalDatesMarkdown: "src/report/exports.ts",
    buildClosingChecklistMarkdown: "src/report/exports.ts",
    buildNegotiationPostureMarkdown: "src/report/exports.ts",
    // HTML is prose too, and this one is the sheet a negotiator carries into a
    // call — separately obtainable as a file via `--format posture-sheet`.
    buildNegotiationSheet: "src/report/negotiation-sheet.ts",
  };

  it("names every Markdown builder in exports.ts", () => {
    const src = readFileSync(join(process.cwd(), "src/report/exports.ts"), "utf8");
    const found = [...src.matchAll(/export function (build\w*Markdown)\(/g)].map((m) => m[1]!);
    expect(
      found.filter((f) => !(f in PROSE_BUILDERS)),
      "a new Markdown artifact must join this list and take the caveats",
    ).toEqual([]);
  });

  it("each one takes the caveats and the CLI hands them over", () => {
    const cli = readFileSync(join(process.cwd(), "tools/cli/run.ts"), "utf8");
    const missing: string[] = [];
    for (const [fn, file] of Object.entries(PROSE_BUILDERS)) {
      const src = readFileSync(join(process.cwd(), file), "utf8");
      // The fix list takes the whole IngestResult, which is where its two
      // fields come from; the other three take an ArtifactCaveats.
      const sig = new RegExp(`export function ${fn}\\(([^)]*)\\)`, "s").exec(src);
      if (!sig) {
        missing.push(`${fn}: not found`);
        continue;
      }
      if (!/caveats\??:|ingest\??:/.test(sig[1]!)) missing.push(`${fn}: takes no caveats`);
      // And the CLI must actually pass them, or the parameter is decoration.
      const call = new RegExp(`${fn}\\([^;]*?(caveats|r\\.ingest)`, "s");
      if (!call.test(cli)) missing.push(`${fn}: the CLI never passes them`);
    }
    expect(missing).toEqual([]);
  });
});

describe("the honesty caveats reach every findings surface", () => {
  it("each surface reads the classification notice", () => {
    const missing: string[] = [];
    for (const [file, what] of FINDING_SURFACES) {
      const src = readFileSync(join(process.cwd(), file), "utf8");
      if (!/classification_notice/.test(src)) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface renders findings without the notice that says they may not apply",
    ).toEqual([]);
  });

  it("each surface reads the ingest's warnings", () => {
    const missing: string[] = [];
    for (const [file, what] of FINDING_SURFACES) {
      const src = readFileSync(join(process.cwd(), file), "utf8");
      // `warnings` as a property read or a parameter — never a comment.
      const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");
      if (!/\bwarnings\b/.test(code)) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface renders findings without saying what the ingest could not read",
    ).toEqual([]);
  });

  it("detects a surface that drops one", () => {
    // The guard is only worth its runtime if it fails on the real shape of the
    // defect. A file that renders findings and mentions neither field is
    // exactly what every one of the four historical misses looked like.
    const src = "export function render(run) { return run.findings.map(f => f.title); }";
    expect(/classification_notice/.test(src)).toBe(false);
    expect(/\bwarnings\b/.test(src)).toBe(false);
  });
});

/**
 * The THIRD caveat, and the rule that keeps it honest: a surface that shows the
 * overlays has to show the gap in them.
 *
 * `StateOverlayResult.uncovered_states` is the same kind of fact as the two
 * above — about the ANALYSIS, not the contract. A document names North Dakota,
 * the catalog has no North Dakota overlay for that family, and the card must
 * say *"an honest coverage gap, not a clean pass"*, because silence there is
 * indistinguishable from "we checked and it is fine."
 *
 * The rule is conditional rather than universal, and deliberately so. Measured
 * 2026-09-09 across the eight surfaces above: four render overlays at all — the
 * JSON report (which emits the whole `StateOverlayResult`, gap included), the
 * DOCX, the standalone HTML and the in-tab card. **SARIF, the bundle report,
 * the Markdown fix list and the CLI's terminal output render no overlay of any
 * kind**, so for them the gap does not arise; adding overlays to SARIF — the
 * surface a CI pipeline actually reads — is a product decision, recorded rather
 * than guessed at.
 *
 * So: whoever shows the good news shows the gap with it.
 */
describe("a surface that renders jurisdiction overlays renders their coverage gap", () => {
  /**
   * The three surfaces that WRITE the gap into their own prose. The JSON
   * report is deliberately not here: it emits the whole `StateOverlayResult`
   * object, so the gap rides along structurally and its own name never appears
   * in the file. Structural pass-through is a render — it just cannot be shown
   * by a grep, so the JSON is asserted behaviourally below.
   */
  const OVERLAY_SURFACES: ReadonlyArray<[file: string, what: string]> = [
    ["src/report/docx.ts", "the DOCX report"],
    ["src/report/html.ts", "the standalone HTML report"],
    ["src/ui/states.ts", "the in-tab result states"],
    ["src/report/sarif.ts", "the SARIF (CI) surface"],
    ["tools/cli/run.ts", "the CLI's terminal output"],
  ];

  /** Comments are documentation, not rendering. */
  const code = (file: string): string =>
    readFileSync(join(process.cwd(), file), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");

  it("names the surfaces that actually render an overlay", () => {
    // Anti-vacuity: if a surface stopped rendering overlays entirely this list
    // would be wrong, and the guard below would pass by rendering nothing.
    for (const [file, what] of OVERLAY_SURFACES) {
      expect(/matched\b/.test(code(file)), `${what} no longer reads the matched overlays`).toBe(
        true,
      );
    }
  });

  it("every one of them also reads uncovered_states", () => {
    const missing: string[] = [];
    for (const [file, what] of OVERLAY_SURFACES) {
      if (!/uncovered_states/.test(code(file))) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface shows which states the catalog covers and stays silent about the ones it does not",
    ).toEqual([]);
  });

  it("the JSON report carries the gap in its output, not just in its type", async () => {
    const { selectStateOverlays } = await import("../../src/dkb/state-overlays.js");
    // A governing-law state the catalog has no non-compete overlay for. If the
    // corpus's own catalog ever covers every state this falls back to
    // asserting the field's presence, which is still the property that matters.
    const overlays = selectStateOverlays("employment-at-will-us", [
      { state: "us-nd", raw_text: "governed by the laws of the State of North Dakota" },
    ] as never);
    expect(overlays, "the selector produced nothing to assert on").not.toBeUndefined();
    expect(
      Object.keys(overlays ?? {}),
      "the overlay result stopped carrying its coverage gap",
    ).toContain("uncovered_states");
  });

  it("the two surfaces that render no overlay are still the two", () => {
    // Not a prohibition — a record. If one of these grows an overlay section,
    // this test fails and the author has to add it to OVERLAY_SURFACES above,
    // which is what puts the gap question in front of them.
    //
    // Measured 2026-09-09, so the next reader does not have to re-open it: the
    // BUNDLE report is not the same kind of omission as SARIF was. Its
    // per-document subsections are a capped SUMMARY, and the per-document DOCX
    // and JSON that ride in the same package carry the overlays in full — a
    // bundle user does get them. SARIF had no artifact that carried them at all.
    for (const [file, what] of [
      ["src/report/bundle.ts", "the bundle report"],
      ["src/report/exports.ts", "the Markdown fix list"],
    ] as const) {
      expect(
        /selectStateOverlays|jurisdiction_overlays/.test(code(file)),
        `${what} now renders overlays — add it to OVERLAY_SURFACES and give it the gap`,
      ).toBe(false);
    }
  });
});

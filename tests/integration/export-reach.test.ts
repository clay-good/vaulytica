/**
 * Every report artifact the browser can produce, the CLI must be able to
 * produce too.
 *
 * The builders in `src/report/` are pure functions: give one a run and it
 * returns a string. Both surfaces call the same ones — the browser wraps the
 * string in a `Blob` for a download, the CLI writes it to a file. So a builder
 * with a browser caller and no headless caller is an artifact that exists,
 * ships, is tested, is advertised in the README, and **cannot be obtained from
 * a script**.
 *
 * Nine of them were in exactly that state until 9.532.0–9.533.0: the closing
 * checklist (Markdown, CSV), the critical-dates register (Markdown, `.ics`),
 * the obligations ledger, the v6 deadlines calendar, the negotiation posture
 * (Markdown, CSV, and the standalone sheet), and the defined-terms CSV. Nothing
 * could notice, because each half was correct on its own terms.
 *
 * 🥇 Giving one of them its first real caller is what surfaced a second defect:
 * `buildDefinitionsCsv` ended its rows with bare LF, the only CSV in the tree
 * that did. A `Blob` handed to a browser download is never split on a line
 * ending, so the browser could not have noticed either.
 *
 * This is a REACH test: it asserts a headless caller exists, not what it does
 * with the result. A new report builder wired into the UI has to be wired into
 * `tools/` as well, or declared here with the reason.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const read = (p: string): string => readFileSync(join(ROOT, p), "utf8");

/** Every `.ts` under `src/report/` (recursively), POSIX-separated. */
function reportSources(dir = "src/report"): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(ROOT, dir), { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : 1,
  )) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...reportSources(p));
    else if (e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

/**
 * Builders that RENDER an artifact.
 *
 * 🚨 This matched `export function build*` only, so every `export **async**
 * function build*` was invisible to the whole guard — including
 * `buildDocxReport`, the **full attorney-facing report**, the artifact this
 * tool's output is shaped around. It was browser-only from the day the CLI
 * existed until 9.570.0, and the test written to make exactly that impossible
 * could not see it. A sweep's blind spot is not a gap in the thing it sweeps.
 */
function artifactBuilders(): string[] {
  const names = new Set<string>();
  for (const file of reportSources()) {
    for (const m of read(file).matchAll(/^export (?:async )?function (build[A-Za-z0-9]+)\s*\(/gm)) {
      names.add(m[1]!);
    }
  }
  return [...names].sort();
}

/**
 * builder → the `*Blob` wrapper names that call it.
 *
 * 🚨 This map is what keeps the test from being VACUOUS, and the first draft
 * did not have it. The browser never names a builder: it downloads files, so it
 * calls `obligationsCsvBlob`, not `buildObligationsCsv`. Without the mapping,
 * `calls(browserSource, builder)` was false for nearly every builder, the
 * "browser-called" set was almost empty, and the assertion passed no matter
 * what — proven by deleting the CLI's `buildObligationsCsv` call and watching
 * it stay green.
 *
 * Read from the wrapper bodies rather than derived from the name, so a wrapper
 * that does not follow the naming convention still counts.
 */
function blobWrappersByBuilder(): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const builders = artifactBuilders();
  for (const file of reportSources()) {
    const src = read(file);
    for (const m of src.matchAll(/^export function ([a-zA-Z0-9]+Blob)\s*\([^)]*\)[^{]*\{/gm)) {
      const start = m.index! + m[0].length;
      const body = src.slice(start, start + 600);
      const end = body.indexOf("\n}");
      const inner = end === -1 ? body : body.slice(0, end);
      for (const b of builders) {
        if (new RegExp(`\\b${b}\\b`).test(inner)) {
          out.set(b, [...(out.get(b) ?? []), m[1]!]);
        }
      }
    }
  }
  return out;
}

const browserSource = ["src/ui/pipeline.ts", "src/ui/states.ts", "src/ui/main.ts"]
  .map(read)
  .join("\n");
const headlessSource = readdirSync(join(ROOT, "tools", "cli"))
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
  .sort()
  .map((f) => read(`tools/cli/${f}`))
  .join("\n");

/**
 * Declared, with the reason. Each entry is asserted to be USED below, so a
 * stale exception fails here rather than sitting unnoticed — the same rule the
 * recognizer sweeps follow.
 */
const DECLARED: ReadonlyMap<string, string> = new Map([
  [
    "buildSarifJson",
    // A one-line wrapper: `JSON.stringify(buildSarif(...), null, 2)`. The CLI
    // deliberately calls `buildSarif` instead, because it needs the LOG OBJECT
    // to run `sarifConformanceViolations` over it before writing — SARIF is
    // the artifact the Action uploads and a malformed one is dropped silently
    // by GitHub Code Scanning, so the self-check has to happen on the way out.
    // The artifact itself is fully reachable: `--format sarif`.
    "a stringify wrapper; the CLI calls buildSarif directly so it can self-check the log first",
  ],
  [
    "buildComparisonJson",
    "belongs to the compare command, which reaches it through runCompare's own renderer",
  ],
  [
    "buildClauseEvidence",
    // Same shape as `buildReviewCoverage` below: a projection of the findings
    // that the artifact builders embed, not a downloadable artifact. The tab
    // names it to render the sentence under the counts; a script obtains the
    // same numbers in the JSON report's `clause_evidence` and in SARIF's
    // attorney-review result properties.
    "a projection helper, not a downloadable artifact; headless callers reach it inside buildJsonReport and buildSarif",
  ],
  [
    "buildReviewCoverage",
    // Not an artifact — a pure projection of `run.findings` that the artifact
    // builders embed. The tab names it directly (it renders the sentence under
    // the counts); a script obtains the same numbers inside SARIF's
    // VAULYTICA-ATTORNEY-REVIEW-COVERAGE result and the bundle JSON's
    // `review_coverage`, so there is nothing here a script cannot get.
    "a projection helper, not a downloadable artifact; headless callers reach it inside buildSarif and buildBundleJson",
  ],
]);

/**
 * Browser-only builders that are a KNOWN GAP, not an exemption.
 *
 * The difference matters. `DECLARED` above says "this is fine, here is why".
 * This says "this is a real gap, it is counted, and it will be closed" — and
 * the assertion below pins the list by EQUALITY, so the set can only shrink
 * deliberately. Adding a name here is a decision someone has to make on the
 * record; it is not a way to make a red test green.
 *
 * It held four entries for one release. All four became visible in 9.570.0
 * when this file learned to see `export async function` (it had matched
 * `export function` only, which is why `buildDocxReport` — the full
 * attorney-facing report — was browser-only from the day the CLI existed and
 * nothing noticed): the bundle DOCX, bundle JSON and bundle zip, plus the
 * comparison DOCX. All four were closed in 9.571.0 (`--format
 * bundle-json|bundle-docx|bundle-zip` and `compare --format docx`), so the
 * list is empty — which is the state it is supposed to be in.
 */
const KNOWN_GAPS: readonly string[] = [];

function calls(source: string, name: string): boolean {
  return new RegExp(`\\b${name}\\b`).test(source);
}

/**
 * A builder is browser-reachable when the UI names it OR names a `*Blob`
 * wrapper around it — the browser's normal route, since it downloads files.
 */
function browserReachable(): string[] {
  const wrappers = blobWrappersByBuilder();
  return artifactBuilders().filter(
    (b) => calls(browserSource, b) || (wrappers.get(b) ?? []).some((w) => calls(browserSource, w)),
  );
}

describe("report-artifact reach: browser and headless", () => {
  it("derives a plausible surface (guards the derivation itself)", () => {
    // An empty list — or a browser-reachable set of one — would make the
    // assertion below vacuously true. It was, before the Blob mapping landed.
    const builders = artifactBuilders();
    expect(builders.length).toBeGreaterThan(15);
    expect(builders).toContain("buildFixListMarkdown");
    expect(browserSource.length).toBeGreaterThan(10_000);
    expect(headlessSource.length).toBeGreaterThan(10_000);
    const wrappers = blobWrappersByBuilder();
    expect(wrappers.get("buildObligationsCsv")).toContain("obligationsCsvBlob");
    expect(browserReachable().length).toBeGreaterThan(10);
  });

  it("every builder the browser calls is also reachable from the CLI", () => {
    const unreachable = browserReachable().filter(
      (b) => !calls(headlessSource, b) && !DECLARED.has(b) && !KNOWN_GAPS.includes(b),
    );
    expect(
      unreachable,
      `these render an artifact the browser can download and a script cannot obtain:\n  ${unreachable.join(
        "\n  ",
      )}\nWire each into tools/cli (a --format value, or an existing one), or declare it here with the reason.`,
    ).toEqual([]);
  });

  it("the known-gap list is exactly what the tree still has", () => {
    // Pinned by EQUALITY in both directions. A new browser-only builder cannot
    // slip in under this list, and a gap that gets closed must be deleted from
    // it rather than left as a stale claim about the tree.
    const stillBrowserOnly = browserReachable().filter((b) => !calls(headlessSource, b));
    expect(
      stillBrowserOnly.filter((b) => !DECLARED.has(b)).sort(),
      "a report builder is browser-only — wire it into tools/, or add it to KNOWN_GAPS deliberately",
    ).toEqual([...KNOWN_GAPS].sort());
  });

  it("every declared exception is actually used", () => {
    // An exception matching nothing is indistinguishable from one that is
    // doing work, and it outlives the reason it was written for.
    const builders = new Set(artifactBuilders());
    for (const [name, why] of DECLARED) {
      expect(builders.has(name), `declared exception "${name}" is not a report builder`).toBe(true);
      expect(
        browserReachable().includes(name) && !calls(headlessSource, name),
        `declared exception "${name}" (${why}) is no longer browser-only — delete the entry`,
      ).toBe(true);
    }
  });
});

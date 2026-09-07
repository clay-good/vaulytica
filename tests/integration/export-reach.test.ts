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
 * Builders that RENDER an artifact — `build*` returning a string.
 */
function artifactBuilders(): string[] {
  const names = new Set<string>();
  for (const file of reportSources()) {
    for (const m of read(file).matchAll(/^export function (build[A-Za-z0-9]+)\s*\(/gm)) {
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
    "buildComparisonJson",
    "belongs to the compare command, which reaches it through runCompare's own renderer",
  ],
]);

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
      (b) => !calls(headlessSource, b) && !DECLARED.has(b),
    );
    expect(
      unreachable,
      `these render an artifact the browser can download and a script cannot obtain:\n  ${unreachable.join(
        "\n  ",
      )}\nWire each into tools/cli (a --format value, or an existing one), or declare it here with the reason.`,
    ).toEqual([]);
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

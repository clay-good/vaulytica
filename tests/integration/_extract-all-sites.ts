/**
 * Find `extractAll` call sites and say which ones omit the jurisdiction lookup.
 *
 * ONE scanner, used by both guards that need it — the product sweep over `src/`
 * and `tools/`, and the harness sweep over the tests whose output is committed,
 * compared across surfaces, or rendered into a report. Two scanners for one
 * question would drift, and the drift would be invisible: a scanner that misses
 * a call shape reports zero problems, which reads exactly like success.
 *
 * 🚨 That is not hypothetical. The first version of the product sweep was a
 * regex requiring an options object, so `extractAll(tree)` with no second
 * argument matched nothing — and unwiring a real call site left the guard
 * GREEN. Every call shape below is here because something was missed.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export type CallSite = { file: string; args: string; wired: boolean };

/** Every `.ts` under `dir`, POSIX-separated. `tests` keeps its test files. */
export function sourcesUnder(root: string, dir: string, opts: { includeTests: boolean }): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(root, dir), { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : 1,
  )) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === "dist" || e.name === "coverage") continue;
      out.push(...sourcesUnder(root, p, opts));
    } else if (e.name.endsWith(".ts")) {
      if (!opts.includeTests && e.name.endsWith(".test.ts")) continue;
      out.push(p);
    }
  }
  return out;
}

/**
 * Scan one file's source for `extractAll(` calls, with balanced delimiters.
 *
 * Skipped, each for a reason that cost something to learn:
 * - a longer identifier ending in the name, and a member call
 * - **but not a spread** (`...extractAll(`), which IS a call — the member-call
 *   rule swallowed it, and that hid the one in `html-report-content-parity`
 * - the declaration in `src/extract/index.ts`, which is the function itself
 * - a string literal, so a scanner can read ITSELF without finding its needle
 * - a comment, because prose naming `extractAll(tree)` to explain the bare form
 *   is not a call; two of three hits on one run were JSDoc, one of it written
 *   in the very change that added the scan
 */
export function callSitesIn(file: string, src: string): CallSite[] {
  const out: CallSite[] = [];
  const needle = "extractAll(";
  for (let i = src.indexOf(needle); i !== -1; i = src.indexOf(needle, i + 1)) {
    const before = src[i - 1];
    if (before !== undefined) {
      if (before === '"' || before === "'" || before === "`") continue;
      // A member call (`x.extractAll(`) is not ours; a spread (`...extractAll(`)
      // is. Both end in a dot, so look one further back.
      if (before === ".") {
        if (src[i - 2] !== ".") continue;
      } else if (/[A-Za-z0-9_$]/.test(before)) {
        continue;
      }
    }
    const lineStart = src.lastIndexOf("\n", i) + 1;
    const linePrefix = src.slice(lineStart, i);
    if (/\bfunction\s+$/.test(linePrefix)) continue;
    const trimmed = linePrefix.trimStart();
    if (trimmed.startsWith("*") || trimmed.startsWith("//")) continue;

    let depth = 0;
    let j = i + needle.length - 1;
    for (; j < src.length; j++) {
      const c = src[j]!;
      if (c === "(" || c === "{" || c === "[") depth++;
      else if (c === ")" || c === "}" || c === "]") {
        depth--;
        if (depth === 0) break;
      }
    }
    const args = src.slice(i + needle.length, j);
    out.push({ file, args, wired: /jurisdictionLookup\s*:/.test(args) });
  }
  return out;
}

/** Scan a set of files. */
export function callSites(root: string, files: string[]): CallSite[] {
  return files.flatMap((f) => callSitesIn(f, readFileSync(join(root, f), "utf8")));
}

/** Report artifact builders — a file that calls one RENDERS something a user reads. */
const RENDERS =
  /\bbuild(?:Docx|Html|Json|Sarif|FixList|Obligations|Deadlines|Definitions|Abstract|Bundle|CriticalDates|ClosingChecklist|Negotiation)[A-Za-z]*\s*\(/;

/**
 * Why a test harness is held to the product's extraction options.
 *
 * Not every harness is: `tests/` holds ~90 `extractAll` calls and most are unit
 * fixtures asserting things jurisdictions have nothing to do with. Requiring
 * the option there would be churn with no reader. These three reasons are the
 * ones where omitting it changes what the harness proves.
 */
export function harnessReasons(src: string, inheritsCommitted = false): string[] {
  const why: string[] = [];
  // Its output is COMMITTED. A pin built from inputs the product never produces
  // enshrines an artifact no user receives.
  if (src.includes("VAULYTICA_REGEN_GOLDEN") || inheritsCommitted) why.push("committed output");
  // It RENDERS a report. This is where a missing option becomes a wrong cell —
  // the DOCX jurisdiction column printed "—" in every report ever exported.
  if (RENDERS.test(src)) why.push("renders a report artifact");
  // It READS the field. An assertion over a field the harness never populates
  // compares one empty string to another and passes forever.
  if (src.includes("jurisdiction_id")) why.push("asserts on jurisdiction_id");
  return why;
}

/**
 * Files a REGEN-gated test imports locally, which inherit its committed-output
 * reason.
 *
 * 🚨 Without this the rule had a hole, and proving the guard by failing is what
 * found it: the `VAULYTICA_REGEN_GOLDEN` gate sits in `golden.test.ts` while
 * the extraction happens in its `_pipeline.ts` helper, so unwiring the helper
 * left the sweep GREEN. The gate and the extraction are in different files, and
 * the reason belongs to both. One level of local imports is enough for the
 * three golden pipelines here; a deeper chain would need a real resolver, and
 * the vacuity assertions would catch its absence.
 */
export function committedOutputHelpers(root: string, files: string[]): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    const src = readFileSync(join(root, f), "utf8");
    if (!src.includes("VAULYTICA_REGEN_GOLDEN")) continue;
    const dir = f.slice(0, f.lastIndexOf("/"));
    for (const m of src.matchAll(/^import[^"']*["'](\.[^"']+)["']/gm)) {
      const spec = m[1]!.replace(/\.js$/, ".ts");
      const parts = `${dir}/${spec}`.split("/");
      const stack: string[] = [];
      for (const part of parts) {
        if (part === "." || part === "") continue;
        if (part === "..") stack.pop();
        else stack.push(part);
      }
      const resolved = stack.join("/");
      if (files.includes(resolved)) out.add(resolved);
    }
  }
  return out;
}

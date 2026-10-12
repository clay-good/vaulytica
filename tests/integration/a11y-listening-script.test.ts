/**
 * The human task stays in step with the report it describes.
 *
 * BUILD_PROGRESS step 37's remainder is the one item blocked on a person:
 * somebody has to hear a screen reader read the produced DOCX's tables. This
 * does not automate that — `cli-docx-report.test.ts` already asserts the
 * MARKING in the XML, and a listener is for what that assertion cannot see.
 *
 * 🚨 What it guards is the step's own history. Step 37 asked, until 9.900.0,
 * for verification of "the compliance-matrix table in the produced DOCX" — a
 * table that is NEVER PRODUCED, because `report/v3/inputs.ts` declines to
 * build it. The human task named a table that cannot exist, and nothing
 * noticed for months. `docs/a11y/listening-script.md` is generated from a real
 * `--format docx` run so it cannot drift that way again, and this test fails
 * when the committed copy no longer matches what the report produces.
 */
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = join(process.cwd(), "docs", "a11y", "listening-script.md");

/**
 * 🚨 `execFileSync("npx", …)` FAILED ON WINDOWS with `spawnSync npx ENOENT`,
 * and it took down the cross-OS determinism matrix — `npx` is `npx.cmd` there
 * and `execFileSync` does not resolve a `.cmd` without a shell. The portable
 * form is the one `mcp-server.test.ts` already uses: hand the `tsx` loader to
 * the Node binary that is already running. No shell, no PATH lookup, no
 * platform branch.
 */
const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

describe("the screen-reader listening script", () => {
  it("matches the report the tool currently produces", () => {
    const committed = readFileSync(SCRIPT, "utf8");
    // Written to a temp path, NOT over the tracked file: a failing test that
    // rewrites `docs/` leaves the tree dirty and the next release picks it up
    // silently.
    const tmp = join(mkdtempSync(join(tmpdir(), "vaulytica-a11y-cmp-")), "listening-script.md");
    execFileSync(process.execPath, ["--import", TSX, "tools/a11y/write-listening-script.ts"], {
      cwd: process.cwd(),
      encoding: "utf8",
      timeout: 300_000,
      env: { ...process.env, VAULYTICA_A11Y_OUT: tmp },
    });
    const fresh = readFileSync(tmp, "utf8");
    expect(fresh, "docs/a11y/listening-script.md is stale — run `npm run a11y:script`").toBe(
      committed,
    );
  }, 300_000);

  it("names every table the report ships, and none that it does not", () => {
    const text = readFileSync(SCRIPT, "utf8");
    const headings = [...text.matchAll(/^### \d+\. (.+)$/gm)].map((m) => m[1]!);
    // Anti-vacuity: a script with no tables listed would satisfy any check on
    // their contents, which is the shape this file exists to prevent.
    expect(headings.length).toBeGreaterThanOrEqual(9);
    // The two a reader is most likely to be misled by: a findings index and an
    // obligations ledger both read as "value, value, value" without a header.
    expect(headings.join("\n")).toMatch(/Obligor · Modal · Action/);
    expect(headings.join("\n")).toMatch(/Severity · Rule · Finding/);
    // 🚨 The table the step asked about until 9.900.0 is not produced, so it
    // must not appear here either. A script that lists it is asking a person to
    // listen to something that does not exist.
    expect(text).not.toMatch(/compliance matrix/i);
  });

  it("tells the listener what a FAILURE sounds like, not only a pass", () => {
    const text = readFileSync(SCRIPT, "utf8");
    // A checklist that describes only success cannot be failed on purpose.
    expect(text).toMatch(/bare value, with no column/i);
    expect(text).toMatch(/heading row repeats/i);
  });
});

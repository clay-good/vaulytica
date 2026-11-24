/**
 * `npm run redline:exports` — write the five-kind redline fixture, and say
 * exactly how to produce the Accept-All / Reject-All exports the round-trip
 * test needs (add-redline-two-sided-analysis task 1).
 *
 * The fixture half needs nothing but this repository, so it is written
 * unconditionally. The two EXPORTS need an independent Word-compatible
 * application, because the round-trip exists to compare this product's rewrite
 * against someone else's reading of ECMA-376 — if the expected side were
 * generated here it would compare the rewrite with itself, which is the one
 * thing that test is designed to rule out.
 *
 * This script therefore does not pretend to generate them. It writes the
 * fixture, reports whether a Word-compatible application is even present, and
 * prints the exact steps and file names the test looks for. It exits 0 either
 * way: a convenience, never a gate.
 *
 * ⚠️ LibreOffice is not Word. Where the two disagree, Word is the authority a
 * user's document actually came from, so the file name records which produced
 * an export (`-word` or `-soffice`) and the test reports which it compared
 * against rather than conflating them.
 *
 * 🚨 CORRECTION to what this script said at 9.1016.0. It claimed LibreOffice's
 * accept/reject-all "only exists in its UI". That was an overstatement I had
 * not checked. What the official documentation actually supports, read on
 * 2026-11-24:
 *
 *   - CONFIRMED: `--convert-to` only converts, and cannot apply a redline
 *     operation first, so a one-line CLI conversion is genuinely not enough.
 *   - CONFIRMED: `com.sun.star.document.XRedlinesSupplier` exposes exactly one
 *     method, `getRedlines()`, returning an enumeration; `com.sun.star.text.
 *     XRedline.makeRedline()` CREATES redlines. Neither documents an accept-all
 *     or reject-all.
 *   - CONFIRMED: `com.sun.star.frame.XDispatchHelper.executeDispatch(...)`
 *     exists, which is how a `.uno:` command would be invoked.
 *   - NOT CONFIRMED: the names `.uno:AcceptAllTrackedChanges` /
 *     `.uno:RejectAllTrackedChanges` — the wiki page listing dispatch commands
 *     refuses automated reads — and whether a Basic macro runs under
 *     `--headless` in the form this would need.
 *
 * So a scripted route is PLAUSIBLE and unverified, which is not the same as
 * impossible. No macro is shipped here because it would be built on a command
 * name no official source confirmed and could not be run on this machine, and
 * untested tooling in a repository is worse than an honest instruction. Anyone
 * with LibreOffice installed can settle it in a minute — see
 * `openspec/changes/add-redline-two-sided-analysis/tasks.md`.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fiveKindRedlineDocx } from "../../tests/integration/_redline-docx.js";

export const FIXTURE_DIR = join("tests", "fixtures", "redline");
export const REDLINE_NAME = "five-kind-redline.docx";

/** A Word-compatible application on PATH, if there is one. */
function findOfficeApp(): string | undefined {
  for (const candidate of [
    "soffice",
    "libreoffice",
    "/Applications/LibreOffice.app/Contents/MacOS/soffice",
  ]) {
    try {
      execFileSync(candidate, ["--version"], { stdio: "ignore", timeout: 30_000 });
      return candidate;
    } catch {
      // Not this one; try the next.
    }
  }
  return undefined;
}

const BY_HAND = `
The round-trip assertion SKIPS until both exports exist, and runs on every test
pass once they do. To supply them:

  1. open ${join(FIXTURE_DIR, REDLINE_NAME)} in Word
  2. Review > Accept > Accept All Changes, then Save As
     ${join(FIXTURE_DIR, "five-kind-accepted-word.docx")}
  3. reopen the redline, Review > Reject > Reject All Changes, then Save As
     ${join(FIXTURE_DIR, "five-kind-rejected-word.docx")}
  4. commit both

LibreOffice works too (Edit > Track Changes > Manage > Accept All / Reject All),
saved as five-kind-accepted-soffice.docx and five-kind-rejected-soffice.docx.
The test reports which application it compared against.
`;

async function main(): Promise<void> {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  const path = join(FIXTURE_DIR, REDLINE_NAME);
  writeFileSync(path, await fiveKindRedlineDocx());
  process.stdout.write(`wrote ${path} (insertion, deletion, move, formatting-only, table cell)\n`);

  const app = findOfficeApp();
  process.stdout.write(
    app
      ? `found ${app}.\n` +
          "⚠️ `--convert-to` only converts and cannot accept or reject revisions\n" +
          "first, so the exports still need either its UI or a macro through the\n" +
          "UNO API. A scripted route is plausible and was NOT verified here; see\n" +
          "the header of this file for exactly what is confirmed and what is not.\n" +
          BY_HAND
      : "no Word-compatible application found on this machine.\n" + BY_HAND,
  );
}

await main();

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
          "⚠️ It has no command-line filter for accepting or rejecting revisions —\n" +
          "the operation only exists in its UI — so the exports still need a person.\n" +
          BY_HAND
      : "no Word-compatible application found on this machine.\n" + BY_HAND,
  );
}

await main();

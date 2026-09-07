/**
 * A status board nobody updates is worse than no status board.
 *
 * `BUILD_PROGRESS.md` is the append-log of the numbered build plans. It stopped
 * being maintained at **9.381.0** — the newest version it names — and the repo
 * has shipped well over a hundred releases since. Six of its steps still read
 * **🟡 partial**.
 *
 * That would be harmless history except that a dozen spec documents link to it
 * in the present tense ("Progress tracked in BUILD_PROGRESS.md"), so a reader
 * following one of those links lands on a stale board with no way to know it.
 * The file now opens by saying what it is and as of when.
 *
 * This guard keeps the two facts from drifting apart: whatever version the
 * header claims it was last maintained at must actually be the newest version
 * the file mentions. Someone who resumes maintaining it will update both; a
 * later reader gets a header that is true either way.
 *
 * 🚨 Deliberately NOT asserted: that the six partial steps are still partial.
 * Confirming a step against its spec's acceptance criteria is real
 * verification, and none was done — so the header says that plainly rather
 * than implying a status it never checked.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FILE = join(process.cwd(), "BUILD_PROGRESS.md");

describe("BUILD_PROGRESS.md declares its own staleness", () => {
  const text = readFileSync(FILE, "utf8");

  it("opens with an as-of header naming a version", () => {
    const head = text.slice(0, 1500);
    expect(head, "a reader arriving from a spec link must see this first").toMatch(
      /Historical record — last maintained at \*\*\d+\.\d+\.\d+\*\*/,
    );
    expect(head).toContain("CHANGELOG.md");
  });

  it("the version it claims is the newest version it actually mentions", () => {
    const claimed = /last maintained at \*\*(\d+\.\d+\.\d+)\*\*/.exec(text)?.[1];
    expect(claimed, "the header must name a version").toBeDefined();

    // 🚨 In a legal codebase a bare `\d+\.\d+\.\d+` is as likely to be a
    // STATUTE as a version — this log cites Cal. Civ. Code § 1798.199.55, which
    // a naive version regex happily reports as the newest release. Anchor on
    // the product's actual major from package.json instead.
    const major = (
      JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as { version: string }
    ).version.split(".")[0]!;
    // Scan the LOG, not the header — filtering by value would also discard the
    // log's own genuine mentions of that same release.
    const body = text.slice(text.indexOf("Tracks completion of"));
    const mentioned = [...body.matchAll(new RegExp(`\\b${major}\\.(\\d+)\\.(\\d+)\\b`, "g"))].map(
      (m) => [Number(m[1]), Number(m[2])] as const,
    );
    expect(mentioned.length, "anti-vacuity: the log names versions").toBeGreaterThan(50);

    const newest = mentioned.reduce((a, b) =>
      b[0] !== a[0] ? (b[0] > a[0] ? b : a) : b[1] > a[1] ? b : a,
    );
    expect(
      `${major}.${newest[0]}.${newest[1]}`,
      "the header's as-of version drifted from the log's newest entry — update the header, or the note is itself stale",
    ).toBe(claimed);
  });
});

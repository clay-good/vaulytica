/**
 * The pre-disclosure scan must not miss a secret because the document was
 * re-wrapped.
 *
 * `HANDOFF-005` is the "do not send this out" check — an SSN, an account or
 * card number, a direct line left in a draft about to be disclosed. Its
 * failure direction is the worst one available in the tree: a false NEGATIVE
 * that reports a document clean. 67 of the 312 specimens exercise it, and no
 * relation constrained it, because the delivery report is a second surface
 * that lives outside `run.findings` behind its own `delivery_hash`.
 *
 * The load-bearing detail this file exists to pin is WHERE the text comes
 * from. `scanDelivery` takes a `text` argument, and the caller in
 * `tools/cli/api.ts` passes `flattenText(ingest.tree)` — the INGESTED text,
 * after normalization and after `hyphenation.ts` has resolved line breaks.
 * Passing the raw bytes' text instead would look equivalent and is not:
 * measured, a 62-column wrap over the raw text costs three specimens a match,
 * two of them their ONLY finding, so the report goes from "sensitive data
 * present" to silent. Through the real pipeline all four transforms move
 * nothing.
 *
 * So a green here is not "the scanner is stable" — it is "the scanner is
 * stable BECAUSE it reads ingested text", and the day someone hands it
 * something rawer, this fails.
 *
 * The second test pins the half of that which is easiest to break and worst to
 * lose. A wrapped line can end ON the hyphen inside a number — "123-45-" over
 * "6789" — and `joinWrappedLines` restores it only because a line ending in
 * `\w-` is joined with NO space. Change that one branch and an SSN in a
 * hard-wrapped draft becomes invisible to the check whose whole job is to find
 * it before the draft is sent.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanDelivery } from "../../src/delivery/index.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { flattenText } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/** Rule ids and counts — never the evidence, which is masked and positional. */
async function scan(text: string): Promise<string> {
  const ingest = await ingestPaste(text);
  const report = await scanDelivery({
    bytes: new ArrayBuffer(0),
    source: "paste",
    text: flattenText(ingest.tree),
  });
  return report.findings
    .map((f) => `${f.rule_id}:${f.count}`)
    .sort()
    .join("|");
}

const stripBlankLines = (t: string): string =>
  t
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .join("\n");
const crlf = (t: string): string => t.replace(/\n/g, "\r\n");
const doubleSpaced = (t: string): string => t.split("\n").join("\n\n");

/** 62 columns, breaking AT a hyphen — which is what splits a phone number. */
function hardWrap(text: string, width = 62): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim().length === 0) {
      out.push("");
      continue;
    }
    let rest = line.trim();
    while (rest.length > width) {
      const slice = rest.slice(0, width + 1);
      const cut = Math.max(slice.lastIndexOf(" "), slice.lastIndexOf("-"));
      if (cut <= 0) break;
      out.push(rest.slice(0, cut + (slice[cut] === "-" ? 1 : 0)).trimEnd());
      rest = rest.slice(cut + 1).trimStart();
    }
    out.push(rest);
  }
  return out.join("\n");
}

const TRANSFORMS: Array<[string, (t: string) => string]> = [
  ["blank lines stripped", stripBlankLines],
  ["CRLF line endings", crlf],
  ["double-spaced", doubleSpaced],
  ["hard-wrapped at 62 columns", hardWrap],
];

describe("the pre-disclosure scan is not a function of the format", () => {
  it("no transform loses a sensitive-data match on any specimen", async () => {
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const base = await scan(text);
      // A specimen with nothing to find cannot lose anything.
      if (base === "") continue;
      probed++;
      for (const [label, fn] of TRANSFORMS) {
        const mutated = fn(text);
        if (mutated === text) continue;
        const after = await scan(mutated);
        if (after !== base) broken.push(`${name} [${label}]: ${base} -> ${after || "NOTHING"}`);
      }
    }
    // The relation is only worth its runtime if the corpus exercises the scan.
    expect(
      probed,
      "no specimen produces a delivery finding — the probe is vacuous",
    ).toBeGreaterThan(40);
    expect(broken).toEqual([]);
  }, 600_000);

  it("finds an SSN whose line broke on its own hyphen", async () => {
    // The shape a justified column actually produces, in a document laid out
    // like a document: a heading, blank lines, and a paragraph whose wrap fell
    // on the hyphen inside a number. Both halves must be rejoined for the scan
    // to see anything at all.
    const wrapped = [
      "WHISTLEBLOWER POLICY",
      "",
      "1. Reporting.",
      "",
      "Employees may report concerns to the Ethics Line at 1-877-322-",
      "8228 at any time. The reporting employee's tax identification",
      "number 123-45-",
      "6789 will not be recorded in the intake log.",
      "",
    ].join("\n");
    const ingest = await ingestPaste(wrapped);
    const flat = flattenText(ingest.tree);
    // The join is what makes the rest possible; assert it directly so a
    // failure says which half broke.
    expect(flat).toContain("1-877-322-8228");
    expect(flat).toContain("123-45-6789");

    const report = await scanDelivery({
      bytes: new ArrayBuffer(0),
      source: "paste",
      text: flat,
    });
    const evidence = report.findings.flatMap((f) => f.evidence).join(" | ");
    expect(evidence).toContain("ssn");
    expect(evidence).toContain("phone");
    // §13's masking rule: no surface may carry the unmasked value.
    expect(evidence).not.toContain("123-45-6789");
    expect(evidence).not.toContain("1-877-322-8228");
  }, 60_000);
});

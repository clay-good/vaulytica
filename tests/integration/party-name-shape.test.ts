/**
 * A PARTY NAME IS A NAME, and the extracted-data appendix of every report
 * prints it verbatim.
 *
 * 🚨 Found by probing a relation that turned out not to hold yet: renaming
 * every party in all 363 specimens and diffing the findings. The engine itself
 * proved to be party-name independent — 323 documents, 744 names renamed, and
 * not one finding moved for a reason other than the probe's own rewriting. But
 * the probe could not be trusted until the NAMES were trusted, and they were
 * not: `extractParties` was returning `"Trust Agreement. The"`,
 * `"ORDER FORM Northbridge Cloud"`, `"Counterparty with respect to its subject
 * matter"`, `"Lender dated January 20"` and `"Evanston, Illinois"`. Renaming
 * the head word of one of those rewrites the document's own vocabulary, so the
 * relation measured itself four times over before the inputs were clean.
 *
 * Two things live here.
 *
 * **Held at zero**: no name ends with the first word of the following
 * sentence. Five specimens published one, and `cleanPartyName` now cuts it.
 *
 * **Pinned by equality**: the names that still carry a decidable sign of a
 * fragment — a lowercase function-word run, a digit, or a sentence boundary
 * that is not an honorific. The ledger is in `_known-debt.ts` with the others,
 * so the published known-limitations page carries it. ⚠️ Length is NOT one of
 * the signs: "The Regents of Calloway State University", "Wexley Distressed
 * Opportunities Fund II, L.P" and "Willow Bend Estates Homeowners Association,
 * Inc" are all long and all correct, and a word-count test would have demanded
 * they be "fixed".
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractParties } from "../../src/extract/parties.js";
import { KNOWN_DEBT } from "./_known-debt.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const FRAGMENT_DEBT = KNOWN_DEBT["party-name-fragments"].entries;

/** The first word of the NEXT sentence, left on the end of a name. */
const RUNS_ON = /\.\s+(?:the|this|that|these|those|such|a|an|no|it)\s*$/i;

/** An honorific's full stop is not a sentence boundary. */
const HONORIFIC = /\b(?:Dr|Mr|Mrs|Ms|Prof|Rev|Hon|Jr|Sr|St|Messrs)\.|\b[A-Z]\.\s/;

/** A lowercase run that belongs to a sentence, not to a name. */
const FUNCTION_RUN =
  /\s(?:with\s+respect|dated|as\s+(?:landlord|tenant|seller|buyer|borrower|lender|guarantor)|following\s+your)(?=\s|$)|^(?:VALUE\s+RECEIVED|FAVOR\s+OF|AGREED\s+TO|ONE,)/;

async function names(file: string): Promise<string[]> {
  const tree = (await ingestPaste(readFileSync(join(DIR, file), "utf8"))).tree;
  return extractParties(tree).map((p) => p.name);
}

const FILES = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

describe("the shape of an extracted party name", { timeout: 900_000 }, () => {
  it("never ends with the first word of the next sentence", async () => {
    const bad: string[] = [];
    let seen = 0;
    for (const file of FILES) {
      for (const n of await names(file)) {
        seen++;
        if (RUNS_ON.test(n)) bad.push(`${file} ${n}`);
      }
    }
    // Anti-vacuity: a green here must mean the names were READ.
    expect(seen).toBeGreaterThan(900);
    expect(bad).toEqual([]);
  });

  it("carries exactly the fragments the ledger publishes", async () => {
    const found: string[] = [];
    for (const file of FILES) {
      for (const n of await names(file)) {
        const sentenceBreak = /[a-z]\.\s+[A-Z]/.test(n) && !HONORIFIC.test(n);
        // 🚨 A DIGIT IS NOT A SIGN OF A FRAGMENT WHEN THE NAME IS AN ENTITY.
        // This predicate flagged `GRANDVIEW HOLDINGS 447 LLC` — a real party,
        // "…and GRANDVIEW HOLDINGS 447 LLC, a New York limited liability
        // company (\"Landlord\")" — so the published ledger called a correct
        // name debt for two releases. A corporate suffix is what tells a
        // numbered entity from an address line or a contract number.
        const entity =
          /\b(?:LLC|L\.L\.C|Inc|Incorporated|Corp|Corporation|Co|Company|Ltd|Limited|LLP|LP|L\.P|PLC|PC|PA|GmbH|B\.V|N\.V|Pty|AB|AG|SA|SAS|Oy|Trust|Foundation|Association|Partners|Partnership)\.?$/i.test(
            n,
          );
        if (sentenceBreak || FUNCTION_RUN.test(n) || (/[0-9]/.test(n) && !entity))
          found.push(`${file} ${n}`);
      }
    }
    expect([...new Set(found)].sort()).toEqual([...FRAGMENT_DEBT].sort());
  });
});

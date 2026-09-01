/**
 * `expected_defined_terms` promises a check it cannot yet support.
 *
 * 217 of the 255 catalog families declare a list of terms with a
 * `severity_if_missing` beside each one. Nothing reads it. The name, the
 * severity field, and the schema all describe the same obvious check — this
 * family's documents define these terms; this one does not — and this file is
 * the measurement of what that check would actually say.
 *
 * Run against the 243 specimens that route to a family with a list, and
 * counting only terms used at least three times, capitalized, mid-sentence,
 * and absent from the definitions the extractor found: **45 correct documents
 * would be told they forgot to define a term.** The lists conflate three
 * different things:
 *
 *   1. Terms a document of the family really must define — `ePHI` in a BAA,
 *      `APR` in a credit card agreement, `Contract Sum` in a construction
 *      contract. These are the ones the field was meant for.
 *   2. The PARTY ROLE, which the preamble or the caption introduces and no
 *      definitions section repeats. A complaint does not define "Plaintiff",
 *      a codicil does not define "Testator", and a franchise agreement does
 *      not define "Franchisee" — it names one. Sixty-seven specimens fire on
 *      a role alone.
 *   3. The document's own SUBJECT — "Insertion Order", "Referral", "Study",
 *      "Work", "Closing", "Judgment", "Arbitration". A well-drafted document
 *      uses its subject in Title Case throughout without ever stopping to
 *      define the word.
 *
 * Shapes 2 and 3 are not defects in the documents. They are defects in the
 * lists, and the lists are data, not code, so the fix is curation.
 *
 * This file is therefore a RATCHET toward a consumer, not a pass/fail line.
 * Two assertions:
 *
 *   - The false-accusation count may only shrink. Removing a role or a
 *     subject word from a family's list is the work.
 *   - The field is still unconsumed. When it gains a consumer, this test
 *     fails and points at the count — wire it when the count is near zero,
 *     not before.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import type { Playbook } from "../../src/playbooks/types.js";

const ROOT = process.cwd();
const PLAYBOOKS: Playbook[] = [
  ...LAUNCH_PLAYBOOK_IDS.map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(ROOT, "playbooks", `${id}.json`), "utf8"))),
  ),
  ...parsePlaybooks(JSON.parse(readFileSync(join(ROOT, "playbooks", "extended.json"), "utf8"))),
];
const dkb = loadStarterDkbSync();
const SPECIMEN_DIR = join(ROOT, "tests", "fixtures", "specimens");

/**
 * The count as of 9.349.0. **This may only shrink.** It is the number of
 * correct, hand-written specimens that a naive wiring of
 * `expected_defined_terms` would accuse of a drafting defect.
 */
const FALSE_ACCUSATIONS = 28;

/** A term used fewer times than this is not being used as a defined term. */
const DEFINED_TERM_USE_FLOOR = 3;

/**
 * A party's role. The preamble introduces it — `Halbrook Diagnostics, Inc.
 * ("Client")` — and a definitions section never repeats it, so every family
 * that lists its own role is listing something no document will satisfy.
 */
const PARTY_ROLE =
  /^(?:plaintiff|defendant|claimant|respondent|petitioner|testator|testatrix|trustee|member|agency|company|partner|contributor|participant|employee|employer|landlord|tenant|lessor|lessee|buyer|seller|purchaser|vendor|licensor|licensee|borrower|lender|guarantor|grantor|grantee|assignor|assignee|franchisor|franchisee|supplier|customer|client|contractor|subcontractor|consultant|investor|founder|shareholder|stockholder|settlor|declarant|principal|agent|donor|donee|obligor|obligee|indemnitor|indemnitee|sublessor|sublessee|subtenant|sublandlord|media\s+company|business|service\s+provider|covered\s+entity|business\s+associate|controller|processor|subprocessor|disclosing\s+party|receiving\s+party)$/i;

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Uses of `term` that are capitalized and not at the start of a sentence. */
function definedTermUses(body: string, term: string): number {
  const re = new RegExp(`(?<![.:;!?]\\s)(?<!^)\\b${escape(term)}\\b`, "gm");
  return (body.match(re) ?? []).length;
}

async function accusationsFor(file: string): Promise<string[] | null> {
  const text = readFileSync(join(SPECIMEN_DIR, file), "utf8");
  const tree = (await ingestPaste(text)).tree;
  const extracted = extractAll(tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });
  const matched = matchPlaybook(extracted, extracted.classified, PLAYBOOKS, {
    title: titleCorpus(tree, file),
    body_text: text,
  });
  const pb = PLAYBOOKS.find((p) => p.id === matched.playbook_id);
  if (!pb?.expected_defined_terms.length) return null;

  const defined = new Set([
    ...extracted.definitions.entries.map((e) => e.term.toLowerCase()),
    ...extracted.parties.flatMap((p) => [
      p.name.toLowerCase(),
      ...(p.role ? [p.role.toLowerCase()] : []),
    ]),
  ]);
  return pb.expected_defined_terms
    .map((t) => t.term)
    .filter(
      (t) =>
        !PARTY_ROLE.test(t) &&
        !defined.has(t.toLowerCase()) &&
        definedTermUses(text, t) >= DEFINED_TERM_USE_FLOOR,
    );
}

describe("expected_defined_terms — the ratchet toward a consumer", () => {
  it(`false-accuses no more than ${FALSE_ACCUSATIONS} specimens`, async () => {
    const files = readdirSync(SPECIMEN_DIR).filter((f) => f.endsWith(".txt"));
    const accused: string[] = [];
    for (const f of files) {
      const missing = await accusationsFor(f);
      if (missing && missing.length > 0) accused.push(`${f}: ${missing.join(", ")}`);
    }
    // The message names the documents, so a failure is a worklist rather
    // than a number that moved.
    expect(accused.length, accused.join("\n")).toBeLessThanOrEqual(FALSE_ACCUSATIONS);
  }, 300_000);

  it("is still declared by most of the catalog and read by nothing", () => {
    const withTerms = PLAYBOOKS.filter((p) => p.expected_defined_terms.length > 0);
    // If this shrinks sharply, the curation happened and the floor above
    // should come down with it.
    expect(withTerms.length).toBeGreaterThan(200);

    // The consumer check. `src/playbooks/types.ts` declares the field and
    // `self-penalizing-features` reads `expected_clauses`; no rule, report,
    // or export reads the TERMS. When one does, lower `FALSE_ACCUSATIONS`
    // first — wiring it at 45 ships 45 false accusations.
    const consumers = ["src/engine", "src/report", "src/ui", "src/export"]
      .flatMap((d) => grepRecursive(join(ROOT, d), "expected_defined_terms"))
      .filter((f) => !f.endsWith(".test.ts"));
    expect(consumers).toEqual([]);
  });
});

function grepRecursive(dir: string, needle: string): string[] {
  const out: string[] = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...grepRecursive(full, needle));
    else if (e.name.endsWith(".ts") && readFileSync(full, "utf8").includes(needle)) out.push(full);
  }
  return out;
}

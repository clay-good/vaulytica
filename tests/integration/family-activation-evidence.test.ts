/**
 * What actually makes a secondary family activate — measured, not assumed.
 *
 * `familyIsPresent` admits a family on a title keyword, or on three signals
 * drawn from `distinguishing_phrases` and `required_clauses`. Reading the code
 * suggests three sources of evidence. Over the 312 specimens there are two:
 *
 *   title keyword        77
 *   required_clauses      0   ← never the evidence for a single activation
 *   phrases only        247
 *
 * 🚨 **`required_clauses` backs ZERO activations**, and that is worth pinning
 * because it is an inviting thing to design around. It is *not* dead code —
 * the classifier really does emit those categories (over the specimen corpus:
 * 9,941 classified paragraphs, 15 distinct categories, 5 of the 8 declared
 * `required_clauses` among them) — they are simply too sparse to be the
 * deciding signal when three are needed. `governing-law` leads at 149
 * paragraphs, `confidentiality-obligation` 98, `indemnification` 58, and
 * everything below that is in the tens.
 *
 * The dead end this closes: "let a secondary family report ABSENCE findings
 * only when it has structural `required_clauses` evidence, and red flags
 * otherwise". It reads well and it is unavailable — with `reqBacked = 0` it
 * silences absence findings for every secondary family there is, including the
 * composite MSA-with-a-DPA-exhibit case the feature exists to serve.
 *
 * 🚨 **FEED THE CLASSIFIER WHAT THE REAL CALLERS FEED IT.** Both
 * `src/ui/pipeline.ts` and `tools/accuracy/pipeline.ts` call
 * `extractAll(tree, { classifier: { vocab: { vocab: {} }, patterns:
 * dkb.classifier.patterns } })`. A probe that calls `extractAll(tree)` bare
 * classifies every paragraph `unclassified`, which makes `required_clauses`
 * look categorically broken and understates every activation measurement taken
 * with it. That mistake understated 9.512.0's own reported impact — the real
 * figures are 23 activations / 40 findings / 20 critical, not 14 / 27 / 17.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import {
  selectMatchCandidates,
  selectSecondaryFamilies,
} from "../../src/ui/playbook-candidates.js";
import { matchPlaybook, titleCorpus, featureMatcher } from "../../src/playbooks/matcher.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { flattenText } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

describe("secondary-family activation evidence", () => {
  it("is title keywords and phrases — required_clauses never decides one", async () => {
    const deps = await loadAccuracyDeps();
    const files = readdirSync(DIR).filter((f) => f.endsWith(".txt"));
    expect(files.length, "the specimen corpus").toBeGreaterThan(250);

    let byTitle = 0;
    let byRequiredClause = 0;
    let byPhrasesOnly = 0;
    let classifiedParagraphs = 0;
    const categories = new Set<string>();

    for (const f of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, f), "utf8"));
      // Exactly what src/ui/pipeline.ts and tools/accuracy/pipeline.ts pass.
      const extracted = extractAll(ingest.tree, {
        classifier: { vocab: { vocab: {} }, patterns: deps.dkb.classifier.patterns },
      });
      for (const c of extracted.classified) {
        classifiedParagraphs++;
        categories.add(c.category);
      }
      const body = flattenText(ingest.tree);
      const title = titleCorpus(ingest.tree, f);
      const signals = { title, body, classified: extracted.classified, extracted };
      const candidates = selectMatchCandidates(
        deps.launchPlaybooks,
        deps.extendedPlaybooks,
        signals,
      );
      const match = matchPlaybook(extracted, extracted.classified, candidates, {
        title,
        body_text: body,
      });

      const inTitle = featureMatcher(title);
      const cats = new Set(extracted.classified.map((c) => c.category));
      const terms = new Set(extracted.definitions.entries.map((e) => e.term.toLowerCase()));

      for (const p of selectSecondaryFamilies(deps.extendedPlaybooks, signals, match.playbook_id)) {
        if (p.match_features.title_keywords.some(inTitle)) byTitle++;
        else if (
          p.match_features.required_clauses.some((c) => cats.has(c) || terms.has(c.toLowerCase()))
        )
          byRequiredClause++;
        else byPhrasesOnly++;
      }
    }

    // The classifier is genuinely working — this is what makes the zero below
    // a fact about sparsity rather than a broken feed.
    expect(classifiedParagraphs, "classified paragraphs").toBeGreaterThan(5000);
    expect(categories.size, "distinct classifier categories").toBeGreaterThan(5);
    expect([...categories], "the classifier is not returning only 'unclassified'").toContain(
      "governing-law",
    );

    // Anti-vacuity: activations exist to be classified.
    expect(byTitle + byPhrasesOnly, "secondary activations").toBeGreaterThan(200);
    expect(byTitle, "title-backed activations").toBeGreaterThan(50);

    // The finding this file exists to hold.
    expect(
      byRequiredClause,
      "a required_clauses hit now decides an activation — the 'structural evidence' design this file rules out may be back on the table; re-measure before building on it",
    ).toBe(0);
  }, 900_000);
});

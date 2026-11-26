# wire-jurisdiction-id-resolution

## Why

`extractAll` accepts a `jurisdictionLookup` and `JurisdictionReference` carries an optional
`jurisdiction_id`. **No caller in the product ever passes the lookup.** `lookup` is always the
default `() => undefined`, so the field is `undefined` on every entry the product has ever
produced, and the seven `lookup(raw)` call sites in `extract/jurisdictions.ts` are decoration.

This was found while closing `enforce-rule-liveness`: it is the reason `CHOICE-009` was dead
(`retire-shadowed-choice-rule`). The field's deadness has three consequences that have shipped.

| consequence | where | what a user sees |
| --- | --- | --- |
| A report column that is always a dash | `report/docx.ts` jurisdiction table prints `jurisdiction_id ?? "—"` | every row's id cell reads `—`, in every DOCX ever exported |
| A custom playbook written with DKB ids silently fails | `playbooks/custom-interpreter.ts` `governing_law_in` compares `allowed` against `g.jurisdiction_id?.toLowerCase()` | `allowed: ["us-de"]` matches nothing, so a Delaware-law document is reported **violated** — a false positive the author cannot debug |
| The same normalization written three times | `dkb/state-overlays.ts`, `CHOICE-012`, `custom-interpreter.ts` | three resolvers with different coverage, because the field they were meant to read was empty |

The third is the structural cost. `state-overlays.ts` carries a 51-entry state-name map whose own
docstring says *"Runtime extraction does not populate `jurisdiction_id` (no DKB lookup is passed),
so this map is the resolver."* A dead field does not stay dead; it gets worked around.

## What changes

Wire the resolver that already exists, and say what it proves.

1. Move the state-name resolver out of `state-overlays.ts` into `dkb/jurisdiction-ids.ts` and
   export it as a `DkbLookup`. `state-overlays.ts` delegates to it — one resolver, not two.
2. `ui/pipeline.ts` passes it at both `extractAll` call sites, which are the only two in the
   product. `jurisdiction_id` becomes populated.
3. Guard the reach: a test asserts the **product pipeline** yields populated ids, so the parameter
   cannot silently come unwired again. The guard's vocabulary is written independently of the
   resolver's map.
4. Pin the two latent behaviours as tests: the DOCX column shows a real id, and
   `governing_law_in` accepts a DKB id in `allowed`.
5. Correct the four docstrings that assert the lookup is not wired. They become false statements
   the moment this ships.

## Measured impact — no finding moves

Stated before measuring: *"wiring the lookup would change which documents draw law/venue findings,
so it moves findings and routing, not just hashes."* **That was wrong.** Measured over the 363
specimens plus the 14 liveness fixtures (377 documents, 404 jurisdiction entries):

| | |
| --- | --- |
| entries that resolve to a `us-XX` id | **371 / 404 (91.8%)** |
| documents with both a governing-law and a venue clause | 149 |
| …where the two `raw_text` values are already identical (CHOICE-004 returns at the raw compare) | **147** |
| …where they differ and resolve to **different** states (rule still fires, correctly) | 2 |
| …where they differ and resolve to the **same** state (the id branch would suppress) | **0** |
| **CHOICE-004 findings suppressed by wiring** | **0** |

The 33 unresolved entries are honest misses, not failures: `England and Wales` (9), `Ireland` (6),
`United States` (2), and three formula clauses that name no jurisdiction at all
(`"jurisdiction where the Equipment is located"`). The resolver is a US-state map and returns
`undefined` outside it — the honest-N/A path, unchanged.

So this change moves the DOCX jurisdiction column and **no finding**.

⚠️ **Nor does it move a single golden** — 696 of 697 test files passed unchanged, and the one
failure was the mutation-scope config naming a new test file. Stated beforehand as *"the extraction
digest and DOCX artifacts move"*; wrong again, and the reason is worth recording. `result_hash`
covers the findings and the execution log, not the extracted data, and
`tests/golden/artifact-digests.test.ts` digests the **HTML and SARIF** reports — not the DOCX.

🥇 **So the DOCX report has no byte-pinned coverage, which is why an always-dash column survived in
the product's primary deliverable.** `docx.test.ts` asserts `blob.size` and nothing about the text:
a dash is the same number of bytes as an id. The new test reads the rendered table through mammoth
instead. Extending the digests to the DOCX is a separate change — it is the artifact this tool's
output is shaped around, and it is the least pinned of the three.

## Impact

- Rules: none change behaviour on any committed document.
- `CHOICE-004`'s id branch: still has no corpus document that reaches it, because the extractor
  normalizes `raw_text` hard enough that a same-state pair is already raw-equal 147 times out of
  149. The branch is now *reachable in principle* rather than dead by construction, and a unit test
  proves it suppresses. **This is recorded, not hidden:** no specimen exercises it.
- `CHOICE-012`'s `normalizeJurisdiction` is deliberately left alone. It is a comparison key, not a
  `us-XX` id — it handles venue-prefix noise and non-US names (`england and wales`, `uk`) that the
  state map does not. Unifying the two is a separate change with its own false-positive hunt.
- Goldens: nothing moves. See the measured section — the extracted data is outside `result_hash`
  and the DOCX is outside the artifact digests.
- Follow-up this surfaced, not fixed here: the DOCX report is not digest-pinned, so its prose and
  tables can change without any test noticing.

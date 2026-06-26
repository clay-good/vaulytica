# Bundle splitting

Vaulytica ships the entire analysis engine to the browser — there is no server, so the rules, extractors, classifier, and report builder all run in the tab. That is a lot of code (~70,000 lines of application TypeScript on top of the parser vendors). This document explains how it is split into cacheable chunks, why the split is purely a packaging concern, and the rules a change to it must keep.

## The shape of the bundle

The site has a tiny eager entry and a large lazy body. First paint loads only `main-*.js` (~16 KB gzipped) plus the HTML and CSS — enough to render the hero and the dropzone. Nothing else is on the critical path.

The moment the user drops a file, the entry calls `import("./pipeline.js")`. That dynamic import pulls in the analysis body: the engine, the rule catalog, the extractors, the classifier, the DKB loader, and the playbook matcher. The heavy parser vendors (`pdfjs`, `mammoth`, `tesseract`) and the `docx` report builder are separate chunks loaded behind the same gesture. See [`src/ui/main.ts`](../src/ui/main.ts) for the drop handler and [`vite.config.ts`](../vite.config.ts) for the chunking.

```
first paint    main-*.js (16 KB gz)  ──────────────  hero + dropzone
                                                       │ user drops a file
file drop      pipeline-*.js          31 KB gz         engine core + orchestration
               rules-core-*.js        98 KB gz         launch + v3 compliance rules
               v4-rules-corp-*.js     78 KB gz         v4: m&a, governance, equity,
                                                        trust-estate, banking, ip-licensing
               v4-rules-reg-*.js      76 KB gz         v4: every other sector family
               vendor-pdfjs / mammoth / docx / ...     parsers + report builder, on demand
```

## Why the rule catalog is its own set of chunks

The rule catalog is roughly 40% of the analysis code (~28,000 lines), and it changes far more often than anything else — most feature commits add or tune rules. The engine core, the extractors, and the report builder are comparatively stable.

`/assets/*` is served `Cache-Control: public, max-age=31536000, immutable`, so a returning visitor re-downloads only the chunks whose content hash changed. If the whole analysis body were one chunk (it was — a single 1,045 KB `pipeline-*.js`), every rule tweak would invalidate the engine core and the report builder for every returning user. Peeling the catalog out means a rule-only commit re-downloads only the affected rule chunk.

The v4 sub-domain families are split again into two thematic buckets — `v4-rules-corp` (corporate / finance) and `v4-rules-reg` (regulatory / sector) — for two reasons: it keeps each chunk comfortably under Vite's 600 KB warning threshold, and it lets a single-family edit invalidate only its half. The bucket assignment lives in `V4_CORP_FAMILIES` in [`vite.config.ts`](../vite.config.ts); a new family joins the regulatory bucket by default.

## This is packaging only — the engine is unchanged

The split is a `manualChunks` boundary. It does **not** change the module graph, the load order, or what executes. The engine still imports every rule **synchronously** — that synchronous-pure-function property is the foundation of the determinism contract (see [determinism.md](determinism.md)), and lazy *per-family* rule loading would break it by forcing the engine to become async. So all of `pipeline`, `rules-core`, `v4-rules-corp`, and `v4-rules-reg` are static dependencies of the pipeline import: the browser fetches them together, in parallel, before the engine runs.

The consequence worth being honest about: this does **not** reduce the bytes downloaded for the first analysis. The same code loads on file drop either way. What it buys is cache granularity for returning users and an honestly-resolved build warning — not a smaller first-analysis payload. Reducing that payload would require lazy per-family loading, which is rejected because it would make the engine async and undermine the pure-function guarantee. The first-*paint* payload was already minimal and is untouched.

Because nothing about execution changes, the `result_hash` of every report is byte-identical before and after the split. The golden-output tests and the full suite confirm it.

## The guard rails

[`tests/integration/bundle-size.test.ts`](../tests/integration/bundle-size.test.ts) enforces the budgets a chunking change must respect:

- The eager `main-*.js` entry stays under **50 KB gzipped** (first-paint cost).
- Total gzipped JS stays under the **1,065 KB** ceiling (v2 baseline + v3 + v4 budgets).
- Any chunk over **600 KB raw** must match the allow-list (`vendor-mammoth`, `vendor-pdfjs`, `vendor-docx`, `vendor-v4-*`, `pipeline-*`). After this split every chunk is under 600 KB, so the allow-list is currently slack — keep it rather than tighten it, so a future regression surfaces as an explicit decision.
- v4 rule chunks (`v4-*` / `vendor-v4-*`) must be separate files, never inlined into the eager entry.

[`tests/integration/sri.test.ts`](../tests/integration/sri.test.ts) checks Subresource Integrity for the referenced scripts; new code-split chunks are covered by the same mechanism.

## Changing the chunking

1. Edit `manualChunks` (and `V4_CORP_FAMILIES` if rebalancing v4) in [`vite.config.ts`](../vite.config.ts).
2. `npm run build` and confirm there is no "larger than 600 kB" warning.
3. `npx vitest run tests/integration/bundle-size.test.ts tests/integration/sri.test.ts`.
4. Keep chunk **names** stable where you can — renaming a chunk invalidates its cache for every returning user even when its content did not change.

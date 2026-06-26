# Sample documents for end-to-end testing

A small, hand-droppable corpus for exercising the **live site** and the
`vaulytica analyze` CLI by hand. Drop these onto the dropzone at
`https://vaulytica.com` (or a local `npm run preview`) and watch the
report come back — nothing leaves the tab.

These are **not** golden fixtures. The `result_hash` regression gate
lives in [`tests/fixtures/`](../../fixtures/); these files exist purely
so a human (or a Playwright smoke run) can drive the three headline
flows the README advertises and see realistic output. Editing them does
not break any test.

## What's here

```
tests/e2e/sample-docs/
├── single/
│   ├── vendor-saas-agreement.docx   # problematic single doc — lots of findings
│   └── clean-mutual-nda.docx        # tidy single doc — the low-noise baseline
├── bundle/                          # drop the WHOLE folder → bundle mode
│   ├── master-services-agreement.docx
│   ├── statement-of-work.docx
│   └── data-processing-addendum.docx
├── pasted-services-agreement.txt    # paste into the textarea
└── build-sample-docs.ts             # generator (source of truth)
```

## The three flows to test

### 1. Single-document analysis

Drop **`single/vendor-saas-agreement.docx`**. It's a realistic vendor SaaS
subscription agreement seeded with several plain issues so the report has
something to say:

- auto-renewal with a 10-day non-renewal window (§2),
- word-vs-numeral fee mismatch — "twenty-five thousand dollars ($20,000)" (§3),
- 3%/month late fee = 36%/year (§3),
- unilateral modification by posting to the website (§4),
- a blanket no-liability clause (§5),
- one-way, customer-only indemnification (§6),
- suspension/termination at any time without notice (§7).

It classifies to the `saas-customer` playbook and returns ~18 findings.

Drop **`single/clean-mutual-nda.docx`** for the contrast: a tidy mutual NDA
with definitions, exclusions, compelled-disclosure carve-out, explicit
survival, and governing law — the "looks clean" baseline.

### 2. Multi-document bundle / cross-document mode

Drop the **whole `bundle/` folder** (or zip it and drop the zip). Two or
more documents trigger **bundle mode** — per-document reports plus a
portfolio matrix and the cross-document consistency pass. The three docs
disagree **on purpose** so that pass has something to find:

| Conflict                                                                             | Where                  |
| ------------------------------------------------------------------------------------ | ---------------------- |
| Governing law: Delaware (MSA, DPA) vs California (SOW)                               | MSA §5, DPA §5, SOW §4 |
| Order-of-precedence: MSA says MSA controls; SOW says SOW controls                    | MSA §1 vs SOW preamble |
| "Services" defined narrowly (Provider's employees) vs broadly (incl. subcontractors) | MSA §2 vs SOW §1       |
| Fee figures: $100,000 NTE (MSA) vs $180,000 total (SOW)                              | MSA §3 vs SOW §3       |

Expect `CROSS-JURIS`, `CROSS-PRECEDENCE`, `CROSS-DEFTERM`, and
`CROSS-AMOUNT`-style cross-document findings on top of each document's own
single-document findings.

### 3. Pasted-text path

Open **`pasted-services-agreement.txt`**, copy its contents, and paste them
into the textarea (no file needed). Exercises the `ingestPaste` path.

## Not covered: the v9 pre-disclosure scan

The "clean to send" scan (`HANDOFF-*`) reads the **original container
bytes** for tracked changes, comments, hidden text, and authoring
metadata. The `docx` library used by the generator can't emit those
constructs, so a faithful sample has to come from a real Word round-trip:
open one of these `.docx` files in Word, turn on Track Changes, leave a
comment, edit a number, save, and drop the result. The delivery report
will then surface what the flattened-text engine never sees.

## Regenerating

```
npm run e2e:samples
```

`build-sample-docs.ts` deterministically rewrites every file here. Don't
hand-edit the generated `.docx`/`.txt` — edit the generator and re-run.

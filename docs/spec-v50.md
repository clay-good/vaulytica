# Vaulytica v50 — What Using It Found (Input, Output, and the Empty Report)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v49.md`](spec-v49.md), beginning at **Step 313**.
> **Scope:** one idea — fix what a first-time user and a first-time script hit in the first five minutes. Every item was reproduced on 9.853.0 by running the tool; an adversarial pass then re-ran each one, corrected four, and added the rest of the eleven below.
> **Posture (unchanged):** deterministic, no AI, nothing uploaded. Steps 313–315 change no finding on any document. Steps 316–317 change reports, and say which.
> **Cousin docs:** [`spec-v48.md`](spec-v48.md) (shares the compact projection), [`spec-v49.md`](spec-v49.md) (the catalog half of §11), [`reference.md`](reference.md).

---

# Part 0 — The list

| §   | Defect                                                                                              | Who hits it                               |
| --- | --------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| §1  | The browser has no paste box and takes no `.txt` or `.md`, though three places say it does          | Anyone whose contract is in an email      |
| §2  | No stdin                                                                                            | Pipelines, agents                         |
| §3  | `verify` fails on a renamed copy of the same file and blames determinism                            | Anyone who verifies a report              |
| §4  | The default JSON is 293,645 bytes for a 6-finding NDA                                               | Scripts, agents                           |
| §5  | `--format html > report.html` writes summary lines before `<!doctype html>`                         | Anyone who redirects                      |
| §6  | Two inputs with the same stem overwrite each other in `--out`, and the run reports both written     | Anyone with `deal.docx` beside `deal.pdf` |
| §7  | `analyze --help` is an error; `--help` omits 4 of 20 formats; a `.zip` is refused with wrong advice | Every new CLI user                        |
| §8  | Node 26 prints an `ExperimentalWarning` on every run                                                | Users on current Node; CI cannot see it   |
| §9  | A `.txt` file is told "Pasted text loses document structure"                                        | CLI users                                 |
| §10 | An exhibit titled after its parent is judged as the parent                                          | Anyone reviewing an SLA or a schedule     |
| §11 | The generic fallback skips rules that already exist for clauses worth naming                        | Everyone the catalog does not match       |

---

# Part I — Input

## §1. Paste and plain text in the browser

`validateFile` in `src/ui/dropzone.ts` accepts `.pdf` and `.docx`; the picker adds `.csv`, `.zip`, `.json` for bundles. There is no text path and no clipboard listener anywhere in `src/ui`. Yet:

- the same file's docstring says "drag, paste, and click-to-pick";
- `docs/reference.md` lists "Pasted text / Markdown" among inputs handled in the tab;
- `tests/e2e/sample-docs/README.md` tells the reader to paste into "the textarea," and ships a file for it.

The engine has read text since v1 — `ingestPaste` is what all 327 specimens go through. The fix is the missing surface:

- A "paste text" control beside the dropzone; `.txt` and `.md` accepted on drop and as bundle and folder members.
- Pasted text is named `pasted-text.txt`. The name matters: it is inside `result_hash` (§3).
- Less depends on the original bytes than it looks: the Word-comments export is already conditional on DOCX bytes (PDFs lack it today), and the delivery scan already answers "pasted text has no container to inspect."
- A cap well below `MAX_PASTE_CHARS` (20 MiB) for the textarea, which runs on the main thread. Measure a 1 MB paste before choosing it.
- Every "PDF or DOCX" sentence follows: seven places in `site/index.html` (including JSON-LD and the HowTo), `tools/site/seo-pages.ts`, the dropzone's aria-label, and the accept lists in `src/ui/states.ts`.
- **Verify:** the browser's `result_hash` for a pasted text equals `vaulytica analyze pasted-text.txt` on the same bytes.

## §2. Stdin

`analyze -` reads UTF-8 from stdin as text, named `stdin.txt`. Binary formats still need a path. `-` with `--out` writes `stdin.<format>`; `-` with `--delivery` or `docx-comments` is an error that says why.

**Verify:** `cat x.txt | vaulytica analyze - --format json` equals `analyze stdin.txt` on the same bytes, exactly — not "except for the filename," because the filename moves the hash.

## §3. `verify` and the filename

`result_hash` covers `run.source_file.name`. So a byte-identical copy under another name does not reproduce:

```
$ vaulytica verify nda.json renamed-copy.txt
✗ Not reproduced. … No input/engine/DKB drift was detected, so the divergence
  is unexpected — investigate as a possible determinism defect.
```

The tool accuses itself of the one failure it exists to rule out. The hash stays as it is (changing it would orphan every saved report). `verify` changes:

- When the input's SHA-256 matches the report's and only the name differs, re-derive **under the recorded name** and report "Reproduced (file was renamed from `nda.txt`)."
- **Verify:** the transcript above ends in a reproduction; a genuinely different file still fails with `input` as the divergence kind.

This is what makes §1 and §2 verifiable at all: nobody saves a paste as `pasted-text.txt`.

---

# Part II — Output

## §4. `--format brief-json`

Of the 293,645 bytes, `run.execution_log` is 274,412; the 1,700 rows for rules that **did not run** are 255,314 of that. The full JSON stays exactly as it is — `verify`, the certificate, and every golden depend on it. A second format carries the projection [`spec-v48.md`](spec-v48.md) §6 defines.

- **Minified**, written as `<stem>.brief.json` so it cannot collide with `json` under `--out`.
- **Secondary families as ids and counts** by default. They are "detected, not confirmed"; carrying their findings takes the NDA from 4.7 KB to 7.8 KB and the largest specimen to 57.9 KB.
- **Budget:** NDA ≤ 8 KB (measured 4.7 KB); every specimen ≤ 40,000 characters.
- **A fifth JSON kind** in `tools/cli/json-kind.ts`, so `verify brief.json` says "this is a brief; verify needs the full report" rather than dumping a shape.
- **Guards it must join:** `cli-surface-drift.test.ts` (the format row in `ci-integration.md`, `action.yml`, and the export-format count in `reference.md`), `export-reach.test.ts`, and the usage text (§7).
- **Verify through the CLI subprocess**, not by mapping the same array twice: for every specimen, the brief's finding ids equal the full JSON's.

## §5. A redirected artifact is the artifact

`analyze x.txt --format html > report.html` produces a file whose first lines are the terminal summary. The help documents this ("human formats keep stdout") and it is still a broken file. Rule: **when stdout carries a rendered artifact of any format, it carries only that**; summaries and notes go to stderr. With no `--format`, the summary remains the output.

## §6. No silent overwrite

`deal.md` beside `deal.txt` yields one `deal.json` and the message `wrote json for 2 file(s)`. When two inputs share a stem, both outputs keep their source extension (`deal.md.json`, `deal.txt.json`). Unique stems are named as today, so no existing output path changes. **Verify:** the count of files written equals the count reported.

## §7. Help that helps

- `analyze --help`, `verify --help`, `compare --help` print that command's usage and exit 0. Today the first says "missing argument" and the others "unknown flag."
- The usage text lists every member of `VALID_FORMATS` (it omits `docx`, `bundle-json`, `bundle-docx`, `bundle-zip`), and its "stream contract" paragraph names the real machine formats. `cli-surface-drift.test.ts` gains the usage text as a third surface; it checks the docs and the Action today, not `--help`.
- `analyze bundle.zip` is refused with "pass `--as-text`," which would decode a zip as UTF-8. `reference.md` lists `.zip` as an input and the browser takes one. The CLI unpacks it as a folder, as it already does for `--production-qa`.

## §8. The Node warning

It comes from a browser `util-deprecate` shim bundled in the `docx` package, which reads `globalThis.localStorage` at import. It appears on Node 26.8, not on 22.23 or 24.21. Every workflow pins Node 22, so **CI cannot see it**, and a test "on the newest Node in the matrix" would pass with no fix.

- Fix: a one-line module, imported first, that defines `globalThis.localStorage` as `undefined`. Tested: the warning goes and `docx` loads. (Lazy-importing `docx` was the first proposal; it has five static import edges from the CLI, one through SARIF, the Action's default format.)
- Add the current Node release to the test matrix, non-blocking at first.
- **Verify:** on that Node, stderr for a clean `.txt` analysis contains only Vaulytica's own lines.

## §9. A caveat true of its surface

`ingestPaste` returns one warning for every text input, and `IngestSource` has one value for a paste and a file. The sentence must be true of both — and of Markdown, whose `#` headings the ingest **does** parse:

> Read as plain text. Headings are taken from the text's own markers; rules that depend on Word styles or page layout may be skipped.

One string, one owner (`src/ingest/paste.ts`). No report golden contains the old sentence; `tests/golden/artifact-digests.json` moves for two specimens, and two tests assert the phrase.

---

# Part III — The report itself

## §10. An exhibit is not its parent

The first draft proposed a new "subordinate document" downgrade. The mechanism already exists: `amendsParentAgreement`, `isIncorporatedExhibit`, and `borrowsParentVocabulary` in `src/engine/rules/_helpers.ts` are consulted by a dozen universal rules, and they **suppress** whole-agreement absences when a document says it is incorporated into another. A second mechanism would be a second policy.

The real defects, measured on one SLA text (a different text from [`spec-v49.md`](spec-v49.md) §1, with no signature block — hence the second critical):

| Form                                                                               | Routed to           | Findings                         |
| ---------------------------------------------------------------------------------- | ------------------- | -------------------------------- |
| Standalone "Service Level Agreement"                                               | `saas-customer`     | 2 critical, 5 warnings           |
| With the recital "attached to and incorporated into the Master Services Agreement" | `saas-customer`     | Universal absences suppressed    |
| Headed "EXHIBIT B TO THE MASTER SERVICES AGREEMENT", with the recital              | `msa-customer-deep` | **21 findings**, MSA family pack |
| Headed that way, no recital                                                        | `msa-customer-deep` | **31 findings, 2 critical**      |

1. **Routing reads the parent's name as the document's own.** A title after "to the" names the parent. This is the title-routing class fixed earlier for a name inside a longer name, one preposition further.
2. **The helpers read the recital and not the heading.** "Exhibit B to the …" is as plain a statement as "incorporated into."
3. **Family packs do not consult the helpers.** Not fixed wholesale: a DPA that "forms part of" an MSA must still be checked for its own Article 28 terms. Each family that wants the exemption names its whole-agreement rules explicitly.

**Verify:** all four rows route to one family, and rows 2–4 draw the same findings. Eleven existing specimens name a parent and have their own playbook (`dpa-defined-term.txt`, `ai-addendum.txt`, the three `sow*.txt`, and others); none of their findings may move.

## §11. The fallback already has most of these rules

A fallback document runs 66 of 1,825 rules. A probe containing each clause below drew one finding (`DARK-005`). Most of the rest exist and are switched off:

| Clause                       | Existing rule                                       | On the fallback today                                                  | Change                                                                                                                              |
| ---------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Class-action waiver          | `DARK-005`, critical                                | Fires                                                                  | None                                                                                                                                |
| Jury-trial waiver            | `CHOICE-008`, info                                  | Skipped by `generic-fallback.json`                                     | Un-skip                                                                                                                             |
| Liquidated damages           | `FIN-006`, info                                     | Skipped by `generic-fallback.json`                                     | Un-skip                                                                                                                             |
| Unilateral amendment         | `DARK-001`, warning                                 | Runs, misses "this Memorandum" and any party not on its role-noun list | Widen the recognizer                                                                                                                |
| Confession of judgment       | `BNK-051`, gated to note, loan, guaranty            | Not run                                                                | Admit to the fallback, at `info` with a practice citation; 16 C.F.R. Part 444 is not carried over ([`spec-v49.md`](spec-v49.md) §3) |
| Wage-deduction authorization | The `wage-deduction` rule in the v5 employment pack | Not run                                                                | Admit to the fallback at `info`                                                                                                     |
| Acceleration                 | Banking, M&A, and settlement packs                  | Not run                                                                | Admit one to the fallback at `info`                                                                                                 |
| Personal guaranty            | Only `BNK-111`, specific to SBA loans               | Not run                                                                | No generic recognizer exists; deferred to the family in v49                                                                         |

- **Prefer admitting an existing rule to adding one.** `execution_log` has a row for every registered rule and is hashed, so a new rule id changes every report ever compared. Un-skipping and widening `applies_to_playbooks` moves fallback documents only.
- **Presence at `info`, neutral wording.** "This document contains a confession of judgment (§ 9)" — a fact and a location. Enforceability varies by state and is a legal conclusion.
- **The fallback notice must stay true.** `GENERIC_FALLBACK_NOTICE` says it applied "the structural, basic-financial, temporal, and dark-pattern" rules. The 66 already include choice-of-law, IP, obligations, personnel, and risk rules. Replace the list with a count and a pointer, in the same release — it is hashed text, so fallback hashes move once.
- **Read the golden diff.** Every new line should be a clause the document plainly contains.

---

# Part IV — Steps

| Step | Work                                                                                        | Verify                                                                                                                          |
| ---- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 313  | §6, §7, §8, §9: collisions, help, the Node shim, the caveat                                 | File count equals reported count; usage drift guard; stderr test on current Node                                                |
| 314  | §2, §3, §4, §5: stdin, `verify` under the recorded name, `brief-json`, artifact-only stdout | Byte equality with the path form; the renamed copy reproduces; budgets; the redirected file's first bytes are `<!doctype html>` |
| 315  | §1: browser paste and text files, and the three false descriptions                          | Browser and CLI hashes equal; e2e paste; every "PDF or DOCX" sentence updated                                                   |
| 316  | §10: exhibit routing and the heading form                                                   | The four-row table converges; the eleven parent-naming specimens do not move                                                    |
| 317  | §11: un-skip, widen, admit, and the fallback notice                                         | Per-row probe fires; no duplicate findings; golden diff read line by line                                                       |

Cheapest and safest first: 313–315 change no finding. 316 and 317 change reports and ship one release each.

§4 is the same work as [`spec-v48.md`](spec-v48.md) Step 303. Whichever is built first does it once; the other step becomes its guards.

---

# Part V — Noted, not specified

- **The shipped "clean" sample is not clean.** `tests/e2e/sample-docs/single/clean-mutual-nda.docx`, described as the low-noise baseline, draws 1 critical and 8 warnings. Either the sample or the rule (`NDA-D-013`) is wrong; reading it is a first task for whoever picks this up.
- **A non-English document** gets the correct "does not read as English" warning and a critical "no signature block" anyway. Whether a language warning should stand down absence rules is a judgment call, left open.
- **A bare `analyze <dir>`** exits 1 asking for `--out`. [`spec-v52.md`](spec-v52.md) gives a folder a stdout answer.

# Part VI — Open questions

1. **Screenshots in the paste box.** People will paste images. Out of scope; the control accepts text and says so.
2. **Should a confession of judgment ever be `warning` on the fallback?** In a consumer document, probably. That is a judgment about a document class the fallback, by definition, has not identified.

# Vaulytica v52 — Folder Triage (One Ranked Page for a Directory, and Where to Spot-Check)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v51.md`](spec-v51.md), beginning at **Step 322**.
> **Scope:** one idea — point the tool at a folder and get **one** artifact that says which documents need a person first, and exactly which things to open to check the tool's work. No new rule.
> **Posture (unchanged):** deterministic, no AI, no server. The ranking is a sort on facts the run already has, never a risk score.
> **Cousin docs:** [`spec-v48.md`](spec-v48.md) (`analyze_folder` returns this), [`spec-v50.md`](spec-v50.md) (the compact projection; output naming), [`ci-integration.md`](ci-integration.md).

---

# Part 0 — What a folder run gives today

Measured on `tests/fixtures/contracts` (24 `.docx` and one `.txt`), 9.853.0:

| Run                           | Result                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `analyze <dir>`               | Exit 1: "multiple formats/inputs require --out"                                           |
| `analyze <dir> --out o`       | About 2 s. 25 JSON files, **8.0 MB**. Nothing on stdout                                   |
| What says which file is worst | 25 lines on stderr in **filename order**, interleaved with caveats. No totals, no ranking |

And on a scratch folder built to be awkward:

| Input                                                   | Today                                                                              |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Subdirectories                                          | Walked recursively                                                                 |
| Corrupt `.docx`, bad `.pdf`                             | Caught per file; the run continues and exits 1 naming them. Good                   |
| Unsupported files (`.png`, `.xlsx`, `.doc`)             | Listed on stderr                                                                   |
| **Dotfiles and dot-directories**                        | **Silently dropped** — not analyzed, not listed                                    |
| **Two files with one basename in different subfolders** | **Both write the same report; one is lost.** The run said "wrote 7" with 6 on disk |
| A zero-byte `.txt`                                      | Analyzed as an unmatched document, with findings                                   |
| A scanned PDF with no text layer                        | A warning string; headless runs have no OCR                                        |
| Byte-identical duplicates                               | Both analyzed; not noticed                                                         |

The per-document reports are complete. The page a person reads first does not exist, and three rows above would make any such page wrong.

---

# Part I — Before the page: facts it has to be able to read

## §1. Structured signals

The tiers below need facts that today exist only as sentences:

- **Ingest warnings get codes.** `IngestResult.warnings` is a list of strings. Every `.txt` carries one, so "has a warning" cannot define a tier. Add a code beside each message (`no-text-layer`, `tracked-changes`, `not-english`, `plain-text`, `empty`); the strings do not change, and `warnings` sits outside `run`, so no hash moves.
- **The near-miss family is a field.** It exists only inside a sentence ("Best score was employment-at-will-us at 0.4"), and only on unmatched runs. Record the family and score, with a floor: a blank file's "best score … at 0" names an arbitrary family.
- **Every file is accounted for.** Dotfiles are reported as skipped. Report files under `--out` mirror the input's relative path, so nothing collides ([`spec-v50.md`](spec-v50.md) §6 fixes the same-folder case). This changes report paths for inputs in subdirectories.

## §2. Test coverage that does not exist yet

None of the 327 specimens is unmatched, and none has a crashed rule. Tiers 1 through 3 would ship with no corpus behind them. Step 322 adds fixtures for each: a corrupt file, a text-less PDF, an empty file, an unmatched document (the probe documents from [`spec-v49.md`](spec-v49.md)), and a document with tracked changes.

---

# Part II — The triage artifact

## §3. One artifact for many inputs

`analyze <dir|glob|.zip> --format triage-md` (and `triage-json`). It is a single artifact, so it streams to stdout like any one-input run; per-document formats still require `--out`. With `--out` it is also written as `TRIAGE.md`, which the GitHub Action (`action.yml`) places at the top of the job summary it already writes.

## §4. The order is tiers, not a score

Match confidence takes five values across the 327 specimens (1.0 on 260 of them), so it cannot rank, and a blended score would be an invented number.

| Tier | Meaning                                                                       | Why it is first                                        |
| ---- | ----------------------------------------------------------------------------- | ------------------------------------------------------ |
| 1    | **Not read**: corrupt, unsupported, over the size limit, no text layer, empty | The tool has no opinion; a person must look            |
| 2    | **Read with a caveat**: tracked changes, not English, a crashed rule          | Findings may be incomplete or wrong                    |
| 3    | **Unmatched**: generic fallback                                               | Family checks did not run; a short report means little |
| 4    | **Matched**, by criticals, then warnings, then path                           | The ordinary case                                      |

Every input appears in exactly one row. Byte-identical duplicates share one row and are analyzed once.

## §5. The columns

Path · document type · tier and reason · C / W / I · actionable count ([`spec-v51.md`](spec-v51.md) §4) · the first critical **in document order**, with its section · rules run (family + general) · input SHA-256 (first 12) · report path.

- **Counts are the primary match only**, as `--fail-on` counts them. A document with secondary families shows a flag, not their findings.
- Below the table: totals per tier and severity; duplicates; each caveat once, with its files.
- **Systemic rules only.** A rule is listed when it fires on at least three documents of a type and at least half of them — "`NDA-D-001` on 14 of 20 NDAs" is a template problem. Listing every rule made this section 10 KB of an 18 KB page.

## §6. The spot check

The use this exists for: an agent lints a folder, a person decides whether to believe it. The first draft sampled ten findings by hash. Simulated, that sample was dominated by "clause present" observations, contained no critical four times in five on a mixed folder, never questioned a matched document's type, and never looked at a document that came back clean.

The sample is **fixed slots**, each answering a different way the run could be wrong:

| Slot          | What is picked                                                                                                  | The question for the person                                                                    |
| ------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Type**      | Every tier-3 document with a near-miss; the three lowest-confidence matched documents; one per type, up to five | "Is this document what the tool says it is?" The title line is printed beside the matched type |
| **Criticals** | One finding per distinct critical rule, different documents first                                               | "Is this really wrong?"                                                                        |
| **Systemic**  | One finding from each systemic rule                                                                             | "Is the template wrong, or the rule?"                                                          |
| **Absence**   | At least two absence findings, each with the rule's description of what it looks for                            | "Is the clause truly missing?"                                                                 |
| **Quoted**    | At least two findings with a quoted excerpt, with offsets                                                       | "Does the quote say what the finding says?"                                                    |
| **Clean**     | The two documents with the fewest findings, each naming two rules that ran and stayed silent                    | "Should something have fired here?"                                                            |

- **Ties are broken by `SHA-256(input SHA-256 + rule id)`**, so the same folder gives the same sample, across machines, and across an engine upgrade that changes no finding.
- At most one observation in the sample.
- The page states its coverage — "k of N findings, m of D documents" — and that this is a check of the tool, **not an estimate of an error rate**.
- **What a failed check means**, printed with each slot: a wrong type means disregard that document's family findings; a wrong critical means read that rule's other findings before acting on them.

## §7. Size

| Folder                                | Budget  | Measured in a prototype (not committed)                                                                                               |
| ------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 25 files, `triage-md`                 | ≤ 10 KB | 17.7 KB with every rule listed; about 8 KB with systemic rules only                                                                   |
| 327 files, `triage-md`                | No cap  | 112 KB — a file to open, not a tool result                                                                                            |
| Any folder, `analyze_folder` over MCP | ≤ 20 KB | Totals, tiers 1–3 in full, the top 20 tier-4 rows, systemic rules, the sample, `triage_hash`, the path to the full page, and a cursor |

## §8. Honesty

The artifact carries the not-legal-advice and determinism statements from `src/report/disclaimers.ts`, joins `honesty-caveat-reach.test.ts`, links `/known-limits` ([`spec-v53.md`](spec-v53.md)), and carries a `triage_hash` outside every `result_hash`.

## §9. A folder is not a bundle

Cross-document consistency over an arbitrary directory produces true, meaningless conflicts (1,291 over 60 unrelated specimens, per the CHANGELOG). Triage never runs it. `--consistency` remains the explicit statement that these files are one deal; when passed, the page adds the conflicts as a section.

---

# Part III — Steps

| Step | Work                                                                                            | Verify                                                                                                    |
| ---- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 322  | §1, §2: warning codes, near-miss field, dotfile reporting, mirrored output paths, tier fixtures | No `result_hash` moves; files written equals files reported; each fixture exists                          |
| 323  | §4, §5: the triage model                                                                        | Every input in exactly one row; each tier fixture lands in its tier                                       |
| 324  | §6: the spot check                                                                              | Same sample across runs, input order, and an engine version bump; every slot filled on the 25-file folder |
| 325  | §3, §7: `triage-md`, `triage-json`, `TRIAGE.md`; `analyze_folder` over MCP                      | `export-reach`, `cli-surface-drift`, usage guards; the two budgets                                        |
| 326  | The GitHub Action puts `TRIAGE.md` at the top of its job summary                                | Above the existing stderr block; SARIF on stdout unchanged; the smoke fixture renders                     |

**Open the rendered `TRIAGE.md` for the 25-file folder and read it before shipping.** This repository's own history is that render defects are found by reading the artifact, not by its tests.

---

# Part IV — Open questions

1. **Recording the verdict.** A person who finds a false positive has nowhere to put that so the next run knows. A custom playbook's `rule_overrides` is the existing mechanism; wiring the spot check to it is a later design.
2. **Incremental runs.** Skipping files whose SHA-256 has not changed, and "what changed since the last triage," follow naturally from the hashes. Not until the page has real use.
3. **The browser.** A folder drop runs as a bundle of up to four. A triage view for a larger folder is a separate design: the tab holds every document in memory.
4. **Grouping by deal.** Inferring which files belong together is exactly the inference §9 refuses. Deferred.

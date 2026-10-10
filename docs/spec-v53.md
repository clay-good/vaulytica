# Vaulytica v53 — The Error Ledger (Publishing What Is Measured, and Saying What Is Not)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v52.md`](spec-v52.md), beginning at **Step 327**.
> **Scope:** one idea — a tool that asks to be trusted should publish where it is known to be wrong. v53 does **not** publish an accuracy number, because there is not one. It publishes what exists, removes six sentences the site cannot support, and builds the one channel that could produce more.
> **Posture (unchanged):** no telemetry, no server, no account. Nothing in v53 learns anything about a user's document.
> **Relation to [`spec-v5.md`](spec-v5.md):** v5 §22 (the accuracy report) and §24 (honest-limits disclosure) remain the destination and remain blocked on attorney annotation. v53 is the interim form of §24, built from what the test suite already holds, and the routing half of §18 without annotation.
> **Cousin docs:** [`tools/accuracy/SCOREBOARD.md`](../tools/accuracy/SCOREBOARD.md), [`spec-v47.md`](spec-v47.md), [`threat-model.md`](threat-model.md).

---

# Part 0 — What is true today

| Fact                                                                | Source                                                                                                                                                |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Measured precision and recall on real documents: **none**           | `SCOREBOARD.md`: status `empty`, 0 graded pairs                                                                                                       |
| Real documents in the ground-truth corpus: **0**                    | `corpus/manifest.json` has no splits; gated on attorney annotation                                                                                    |
| Rules signed off by an attorney: **0 of 1,825**                     | Already on the homepage (`data-ledger-signed`), guarded by a test                                                                                     |
| A way to report a wrong finding that any report points to: **none** | No link in the tab or any report; no issue template. `CONTRIBUTING.md` asks for an issue with a redacted fixture, and nothing a user sees leads there |
| Known, measured defects held open on purpose                        | About twenty debt lists asserted by equality in `tests/integration/`                                                                                  |

Roughly 5,000 unique visitors a month reach the site (the owner's figure). The project learns about a false accusation only when a maintainer happens to write the document that draws it.

**The site also says things this page would contradict:**

| Where                           | Sentence                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `site/index.html`               | "exhaustive, identical, cited checking"                                                                |
| `site/index.html`               | "catches that failure mode every time"                                                                 |
| `site/index.html`, closing line | "Stop hoping you didn't miss anything. Prove you didn't."                                              |
| `tools/site/seo-pages.ts`       | "Exhaustive by design"; "it will never skip a check"; "makes sure nothing on the checklist was missed" |

What is true is narrower and still worth saying: the same checks run every time, and the report lists them. A tool with no measured recall cannot prove nothing was missed.

---

# Part I — Publish what exists

## §1. `/known-limits`

A static page. (The homepage section `#limits`, "What it does not do," stays and links to it.) Five sections, in this order:

1. **Not measured.** There is no precision or recall figure for this tool on real contracts, and no rule has been signed off by an attorney. Why, and what to conclude: treat every finding as a prompt to read the clause, and every silence as silence. Also unmeasured and said so: OCR quality on scans; defects no rule exists for; whether severities are calibrated.
2. **What it reads.** English only. US law. PDF, DOCX, and text; size and OCR-page caps. A document matching no family gets a small generic rule set, and **a short report on an unmatched document is not a clean bill**. Up to four secondary families are detected from vocabulary, not confirmed. Each fact is read from the constant that enforces it (`MAX_DOCUMENT_BYTES`, `MAX_OCR_PAGES`, `MAX_SECONDARY_FAMILIES`, `MATCH_THRESHOLD`).
3. **Measured on documents we wrote.** 327 author-written specimens whose findings are pinned exactly; how many families have a complete specimen (14 of 268 today); for each reformatting relation, how many specimens were probed and how many moved. Labeled as self-measured on synthetic documents.
4. **Known wrong, held open.** One row per debt list: a count and **one plain sentence**, never the raw entries. For example: "On 9 specimens, a late-fee rate written in words is not read, so the usury check stays silent."
5. **Reported by users** (§5), once there are any.

## §2. How the page stays true

The first draft said "the generator reads the test constants." They are private constants inside test files, which a site build must not import. The design that works, modeled on `tools/site/doc-types.json` and its guard `site-doc-types.test.ts`:

- **One ledger module** (`tests/integration/_known-debt.ts`): `{ id, entries, reason }` per list. Each debt test imports its list from it instead of declaring its own; the generator imports the same module.
- **`reason` is a field, written for a reader.** Today's reasons are maintainer narrative ("57 → 47 … glue"). Rewriting about twenty of them in one sentence each is the real work of Step 327.
- **A committed `known-limits.json`** and a guard that fails when it differs from the generator's output.
- **The rule:** a number about the engine's behavior appears on the page only if a test asserts it by equality. One ceiling (`FALSE_ACCUSATIONS ≤ 27` in `expected-defined-terms.test.ts`) is tightened to equality so it qualifies.

The page's **numbers** cannot drift from the code. Its sentences can; they are reviewed like any other prose.

## §3. The site stops overclaiming

Rewrite the sentences in Part 0 to the determinism claim. A guard, like the vacated-authority registry, bans "exhaustive," "catches that failure mode every time," "never skip," "nothing on the checklist was missed," and "prove you didn't" from the site sources. "The same answer every time" stays: it is the determinism claim, and it is true.

`/known-limits` is linked from the homepage, the footer of every report format, the CLI's caveat output, SARIF's `informationUri`, `/review/<id>` pages, `llms.txt`, and — when [`spec-v48.md`](spec-v48.md) is built — the MCP server's instructions.

---

# Part II — The channel that could produce more

## §4. "Report a wrong finding"

A link that opens a new GitHub issue in the user's own browser. The site sends nothing; no request happens until the user clicks, and nothing is posted until they submit.

**What it carries:** rule id, rule version, engine version, DKB version, matched document type. A test pins the URL to those five fields and a length cap.

**Constraints:**

- **Never for a custom playbook.** A user's own rule ids and playbook id are theirs. No link on a `custom-playbook` finding, and none anywhere while a custom playbook is loaded. Tested with a marker string, beside `custom-playbook-privacy.test.ts`.
- **The issue is public, and says so first.** The pre-filled body opens: "This issue is public. Do not paste client or confidential text; describe the clause in your own words." The audience includes lawyers.
- **Per finding in the tab; once in a report.** A DOCX or HTML report is a deliverable people send to clients and counterparties. It gets one link in its audit trail, not "this finding is wrong" beside every finding.
- **No referrer from a hosted report.** The site already sends `Referrer-Policy: no-referrer`. The standalone HTML report gains the equivalent meta tag and `rel="noopener noreferrer"`, so a report on an intranet does not hand its URL to GitHub.
- **The threat model is amended in the same step.** It currently says the rich reports "carry no active link" beyond citations.
- **Labels come from an issue template,** not from a `labels=` parameter, which needs permissions an anonymous reporter lacks.
- **A second link on the unmatched banner:** "What kind of document is this?" It carries the engine version and the nearest family's id, and **not** the match score, which is derived from the document.
- **For people without a GitHub account** — most visitors — a "copy details" button puts the same five fields on the clipboard to send however they like.

The link sits outside `EngineRun`, so no `result_hash` moves. Report bytes change, so `artifact-digests.json` is regenerated.

## §5. What happens to a report

- Outcomes: `confirmed-false-positive`, `confirmed-miss`, `works-as-designed`, `needs-document`. Labels are created by hand in the repository settings.
- A confirmed defect follows the existing method: a specimen, the fix, a guard, and a CHANGELOG entry linking the issue.
- A maintainer script exports counts to a committed `docs/reported-findings.json` with an `as_of` date. The build reads the file; a guard asserts `tools/site` and `vite.config.ts` import no network module.
- The page prints the date and, **beside the numbers**, the sentence: "These are reports people chose to send. They are not a rate, and cannot be divided by anything."

---

# Part III — A real-document number that needs no lawyer

## §6. Routing on public filings

"Is this finding legally right" needs an attorney. "Did the tool recognize a document for what its own title says it is" does not.

- **Source:** EDGAR material-contract exhibits, selected **by rule** — the first N Exhibit 10s from a fixed date range — not by hand, and fetched manually within the SEC's access rules.
- **Nothing copyrightable is committed.** Exhibits are written by private parties; "publicly filed" is an access statement, not a license. Each record holds the accession number, exhibit URL, retrieval date, SHA-256 of the extracted text, the exhibit's title, its label, and the observed route. No redaction, because no text. (v5 labels such sources `US-Gov-PD`; that is wrong in kind and should be corrected there.)
- **Label:** a committed table from title to an **acceptable set** of families, reusing the ties the suite already declares (`msa-general` / `msa-customer-deep` / `msa-vendor-deep`).
- **Measure, per family and overall:** exact family, acceptable family, wrong family, fallback — and a fifth share, **no family exists for this title**, which is kept, not filtered out.
- **Schema work it needs:** a `routing` split (the manifest enum allows only `regression` and `development`) and a routing-record schema.

**Printed with the number, every time:**

- The title is both the label and the classifier's strongest feature, so this is an **upper bound** for well-titled documents.
- EDGAR is large-company commercial paper, as HTML. It says nothing about residential leases, consumer documents, court filings, or PDF and DOCX ingest.
- "Families with zero real documents: K of 268."

Because no text is committed, CI cannot re-run this; a maintainer re-fetches to reproduce. That is the price of not redistributing other people's contracts.

---

# Part IV — Steps

| Step | Work                                                                          | Verify                                                                                             |
| ---- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| 327  | The ledger module; each debt test imports from it; one-sentence reasons       | Every debt test passes unchanged; no entry lacks a reason; no test file declares its own debt list |
| 328  | `/known-limits`, `known-limits.json`, and the drift guard                     | Guard fails when a ledger entry changes without the page                                           |
| 329  | §3: rewrite the overclaims; the banned-phrase guard; links from every surface | Guard fails on the old sentences; reach test over report formats, CLI, SARIF                       |
| 330  | §4: the links, the copy button, referrer handling, threat-model amendment     | URL-content test; custom-playbook test; the existing privacy e2e extended to the links             |
| 331  | §5: issue template, export script, `reported-findings.json`                   | Import-ban guard; page pinned to the JSON; the adjacent sentence asserted                          |
| 332  | §6: routing split, record schema, label table, first sample                   | Schema validates; `npm run accuracy` prints the five shares and the caveats                        |

Steps 327–330 need no one outside the project. Step 331 needs repository settings and a token. Step 332 needs a maintainer's time and an owner's decision on sample size.

---

# Part V — Open questions

1. **The attorney corpus.** Still the only route to precision and recall. A public tool with this many users might find volunteer annotators; asking is the owner's call.
2. **Committing exhibit text.** It would let CI catch routing regressions on real documents. It is a copyright judgment — fair use for measurement, or not — and is the owner's to make.
3. **Issue volume.** Start with the link on critical and warning findings only, and read the first month.
4. **An absence tag on rules.** "Complete documents draw zero absence findings" cannot be published because findings do not say whether they report an absence. Adding the tag is a rule-schema change that would also sharpen [`spec-v51.md`](spec-v51.md) and [`spec-v52.md`](spec-v52.md).

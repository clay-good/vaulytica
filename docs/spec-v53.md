# Vaulytica v53 — The Error Ledger (Publishing What Is Measured, and Saying What Is Not)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v52.md`](spec-v52.md), beginning at **Step 327**.
> **Scope:** one idea — a tool that asks to be trusted should publish where it is known to be wrong. v53 does **not** publish an accuracy number, because there is not one. It publishes what exists, removes six sentences the site cannot support, and builds the one channel that could produce more: a single report page.
> **Posture:** no telemetry, no account, and no part of a document ever leaves the machine. **One thing changes:** the site gains a single endpoint that receives a problem report a person chooses to send (§5), so "there is no server" stops being true and is rewritten (§6).
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
5. **Reported by users** (§7), once there are any.

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

## §4. One page: `/report`

**Decided 2026-10-10:** reports go to a small Cloudflare Worker with a D1 database behind Turnstile — the design roughlogic.com already runs for its calculators. An earlier draft used a pre-filled public GitHub issue; that needs an account most visitors lack and puts a lawyer's report in public.

Vaulytica has one screen, so it gets one report page, not a dialog per finding:

- **A static page at `/report`** with its own small script. It is a separate document from the app: it shares no memory with the tab that analyzed a contract, and the app stores no document anywhere a second page could read. It cannot see a contract even by mistake.
- **Links carry context in the URL fragment**, which browsers never send to a server: `/report#rule=NDA-D-019&rv=1.0.0&engine=9.853.0&dkb=…&type=mutual-nda-deep`. A finding links there in the tab; a DOCX or HTML report links there once, in its audit trail; the CLI and MCP server print the address and never call the endpoint themselves.
- **The form:** what kind of problem (a finding is wrong · something was missed · wrong document type · the site or a download is broken), the context from the link, and an optional note of at most 280 characters.
- **The person sees exactly what will be sent**, as a short list above the button, with the line: "Do not paste contract text. Describe the clause in your own words."
- **From the unmatched banner:** "What kind of document is this?" opens the same page with the nearest family's id and no score. That is the demand signal [`spec-v49.md`](spec-v49.md) had to simulate.
- **Never for a custom playbook.** A user's own rule and playbook ids are theirs. No link on a `custom-playbook` finding, and none while a custom playbook is loaded.

## §5. The endpoint

A separate Worker, `vaulytica-reports`, routed only at `vaulytica.com/api/reports*`. Pages keeps serving every static file; ordinary use never invokes the Worker. It follows roughlogic's Worker closely, because that one is already in production:

| Concern           | Design                                                                                                                                        |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Bots              | Turnstile, verified server-side with a fixed action name. A WAF rate limit on the path sits in front of the Worker                            |
| Volume            | 5 accepted reports per reporter per day; 200 per day in total; separate caps on verified attempts. Ceilings are constants in code             |
| Reporter identity | None stored. The per-reporter cap uses a daily HMAC of the IP under a secret; the raw IP, user agent, and Turnstile token are never written   |
| Duplicates        | A dedupe key over the report's fields; the same report twice is one row                                                                       |
| Retention         | Every report is deleted after 30 days, by a daily cron and before each write. Durable reasoning goes in the spec, the test, and the CHANGELOG |
| Reading reports   | No public read endpoint. A maintainer reads D1 through authenticated `wrangler`                                                               |
| Failure           | Missing configuration fails closed: the page says reporting is unavailable. The app is unaffected                                             |
| Exposure          | No `workers.dev` URL, no preview URLs, invocation logs off                                                                                    |
| Cost              | Inside the free tiers of Workers, D1, and Turnstile at these ceilings                                                                         |

**The endpoint is built so a contract cannot fit through it.** It accepts a JSON body of at most 4 KB with an exact set of keys. `rule_id` and `document_type` must be ids in the shipped catalog — the Worker carries a generated list — so a custom id is rejected even if a client sends one. The note is capped at 280 characters and stripped of control and bidirectional-override characters. There is no field for an excerpt, a filename, a document hash, or a `result_hash`.

What is stored, in full:

```sql
CREATE TABLE finding_reports (
  id TEXT PRIMARY KEY NOT NULL,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('wrong-finding','missed','wrong-type','site')),
  rule_id TEXT, rule_version TEXT,
  engine_version TEXT NOT NULL, dkb_version TEXT,
  document_type TEXT, near_family TEXT,
  note TEXT CHECK (note IS NULL OR length(note) <= 280),
  dedupe_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','wont_fix')),
  resolved_at TEXT,
  resolution_note TEXT CHECK (resolution_note IS NULL OR length(resolution_note) <= 1000)
);
```

Plus two small counter tables for the daily limits, as roughlogic has. The Worker lives in `workers/reports/` with its own `wrangler.jsonc` and migrations, and is imported by nothing in `src/` or `tools/`.

## §6. What this changes about "no server"

This is the cost, and it is not small. The site says "There is no server" in the homepage, its FAQ structured data, and the README, and shows a tile reading "**0** servers." After this ships, there is one: it receives a short form when a person chooses to send it.

- **Every such sentence is rewritten in the same release** to the claim that stays true: _your document is never sent anywhere; the only thing this site can receive is a problem report you choose to send, and it contains no part of your document._ The tile becomes "**0** uploads."
- **The app page keeps its CSP exactly.** Turnstile's script and frame are allowed on `/report` only, by a path-specific header that replaces the inherited policy there. How Cloudflare Pages combines two matching header rules is confirmed in Step 331 before anything depends on it.
- **The app never talks to the endpoint, and tests hold that.** The existing privacy e2e (which today flags cross-origin requests during analysis) is extended to assert zero requests to `/api/` across every analysis journey. A new static guard asserts no module reachable from the app's entry contains the endpoint's path. The service worker never caches or replays `/api/`.
- **Turnstile is a third party.** On `/report`, and only there, Cloudflare's challenge sees the visitor's IP and browser signals. The page says so above the form.
- **The threat model gains a section** for the endpoint: what it accepts, what it stores, how to turn it off.

"Open DevTools and watch the network tab" remains a true instruction for the app.

## §7. What happens to a report

- A weekly review, oldest first, grouped by rule. Outcomes are recorded on the row: `resolved` or `wont_fix`, with a note.
- A confirmed defect follows the existing method: a specimen, the fix, a guard, and a CHANGELOG entry.
- A maintainer script exports **counts by rule and outcome** — never notes — to a committed `docs/reported-findings.json` with an `as_of` date. The build reads the file and opens no socket.
- `/known-limits` prints the date and, **beside the numbers**, the sentence: "These are reports people chose to send. They are not a rate, and cannot be divided by anything."
- A runbook, `docs/finding-reports.md`: the launch checklist (D1, Turnstile, the two secrets, the WAF rule), the review queries, and the kill switch.

GitHub issues remain open for anyone who prefers to report in public; `CONTRIBUTING.md` already describes that path.

---

# Part III — A real-document number that needs no lawyer

## §8. Routing on public filings

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

| Step | Work                                                                                                                                                         | Verify                                                                                                                                                                                               |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 327  | The ledger module; each debt test imports from it; one-sentence reasons                                                                                      | Every debt test passes unchanged; no entry lacks a reason; no test file declares its own debt list                                                                                                   |
| 328  | `/known-limits`, `known-limits.json`, and the drift guard                                                                                                    | Guard fails when a ledger entry changes without the page                                                                                                                                             |
| 329  | §3: rewrite the overclaims; the banned-phrase guard; links from every surface                                                                                | Guard fails on the old sentences; reach test over report formats, CLI, SARIF                                                                                                                         |
| 330  | §4: the `/report` page, the fragment links from findings, reports, CLI, and the unmatched banner                                                             | URL-content test (fragment only, five fields); no link on a custom-playbook finding; the page shows "unavailable" until Step 331                                                                     |
| 331  | §5–§7: the Worker, D1 migrations, Turnstile, limits, retention, the `/report` CSP, the "no server" rewrite, the threat-model section, the runbook and export | Worker unit tests on validation, limits, dedupe, cleanup; an oversized or unknown-key body is rejected; privacy e2e shows zero `/api/` requests from the app; old "no server" sentences fail a guard |
| 332  | §8: routing split, record schema, label table, first sample                                                                                                  | Schema validates; `npm run accuracy` prints the five shares and the caveats                                                                                                                          |

Steps 327–330 need no one outside the project. Step 331 needs the owner's Cloudflare account: a D1 database, a Turnstile widget, two secrets, and a WAF rule. Step 332 needs a maintainer's time and an owner's decision on sample size.

---

# Part V — Open questions

1. **The attorney corpus.** Still the only route to precision and recall. A public tool with this many users might find volunteer annotators; asking is the owner's call.
2. **Committing exhibit text.** It would let CI catch routing regressions on real documents. It is a copyright judgment — fair use for measurement, or not — and is the owner's to make.
3. **Which findings carry the link.** Start with critical and warning findings only, and read the first month of the queue. The daily ceilings bound the worst case either way.
4. **An absence tag on rules.** "Complete documents draw zero absence findings" cannot be published because findings do not say whether they report an absence. Adding the tag is a rule-schema change that would also sharpen [`spec-v51.md`](spec-v51.md) and [`spec-v52.md`](spec-v52.md).

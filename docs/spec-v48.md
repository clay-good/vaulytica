# Vaulytica v48 — The Agent Surface (A Local-Only MCP Server Over the Same Engine)

> **Status:** **Proposed (2026-10-10).** Not built. Continues the global step numbering after Step 301, beginning at **Step 302**.
> **Scope:** one idea — a coding agent should be able to lint a folder of contracts with the same engine a person uses in the browser, hand back something small enough to read, and leave a person able to spot-check it. No new rule, no engine logic, no hosted service.
> **Distribution (decided):** the static site, the GitHub repository, and this server run from a clone. **Nothing is published to npm, now or later.**
> **Posture (unchanged):** deterministic, no AI in the engine, nothing uploaded, no socket. The agent is a _consumer_ of the report, never a participant in producing it. Vaulytica is the deterministic linter beside the agent.
> **Cousin docs:** [`spec-v8.md`](spec-v8.md) §22 (the Node API this wraps), [`spec-v50.md`](spec-v50.md) (the compact projection), [`spec-v51.md`](spec-v51.md) (the drafting loop), [`spec-v52.md`](spec-v52.md) (folder triage), [`threat-model.md`](threat-model.md).

---

# Part 0 — Why

## §1. What an agent gets today

An agent in a clone can already shell out to `vaulytica analyze`. Measured on 9.853.0:

| Measured                                                         | Result                                                                                                                      |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `analyze mutual-nda-complete.txt --format json`, 6 findings      | **293,645 bytes** (~75K tokens). 274 KB is `run.execution_log`; 255 KB of that is rows for the 1,700 rules that did not run |
| `analyze` on `tests/fixtures/contracts` (24 `.docx`, one `.txt`) | 8.0 MB of JSON across 25 files; the only ranking is 25 stderr lines in filename order                                       |
| Process start per CLI call                                       | ~1.4 s of CPU before analysis begins                                                                                        |
| The same analysis in a warm process                              | 58 ms median, 272 ms maximum, across all 327 specimens                                                                      |
| Text the agent already holds                                     | No stdin: `analyze -` is "no such file or directory"                                                                        |

Six findings cost 75K tokens, and a warm process is twenty times faster than the CLI. Both are packaging problems.

## §2. What v48 is and is not

**It is** `vaulytica mcp`: a Model Context Protocol server over **stdio**, started by the agent host as a child process on the user's own machine, wrapping `tools/cli/api.ts`.

**It is not** a hosted endpoint, an HTTP transport, or anything on vaulytica.com that receives a document. The website is static and stays static. An MCP server needs a process; the site has none, so the site documents the server and the repository ships it.

---

# Part I — The server

## §3. Protocol and dependencies

The first draft of this spec proposed hand-rolling "four JSON-RPC methods." A review against the current protocol found that wrong twice, and both corrections are adopted:

- **The protocol has two live eras.** Revision 2025-11-25 opens with `initialize`; revision 2026-07-28 replaces it with `server/discover` and adds per-request version metadata. Agent hosts in the field probe for the newer one and fall back. A server must answer both, promptly reject unknown methods with `-32601`, accept notifications silently, and exit on stdin EOF.
- **The SDK no longer brings an HTTP stack.** The v1 package (`@modelcontextprotocol/sdk`) depends on `express`, `hono`, and `cors`. The v2 server package (`@modelcontextprotocol/server` 2.3.1) depends on `zod` and its own core, and nothing else. `zod` is already a dependency of this repository.

**Decision:** take `@modelcontextprotocol/server` 2.x as a runtime dependency and use only its stdio transport. A dependency-tree test asserts the package adds no HTTP framework, so an upstream change fails here first. Conformance is tested with `@modelcontextprotocol/client` 2.x as a `devDependency`, over a real spawned process, on both handshake paths.

Other rules of the process:

- **stdout carries protocol frames and nothing else.** At startup the server rebinds `console.log`, `console.info`, and `console.debug` to stderr. The engine writes nothing to stdout today (measured over 327 specimens plus `.docx` and `.pdf`), but nothing guards that; a test now does.
- **No socket, asserted for Node.** `custom-playbook-privacy.test.ts` stubs the browser's network primitives. The MCP guard additionally fails on `net.Socket.prototype.connect`, `http(s).request`, `dgram.createSocket`, and `dns.lookup` across a full session.
- **Not through the current shim.** `bin/vaulytica.mjs` uses `spawnSync`, which cannot forward signals: killing the launcher orphans the child. The `mcp` path either runs `node --import tsx tools/mcp/server.ts` directly or spawns asynchronously and forwards SIGTERM and SIGINT.
- **Lives in `tools/mcp/`**, imports only `tools/cli/api.ts`, and is never imported by `src/`.

## §4. The API has to exist first

Only `analyze_document` is backed by a callable function today. Folder runs, comparison, and export live inside `runAnalyze` and `runCompare`, which parse argv, write to stdout, and set `process.exitCode` in about forty places. Wrapping them would corrupt the protocol stream.

So the first step extracts pure functions into `tools/cli/api.ts` — `analyzeFolder`, `compareFiles`, `exportArtifacts`, `listDocumentTypes`, `describeDocumentType`, `explainRule` — and reduces the CLI commands to thin callers. The existing CLI goldens prove nothing moved. This is the largest piece of work in v48 and it benefits the CLI regardless of MCP.

## §5. The tools

Seven tools, because every extra tool costs an agent context and accuracy. The 29 coherence walkers and `verify` stay CLI-only.

| Tool                     | Input                                                                                             | Returns                                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `analyze_document`       | `path` or `text` (+ `filename`); `document_type`, `min_severity`, `include`, `excerpts`, `cursor` | The compact report (§6)                                                                              |
| `analyze_folder`         | `dir` or `paths[]`; `spot_check`, `related`, `cursor`                                             | The triage result of [`spec-v52.md`](spec-v52.md); `related: true` adds cross-document conflicts     |
| `compare_documents`      | `base_path` or `base_text`; `revised_path` or `revised_text`                                      | `fixed`, `introduced`, `remaining`, `no_longer_present`, `removed` ([`spec-v51.md`](spec-v51.md) §3) |
| `list_document_types`    | `query`, `limit`                                                                                  | `id` and name; description only when `query` is given                                                |
| `describe_document_type` | `id`                                                                                              | The checks that family runs, in plain words, with authorities                                        |
| `explain_rule`           | `rule_id`                                                                                         | Name, version, category, default severity, description, applicable types, resolved citations         |
| `export_report`          | `path`, `formats[]`, `out_dir`, `overwrite`                                                       | Writes the existing artifacts (DOCX, Word comments, `.ics`, CSV); returns the paths                  |

- **Schemas are flat.** `path` and `text` are both optional properties and the server validates that exactly one is present; a root-level `oneOf` is not reliably enforced by hosts.
- **`explain_rule` returns what a rule carries.** Rules have no "what satisfies it" field, so the tool does not promise one.
- **Annotations:** all but `export_report` are read-only and idempotent; none is open-world. `export_report` is not read-only, is non-destructive, and refuses to overwrite without `overwrite: true`.
- **Errors:** an unknown tool is a protocol error; a bad argument or an unreadable file is a result with `isError: true` and a sentence a person can act on.
- **Descriptions fit in 2,048 characters with the caveat first** — one host truncates there.

## §6. The compact result, with budgets

One projection, owned by one module, shared with `--format brief-json` ([`spec-v50.md`](spec-v50.md) §4). It is a **view**: the full JSON, `result_hash`, and `verify` are untouched.

**Kept per finding:** `id`, `rule_id`, `rule_version`, severity, `actionable` (added by [`spec-v51.md`](spec-v51.md) Step 318), title, explanation, recommendation when present, `section_label` when present, `start_offset` and `end_offset` into the ingested text, the excerpt, one citation plus `citations_total`. The offsets and `id` are what let a person open the document and check the finding; they survive `excerpts: false`.

**Kept per document:** matched type, confidence, the match reasoning, severity counts, secondary families as ids and counts (their findings on request — they are "detected, not confirmed"), every caveat (§7), `result_hash`, `dkb_version`, engine version, input SHA-256, and `rules_run` in place of the execution log.

Budgets, each a test, measured against a prototype of this projection (not committed; each step's test replaces it):

| Result                               | Budget                                           | Measured today                                          |
| ------------------------------------ | ------------------------------------------------ | ------------------------------------------------------- |
| `analyze_document`, the NDA specimen | ≤ 8 KB minified                                  | 4.7 KB (7.8 KB with secondary findings included)        |
| `analyze_document`, any specimen     | ≤ 40,000 characters, else truncate with a cursor | With secondary findings: median 3.8 KB, maximum 57.9 KB |
| `analyze_folder`, per document row   | ≤ 300 bytes                                      | 50 full projections would be 254 KB — hence rows        |
| `list_document_types`, no query      | `id` and name only, 50 per page                  | All 268 with descriptions: 74.6 KB                      |

The result is returned once, as text JSON. Returning it again as `structuredContent` doubles every budget; that waits until a host needs it.

**Paging is stateless.** A cursor encodes the input SHA-256 and an offset. If the file changed, the call returns an error, never a page from a different document.

## §7. Honesty, carried to a new surface

An MCP result is a render surface, so it joins `honesty-caveat-reach.test.ts`. Every result carries, when present: the ingest warnings; the `classification_notice` for an unmatched document; the secondary-family caveat; the crashed-rule notice; **`not_analyzed`** for a file that could not be read; and the not-legal-advice line. For a folder: `unreadable[]` and `skipped[]`, so a partial run is never reported as complete.

**Scanned PDFs.** The headless path does not run OCR. A PDF with no text layer must come back as `not_analyzed: no text layer`, not as a short clean report. Today it returns a report with a warning string ([`spec-v52.md`](spec-v52.md) Part 0); Step 305 pins that and changes it.

---

# Part II — Privacy and safety, said plainly

## §8. What "nothing leaves your machine" means under an agent

The engine still opens no socket. But the homepage claim is about the _tool_, and an agent host is not the tool:

- **`path` input:** the engine reads the file locally. The model sees what the result carries, which includes **quoted excerpts**.
- **`text` input:** the agent already held the text, so it had reached the model provider before Vaulytica was called.

The server description says this in its first sentence. `excerpts: false` returns findings with offsets and no quoted text. The server never claims a privacy property the host can break.

## §9. Boundaries

- **Allowed roots.** `--root <dir>` (repeatable) or `VAULYTICA_MCP_ROOTS`; the default is the process working directory. Every input path and `out_dir` is resolved with `realpath` and must sit under a root, so a symlink cannot reach outside. The protocol's own roots feature is deprecated in the newer revision and is not relied on.
- **Caps.** A folder call reads at most 200 files to depth 8; more is an error naming the count. MCP input is capped well below the CLI's 50 MB (Step 306 sets the number from a measurement and tests it), because analysis is about 5 ms per KB and synchronous: a 2 MB text takes 10 seconds, during which the server can answer nothing.
- **Long calls.** `analyze_folder` yields between documents, honors cancellation, and reports progress when the host asks for it.
- **Document text is data.** A contract can say "ignore your instructions." Every document-derived string — excerpt, section label, filename, an interpolated defined term — is confined to named fields, capped (excerpt ≤ 300 characters), and stripped of control characters. A fixture containing an instruction and a forged protocol line must come back with that text inside `excerpt` only, and stdout still valid.
- **No "No AI" drift.** The server's `instructions` string says it is a deterministic rule engine, that findings are prompts to read a clause, and that any narrative the agent adds is the agent's.

---

# Part III — Getting it into an agent

## §10. Install: a clone, and nothing else

```bash
git clone https://github.com/clay-good/vaulytica ~/vaulytica && cd ~/vaulytica && npm ci
```

Then, for Claude Code, from the folder that holds the contracts:

```bash
claude mcp add --scope user vaulytica -- node ~/vaulytica/bin/vaulytica.mjs mcp
```

- The shim's `mcp` path is the one §3 changes.
- The repository also commits a `.mcp.json` for people working **inside** the clone. Contracts are rarely there, so the line above is the documented path.
- Other hosts take the same command in their own config format. The README shows the JSON once.
- Node 22 or newer, as the CLI already requires.
- The site gains `/contract-review-mcp` and an `llms.txt` entry: what the server is, the two lines above, and the privacy paragraph from §8. It is documentation only.

The host behavior above was read from Claude Code's documentation on 2026-10-10, not exercised. Step 307 exercises it.

## §11. The workflow this is for

1. A person asks their agent to check a folder. The agent calls `analyze_folder` and gets one ranked page.
2. The agent opens the two or three documents the page puts first with `analyze_document`.
3. The person checks the named spot-check sample against the documents, using the offsets.
4. If the agent revises a draft, `compare_documents` says what cleared and what did not.

Each step returns something a person can verify without trusting the agent's summary.

## §12. Steps

| Step | Work                                                                                                                                                                                                                 | Verify                                                                                                                                   |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 302  | Extract the pure API functions (§4); CLI commands become thin callers                                                                                                                                                | Every existing CLI golden and drift guard passes unchanged; each extracted function is called by a test with no argv and no stdout write |
| 303  | Compact projection module and `--format brief-json`                                                                                                                                                                  | The §6 budgets; findings equal the full JSON's by `id`                                                                                   |
| 304  | Server process: both handshakes, `analyze_document`, `list_document_types`, stdout and no-socket guards, signal handling                                                                                             | Client conformance on both paths; every stdout line parses; killing the launcher leaves no child                                         |
| 305  | `analyze_folder` returning per-document rows (the triage shape lands in [`spec-v52.md`](spec-v52.md) Step 325), `compare_documents`, `describe_document_type`, `explain_rule`, `export_report`; scanned-PDF status   | `result_hash` equals the CLI's for txt, docx, pdf; comparison hash equals `compare --format json`; exported bytes equal `--out`          |
| 306  | Caveat reach, `excerpts: false`, roots, caps, the injection fixture                                                                                                                                                  | Each guard is broken once on purpose and seen to fail                                                                                    |
| 307  | `.mcp.json`, README, site page, `llms.txt`, `--help`; remove the "Publishing to npm" section and the `npx vaulytica` examples from `ci-integration.md`, and correct the "published npm package" line in `spec-v8.md` | Copy the tracked tree to a temp dir, `npm ci`, start the server from another directory, complete a call                                  |

## §13. Build order across v48–v53

Step numbers follow the specs; the order worth building in does not.

| Order | Steps                                          | Why here                                                                                                                                   |
| ----- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1     | v49 Step 309; v53 Step 329                     | A shipped rule may state a superseded effective date; the site overclaims. Step 329's rewrite and guard only — its links wait for Step 328 |
| 2     | v50 Steps 313–314                              | CLI hygiene and `brief-json`. No finding moves; everything after depends on it                                                             |
| 3     | v48 Steps 302–307                              | The server                                                                                                                                 |
| 4     | v51 Step 318, then v52, then v51 Steps 319–321 | Triage a folder, revise a draft. `actionable` comes first because the triage page counts it                                                |
| 5     | v53 Steps 327–328, 330–331                     | The limits page and the report page (the endpoint needs the owner's Cloudflare account)                                                    |
| 6     | v50 Steps 315–317; v49 the rest; v53 Step 332  | Changes to reports and the catalog, one release each                                                                                       |

---

# Part IV — Open questions

1. **Custom playbooks over MCP.** `--playbook-file` and `--posture` work headless today. Exposing them is a second step, after the seven tools have real use.
2. **A worker thread.** Synchronous analysis is acceptable under the caps in §9. If real folders exceed them, the engine moves off the main thread; that is a change to measure, not assume.
3. **No registry listing.** Distribution is the site, the repository, and the clone.

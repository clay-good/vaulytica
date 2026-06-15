# Vaulytica v16 — Document-Free Coherence Movement

> **Status:** **Shipped (9.13.0).** This spec turns the v15 deferral's own recommendation — "a consumer can recompute the movement from two coherence artifacts, which is the more auditable input" — into the command that actually does it. It continues the global step numbering after v15's Step 195, beginning at **Step 196**. v14 let round one emit its coherence once so round two could gate without round one's documents on disk — but round two still re-analyzed *its own* documents. v16 removes the documents from **both** sides: a new headless `compare-coherence <base.coherence.json> <revised.coherence.json>` subcommand diffs two saved coherence artifacts with the same pure `compareCoherence` the `--baseline-coherence` path uses, verifies both on load (the v14 integrity hash and the v15 cross-ladder guard, now run **between the two artifacts**), and reports the round-over-round movement — with no documents present for either round. One new subcommand, zero new posture math.
> **Scope:** one idea, sitting one axis over from where v14/v15 left the artifact. The posture arc has been a steady removal of what the gate needs on disk: v13 needed *both* rounds' documents (re-analyze the baseline bundle every run); v14 archived round one's coherence so only round two's documents were needed; v16 archives *both* rounds' coherences so **no** documents are needed at gate time. The use case is a dashboard or audit log that stores each negotiation round's kilobyte coherence artifact and shows the binding-floor delta from the archive alone — no clause text, no re-ingestion, no re-analysis. The diff is identical (`compareCoherence` is unchanged); only the *sources* change — from "one artifact + one re-analyzed round" to "two artifacts."
> **Posture (unchanged, non-negotiable):** deterministic (the movement is the same pure `compareCoherence` over two `PostureCoherence` objects — same artifacts → identical `movement_hash`, on any machine, forever), no AI / no probabilistic path, no server (two local files in, one summary out; no socket), citable (the artifacts carry the same per-front, per-document rungs v12 derived from each document's own clause and the team's own playbook — v16 adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The command is **advisory and verifiable**: both artifacts are hash-verified (a tampered baseline is a hard error), the ladders are checked for a match (a cross-ladder diff is refused), and the movement it prints is the same advisory round-over-round signal v13 produces. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on; `diff`/`compare` are its sibling subcommands), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the artifact's payload), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — **the diff this drives**), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — **the artifact this consumes; this command is v14 OQ#2 / v15's "recompute from two artifacts" deferral, now built**), [`spec-v15.md`](spec-v15.md) (Ladder-Pinned Coherence Baselines — **the cross-ladder guard this runs between two artifacts**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

The headless posture surface gates a negotiation round-over-round: `analyze --posture --baseline-coherence round1.coherence.json --fail-on-coherence-regression` fires when the binding floor that governs your exposure regressed. v14 removed round one's documents from that gate; round two's documents still have to be present, because the gate re-analyzes them to compute round two's coherence.

But a dashboard does not re-analyze — it *archives*. The natural workflow that v14's `--emit-coherence` enables is: every round, emit the coherence artifact and store it (a CI build artifact, a commit in the deal repo, a row in an audit log — kilobytes, no clause text). To show "how did the binding floor move from round 3 to round 4," that dashboard already has both coherence artifacts in hand; it has no reason to check out either round's documents. v15's deferral named this exactly: it recommended *against* emitting a derived movement artifact, on the grounds that "a consumer can recompute it from two coherence artifacts, which is the more auditable input." That recommendation assumed a way to recompute a movement from two artifacts. There wasn't one. v16 is that command.

The composition is small because everything it needs already exists and is already tested: `parsePostureCoherenceJson` (v14) verifies each artifact's integrity hash and surfaces its ladder pin; `compareCoherence` (v13) is the pure diff; `coherenceRegressed` (v13) is the gate predicate; `renderCoherenceMovementSummary`/`buildCoherenceMovementJson` (v13) render it. v16 wires them into one subcommand and runs the v15 cross-ladder guard between the two pins.

## §2. What v16 is and is not

**It is:**
- A **document-free movement command.** `compare-coherence <base.coherence.json> <revised.coherence.json>` reads two saved coherence artifacts, verifies both, diffs them, and prints the v13 movement summary (`--format markdown`, default) or its structured JSON (`--format json`). No documents are read; the engine is never run.
- A **CI gate primitive.** `--fail-on-coherence-regression` exits 2 when any front's binding floor regressed to a strictly worse stated rung — the same exit-2 contract `analyze --fail-on-coherence-regression` ships, now over two artifacts. The default (no flag) prints and exits 0.
- A **double-verified input.** Each artifact's `coherence_hash` is re-derived and checked on load (a tampered/corrupt artifact is a hard error, errors prefixed `base:`/`revised:` so you know which side). The v15 cross-ladder guard runs **between the two artifacts**: if both are ladder-pinned (`v2`) and the pins differ, the diff is refused (exit 1); an unpinned (`v1`) artifact on either side proceeds with a note.

**It is not:**
- **Not a new diff, predicate, extractor, or artifact format.** `compareCoherence`, `coherenceRegressed`, `parsePostureCoherenceJson`, the `v1`/`v2` coherence schema, and `TIER_RANK` are all unchanged. v16 is a subcommand that composes them.
- **Not a movement artifact.** v16 does not introduce a third on-disk format (v14 OQ#2's "emit the movement"); it keeps the movement *derived*, recomputed on demand from the two auditable coherence inputs — the path v15 recommended.
- **Not a browser surface.** The browser already does an in-session two-round comparison (v13 Thrust B) where both coherences are computed live in one tab; a "diff two uploaded coherence files" card is a larger UI surface with no demonstrated need (Part XVI).

## §3. The posture filter (unchanged)

1. **Deterministic** — `compareCoherence` over two `PostureCoherence` objects is pure; identical artifacts → identical `movement_hash` on any machine. The two parses and the ladder compare add no nondeterminism.
2. **Honest about unstated data** — the artifacts carry `unevaluable` rungs and `null` floors verbatim; an unstated front round-trips as unstated and is never folded into a movement (the v13 §3 contract, carried over the new sources).
3. **Advisory** — the command prints a movement and, optionally, gates on a regression. It asserts no legal conclusion.
4. **No server** — two local files in, one summary out. No socket, no engine run.
5. **Additive** — a brand-new subcommand. Every existing command (`analyze`, `diff`, `compare`, `verify`) is byte-for-byte unchanged, and every golden is unchanged.

---

# Part I — The command (headless)

`tools/cli/compare-coherence.ts` (a new sibling to `diff.ts`/`compare.ts`):

- **`compareCoherenceArtifacts(baseText, revisedText, format?)`** — the pure, IO-free core (unit-testable like `formatPlaybookDiff`). Parses + verifies both artifacts via `parsePostureCoherenceJson`; on a malformed/tampered side returns `{ ok: false, errors }` with each error prefixed `base:`/`revised:`. Runs the v15 cross-ladder guard between the two `ladderHash` values (both pinned + equal → verified; both pinned + different → `{ ok: false }` with a `ladder mismatch` error; either unpinned → `{ ok: true }` with a `ladderNote`). Then `compareCoherence(base, revised)` and renders the movement (markdown summary or JSON), returning `{ ok: true, output, regressed, ladderNote }`.
- **`runCompareCoherence(argv)`** — the CLI handler: reads the two files, calls the core, writes the `ladderNote` (if any) to stderr, prints the movement to stdout, and — under `--fail-on-coherence-regression` — exits 2 on a regression. A malformed/tampered/cross-ladder input is a hard exit-1 error.

`tools/cli/run.ts` (the dispatcher) gains a `compare-coherence` case and a `USAGE` entry. The `renderCoherenceMovementSummary` renderer moved from `run.ts` to `src/report/coherence-movement.ts` (beside its `buildCoherenceMovementJson` sibling) so both the `analyze --baseline*` path and this command render the movement from one definition, with no cross-import between sibling CLI modules; `run.ts` re-exports it for back-compat.

```
# Each round, archive its coherence (kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture \
  --emit-coherence round1.coherence.json
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture \
  --emit-coherence round2.coherence.json

# Later — show/gate the round-over-round delta from the archive alone, no documents:
vaulytica compare-coherence round1.coherence.json round2.coherence.json \
  --fail-on-coherence-regression
```

---

# Part XV — Build plan

Continuing the global numbering after v15's Step 195. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 196 ✅ | `compare-coherence` subcommand | `tools/cli/compare-coherence.ts` — `compareCoherenceArtifacts` (pure: verify both, cross-ladder guard between the two pins, `compareCoherence`, render markdown/JSON) + `runCompareCoherence` (file IO + exit codes); dispatcher + `USAGE` wired; `renderCoherenceMovementSummary` relocated to `coherence-movement.ts` and re-exported from `run.ts`. Tests: disk-vs-in-memory `movement_hash` identity, markdown summary, no-regression on improve, cross-ladder refusal, unpinned-v1 note, tamper rejection (prefixed), malformed rejection, gate-predicate parity. | Reach |

Total work shipped this spec: **1 build step (196).** Purely additive — a new subcommand; every existing command and golden is unchanged.

---

# Part XVI — Principled deferrals

- **A browser surface for diffing two uploaded coherence files.** ⬜ Deferred. The browser already does an in-session two-round comparison (v13 Thrust B) where both coherences are computed live; uploading two saved artifacts to a tab is a larger UI surface with no demonstrated need. The artifact-diff is a CI/dashboard concern, which is what this command serves.
- **A standalone movement artifact (`--emit-movement`).** ⬜ Still deferred (v14 OQ#2), and now doubly so: v16 makes the movement cheaply recomputable from the two coherence artifacts on demand, which keeps the auditable inputs (the coherences, each ladder-pinned and hash-verified) as the source of truth rather than a derived, separately-stored number.
- **Accept a directory/glob of coherence artifacts and diff a sequence.** ⬜ Not built. A multi-round trend (`round1 → round2 → round3`) is a dashboard concern that can call `compare-coherence` pairwise; a built-in sequence walker is more surface than the one-pair primitive needs. Noted, not built.

---

# Part XVII — Open questions for the maintainer

1. **Should `compare-coherence` accept the same `--format json|markdown` *and* a SARIF emitter?** Today it emits markdown or the movement JSON. A SARIF movement has no consumer (SARIF describes findings on files, and this command has no files), so it is omitted. Recommendation: **leave as markdown/JSON** until a dashboard asks for a different shape.
2. **Print the ladder hash in the summary?** The cross-ladder guard runs silently on success. A team auditing "which ladder did both rounds sit on" reads it from either artifact's `ladder_hash`. Recommendation: **defer** — the artifacts are the auditable source (mirrors spec-v15 OQ#2).

---

# Part XVIII — What this gives the user

- **Gate a negotiation round-over-round with no documents on disk at all.** Archive each round's kilobyte coherence artifact as you go; `compare-coherence` shows or gates the binding-floor delta from the archive alone — no clause text checked out, no re-analysis run, for either round. The thing you most need round-over-round (*did the floor that governs my exposure get worse*), computed from two small, verifiable files.
- **A diff you can trust on both ends.** Both artifacts are hash-verified (a tampered baseline is a hard, side-labeled error), and the v15 cross-ladder guard now runs between them — so a dashboard can never silently diff two rounds that sat on different ladders. The number it shows is provably the movement between the two rounds the team actually emitted.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v16 passes the §3 gate. It composes v13's pure `compareCoherence`, v14's verifying parser, and v15's ladder guard into one headless command; it adds no posture math and no on-disk format, and it leaves every existing surface byte-for-byte unchanged.

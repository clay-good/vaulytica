# Vaulytica v14 — Saved Coherence Baselines

> **Status:** **Thrust A (the artifact) and Thrust B (the headless emit/consume surface + gate) implemented and shipped (9.11.0).** This spec resolves spec-v13's [Open Question #2](spec-v13.md) ("persist a coherence as a baseline artifact instead of re-analyzing?") into a small, additive, headless feature: a **portable, hash-verified coherence artifact**. It continues the global step numbering after v13's Step 191, beginning at **Step 192**. **Thrust A** — a stable `buildPostureCoherenceJson` serializer and a `parsePostureCoherenceJson` parser that re-derives and verifies the embedded `coherence_hash` before trusting the file — is the engine half. **Thrust B** — the CLI `analyze --posture --emit-coherence <path>` (write this round's coherence as an artifact) and `analyze --posture --baseline-coherence <coherence.json>` (diff against a saved coherence instead of re-analyzing the prior round's documents) — is the headless half, composing with the existing `--fail-on-coherence-regression` gate. A browser/DOCX surface is a **principled deferral** (Part XVI): the artifact is a CI/headless concern, and the browser already does an in-session two-round comparison (v13 Thrust B). Every surface is additive — no flag set, no behavior change — so every existing per-document `result_hash`, `coherence_hash`, `movement_hash`, and golden is byte-unchanged.
> **Scope:** one idea, sitting one axis over from where v13 left the posture matrix. v13 diffs two **coherences** to report how a deal package's posture moved round-over-round, but it re-analyzes the baseline package *every run* — which means the prior round's documents (an MSA, an order form, a DPA — often the most confidential artifacts in the deal) must be present on disk, in CI, at gate time. v14 lets round one **emit its coherence once** as a small JSON artifact, and lets round two **gate against that artifact** without ever seeing round one's documents again. The diff is identical (`compareCoherence` is unchanged); only the *source* of the baseline coherence changes — from "re-analyze the bundle" to "load a verified artifact."
> **Posture (unchanged, non-negotiable):** deterministic (the artifact is byte-stable — same coherence → identical bytes, on any machine, forever; the diff that consumes it is the same pure `compareCoherence`), no AI / no probabilistic path, no server (the artifact is a local file; emitting and consuming it open no socket), citable (the artifact carries the same per-front, per-document rungs the v12 coherence already derived from each document's own clause and the team's own playbook — it adds no new claim), lints / references / positions — but never drafts, and never renders a legal conclusion. The artifact is **advisory and verifiable**: it is a snapshot of where the package's binding floor sat on the team's own ladder at one round, fingerprinted so a corrupted or hand-edited baseline can never silently drive a CI gate. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the posture base), [`spec-v11.md`](spec-v11.md) (Posture Movement — the version-over-version axis), [`spec-v12.md`](spec-v12.md) (Posture Coherence — **the artifact this serializes**), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — **the diff this feeds; Open Question #2 is what v14 answers**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v13 gave a deal lead the round-over-round signal: drop round one's package and round two's package, and the analyze run tells you, per negotiation front, whether the binding floor that governs your exposure improved or regressed, and whether any front the package agreed on quietly fractured. To do it, `analyze --posture --baseline <bundle>` re-analyzes the baseline bundle on every run.

That re-analysis has a cost that only shows up in practice. The baseline is *round one's documents* — and in a live deal, round one's documents are exactly the artifacts a team is most careful with: the executed MSA, the counterparty's first order form, a DPA under NDA. To gate round two in CI, every one of those files has to be checked out into the CI runner next to round two's files, every run, forever. That is more confidential material on disk than the gate actually needs: the gate does not need round one's *documents*, it needs round one's *coherence* — the handful of per-front rungs the v12 engine already distilled from them.

spec-v13's Open Question #2 named this exactly and deferred it ("re-analyze in v13 — a saved-coherence import is a larger surface deferred until asked"). v14 is the answer, now asked. The composition is small because v13 already did the hard part: the diff is `compareCoherence(base, revised)`, a pure function over two `PostureCoherence` objects. v14 only adds a way to **write** one of those objects to disk and **read** it back, verified. Round one runs `analyze --posture --emit-coherence round1.coherence.json` and archives the tiny artifact (a CI build artifact, a commit in the deal repo — kilobytes, no clause text). Round two runs `analyze --posture --baseline-coherence round1.coherence.json --fail-on-coherence-regression`, and the gate fires on a regressed binding floor exactly as v13's gate does — without round one's documents present at all.

## §2. What v14 is and is not

**It is:**
- A **portable, hash-verified coherence artifact.** `buildPostureCoherenceJson(coherence)` serializes a `PostureCoherence` to stable, pretty-printed JSON tagged `vaulytica.posture-coherence.v1`, carrying the `coherence_hash`, the per-kind `counts`, and the full per-front, per-document rung set. `parsePostureCoherenceJson(text)` is the inverse: it structurally validates the file, then **re-derives the `coherence_hash` from the artifact's own dimensions** and rejects the file when it does not match the embedded hash. The hash makes the artifact trustworthy: a truncated, corrupted, or hand-edited baseline is a hard error, never a silent gate input. `counts` is **recomputed** from the verified dimensions on load, never imported (the hash covers dimensions only, so a derived tally is re-derived).
- A **second source for the same diff.** `analyze --posture --baseline-coherence <coherence.json>` resolves a baseline coherence by loading and verifying the artifact, then hands it to the same `compareCoherence` the v13 `--baseline` path uses. The movement — and its `movement_hash` — is byte-identical to re-analyzing the same baseline bundle (proven by test: a coherence emitted to disk, loaded, and diffed yields the same `movement_hash` as the in-memory diff).
- An **emit surface.** `analyze --posture --emit-coherence <path>` writes the current round's coherence artifact (when the round produced a cross-document coherence — ≥2 documents bearing a posture). Off by default; a run with no `--emit-coherence` writes nothing new.

**It is not:**
- **Not a new diff, predicate, or extractor.** `compareCoherence`, `coherenceRegressed`, `bundlePostureCoherence`, and `TIER_RANK` are all unchanged. v14 is serialization plus a CLI wiring; the posture math is v10–v13's.
- **Not a cross-ladder safety net.** The hash verifies the artifact's *integrity*, not that the two rounds used the **same** playbook ladder. Comparing a floor computed from one ladder against a floor from another is nonsense — the same §3 contract v11 enforces for movements and v13 for re-analyzed baselines. The caller owns ladder-match (use the same `--playbook-file` to emit and to consume), exactly as v13's re-analyze path requires.
- **Not a browser/DOCX feature (yet).** The artifact is a headless/CI concern. The browser already does an in-session two-round comparison (v13 Thrust B), and a "upload a saved coherence" card is a larger UI surface deferred until asked (Part XVI), mirroring v13's own deferral of saved-posture import.

## §3. The posture filter (unchanged)

Every v14 surface is checked against the same five-part filter v10 introduced, restated for the artifact:

1. **Deterministic** — `buildPostureCoherenceJson` emits identical bytes for identical input (fixed key order; the dimension/document order is already pinned by `bundlePostureCoherence`). Round-tripping through disk is the identity on the coherence.
2. **Honest about unstated data** — the artifact carries `unevaluable` rungs and `null` binding floors verbatim; an unstated front round-trips as unstated and is never folded into a movement on load.
3. **Advisory** — the artifact is a snapshot of rungs on the team's own ladder. It asserts no legal conclusion; consuming it produces the same advisory movement v13 produces.
4. **No server** — the artifact is a local file. Emit writes one path; consume reads one path. No socket.
5. **Additive** — `--emit-coherence` and `--baseline-coherence` are off by default. With neither flag, the CLI behaves exactly as it did in v13, so every golden is byte-unchanged.

---

# Part I — Thrust A: the artifact (engine)

`src/report/posture-coherence.ts` grows two exports and one factored-out helper:

- **`buildPostureCoherenceJson(coherence): string`** — the serializer. Stable, pretty-printed (2-space) JSON: `{ schema, coherence_hash, counts, dimensions }`, with `dimensions[].tiers[]` in the pinned document order. Modeled on v13's `buildCoherenceMovementJson`.
- **`parsePostureCoherenceJson(text): Promise<ParsedCoherence>`** — the verifying parser. Returns `{ ok: true, coherence } | { ok: false, errors }` (the `parseCustomPlaybookJson` shape — never throws, surfaces every structural error at once). After the structural pass it re-derives the `coherence_hash` via the factored-out `coherenceHash(dimensions)` and rejects on any mismatch. `counts` is recomputed from the verified dimensions.
- **`coherenceHash(dimensions)`** (private) — factored out of `bundlePostureCoherence` so the producer computes it and the parser re-derives it from the same canonical shape. One definition of the fingerprint, used both to stamp and to verify.
- **`COHERENCE_ARTIFACT_SCHEMA`** — the `"vaulytica.posture-coherence.v1"` schema tag, exported for callers/tests.

The verification is the load-bearing idea. A coherence that drives a CI gate is only as trustworthy as the bytes it was loaded from; re-deriving the hash from the artifact's own content (rather than trusting the embedded value) makes tampering and corruption a hard, legible error — `coherence_hash mismatch — the artifact was modified or is corrupt (embedded …, recomputed …)`.

# Part II — Thrust B: emit & consume (headless)

`tools/cli/run.ts` (the `analyze` command) grows two flags:

- **`--emit-coherence <path>`** (requires `--posture`) — after the round's coherence is computed, write `buildPostureCoherenceJson(coherence)` to `<path>`. A round that yields no coherence (fewer than two documents with a posture) prints a clear stderr note rather than silently writing nothing.
- **`--baseline-coherence <coherence.json>`** (requires `--posture`; mutually exclusive with `--baseline`) — read, parse, and verify the artifact, then use it as the baseline for `compareCoherence` instead of re-analyzing a baseline bundle. A missing file or an invalid/tampered artifact is a hard error (exit 1) with the parser's messages.

`--fail-on-coherence-regression` now accepts **either** baseline source (it required `--baseline` in v13; it now requires `--baseline` *or* `--baseline-coherence`). The gate logic — exit 2 when any front's binding floor regressed to a strictly worse stated rung — is unchanged; only the baseline source is pluggable.

```
# Round one — emit the coherence artifact (archive it; kilobytes, no clause text):
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture \
  --emit-coherence round1.coherence.json

# Round two — gate against the artifact, no round-one documents on disk:
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture \
  --baseline-coherence round1.coherence.json --fail-on-coherence-regression
```

---

# Part XV — Build plan

Continuing the global numbering after v13's Step 191. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 192 ✅ | Coherence artifact | `buildPostureCoherenceJson` / `parsePostureCoherenceJson` in `posture-coherence.ts`; `coherenceHash` factored out; `COHERENCE_ARTIFACT_SCHEMA`. Parser re-derives and verifies the hash, recomputes counts, rejects tamper/schema/malformed input. Unit tests: round-trip identity, hash integrity, tamper rejection, wrong schema, malformed JSON, invalid tier/kind, count recomputation. | Artifact |
| 193 ✅ | CLI emit & consume | `analyze --posture --emit-coherence <path>` (write the round's coherence) and `--baseline-coherence <coherence.json>` (diff against a saved coherence; mutually exclusive with `--baseline`); `--fail-on-coherence-regression` accepts either source. Integration test: a disk-round-tripped coherence yields the same `movement_hash` as the in-memory diff. | Artifact |

Total work shipped this spec: **2 build steps (192–193).** Every step is additive — neither flag set means the CLI is byte-identical to v13.

---

# Part XVI — Principled deferrals

- **A browser/DOCX surface for the artifact.** ⬜ Deferred. The artifact is a CI/headless concern — its value is gating round two without round one's documents in the runner. The browser already does an in-session two-round comparison (v13 Thrust B, the "Compare a revised round…" card), and a "download/upload a saved coherence" affordance is a larger UI surface. Recommendation: **headless-only in v14**, mirroring v13's deferral of a saved-posture import, until a user asks for the browser round-trip.
- **Cross-ladder verification.** ⬜ Not built (by design). The hash verifies artifact integrity, not ladder-match between rounds. Stamping the playbook's identity into the artifact and refusing a mismatched consume is a genuine guard, but it requires a stable playbook fingerprint and changes the artifact schema; recommendation: **document the caller's contract in v14** (same `--playbook-file` to emit and consume), and revisit a playbook-pinned artifact if a team reports a cross-ladder foot-gun.
- **Emit in other formats.** ⬜ Not built. A coherence artifact is JSON only; a SARIF/CSV coherence has no consumer (the gate reads JSON). Noted, not built.

---

# Part XVII — Open questions for the maintainer

1. **Pin the playbook into the artifact?** Today the artifact carries the rungs but not the ladder that produced them. A `playbook_hash` field plus a consume-time check would turn the cross-ladder foot-gun into a hard error. Recommendation: **document the caller's contract in v14**; add the pin if a team hits the foot-gun, since it is a schema change (`vaulytica.posture-coherence.v2`).
2. **Emit the movement as an artifact too?** v13 already emits a movement JSON in the DOCX path (`buildCoherenceMovementJson`). A headless `--emit-movement <path>` would let a dashboard ingest the round-over-round delta directly. Recommendation: **defer** — the movement is derived; a consumer can recompute it from two coherence artifacts, which is the more auditable input.

---

# Part XVIII — What this gives the user

- **Gate round two without round one's documents.** Emit round one's coherence once; archive the kilobyte artifact. Round two's CI gate diffs against it — the same regressed-binding-floor gate v13 ships — without ever checking out round one's confidential package. The thing you most need round-over-round (*did the floor that governs my exposure get worse*) computed without re-handling the prior round's documents.
- **A baseline you can trust.** The artifact is fingerprinted; a corrupted or hand-edited baseline is a hard, legible error, never a silent gate input. The number a CI dashboard shows is provably the number the prior round produced.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v14 passes the §3 gate. The artifact serializes a coherence the v12 engine already produced from one posture per document, each citing the team's own playbook and that document's own clause; the diff that consumes it is v13's pure `compareCoherence`, unchanged; and the round-over-round gate fires identically, now without the prior round's documents on disk.

# Vaulytica v15 — Ladder-Pinned Coherence Baselines

> **Status:** **Shipped (9.12.0).** This spec resolves spec-v14's [Open Question #1](spec-v14.md) ("pin the playbook into the artifact?") and the Part XVI "Cross-ladder verification" deferral into one small, additive guard: a saved coherence artifact now **fingerprints the negotiation-posture ladder its rungs were computed against**, and a consuming round **refuses to diff it against a round computed on a different ladder**. It continues the global step numbering after v14's Step 193, beginning at **Step 194**. **Thrust A** — a stable `ladderHash(playbook)` over exactly what determines a tier (each position's `dimension` + `ideal`/`acceptable` predicates, plus the named `thresholds` they reference; per-tier `guidance` excluded) — is the verification key. **Thrust B** — a `vaulytica.posture-coherence.v2` artifact that carries the `ladder_hash`, emitted automatically by `analyze --posture --emit-coherence` (the ladder is always present there), and verified at `--baseline-coherence` consume time — is the headless guard. Every surface is additive: `buildPostureCoherenceJson` with no ladder hash still emits a byte-identical `v1` artifact, the parser still accepts `v1`, and a run with neither emit nor consume flag is unchanged from v14.
> **Scope:** one idea, one axis over from where v14 left the artifact. v14 made the coherence portable and hash-verified for **integrity** (a tampered baseline is a hard error). But integrity is not identity: the hash proves the *bytes* were not altered, not that the two rounds sat on the **same ladder**. A team that emits round one against `inbound-saas.playbook.json` and gates round two against `outbound-msa.playbook.json` gets a movement that is arithmetic over two unrelated ladders — a number, but a meaningless one, and worse, a *green or red CI gate* driven by it. v15 closes that hole: the artifact carries the ladder's fingerprint, and the consume path makes a ladder mismatch a hard, legible error instead of a silent nonsense diff.
> **Posture (unchanged, non-negotiable):** deterministic (`ladderHash` is a pure SHA-256 over a canonical, order-pinned ladder — same ladder → identical fingerprint, on any machine, forever), no AI / no probabilistic path, no server (the artifact is a local file; the guard is a string compare), citable (the artifact still carries the same per-front, per-document rungs v12 derived from each document's own clause and the team's own playbook — the ladder hash adds no new claim, it *protects* the existing one), lints / references / positions — but never drafts, and never renders a legal conclusion. The guard is **advisory and verifiable**: it never says a term is adequate, only that you are about to compare two floors that do not live on the same ladder. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v8.md`](spec-v8.md) (Reach — the headless CLI this rides on), [`spec-v10.md`](spec-v10.md) (Negotiation Posture — the ladder this fingerprints), [`spec-v11.md`](spec-v11.md) (Posture Movement — the cross-ladder contract this enforces), [`spec-v12.md`](spec-v12.md) (Posture Coherence — the rungs the artifact carries), [`spec-v13.md`](spec-v13.md) (Cross-Document Posture Movement — the diff this protects), [`spec-v14.md`](spec-v14.md) (Saved Coherence Baselines — **the artifact this pins; Open Question #1 is what v15 answers**). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

v14 let round one emit its coherence once and round two gate against it, without round one's documents on disk. The artifact is hash-verified, so a corrupted or hand-edited baseline is a hard error — its **integrity** is provable.

But the diff that consumes the artifact, `compareCoherence(base, revised)`, matches fronts **by dimension label** and compares their rungs. Two rungs are only comparable if they sit on the **same ladder** — the same `ideal`/`acceptable` predicates defining what "ideal" and "acceptable" *mean* for that dimension. v10 §3 named this; v11 enforces it for movements (a cross-ladder movement is refused); v13's re-analyze `--baseline` path enforces it implicitly (it runs the **same** `--playbook-file` over both rounds). The one path that did **not** enforce it was v14's `--baseline-coherence`: the artifact carried the rungs but not the ladder, so nothing stopped a team from gating round two against a baseline emitted under a *different* playbook. The result is a movement computed over two unrelated ladders — and a CI gate (`--fail-on-coherence-regression`) firing, or staying green, on that nonsense.

v14's Open Question #1 named this exactly and deferred it ("document the caller's contract in v14; add the pin if a team hits the foot-gun"). v15 adds the pin. The composition is small because the artifact and the ladder both already exist: v15 only fingerprints the ladder, stamps the fingerprint into the artifact, and compares it at consume time.

## §2. What v15 is and is not

**It is:**
- A **stable ladder fingerprint.** `ladderHash(playbook)` is a SHA-256 over the canonical ladder: each negotiation position's `dimension` and its `ideal`/`acceptable` predicates (sorted by dimension, machine-independent), plus the named `thresholds` those predicates may reference. Per-tier `guidance` is **excluded** — it is advisory display text and never changes which tier a document lands on, so editing it must not break a baseline. A playbook with no `negotiation_positions` has no ladder and hashes to `null`.
- A **ladder-pinned artifact.** `buildPostureCoherenceJson(coherence, ladderHash)` emits a `vaulytica.posture-coherence.v2` artifact carrying `ladder_hash` alongside the v14 fields. The `ladder_hash` is **independent of `coherence_hash`** (which still covers `dimensions` only), so the v1 and v2 artifacts of one coherence share the same integrity hash; the pin is an identity field, not part of the integrity fingerprint.
- A **consume-time guard.** `analyze --posture --baseline-coherence <v2.json>` computes this round's `ladderHash` from its `--playbook-file` and **refuses with exit 1** when it does not match the artifact's pin — `ladder mismatch — the artifact was computed against a different playbook ladder`. A `v1` (unpinned) artifact still loads, with a clear note that cross-ladder verification is unavailable (v14's caller-owns-it contract).

**It is not:**
- **Not a new diff, predicate, or extractor.** `compareCoherence`, `coherenceRegressed`, `bundlePostureCoherence`, and `TIER_RANK` are all unchanged. v15 is one fingerprint, one artifact field, and one consume-time compare.
- **Not a breaking change.** `buildPostureCoherenceJson(coherence)` with no ladder hash emits a byte-identical `v1` artifact; the parser accepts both `v1` and `v2`; every existing golden and round-trip is unchanged. The pin is **additive**.
- **Not a content-equivalence proof.** The fingerprint proves the two rounds used the **same ladder definition**, not that the ladder is *correct* or that the documents are comparable in any deeper sense. It closes the foot-gun the spec named; it makes no broader claim.

## §3. The posture filter (unchanged)

1. **Deterministic** — `ladderHash` is a pure SHA-256 over a key-sorted, dimension-sorted canonical ladder; identical ladders → identical fingerprint on any machine. The artifact's key order is fixed; round-tripping through disk is the identity.
2. **Honest about unstated data** — a playbook with no positions has no ladder (`null`); the guard never invents a pin where there is no ladder to fingerprint.
3. **Advisory** — the guard refuses an incomparable diff; it asserts no legal conclusion.
4. **No server** — `ladderHash` is local; the guard is a string compare. No socket.
5. **Additive** — no ladder hash ⇒ a `v1` artifact byte-identical to v14; neither emit nor consume flag ⇒ the CLI is unchanged.

---

# Part I — Thrust A: the ladder fingerprint (engine)

`src/playbooks/custom-interpreter.ts` grows one export:

- **`ladderHash(playbook): Promise<string | null>`** — SHA-256 over `{ positions: [{ dimension, ideal, acceptable }] (sorted by dimension), thresholds }`. `guidance` is excluded by construction. Returns `null` for a playbook with no `negotiation_positions`. It lives beside `evaluateNegotiationPosture` (the function that turns a ladder into rungs), reusing the same `sha256Hex` + `stableStringify` canonicalization the engine uses everywhere.

The fingerprint covers **exactly** what determines a tier — the two predicates per dimension and the thresholds they read — and nothing that does not (`guidance`, `rule_overrides`, `custom_rules`, `required_clauses` all affect findings, not posture). Tight by design: a team can re-word their negotiation guidance without invalidating a baseline, but cannot loosen a floor without the baseline noticing.

# Part II — Thrust B: the pinned artifact + guard (headless)

`src/report/posture-coherence.ts`:

- **`COHERENCE_ARTIFACT_SCHEMA_V2`** (`"vaulytica.posture-coherence.v2"`) joins `…V1`; `COHERENCE_ARTIFACT_SCHEMA` remains an alias of v1 for back-compat. The parser accepts both.
- **`buildPostureCoherenceJson(coherence, ladderHash?)`** — emits `v2` with `ladder_hash` when given one; `v1` (byte-identical to v14) when not.
- **`parsePostureCoherenceJson`** — accepts both; requires `ladder_hash` on `v2`, rejects a stray `ladder_hash` on `v1`, and returns `ladderHash: string | null` on the `ok` result.

`tools/cli/run.ts` (the `analyze` command):

- **Emit** — `--emit-coherence` now computes `ladderHash(customPlaybook)` and passes it to the serializer, so every newly emitted artifact is a pinned `v2`. (The ladder is always available: `--emit-coherence` requires `--posture` requires `--playbook-file`.)
- **Consume** — `--baseline-coherence` compares the artifact's `ladderHash` against this round's. A mismatch is a hard error (exit 1); a `v1` artifact (no pin) loads with a note and falls back to the v14 contract.

```
# Round one — emit a ladder-pinned coherence artifact:
vaulytica analyze 'round1/*.docx' --playbook-file team.playbook.json --posture \
  --emit-coherence round1.coherence.json

# Round two — same ladder → the gate runs; a different --playbook-file → hard error:
vaulytica analyze 'round2/*.docx' --playbook-file team.playbook.json --posture \
  --baseline-coherence round1.coherence.json --fail-on-coherence-regression
```

---

# Part XV — Build plan

Continuing the global numbering after v14's Step 193. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property gates, the v8 fuzz + citation gates, the v9 no-wall-clock gate, and the responsiveness e2e stay green.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 194 ✅ | Ladder fingerprint | `ladderHash(playbook)` in `custom-interpreter.ts` — stable SHA-256 over the canonical ladder (positions + thresholds; guidance excluded); `null` for no positions. Unit tests: order-independence, guidance-insensitivity, predicate/threshold-sensitivity, null on empty. | Posture |
| 195 ✅ | Pinned artifact + guard | `COHERENCE_ARTIFACT_SCHEMA_V2`; `buildPostureCoherenceJson(coherence, ladderHash?)` emits `v2` with `ladder_hash` (v1 byte-identical without); parser accepts both, returns `ladderHash`. CLI: `--emit-coherence` pins the ladder; `--baseline-coherence` refuses a ladder mismatch (exit 1), notes a v1 artifact. Tests: v2 round-trip, coherence_hash independence, v2-missing-pin / v1-stray-pin rejection, guard accept/reject. | Artifact |

Total work shipped this spec: **2 build steps (194–195).** Every step is additive — no ladder hash means a `v1` artifact byte-identical to v14, and neither emit nor consume flag means the CLI is unchanged.

---

# Part XVI — Principled deferrals

- **A browser/DOCX surface for the artifact.** ⬜ Still deferred (v14 Part XVI). The artifact remains a CI/headless concern; the browser does an in-session two-round comparison where the ladder is shared by construction, so it has no cross-ladder foot-gun to guard.
- **Emit the movement as an artifact too** (v14 Open Question #2). ⬜ Still deferred. A movement is derived; a consumer can recompute it from two coherence artifacts, which is the more auditable input — and now both inputs carry their ladder pin.
- **A version field beyond the ladder** (e.g. engine/catalog version in the pin). ⬜ Not built. The ladder is what `compareCoherence` reads; the engine version already rides each document's `result_hash` and the bundle fingerprint. Pinning more than the ladder would reject comparable baselines (a patch engine release that does not touch posture classification), trading a real guard for false alarms. Noted, not built.

---

# Part XVII — Open questions for the maintainer

1. **Pin the threshold *values* a position does not reference?** Today the fingerprint includes the entire `thresholds` map, not only the names a position reads. A team that adds an unrelated threshold (used by a custom *rule*, not a position) invalidates the ladder pin even though no floor moved. Recommendation: **keep the whole map** — it is the simplest correct over-approximation, and a spurious mismatch is a *safe* failure (it refuses a diff that is in fact still comparable, rather than admitting one that is not). Narrow it to position-referenced thresholds only if a team reports the false alarm.
2. **Surface the ladder hash in the human report?** The artifact carries it, but the DOCX/HTML posture section does not print it. A team auditing "which ladder produced this baseline" reads it from the JSON. Recommendation: **defer** — it is a CI/artifact concern, and the JSON is the auditable source.

---

# Part XVIII — What this gives the user

- **A gate you cannot accidentally point at the wrong ladder.** Emit round one against your playbook; gate round two against the artifact. Swap the playbook by mistake — a different file, a renamed fork, a colleague's variant — and the gate **stops** with a legible error instead of reporting a green or red result computed over two unrelated ladders. The most dangerous failure of a CI gate is the *confident wrong answer*; v15 turns that into a hard stop.
- **A baseline you can re-word without breaking.** The fingerprint excludes per-tier `guidance`, so editing your negotiation talking-points never invalidates an archived baseline. Only a change to what `ideal`/`acceptable` actually *test* — the thing that would genuinely make two rounds incomparable — moves the pin.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v15 passes the §3 gate. The pin is a pure hash of the team's own ladder; the guard is a string compare; the artifact it protects still serializes a coherence the v12 engine produced from one posture per document, each citing the team's own playbook and that document's own clause.

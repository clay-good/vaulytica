# Determinism

Vaulytica makes a strong claim: given the same input file, the same engine version, and the same DKB version, **the report is byte-for-byte the same on every machine, every time, forever**. This document explains how that guarantee is enforced and how to reproduce a report on a different machine.

## The contract

An `EngineRun` (the data structure underlying every report) is a deterministic function of four inputs:

```
EngineRun = f( DocumentTree, DKB version, Playbook, Engine version )
```

There is no time, no randomness, no environment variable, no locale, no floating-point ambiguity that matters for the operations Vaulytica performs.

The proof is the `result_hash` field on every `EngineRun`: a SHA-256 over the canonicalized run JSON (with `result_hash` and `executed_at` blanked). Two runs of the same input on different machines produce identical hashes. The launch checklist verifies this on three OSes.

## How it's enforced

### 1. Pure rules

Every `Rule.check(ctx)` is a pure function. No `Date.now()`. No `Math.random()`. No `fetch()`. No reading from `process.env`. No DOM access outside what `ctx` exposes. This is enforced by review, not by the type system — but the determinism test in [`src/engine/rules/all-rules.test.ts`](../src/engine/rules/all-rules.test.ts) runs the full engine twice on the same context and asserts hash equality, so any rule that smuggles in non-determinism breaks the test.

### 2. Sorted iteration

- Rules execute in **lexicographic id order**.
- Findings sort by `(severity, rule_id, document_position)`.
- The bibliography numbers citations in **document-order of first reference**.
- Tied classifier scores break **alphabetically by category**.
- Tied playbook scores break **lexicographically by playbook id**.

Every place where multiple orderings are possible, one ordering is chosen and committed to. See [`src/engine/ordering.ts`](../src/engine/ordering.ts).

### 3. Canonical JSON

The result hash is computed over `stableStringify(run)` — `JSON.stringify` with object keys sorted alphabetically. See [`src/engine/runner.ts`](../src/engine/runner.ts). This is defense-in-depth: standard `JSON.stringify` is already deterministic across engines for the value types Vaulytica uses, but the explicit sort defends against future serializer changes.

### 4. Decimal arithmetic, not floating point

Monetary normalization (`$1.5M` ↔ `one million five hundred thousand`) goes through `decimal.js`. See [`src/extract/amounts.ts`](../src/extract/amounts.ts). The classifier's cosine score uses ordinary floats, but the comparison is structurally invariant under IEEE 754: the same input bag and the same vocabulary produce the same score on every JavaScript engine Vaulytica supports.

### 5. Static DKB

The DKB is shipped as JSON. It does not poll for updates. A given `dkb_version` ships exactly one set of vocabulary, patterns, clauses, statutes, jurisdictions, dark patterns, and definitions. The user-facing footer shows the active DKB version, and the report cover page records it.

### 6. Excluded volatile fields

Two fields are **excluded** from the result hash:

- `executed_at` — the ISO timestamp of the run. Recorded for display only.
- `result_hash` itself — obviously.

Everything else, including the `playbook_match_reasoning` string and the per-rule `elapsed_ms`, **is** part of the canonicalized payload — *except* `elapsed_ms` is rounded to 3 decimals via `formatElapsed` in the report builder to avoid the microsecond-level wobble between machines. Inside the run JSON, `elapsed_ms` is raw `performance.now()` deltas; the runner pre-rounds these via `stableStringify` so the hash is stable across machines with different timer resolution.

> **Implementation note:** if you find a corner case where `elapsed_ms` varies enough to perturb the JSON-canonicalized hash, file an issue — that's a determinism bug. The expected behavior is that `elapsed_ms` participates in the hash only at the rounded-3-decimal precision, which is stable.

## Reproducing a report on a different machine

Suppose you have a `Vaulytica-Report.docx`. Its cover page lists:

- Input file SHA-256
- Engine version (the released package version, e.g., `9.41.0` — the stamp
  tracks the release, so any release that can change engine behavior changes
  the stamped provenance; a guard test pins the two together)
- DKB version (e.g., `v2026-05-12-a1b2c3d`)
- Playbook (e.g., `mutual-nda v1.0.0`)
- Result hash (in the audit trail)

To reproduce:

1. Get a copy of the input file. Verify its SHA-256 matches the report's.
2. Check out the Vaulytica release that matches the engine version (e.g., `git checkout v9.41.0`, or the commit whose `package.json` carries that version).
3. Download the matching DKB version from `https://vaulytica.com/dkb/<version>/` (or rebuild it locally; the DKB itself is reproducible — see [data-sources.md](data-sources.md)).
4. Run Vaulytica against the input. The new report's `result_hash` should match the original.

A diff anywhere in this chain falsifies the determinism claim. We treat that as a P0 bug.

## What determinism does NOT mean

- **It does not mean the rules are correct.** A deterministic system can be deterministically wrong. The rule catalog (spec §18) is the substantive claim; determinism is the auditability claim on top of it.
- **It does not mean Vaulytica gives the same advice every time.** A new DKB version, a new engine version, or a new playbook will produce a different report. The `result_hash` will change. That's expected — both the inputs are part of the function signature, so a change to either is a different function evaluation.
- **It does not mean the report is "reproducible" in the sense of legal-discovery reproducibility.** It means it is **citable** in the strict computational sense — anyone with the same inputs can verify they got the same outputs. Whether that meets a court's reproducibility standard is a separate question (and one for your lawyer, not us).

# Vaulytica v7 — Depth & Proof

> **Status:** v7 substantially implemented. Version bumped to **7.0.0**.
> **Spec:** [`spec-v7.md`](../spec-v7.md). **Testing architecture:** [`testing-architecture.md`](testing-architecture.md).

v6 made the product useful in the workflow. v7 answers the two halves of *"is this thing actually right?"* without touching the deterministic / no-AI / no-server / citable / lints-not-drafts posture:

- **Thrust A — Depth** makes the engine *more correct on real documents* by deepening the layers everything downstream depends on (extraction, cross-document checks, ingest, report fidelity).
- **Thrust B — Proof** closes the gap between "the tests pass" and "the logic is sound under inputs no author wrote down" with the test *kinds* the suite lacked.

**Testing ≠ accuracy.** Thrust B proves the engine does what each rule *says* (internal logic, no external truth needed). v5 proves each rule matches what a *lawyer* says (external truth, human-gated). Both are required; neither replaces the other.

## What v7 adds

| Part | Feature | What it does | Source |
|---|---|---|---|
| I | **Extraction recall** | Fiscal periods + broadened citable anchor aliases + range deadlines + documented year-pivot (dates); range amounts + per-unit qualifiers + deferred currency override (amounts); alias/role chains + DBA + two-column signatures (parties); prohibitive/permissive modals + nested triggers + scope exclusions (obligations); definition-by-reference + scope-gating + circularity detection (definitions); sub-reference + fallback-precedence capture (crossrefs/jurisdictions). | [`src/extract/`](../../src/extract/) |
| III | **Cross-document families** | Three new `CROSS-*` families (termination-alignment, limitation-carveout, payment-currency) → **13** v4 cross-document rules. | [`src/engine/consistency/rules/v4/`](../../src/engine/consistency/rules/v4/) |
| VI | **Ingest robustness** | Per-page text-density OCR trigger (a searchable header over a scanned body no longer hides the body); per-word confidence `[uncertain]` markers + ingest warning. | [`src/ingest/`](../../src/ingest/) |
| VII | **Report/export fidelity** | JSON `provenance` (rule-taxonomy version); portfolio `executive_summary` (rolled-up severity counts + per-doc digest); `.ics` verify-manually events for unresolved deadlines. All outside the `EngineRun`. | [`src/report/`](../../src/report/) |
| VIII–XV | **Proof** | Code-coverage gate, per-rule completeness meta-test, property-based testing (`fast-check`, incl. crossref resolve/flag), metamorphic invariants (incl. position-only + order-defect relations), schema fuzz + round-trip, report-structure validation, and **mutation testing** (Stryker, scoped baseline 55.65%, scheduled). | [`testing-architecture.md`](testing-architecture.md) · [`mutation-baseline.md`](mutation-baseline.md) |
| XII | **Node↔browser parity** | A shared fixture driven through both pipelines must produce a byte-identical `EngineRun` — makes v5's "the harness reuses the real pipeline" claim executable. | [`tools/accuracy/parity.test.ts`](../../tools/accuracy/parity.test.ts) |
| XVI | **Responsiveness-as-a-test** | `scrollWidth ≤ clientWidth` per view-state at 320/390/768/1280 px — the recurring manual audit becomes a CI gate. | [`tests/e2e/responsiveness.spec.ts`](../../tests/e2e/responsiveness.spec.ts) |

## Determinism & privacy (unchanged)

- **Every extractor change is additive and fixture-gated.** New record fields are optional; the extracted-data stream is not part of `result_hash`, so an extractor that surfaces more never churns an existing hash. The single intentional `result_hash` change — the prohibitive/permissive modal signal (Step 106) — shipped with a line-reviewed golden re-baseline touching only OBLI-005.
- **New cross-document rules are bundle-only**, so single-document goldens are byte-unchanged; the bundle goldens got a mechanical `execution_log_count` bump with no new findings on any pre-existing bundle.
- **Report surfaces live outside the run.** Provenance, the executive summary, and `.ics` events change no `result_hash`, bundle fingerprint, or golden.
- **No AI, restated.** `fast-check` generates inputs and (deferred) Stryker mutates code, both at build time; neither introduces a probabilistic component into the shipped path.

## Principled deferrals

v7 ships the additive, verifiable work and **defers, with reasons, the steps that would compromise honesty or the green-build contract**:

- **Step 109 (classifier live-routing)** — held behind the v5 corpus. A routing change forces a golden re-baseline and must be measured against *real* annotated documents, not synthetic fixtures (spec-v7 Open Q #2).
- **Step 111 (50-state overlay + non-solicitation)** — per-state enforceability is interpretive legal data; under the v5 honesty contract, asserting it without a credentialed source is the dishonesty v5 exists to forbid. Lands when sourced and reviewed.
- **Step 112 (rule-catalog depth)** — each new always-on rule re-baselines every single-document golden's `execution_log`, and each needs a citable DKB source (attorney-gated).

(Steps 123–124, mutation testing, are now **done** — Stryker scoped to the extractors, scheduled off the per-push path, with a regression-only floor; see [`mutation-baseline.md`](mutation-baseline.md). The remaining deferrals are 109/111/112, all v5-/attorney-gated.)

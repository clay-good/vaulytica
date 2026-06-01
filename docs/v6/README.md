# Vaulytica v6 — Workflow

> **Status:** v6 complete. All steps 87–102 landed. Version bumped to **6.0.0** (Step 102).
> **Spec:** [`spec-v6.md`](../spec-v6.md).

v4 widened *what* Vaulytica reads. v5 specifies *how well* it reads. **v6 makes it useful in the workflow** — without leaving the deterministic, no-AI, no-server, browser-only, citable posture. Every feature below passed the same five-part posture filter (deterministic / no-AI / no-server / citable / lints-not-drafts).

## What v6 adds

| Part | Feature | What it does | Docs / source |
|---|---|---|---|
| I | **Version comparison** | Diff two runs (base vs revised redline): resolved / introduced / unchanged / carried-clean, with a risk-surface delta and a comparison `result_hash`. | [`src/report/compare.ts`](../../src/report/compare.ts), [`compare-docx.ts`](../../src/report/compare-docx.ts) |
| II | **Bring-your-own playbook** | Load your team's standard as a `.json` playbook, client-side, and enforce it via a bounded declarative DSL. Findings carry `source: custom-playbook`. | [`authoring-a-playbook.md`](authoring-a-playbook.md), [`playbook-schema.md`](playbook-schema.md), [`playbook.schema.json`](playbook.schema.json) |
| III | **Findings to action** | Export the fix-list (Markdown + CSV), the obligations ledger (CSV), and deadlines (`.ics`) — deterministic, two-run-identical. | [`src/report/exports.ts`](../../src/report/exports.ts) |
| IV | **Model-clause references** | "What good looks like" — a pointer to an *existing public* model clause (Common Paper, Bonterms, EU SCCs) with attribution. A reference, never a generated redline. | [`src/dkb/model-clauses.ts`](../../src/dkb/model-clauses.ts) |
| V | **Portfolio mode** | A documents × key-checks risk matrix + rollups across a bundle, with a `portfolio_fingerprint` and a 50-row scale guard. | [`src/report/portfolio.ts`](../../src/report/portfolio.ts) |
| VI | **Depth** | Classifier re-engineering (sub-domain top-1 53/75 → 75/75), three new cross-document families, and **jurisdiction overlays**. | [`jurisdiction-overlays.md`](jurisdiction-overlays.md) |

## Posture — what v6 is *not*

- **Not a drafting tool.** v6 compares, lints, enforces, exports, and *references* — it never generates contract language. Model-clause references surface existing public text with attribution; jurisdiction overlays cite the controlling law. The line stays bright (spec-v6 §3).
- **Not an AI feature.** Comparison is set arithmetic over deterministic runs. Custom-playbook matching is the same pure-function engine. The classifier and overlays are hand-authored, inspectable tables. No model anywhere in the decision path.
- **Not a server feature.** A custom playbook is held in the tab exactly like the user's document — never uploaded. Export artifacts are generated client-side. DevTools still shows zero outbound requests. See the "user-supplied playbook" section of the [threat model](../threat-model.md).

## Determinism & privacy

Every new operation follows the existing canonicalization discipline (sorted keys, wall-clock excluded) and has a two-run byte-identical test. The comparison hash, export bytes, portfolio matrix, custom-playbook runs, and the jurisdiction-overlay block are all reproducible across machines. Built-in findings cite the DKB; custom-rule findings cite the team's reference or are marked `uncited (team policy)`; model-clause and overlay references carry source + license. No finding is ever uncited *and* unmarked.

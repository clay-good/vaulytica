# Jurisdiction overlays

> **Status:** v6 Part VI §21, Step 101 — done 2026-06-01.
> **Spec:** [`spec-v6.md`](../spec-v6.md) §21.
> **Source of truth:** the curated catalog in [`src/dkb/state-overlays.ts`](../../src/dkb/state-overlays.ts), validated by [`src/dkb/state-overlays.test.ts`](../../src/dkb/state-overlays.test.ts).

## What it is

Some document families are sharply state-specific: the identical clause is **void** in one state and **routinely enforced** in the next. Jurisdiction overlays surface that delta for the governing-law state(s) a document names — so a reviewer of a California executive-employment agreement sees, in plain language and with a statutory citation, that the non-compete in front of them is unenforceable.

An overlay is a **citable reference layer**, not a finding. It is selected deterministically from the matched family and the extracted governing-law state, and surfaced alongside the report (DOCX section, `jurisdiction_overlays` in the JSON, a block in the complete-state UI) — never inside the `EngineRun`, so no existing `result_hash` changes.

## The consolidated (family × state) node pattern

State law is too large to encode as one rule per (state, position) — that is the 50 × N node explosion spec-v4 §Part-VII open-question-4 warned about. Instead the catalog carries **one node per (family, state)** holding only the *delta from the federal / common-law baseline*:

```
StateOverlay {
  id            // emp-noncompete-us-ca
  family        // "employment" | "lending"
  topic         // "non-compete enforceability"
  jurisdiction  // "us-ca"
  state_name    // "California"
  posture       // prohibited | restricted | permitted | informational
  headline      // "Void / unenforceable"
  summary       // the state delta, plain-language
  recommendation
  severity      // critical | warning | info
  citation      // real statute + URL + license
}
```

## Coverage

The three served families spec §21 names — each one where state law dominates the outcome:

| Family | Topic | States covered |
|---|---|---|
| **employment** | non-compete enforceability | CA, ND, OK, MN, CO, WA, OR, MA, VA, IL, DC, NV, TX, FL, NY (15) |
| **residential-lease** | security-deposit cap & return window | CA, NY, MA, NJ, DC, TX, FL, IL, WA, OR (10) |
| **lending** | usury / interest-rate cap | CA, NY, TX, FL, IL, DE, MA, PA, WA, CO (10) |

This broadens well beyond the original CA / NY / TX / FL / IL coverage of the v4 state-keyed rules. `STATE_OVERLAY_COVERAGE` publishes the per-family count so the report can state coverage honestly ("non-compete overlays cover 15 states"). The residential-deposit overlays gate to the **residential** lease playbook only (`lease-residential-us`); the commercial-lease playbook is deliberately excluded, because a residential deposit-cap statute applied to a commercial lease would be a confidently-wrong answer.

### Posture shading

`posture` drives the shading discipline, the same as the v3 compliance matrix:

- **prohibited** — the position is void / banned (e.g. a CA non-compete). Rendered critical.
- **restricted** — enforceable / lawful only within statutory limits (an income-threshold non-compete, a capped deposit). Rendered as a warning.
- **permitted** — enforceable under a reasonableness test (TX, FL, NY non-competes). Informational.
- **informational** — a reference figure to check against (the applicable usury cap, a no-cap-but-strict-return deposit rule), not a pass/fail.

## How selection works

`selectStateOverlays(playbookId, jurisdictions)`:

1. Maps `playbookId` → family. Returns `undefined` for non-state-sensitive families (the common case), so callers skip the section entirely.
2. Reads **governing-law** clauses only (venue and arbitration-seat do not determine substantive law) out of the extracted jurisdiction references, normalizing each `raw_text` ("State of California", "Commonwealth of Massachusetts") to a `us-XX` id. Runtime extraction does not populate `jurisdiction_id`, so the module carries the resolver.
3. For each detected state, attaches the matching overlay or records it in `uncovered_states`.

The result is a pure function of its inputs — the same document yields a byte-identical overlay block on any machine.

## Honest N/A, never a wrong answer

- A detected governing-law state with **no overlay node** appears in `uncovered_states` and is rendered as an explicit gap — "No overlay on file for WY — an honest coverage gap, not a clean pass." It is never silently treated as compliant.
- **The commercial-lease playbook is excluded** from the residential-deposit overlays. The deposit-cap statutes are residential-specific; applying a residential cap to a commercial lease would be a confidently-wrong answer, so `overlayFamilyForPlaybook` returns `undefined` for `lease-commercial-multitenant`.
- The usury and no-cap-deposit overlays are **informational references**, not a computed verdict: Vaulytica surfaces the applicable cap / return window and its consequences so a reviewer can check the document, but it does not silently decide whether a given rate or deposit is unlawful.

## Posture compliance

| Filter | How it is met |
|---|---|
| Deterministic | Selection is a pure function of `(playbook id, extracted governing-law states)`; both are already deterministic. Two-run-identical test in `state-overlays.test.ts`. |
| No AI | A hand-authored, inspectable catalog + a string-normalization lookup. No model. |
| No server | The catalog is a frozen module shipped in the bundle; nothing is fetched at runtime. |
| Citable | Every overlay carries a real statutory citation, URL, and public-domain license. |
| Lints, not drafts | Overlays *reference* the controlling law; they never write clause language. |

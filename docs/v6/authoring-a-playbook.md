# Authoring a Vaulytica playbook

> **Status:** v6 Part II, Step 94 — authoring guide + worked examples.
> **Spec:** [`spec-v6.md`](../spec-v6.md) §7–§10.
> **Reference:** the field-by-field schema lives in [`playbook-schema.md`](playbook-schema.md); the authoritative validator is the Zod schema in [`src/playbooks/custom-playbook.ts`](../../src/playbooks/custom-playbook.ts).
> **Examples:** [`examples/saas-buyer.playbook.json`](examples/saas-buyer.playbook.json) (a buyer's standard) and [`examples/vendor-redlines.playbook.json`](examples/vendor-redlines.playbook.json) (a vendor's sell-side red-lines). Both validate against the schema and are exercised by [`src/playbooks/example-playbooks.test.ts`](../../src/playbooks/example-playbooks.test.ts).

## What you get

Vaulytica ships ~1,000 rules encoding *its* opinion. A **custom playbook** lets your team encode *its own* positions — the liability cap you accept, the clauses you require, the terms you always strike — and enforce them on every inbound contract, deterministically. You author one `.json` file, load it in the tab, and Vaulytica runs your standard alongside (or instead of) the built-in catalog.

The whole thing stays in your browser. The file is read, validated, and held in memory client-side; **no bytes leave the tab** (spec-v6 Part VII). Like every Vaulytica artifact it is deterministic and auditable — your `custom_rules` are declarative data the engine reads, never code it executes.

## The five-minute version

1. Copy one of the [examples](examples/) and rename it.
2. Set `id`, `name`, `description`.
3. Pick a `mode`: `augment` (built-ins **plus** your positions — the default) or `replace` (only your positions).
4. Add `custom_rules` and/or `required_clauses` for the positions you care about.
5. In the app, click **"Enforce your own playbook…"**, choose your file, confirm the preview, then drop a contract.

If the file is malformed the loader shows a human-readable list of errors — it never silently mis-runs.

## Modes: augment vs replace

- **`augment`** (default) runs the built-in catalog **and** your positions. Use it to *add* your house rules on top of Vaulytica's checks. You can still narrow the catalog with `rule_selection` (include/exclude specific rule ids) or change severities / skip rules with `rule_overrides`.
- **`replace`** runs **only** your positions — none of the built-in catalog. Use it when you want a tightly-scoped checklist and nothing else. A `replace` playbook must define at least one `custom_rule` or `required_clause`, otherwise it checks nothing (rejected at validation).

The app lets the reviewer switch augment ↔ replace at load time; the file's `mode` is just the default.

## Worked example 1 — a SaaS buyer's standard (augment)

[`examples/saas-buyer.playbook.json`](examples/saas-buyer.playbook.json) is what a procurement team enforces on inbound vendor paper. It keeps every built-in check and layers on the buyer's negotiation positions:

- **Required clauses.** It requires a `limitation-of-liability` clause (critical if missing) and a `confidentiality-obligation` clause (warning). `required_clauses` reference the engine's classifier categories — see the list in [`playbook-schema.md`](playbook-schema.md).
- **Liability cap floor.** `ACME-SAAS-CAP` asserts `liability_cap_multiple >= 12`. A cap below 12x fees fires a critical finding, cited to the team's internal policy.
- **Notice ceiling.** `ACME-SAAS-NOTICE` asserts `notice_period_days <= 30`.
- **Governing law allow-list.** `ACME-SAAS-GOVLAW` allows only Delaware or New York.
- **Strike arbitration.** `ACME-SAAS-NO-ARB` uses `clause_absent` on the pattern `"arbitration"`.
- **Require a DPA.** `ACME-SAAS-DPA` uses `clause_present` on `"data processing addendum"`.

Findings from these rules are tagged `source: "custom-playbook"` and labeled with the rule's citation (or `uncited (team policy)` when none is given), so the report distinguishes *your* flags from Vaulytica's.

## Worked example 2 — a vendor's sell-side red-lines (augment)

[`examples/vendor-redlines.playbook.json`](examples/vendor-redlines.playbook.json) flips the perspective. Northwind is the **vendor**, so its positions *limit* exposure rather than demand protection:

- **Cap ceiling, not floor.** `NW-CAP-LIMIT` asserts `liability_cap_multiple <= 1` — a *higher* cap is the red-line.
- **Payment floor.** `NW-PAYMENT` asserts `payment_term_days >= 30` (no faster than Net 30).
- **No unlimited indemnity.** `NW-NO-UNLIMITED-INDEMNITY` strikes the word `"unlimited"`.
- **Governing law** restricted to Washington or Delaware.
- **A `rule_override`** downgrades the built-in `RISK-002` to `info` because, on Northwind's own paper, that asymmetry is expected.

This is the same engine pointed at the opposite set of positions — proof that the DSL is symmetric: a `gte` for the buyer is an `lte` for the vendor.

## The predicate kinds

Each `custom_rule` pairs a **predicate** (the condition that must hold for a *compliant* document) with metadata. The rule fires when the predicate is **false** — i.e. your position is violated.

| `kind` | Fields | Fires when… |
|--------|--------|-------------|
| `clause_present` | `pattern?`, `section_heading?` | no matching clause is found |
| `clause_absent` | `pattern?`, `section_heading?` | a matching clause **is** found |
| `numeric_threshold` | `metric`, `comparator`, `value` | a stated value breaks the threshold |
| `defined_term_present` | `term` | the term is not defined |
| `governing_law_in` | `allowed[]` | the governing law is outside the allow-list |
| `cross_ref_resolves` | — | an internal cross-reference dangles |

`numeric_threshold` metrics are a bounded set — `liability_cap_multiple`, `liability_cap_amount`, `notice_period_days`, `term_length_days`, `payment_term_days`. A metric the engine cannot locate on a given document is reported **unevaluable** (never a false pass, never a guess). `comparator` is one of `gte`, `lte`, `gt`, `lt`, `eq`.

`governing_law_in` entries may be jurisdiction **names** (`"Delaware"`) or DKB ids (`"us-de"`); both match the extracted clause.

## Citations

Every `custom_rule` may carry a `citation` (`{ reference, url? }`) — your internal policy section or a public authority. When present, the finding cites it. When absent, the finding is marked `uncited (team policy)` — never silently uncited (spec-v6 §9). Citing your positions makes the report defensible in a negotiation.

## Validating before you load

You can validate a playbook programmatically:

```ts
import { parseCustomPlaybookJson } from "../../src/playbooks";

const result = parseCustomPlaybookJson(fileText);
if (result.ok) {
  // result.playbook is a typed CustomPlaybook
} else {
  // result.errors — sorted, human-readable `path: message` strings
}
```

Unknown keys are rejected (a typo surfaces as an error, not a silent no-op). In the app, the loader runs the same validator and shows the same errors, plus a **preview**: which built-in rules your playbook selects, how many of your own rules and required clauses it adds, and warnings for unknown rule ids, uncited rules, or a `catalog_version` that no longer matches the running catalog.

## Versioning

Declare the `catalog_version` your playbook targets. If you authored against an older catalog, the loader warns that referenced rules may have changed — it never fails opaquely. The current catalog version is `0.1.0`.

## Sharing a playbook

A playbook is a plain `.json` file. Share it internally however you share any config — commit it to your contracts repo, drop it in a shared drive, pass it around. It never needs to touch Vaulytica's servers (there are none for it to touch).

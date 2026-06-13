# Vaulytica custom playbook schema

> **Status:** v6 Part II, Step 91 — schema + validator. Loading a playbook in the tab (Step 92) and the custom-rule interpreter (Step 93) build on this contract.
> **Spec:** [`spec-v6.md`](../spec-v6.md) §8–§10.
> **Authoritative source:** the Zod schema in [`src/playbooks/custom-playbook.ts`](../../src/playbooks/custom-playbook.ts). The JSON Schema [`playbook.schema.json`](playbook.schema.json) is an informative mirror for editor autocomplete; where the two ever disagree, Zod wins.

## What a custom playbook is

Vaulytica ships a catalog of ~1,000 rules encoding *its* opinion. A **custom playbook** lets your team encode *its own* positions — the liability cap you accept, the clauses you require, the terms you strike — and enforce them deterministically on every inbound contract. The playbook is a plain `.json` file. It is loaded and validated **entirely in your browser**; no bytes ever leave the tab (spec-v6 Part VII). It is, like every Vaulytica artifact, deterministic and auditable: the `custom_rules` block is declarative data, never executable code.

## Posture

Validation and enforcement are pure functions. There is no AI, no network, and no code execution anywhere in the path. A `custom_rules` predicate is data the engine's interpreter reads — it cannot compute arbitrarily or exfiltrate. Same playbook + same document → same findings, on any machine.

## Top-level shape

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `schema_version` | yes | `"1.0"` | Version of this schema format. |
| `catalog_version` | yes | string | The built-in rule-catalog version this playbook targets. Loading a playbook authored against an older catalog warns about rules retired since (spec-v6 §10). |
| `id` | yes | string | Stable identifier for your playbook. |
| `name` | yes | string | Human-readable name. |
| `description` | yes | string | What this playbook enforces. |
| `mode` | no | `"augment"` \| `"replace"` | `augment` (default) runs the built-in catalog **plus** your positions; `replace` runs **only** your positions. |
| `rule_selection` | no | object | `{ include?, exclude? }` — narrow the built-in catalog to / drop specific rule ids. |
| `rule_overrides` | no | object | Per-built-in-rule `{ severity?, skip? }`, keyed by rule id. |
| `thresholds` | no | object | Named numeric parameters (e.g. `min_cap_multiple`) your positions reference. |
| `required_clauses` | no | array | `{ category, severity }` — clauses you require; a finding fires when one is missing. |
| `custom_rules` | no | array | The bounded declarative DSL (below). |

A `replace`-mode playbook must define at least one `custom_rule` or `required_clause` — otherwise it checks nothing, which is almost always an authoring mistake and is rejected.

## Custom rules — the bounded DSL

Each custom rule pairs a **predicate** (the condition that must hold for a *compliant* document) with metadata. The rule fires a finding when the predicate is **false** — i.e. your position is violated. Phrasing every predicate as a positive assertion keeps the interpreter free of double negatives.

```jsonc
{
  "id": "ACME-1",
  "title": "Liability cap must be at least 12x fees",
  "description": "We do not accept a cap below 12x trailing fees.",
  "severity": "critical",
  "assert": { "kind": "numeric_threshold", "metric": "liability_cap_multiple", "comparator": "gte", "value": 12 },
  "citation": { "reference": "Acme Contracting Policy §4.2", "url": "https://example.com/policy" }
}
```

- `id` is unique within the playbook and becomes the finding's rule id.
- `severity` is `critical` | `warning` | `info`.
- `citation` is optional. When absent, the finding is marked **`uncited (team policy)`** in the report — never silently uncited (spec-v6 §9, §97).

### Predicate kinds

| `kind` | Fields | Compliant when… (finding fires otherwise) |
|--------|--------|--------------------------------------------|
| `clause_present` | `pattern?`, `section_heading?` | a clause matching the pattern/heading is present |
| `clause_absent` | `pattern?`, `section_heading?` | no clause matching the pattern/heading is present |
| `numeric_threshold` | `metric`, `comparator`, `value` | the extracted metric satisfies `comparator value` |
| `defined_term_present` | `term` | the term is defined in the document |
| `governing_law_in` | `allowed[]` | the governing law is one of the allowed jurisdictions (each entry is a jurisdiction **name** like `"Delaware"` or a DKB id like `"us-de"`; matched against the extracted clause either way) |
| `cross_ref_resolves` | — | every internal cross-reference resolves |
| `clause_mutual` | `clause`, `pattern?`, `section_heading?` | the located clause is **mutual** (carries reciprocity language — "each party", "both parties", "mutual", …) rather than one-way |

`clause_present` / `clause_absent` require at least one of `pattern` or `section_heading`; a predicate with neither could never match a concrete clause and is rejected.

`comparator` is one of `gte`, `lte`, `gt`, `lt`, `eq`.

`metric` is one of a **bounded** set, each mapping to an existing extractor output:

- `liability_cap_multiple` — liability cap expressed as a multiple of fees
- `liability_cap_amount` — liability cap as an absolute amount
- `notice_period_days` — notice period in days
- `term_length_days` — agreement term in days
- `payment_term_days` — payment due window in days
- `cure_period_days` — cure window for a breach, in days *(spec-v10 Thrust C)*
- `auto_renewal_notice_days` — non-renewal notice window, in days *(spec-v10 Thrust C)*
- `indemnity_cap_amount` — indemnification cap as an absolute amount *(spec-v10 Thrust C)*
- `uptime_sla_percent` — service-level uptime/availability commitment, in percent *(spec-v10 Thrust C)*

The set is intentionally small for auditability; maintainers grow it as extractor coverage grows. An unknown metric is a validation error, never a silent no-op.

`clause_mutual` (spec-v10 Thrust C) asserts a clause is reciprocal rather than one-way. `clause` is one of a **bounded** set — `indemnification`, `termination`, `confidentiality` — that anchors where the clause is located; an explicit `pattern` or `section_heading` overrides the default anchor. The classifier is a deterministic marker scan (no model): a located clause carrying any reciprocity marker is compliant; one with none is reported one-way; a clause that is not present at all is unevaluable, never a false "one-way".

## Validation

```ts
import { validateCustomPlaybook, parseCustomPlaybookJson } from "../../src/playbooks";

const result = parseCustomPlaybookJson(fileText);
if (result.ok) {
  // result.playbook is a typed CustomPlaybook
} else {
  // result.errors is a sorted list of human-readable `path: message` strings
}
```

`validateCustomPlaybook(raw)` validates already-parsed JSON; `parseCustomPlaybookJson(text)` parses a string first and reports a JSON syntax error as a readable error rather than throwing. Unknown keys are rejected (`strict`) so a typo surfaces as an error instead of being silently ignored. A malformed playbook never silently mis-runs.

## Worked example (augment mode)

```json
{
  "schema_version": "1.0",
  "catalog_version": "0.1.0",
  "id": "acme-saas-buyer",
  "name": "Acme SaaS Buyer Standard",
  "description": "Acme's negotiation positions for inbound SaaS agreements.",
  "mode": "augment",
  "rule_overrides": { "INFO-009": { "skip": true } },
  "thresholds": { "min_cap_multiple": 12, "max_notice_days": 30 },
  "required_clauses": [
    { "category": "limitation-of-liability", "severity": "critical" }
  ],
  "custom_rules": [
    {
      "id": "ACME-1",
      "title": "Liability cap must be at least 12x fees",
      "description": "We do not accept a cap below 12x trailing fees.",
      "severity": "critical",
      "assert": { "kind": "numeric_threshold", "metric": "liability_cap_multiple", "comparator": "gte", "value": 12 },
      "citation": { "reference": "Acme Contracting Policy §4.2" }
    },
    {
      "id": "ACME-2",
      "title": "No mandatory arbitration",
      "description": "We strike mandatory arbitration clauses.",
      "severity": "warning",
      "assert": { "kind": "clause_absent", "pattern": "arbitration" }
    }
  ]
}
```

A fuller authoring guide with a vendor red-line example lands in `docs/v6/authoring-a-playbook.md` (Step 94).

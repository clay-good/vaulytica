# Vaulytica custom playbook schema

> **Status:** v6 Part II, Step 91 — schema + validator. Loading a playbook in the tab (Step 92) and the custom-rule interpreter (Step 93) build on this contract.
> **Spec:** [`spec-v6.md`](../spec-v6.md) §8–§10.
> **Authoritative source:** the Zod schema in [`src/playbooks/custom-playbook.ts`](../../src/playbooks/custom-playbook.ts). The JSON Schema [`playbook.schema.json`](playbook.schema.json) is an informative mirror for editor autocomplete; where the two ever disagree, Zod wins.

## What a custom playbook is

Vaulytica ships a catalog of ~1,000 rules encoding _its_ opinion. A **custom playbook** lets your team encode _its own_ positions — the liability cap you accept, the clauses you require, the terms you strike — and enforce them deterministically on every inbound contract. The playbook is a plain `.json` file. It is loaded and validated **entirely in your browser**; no bytes ever leave the tab (spec-v6 Part VII). It is, like every Vaulytica artifact, deterministic and auditable: the `custom_rules` block is declarative data, never executable code.

## Posture

Validation and enforcement are pure functions. There is no AI, no network, and no code execution anywhere in the path. A `custom_rules` predicate is data the engine's interpreter reads — it cannot compute arbitrarily or exfiltrate. Same playbook + same document → same findings, on any machine.

## Top-level shape

| Field                   | Required | Type                       | Meaning                                                                                                                                                      |
| ----------------------- | -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `schema_version`        | yes      | `"1.0"`                    | Version of this schema format.                                                                                                                               |
| `catalog_version`       | yes      | string                     | The built-in rule-catalog version this playbook targets. Loading a playbook authored against an older catalog warns about rules retired since (spec-v6 §10). |
| `id`                    | yes      | string                     | Stable identifier for your playbook.                                                                                                                         |
| `name`                  | yes      | string                     | Human-readable name.                                                                                                                                         |
| `description`           | yes      | string                     | What this playbook enforces.                                                                                                                                 |
| `mode`                  | no       | `"augment"` \| `"replace"` | `augment` (default) runs the built-in catalog **plus** your positions; `replace` runs **only** your positions.                                               |
| `rule_selection`        | no       | object                     | `{ include?, exclude? }` — narrow the built-in catalog to / drop specific rule ids.                                                                          |
| `rule_overrides`        | no       | object                     | Per-built-in-rule `{ severity?, skip? }`, keyed by rule id.                                                                                                  |
| `thresholds`            | no       | object                     | Named numeric parameters (e.g. `min_cap_multiple`) your positions reference.                                                                                 |
| `required_clauses`      | no       | array                      | `{ category, severity }` — clauses you require; a finding fires when one is missing.                                                                         |
| `custom_rules`          | no       | array                      | The bounded declarative DSL (below).                                                                                                                         |
| `party_roles`           | no       | array                      | The roles your positions can be evaluated as, e.g. `["vendor", "customer"]`. Required when any position uses `role_variants` (below).                        |
| `negotiation_positions` | no       | array                      | Your tiered negotiation ladder — advisory posture, not findings. See [Negotiation positions](#negotiation-positions--the-ladder).                            |

A `replace`-mode playbook must define at least one `custom_rule` or `required_clause` — otherwise it checks nothing, which is almost always an authoring mistake and is rejected.

## Custom rules — the bounded DSL

Each custom rule pairs a **predicate** (the condition that must hold for a _compliant_ document) with metadata. The rule fires a finding when the predicate is **false** — i.e. your position is violated. Phrasing every predicate as a positive assertion keeps the interpreter free of double negatives.

```jsonc
{
  "id": "ACME-1",
  "title": "Liability cap must be at least 12x fees",
  "description": "We do not accept a cap below 12x trailing fees.",
  "severity": "critical",
  "assert": {
    "kind": "numeric_threshold",
    "metric": "liability_cap_multiple",
    "comparator": "gte",
    "value": 12,
  },
  "citation": { "reference": "Acme Contracting Policy §4.2", "url": "https://example.com/policy" },
}
```

- `id` is unique within the playbook and becomes the finding's rule id.
- `severity` is `critical` | `warning` | `info`.
- `citation` is optional. When absent, the finding is marked **`uncited (team policy)`** in the report — never silently uncited (spec-v6 §9, §97).

### Predicate kinds

| `kind`                 | Fields                                   | Compliant when… (finding fires otherwise)                                                                                                                                                   |
| ---------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clause_present`       | `pattern?`, `section_heading?`           | a clause matching the pattern/heading is present                                                                                                                                            |
| `clause_absent`        | `pattern?`, `section_heading?`           | no clause matching the pattern/heading is present                                                                                                                                           |
| `numeric_threshold`    | `metric`, `comparator`, `value`          | the extracted metric satisfies `comparator value`                                                                                                                                           |
| `defined_term_present` | `term`                                   | the term is defined in the document                                                                                                                                                         |
| `governing_law_in`     | `allowed[]`                              | the governing law is one of the allowed jurisdictions (each entry is a jurisdiction **name** like `"Delaware"` or a DKB id like `"us-de"`; matched against the extracted clause either way) |
| `cross_ref_resolves`   | —                                        | every internal cross-reference resolves                                                                                                                                                     |
| `clause_mutual`        | `clause`, `pattern?`, `section_heading?` | the located clause is **mutual** (carries reciprocity language — "each party", "both parties", "mutual", …) rather than one-way                                                             |

`clause_present` / `clause_absent` require at least one of `pattern` or `section_heading`; a predicate with neither could never match a concrete clause and is rejected.

`comparator` is one of `gte`, `lte`, `gt`, `lt`, `eq`.

`metric` is one of a **bounded** set, each mapping to an existing extractor output:

- `liability_cap_multiple` — liability cap expressed as a multiple of fees
- `liability_cap_amount` — liability cap as an absolute amount
- `notice_period_days` — notice period in days
- `term_length_days` — agreement term in days
- `payment_term_days` — payment due window in days
- `cure_period_days` — cure window for a breach, in days _(spec-v10 Thrust C)_
- `auto_renewal_notice_days` — non-renewal notice window, in days _(spec-v10 Thrust C)_
- `indemnity_cap_amount` — indemnification cap as an absolute amount _(spec-v10 Thrust C)_
- `uptime_sla_percent` — service-level uptime/availability commitment, in percent _(spec-v10 Thrust C)_

The set is intentionally small for auditability; maintainers grow it as extractor coverage grows. An unknown metric is a validation error, never a silent no-op.

`clause_mutual` (spec-v10 Thrust C) asserts a clause is reciprocal rather than one-way. `clause` is one of a **bounded** set — `indemnification`, `termination`, `confidentiality` — that anchors where the clause is located; an explicit `pattern` or `section_heading` overrides the default anchor. The classifier is a deterministic marker scan (no model): a located clause carrying any reciprocity marker is compliant; one with none is reported one-way; a clause that is not present at all is unevaluable, never a false "one-way".

## Negotiation positions — the ladder

`negotiation_positions` is advisory **posture**, not findings: each entry says which rung of your fallback ladder a draft currently meets on one dimension. It carries its own `posture_hash`, outside the run's `result_hash`. Run it with the CLI's `--posture` (`vaulytica analyze <doc> --playbook-file <pb> --posture`).

A position's core is two predicates from the same DSL: **`ideal`** (best) and **`acceptable`** (the floor). The engine reports exactly one tier — `ideal`, `acceptable`, `below-acceptable`, or `unevaluable` (the metric is not stated) — and this floor is **binary** by design: `below-acceptable` is the only sub-floor value, which is what lets the cross-round posture-coherence commands compare ladders safely. The v3 fields below all **refine** a ladder without ever adding a new tier.

| Field                  | Type                                  | Meaning                                                                                                                                                                                                                                                            |
| ---------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `dimension`            | string                                | Unique label for the negotiable dimension.                                                                                                                                                                                                                         |
| `ideal` / `acceptable` | predicate                             | The top of the ladder and its floor.                                                                                                                                                                                                                               |
| `guidance`             | `{ ideal?, acceptable?, walk_away? }` | Per-tier advisory text shown beside the position.                                                                                                                                                                                                                  |
| `approved_language`    | string                                | Your team's pre-approved fallback text, quoted (never generated) beside a **below-floor** row.                                                                                                                                                                     |
| `rungs`                | array                                 | Up to 8 intermediate `{ label, predicate }` rungs between ideal and the floor, ordered best-first. The highest met rung is reported as **detail** (`met_rung`) — it never changes the tier or `posture_hash`.                                                      |
| `role_variants`        | object                                | Per-role ladder overrides keyed by a declared `party_roles` name. Select one with `--role <name>`. A position that varies by role with no `--role` is a hard error, never a silent default.                                                                        |
| `size_bands`           | array                                 | Up to 8 `{ min_value, label?, ideal, acceptable, rungs? }` bands. `--deal-value <n>` selects the band with the highest `min_value` at or below `n`; the base ladder is the default when none applies or no value is given (the report says which, as `size_band`). |

`--role` and `--deal-value` resolve into a concrete ladder **before** the posture is evaluated or hashed, so a coherence artifact is pinned to the exact role- and size-resolved ladder it was computed from, and a playbook that uses neither hashes identically to before.

**Auto-detecting the deal value.** For a single-document `--posture` run, if a position has `size_bands` and you pass no `--deal-value`, Vaulytica reads the document's **explicitly labeled** total value — a phrase like `total contract value`, `total consideration`, `aggregate fees`, or `not to exceed` immediately followed by a `$` amount — and selects the band from it, naming the source in the report (`size_band: "≥ $1M (auto-detected from \"total contract value\": $5000000)"`). It never guesses from a stray amount: an unlabeled document keeps each position's base default and says so. Because auto-detection is per-document, a **multi-document (bundle) posture run** and **coherence emission/diff** (`--emit-coherence` / `--baseline-coherence`) require an explicit `--deal-value` with size-banded positions, so every document is scored against one shared ladder.

### Worked example — both sides, three rungs, two size bands

```jsonc
{
  "schema_version": "1.0",
  "catalog_version": "0.1.0",
  "id": "acme-msa",
  "name": "Acme MSA ladder",
  "description": "Liability-cap posture for both sides, scaled by deal size.",
  "mode": "replace",
  "party_roles": ["vendor", "customer"],
  "negotiation_positions": [
    {
      "dimension": "Liability cap",
      // Base = vendor: a LOW cap is ideal.
      "ideal": {
        "kind": "numeric_threshold",
        "metric": "liability_cap_multiple",
        "comparator": "lte",
        "value": 1,
      },
      "acceptable": {
        "kind": "numeric_threshold",
        "metric": "liability_cap_multiple",
        "comparator": "lte",
        "value": 3,
      },
      "approved_language": "Vendor's aggregate liability shall not exceed the fees paid in the prior 12 months.",
      // Customer wants a HIGH cap, and the floor scales with the deal.
      "role_variants": {
        "customer": {
          "ideal": {
            "kind": "numeric_threshold",
            "metric": "liability_cap_multiple",
            "comparator": "gte",
            "value": 12,
          },
          "acceptable": {
            "kind": "numeric_threshold",
            "metric": "liability_cap_multiple",
            "comparator": "gte",
            "value": 6,
          },
          "rungs": [
            {
              "label": "9x cap",
              "predicate": {
                "kind": "numeric_threshold",
                "metric": "liability_cap_multiple",
                "comparator": "gte",
                "value": 9,
              },
            },
            {
              "label": "7x cap",
              "predicate": {
                "kind": "numeric_threshold",
                "metric": "liability_cap_multiple",
                "comparator": "gte",
                "value": 7,
              },
            },
          ],
        },
      },
      "size_bands": [
        {
          "min_value": 1000000,
          "label": "≥ $1M",
          "ideal": {
            "kind": "numeric_threshold",
            "metric": "liability_cap_multiple",
            "comparator": "lte",
            "value": 2,
          },
          "acceptable": {
            "kind": "numeric_threshold",
            "metric": "liability_cap_multiple",
            "comparator": "lte",
            "value": 5,
          },
        },
      ],
    },
  ],
}
```

```sh
# Evaluate as the customer on a $5M deal:
vaulytica analyze contract.docx --playbook-file acme-msa.json --posture --role customer --deal-value 5000000
```

> Note: a position that declares **both** `role_variants` and `size_bands` applies the role first; the selected role's ladder does not carry the base `size_bands`, so combine them on separate dimensions unless a role variant declares its own bands.

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
  "required_clauses": [{ "category": "limitation-of-liability", "severity": "critical" }],
  "custom_rules": [
    {
      "id": "ACME-1",
      "title": "Liability cap must be at least 12x fees",
      "description": "We do not accept a cap below 12x trailing fees.",
      "severity": "critical",
      "assert": {
        "kind": "numeric_threshold",
        "metric": "liability_cap_multiple",
        "comparator": "gte",
        "value": 12
      },
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

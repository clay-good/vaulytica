# Adding a v3 playbook

v3 playbooks live at [`src/playbooks/v3/`](../../src/playbooks/v3/) and
extend v2's `Playbook` schema with four optional fields:

- `regulator_frame` — single-string label (e.g. `"HIPAA"`, `"GDPR"`).
- `applicable_jurisdictions` — e.g. `["US"]`, `["EU", "UK"]`.
- `companion_playbooks` — suggested two-document pairings (other playbook ids).
- `compliance_matrix_columns` — column labels for the §54 matrix.

The base schema is unchanged from v2 — see
[`docs/adding-a-playbook.md`](../adding-a-playbook.md) for the v2 walkthrough.
This guide covers the v3-specific additions.

## 1. Pick the id and family

v3 playbook ids are kebab-case and live in
[`src/playbooks/v3/<id>.json`](../../src/playbooks/v3/). The available
families are:

| Family | Existing ids |
|---|---|
| BAA | `baa`, `baa-subcontractor` |
| DPA-EU | `dpa-controller-processor`, `dpa-processor-subprocessor` |
| DPA-US-state | `dpa-ccpa-service-provider`, `dpa-multi-state-us` |
| SCC | `scc-module-2`, `scc-module-3` |
| UK transfer | `uk-idta-addendum` |
| NDA (deep) | `mutual-nda-deep`, `unilateral-nda-deep` |
| MSA (deep) | `msa-vendor-deep`, `msa-customer-deep` |
| Addenda | `vendor-security-addendum`, `ai-addendum`, `eula`, `saas-tos`, `privacy-policy-lint`, `coi` |

## 2. Author the JSON

```jsonc
{
  "id": "baa-subcontractor",
  "version": "1.0.0",
  "name": "Business Associate Agreement — Subcontractor",
  "description": "Flow-down agreement between a business associate and a subcontractor that creates, receives, maintains, or transmits PHI on behalf of the business associate.",
  "regulator_frame": "HIPAA",
  "applicable_jurisdictions": ["US"],
  "companion_playbooks": ["baa", "msa-vendor-deep"],
  "compliance_matrix_columns": [
    "Permitted Uses",
    "Safeguards",
    "Breach Notification (60 days)",
    "Subcontractor Flow-Down",
    "Return / Destruction",
    "Audit Rights",
    "Term"
  ],
  "match_features": {
    "title_keywords": ["subcontractor business associate agreement", "subcontractor BAA"],
    "required_clauses": ["permitted-uses", "safeguards", "breach-notification", "flow-down", "return-or-destruction"],
    "distinguishing_phrases": ["Business Associate", "Subcontractor", "Protected Health Information", "164.504(e)(1)(ii)"],
    "negative_features": ["the Discloser", "the Recipient", "Subscription Term"]
  },
  "expected_clauses": [
    {"category": "permitted-uses", "severity_if_missing": "critical"},
    {"category": "safeguards", "severity_if_missing": "critical"},
    {"category": "breach-notification", "severity_if_missing": "critical"},
    {"category": "flow-down", "severity_if_missing": "critical"},
    {"category": "return-or-destruction", "severity_if_missing": "warning"},
    {"category": "audit-rights", "severity_if_missing": "info"}
  ],
  "expected_defined_terms": [
    {"term": "Business Associate", "severity_if_missing": "critical"},
    {"term": "Subcontractor", "severity_if_missing": "critical"},
    {"term": "PHI", "severity_if_missing": "warning"},
    {"term": "Breach", "severity_if_missing": "warning"}
  ],
  "rule_overrides": {},
  "balanced_defaults": [
    {"clause": "breach-notification-window", "value": "60 days", "source_dkb_id": "hipaa-164.410"}
  ],
  "sources": [
    "45 CFR § 164.504(e)(1)(ii) (HHS — subcontractor flow-down requirement)"
  ]
}
```

## 3. Pick the compliance-matrix columns

The `compliance_matrix_columns` array is the spine of the §54
compliance matrix. Each column maps to one regulator-required-clause
category. Keep the column count modest (5–10 is typical); too many
turns the matrix into a heat map nobody reads.

Conventional column groups by family:

- **BAA**: Permitted Uses · Safeguards · Breach Notification · Subcontractor Flow-Down · Return/Destruction · Audit · Term
- **DPA-EU**: Subject Matter · Documented Instructions · Confidentiality · Art. 32 Security · Subprocessors · Data-Subject-Rights · Art. 32–36 Assistance · Deletion/Return · Compliance Demonstration · Transfer Mechanism
- **DPA-US-state**: Purpose Limitation · No-Sale · No-Cross-Context Ads · Same Level of Protection · Certification · Monitoring · Consumer-Request Assistance · Inability-to-Comply Notice · Subcontractor Flow-Down
- **NDA-deep**: DTSA Notice · Confidentiality Term · Standard Exclusions · Permitted Use · Return/Destruction · Injunctive Relief · Governing Law
- **MSA-deep**: Indemnification · Liability Cap · IP · Warranties · SLA · Termination · Data Return · Force Majeure · Assignment · Governing Law · Order of Precedence

## 4. Pick companion playbooks

The `companion_playbooks` list seeds the v3 UI multi-document drop hint
("looking for GDPR coverage? add a DPA"). Pick the playbooks a
compliance officer would realistically pair with this one — not every
playbook in the catalog.

Common pairings:

- `msa-vendor-deep` ↔ `dpa-controller-processor`, `baa`, `vendor-security-addendum`, `ai-addendum`
- `baa` ↔ `msa-vendor-deep`, `baa-subcontractor`
- `dpa-controller-processor` ↔ `msa-vendor-deep`, `scc-module-2`, `uk-idta-addendum`
- `scc-module-2` ↔ `dpa-controller-processor`, `uk-idta-addendum`

## 5. Validate

```
npx vitest run src/playbooks/
```

Then a full quality gate:

```
npm run typecheck && npm run lint && npm test && npm run build
```

## 6. Auto-detect

The v3 auto-detect helper at
[`src/ui/v3/auto-detect.ts`](../../src/ui/v3/auto-detect.ts) maps a
detected family to a playbook id via `FAMILY_TO_PLAYBOOK`. If your new
playbook should be the family default, update that mapping.
Otherwise the existing default is preserved and your playbook is
available as a manual override.

A family may also resolve dynamically when more than one playbook is a
viable target for the same family. The current example is `nda-deep`,
which post-processes its base mapping (`mutual-nda-deep`) through
`resolveNdaDeepVariant(text)` to switch to `unilateral-nda-deep` when
the document carries one-way / unilateral / Discloser → Recipient
signals. The resolver appends its signals to the detection audit
trail. If your family needs the same treatment — multiple playbooks
under a single detection family — follow that pattern: keep one
default in `FAMILY_TO_PLAYBOOK` and add a `resolve<Family>Variant`
helper that runs after best-family selection.

## 7. Reference fixtures

Drop one passing fixture and one failing fixture under
[`tests/golden/v3/fixtures/`](../../tests/golden/v3/fixtures/) with a
`<name>.playbook` sidecar that pins your new playbook id. The
goldens harness ([`tests/golden/v3/`](../../tests/golden/v3/)) baselines
the output and locks in regressions.

## 8. Citation discipline

Every v3 playbook's `sources` array must cite the controlling regulator
URL — not the regulator's homepage. Each rule the playbook's columns
depend on must in turn cite a specific DKB node id with a current
`content_hash_at_pin`. See
[`docs/v3/adding-a-baa-rule.md`](adding-a-baa-rule.md) and
[`docs/v3/adding-a-dpa-rule.md`](adding-a-dpa-rule.md) for the
rule-level discipline.

# add-privacy-notice-pack

## Why

Public-facing privacy notices are checklist documents: statutes and regulations enumerate exactly what they must contain, which is the strongest possible fit for the presence-rule factory the v3 DPA/BAA packs already run on (`src/engine/rules/v3/_regulated-rule.ts` — 55 GDPR-DPA + 45 BAA rules prove the pattern). But the existing packs cover B2B *processing agreements*; nothing checks the consumer-facing *notice* against its statutory content lists. Those lists are verified and current: Cal. Civ. Code § 1798.130(a)(5) (rights descriptions — including the § 1798.106 correction right — collection categories per § 1798.140(v)(1), the two sold/shared-vs-disclosed lists or their "none" statements), 11 CCR § 7011(e) (the regulation's fuller enumeration, including sensitive-PI use, opt-out link, and last-updated date; the 2025 amendment package effective 2026-01-01 adds a mobile-app link requirement and puts ADMT pre-use notices in a separate section — out of this pack's scope), GDPR Arts. 13/14 (with Art. 14's two extra items: categories of data and source), and the leading state analogs — Colorado (C.R.S. § 6-1-1308(1)(a) + 4 CCR 904-3 Rule 6.03), Virginia (Va. Code § 59.1-578(C)), Texas (Tex. Bus. & Com. Code § 541.102, which mandates *exact statutory wording* for two notices — the single most linter-shaped requirement in US privacy law), and Oregon (ORS 646A.578(4)).

## What Changes

- **Privacy-notice playbooks**: `privacy-notice-us`, `privacy-notice-gdpr` (the existing `cookie-notice` playbook stays as-is); classifier features from notice-typical headings ("Categories of Personal Information," "Your Rights," "Data Protection Officer").
- **PNOT-### presence rules per regime, selected by asserted regime(s)** (`--regime ccpa,gdpr,tx` / tab multi-select — a notice is often written for several): one presence rule per enumerated content item, built with the `_regulated-rule.ts` factory, each citing its statutory/regulatory item and carrying `retrieved_at`. The Texas rules additionally do exact-wording comparison against the § 541.102(b)–(c) statutory text (quote-level match with whitespace normalization — flagged when the mandated language is absent or altered).
- **Regime coverage table in the report**: for each asserted regime, which enumerated items were found / not detected — presence-only, with the DPA packs' honesty inherited: absence of findings is never "compliant," and the scope statement says content presence was checked, not adequacy, accuracy, or the business's actual practices.
- **No regime asserted → pack dormant** (same posture as court profiles: which law applies is the attorney's call, stamped into the receipt).

## Impact

- Affected specs: `privacy-notices` (new capability spec)
- Affected code: 2 playbooks + classifier features, `src/engine/rules/privacy-notice/` PNOT pack (factory-built), regime data in DKB (item lists + citations + the Texas statutory wording), `--regime` flag + tab picker, coverage-table rendering; tests
- Risk: none to existing hashes (fully gated + dormant-by-default); the DPA/BAA packs are untouched — a DPA classified as a DPA never triggers PNOT rules.

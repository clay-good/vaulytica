# Adding a DPA rule

DPA rules split across two v3 directories:

- [`src/engine/rules/v3/dpa-gdpr/`](../../src/engine/rules/v3/dpa-gdpr/) for GDPR / UK GDPR / Swiss FADP rules.
- [`src/engine/rules/v3/dpa-us-state/`](../../src/engine/rules/v3/dpa-us-state/) for CCPA + the 7 follow-on US state laws.

This guide walks through both flavors with one example each.

## Example A: GDPR Art. 28(3) extension

Hypothetical `DPA-056` — "DPA does not name the categories of data
subjects (Art. 28(3) preamble)". The existing `DPA-001`–`DPA-014` cover
Art. 28(3) introductory paragraph + (a)–(h) but the categories-of-data-
subjects requirement deserves a stricter critical-when-missing check
than the existing presence rule.

### 1. Find the citation

GDPR is fetched into the DKB by
[`dkb/build/v3/fetchers/gdpr.ts`](../../dkb/build/v3/fetchers/gdpr.ts).
Open the snapshot under
[`dkb/fixtures/v3/snapshots/`](../../dkb/fixtures/v3/snapshots/) and
find Article 28(3) preamble. Note the EUR-Lex URL — it is the
authoritative source.

The corresponding DKB node id is `gdpr-art-28-3-preamble` (or
similar — confirm by reading the fetcher output).

### 2. Use the generic factory

GDPR rules use the shared factory at
[`src/engine/rules/v3/_regulated-rule.ts`](../../src/engine/rules/v3/_regulated-rule.ts)
rather than the BAA-specific helpers. The factory exposes
`buildPresenceRule` and `buildLanguageRule` and accepts a `category` +
`applies_to_playbooks` + `cite_for(citation)` mapper.

In [`src/engine/rules/v3/dpa-gdpr/rules.ts`](../../src/engine/rules/v3/dpa-gdpr/rules.ts):

```ts
buildPresenceRule(DPA_GDPR_CONFIG, {
  id: "DPA-056",
  name: "Categories of data subjects not specified",
  citation: "GDPR Art. 28(3) preamble",
  present_patterns: [
    /\bcategories\s+of\s+data\s+subjects?\b/i,
    /\bdata\s+subjects?\s+(?:include|comprise|are)\b/i,
  ],
  missing_title: "DPA does not name the categories of data subjects",
  missing_description:
    "Art. 28(3) preamble requires the DPA to specify the categories of data subjects whose personal data is processed.",
  explanation:
    "An Art. 28(3)-compliant DPA names not just the type of personal data (e.g., names, emails) but also which categories of people the data describes (e.g., 'Customer's end users', 'Customer's employees', 'minor children'). Annex I.B of the EU SCCs requires this expressly.",
  recommendation:
    "Add a 'Categories of data subjects' clause to the DPA's Annex I.B (or its equivalent schedule), enumerating each category processed.",
  default_severity: "critical",
}),
```

### 3. Adjust playbook scope

The factory config (`DPA_GDPR_CONFIG`) sets the `applies_to_playbooks`
list — typically
`["dpa-controller-processor", "dpa-processor-subprocessor", "scc-module-2", "scc-module-3"]`.
A new DPA rule inherits this scope; override only if the rule is
SCC-Module-2-specific or similar.

### 4. Tests

Add a positive + negative case under
[`src/engine/rules/v3/dpa-gdpr/dpa-gdpr-ruleset.test.ts`](../../src/engine/rules/v3/dpa-gdpr/dpa-gdpr-ruleset.test.ts):

```ts
it("DPA-056 fires when categories of data subjects are absent", () => {
  // ...
});

it("DPA-056 does not fire when Annex I.B names data subject categories", () => {
  // ...
});
```

## Example B: US-state DPA rule

Hypothetical `USDPA-026` — "DPA references CCPA but is silent on the
sensitive-personal-information opt-out right."

### 1. Find the citation

CCPA is fetched by
[`dkb/build/v3/fetchers/state-privacy.ts`](../../dkb/build/v3/fetchers/state-privacy.ts).
The sensitive-PI opt-out lives at Cal. Civ. Code § 1798.121.

### 2. Author the rule

In [`src/engine/rules/v3/dpa-us-state/rules.ts`](../../src/engine/rules/v3/dpa-us-state/rules.ts):

```ts
buildLanguageRule(DPA_US_STATE_CONFIG, {
  id: "USDPA-026",
  name: "Sensitive personal information opt-out silent under CCPA",
  citation: "Cal. Civ. Code § 1798.121",
  bad_patterns: [
    // Fires when CCPA is referenced AND sensitive-PI handling is silent.
    // The factory's `bad_patterns` semantics match if *any* fires; the
    // pattern below is one regex written as a negative lookahead.
    /CCPA[^.\n]*(?!sensitive\s+personal\s+information|§\s*1798\.121)/i,
  ],
  bad_title: "DPA references CCPA but is silent on sensitive-PI opt-out",
  bad_description:
    "Cal. Civ. Code § 1798.121 grants consumers the right to limit the use of sensitive personal information. A DPA that processes sensitive PI must address how the service provider receives and honors that signal.",
  explanation:
    "CCPA distinguishes regular personal information from sensitive personal information (SSN, government ID, account credentials, precise geolocation, racial/ethnic origin, religious beliefs, health, etc.). A DPA that talks about CCPA but ignores § 1798.121 leaves a coverage gap the AG's enforcement team has flagged.",
  recommendation:
    "Add a clause acknowledging the § 1798.121 right and describing how the service provider relays sensitive-PI opt-out signals from the consumer to its sub-processors.",
  default_severity: "warning",
}),
```

### 3. State strictness floor

US-state DPA rules often apply across multiple states with overlapping
requirements. The `USDPA-021` "multi-state strictness floor" pattern
shows how to surface the risk at info-severity without flagging a fail.
Mirror this pattern when adding rules that vary across the eight
state-privacy regimes.

## Common pitfalls

- **Citation depth.** "GDPR Art. 28" is not enough; specify the
  subdivision (Art. 28(3)(c), Art. 28(4), Art. 28(9)). Spec §13–§16
  describes the citation discipline.
- **Translation provenance.** International sources (PIPL, APPI, LGPD)
  carry their translation provenance in the `authority` field of the
  fetcher's emitted node. Cite the translation explicitly when the
  rule turns on translation nuance.
- **`applies_to_playbooks`.** A rule that fires on every playbook is
  almost certainly a v2 rule — DPA rules should scope to the DPA
  playbooks so an MSA-with-no-DPA never sees them.

## Tests + gates

```
npm run typecheck && npm run lint && npm test && npm run build
```

If a golden's output drifts, run with `VAULYTICA_REGEN_GOLDEN=1` and
review the diff before committing.

# Adding a BAA rule

A v3 BAA rule lives in [`src/engine/rules/v3/baa/`](../../src/engine/rules/v3/baa/)
and uses the same `Rule` interface v2 ships
([`src/engine/finding.ts`](../../src/engine/finding.ts)). The difference
from a v2 rule is the citation discipline: every BAA rule must cite a
specific 45 CFR § 164.x subdivision (or an HHS OCR resolution
agreement), and the rule's `dkb_citations` must point at a DKB node
whose `content_hash_at_pin` was computed at the last DKB build.

This guide walks through a hypothetical `BAA-046` —
"Privacy Officer not named in the BAA". (BAAs frequently delegate
"any privacy questions" to the MSA's general notice address, and
counsel reviewing the BAA cannot tell who at the business associate
to call when something goes sideways. HHS guidance is silent but
practitioner norms favor a named contact.)

## 1. Confirm the citation depth

Every BAA rule's citation must be to a specific subdivision, not to
"HIPAA" or "45 CFR § 164". Open the eCFR snapshot under
[`dkb/fixtures/v3/snapshots/`](../../dkb/fixtures/v3/snapshots/) and
locate the controlling text. For `BAA-046` there is no statutory anchor
— the rule rests on a practitioner-norm citation. Use
`"category: 'baa'"` and `"default_severity: 'info'"`, and call out in
the rule description that the citation is practitioner guidance, not
statute. (Spec §34 covers the "consensus practice" framing.)

If the rule rests on statute, find the DKB node id. The HIPAA fetcher
(`dkb/build/v3/fetchers/hipaa-ecfr-title-45.ts`) emits
`statutory_clause_requirement` nodes with stable ids derived from the
CFR section. The DKB node id is what goes in `dkb_citations`.

## 2. Pick the id

BAA rule ids are `BAA-NNN`, sorted lexicographically. The next slot is
`BAA-046`. The registry at
[`src/engine/rules/v3/baa/rules.ts`](../../src/engine/rules/v3/baa/rules.ts)
asserts the count at load time — bump the asserted total when you add
the rule.

## 3. Decide presence vs. language

The BAA helpers in
[`src/engine/rules/v3/baa/_helpers.ts`](../../src/engine/rules/v3/baa/_helpers.ts)
expose two factories:

- `buildBaaPresenceRule(spec)` — fires when *none* of `present_patterns`
  matches the document. Use for required-clause checks ("BAA must
  describe permitted uses").
- `buildBaaLanguageRule(spec)` — fires when *any* of `bad_patterns`
  matches a paragraph. Use for quality-of-text checks ("breach
  notification timing is no looser than 60 days").

`BAA-046` is a presence rule: it fires when the BAA does not name a
contact for privacy questions.

## 4. Author the rule entry

In `rules.ts`:

```ts
buildBaaPresenceRule({
  id: "BAA-046",
  name: "Privacy Officer not named",
  citation: "Practitioner guidance",
  present_patterns: [
    /\bprivacy\s+officer\b/i,
    /\bHIPAA\s+(?:compliance\s+)?contact\b/i,
    /\bnamed\s+contact\s+(?:for\s+)?privacy/i,
  ],
  missing_title: "BAA does not name a Privacy Officer or HIPAA contact",
  missing_description:
    "The BAA delegates privacy questions to the MSA's general notice address. There is no named contact at the business associate for HIPAA matters.",
  explanation:
    "OCR has not required a named contact, but practitioner norms favor one. A general MSA notice address routes routine notices but not breach-coordination calls, where time matters and the BA's compliance team needs the right intake.",
  recommendation:
    "Name a Privacy Officer (or HIPAA compliance contact) in the BAA, with a direct address and a backup. Update both when the role turns over.",
  default_severity: "info",
}),
```

Then bump the assertion:

```ts
// Was: if (BAA_RULES.length !== 45) throw new Error(...);
if (BAA_RULES.length !== 46) {
  throw new Error(`Expected 46 BAA rules; got ${BAA_RULES.length}`);
}
```

## 5. Write the tests

Add a single test under
[`src/engine/rules/v3/baa/baa-ruleset.test.ts`](../../src/engine/rules/v3/baa/baa-ruleset.test.ts):

```ts
it("BAA-046 fires when no privacy contact is named", () => {
  const ctx = buildBaaContext({
    body: "Business Associate may use PHI only for the Services...",
    omit: "privacy-officer",
  });
  const findings = BAA_RULES
    .filter((r) => r.id === "BAA-046")
    .map((r) => r.check(ctx))
    .filter((f): f is Finding => f !== null);
  expect(findings).toHaveLength(1);
});

it("BAA-046 does not fire when a Privacy Officer is named", () => {
  const ctx = buildBaaContext({
    body: "Business Associate's Privacy Officer is Jane Doe (jane@globex.com)...",
  });
  const findings = BAA_RULES
    .filter((r) => r.id === "BAA-046")
    .map((r) => r.check(ctx))
    .filter((f): f is Finding => f !== null);
  expect(findings).toHaveLength(0);
});
```

## 6. Update the BAA playbook

If the rule should affect the BAA playbook's compliance matrix, add the
relevant column to
[`src/playbooks/v3/baa.json`](../../src/playbooks/v3/baa.json)'s
`compliance_matrix_columns`. The matrix builder (forthcoming) maps rule
ids to columns by the rule's `dkb_citations`.

## 7. Run the gates

```
npm run typecheck && npm run lint && npm test && npm run build
```

If a golden fixture's output changes, regenerate the affected goldens
deliberately:

```
VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v3
```

Review the diff in `tests/golden/v3/expected/` before committing.

## 8. Citation discipline

Every v3 BAA rule must, at minimum:

- Carry a `citation` string in the BAA shape pointing to the specific
  CFR subdivision (or "Practitioner guidance" for non-statutory rules).
- Reference at least one DKB node id in `dkb_citations` if the rule
  rests on statute.
- Survive the DKB staleness gate — the build pipeline re-fetches every
  cited authority weekly and would disable the rule if the upstream
  text changes without a matching DKB node bump.

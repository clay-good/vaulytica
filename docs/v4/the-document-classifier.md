# The document classifier

v4 adds automatic document classification so the engine loads the right
playbook without requiring the user to select a document type. The
classifier is a two-stage scoring function: a sub-domain stage that
scores all 16 buckets, followed by a family stage that scores within the
winning sub-domain.

## Stage 1 — sub-domain scoring

The classifier reads the extracted text (same surface the rule engine
uses) and scores it against a feature matrix defined in
`dkb/v4/sub-domain-features.json`. Each sub-domain has a list of
weighted keyword and phrase features. The score for sub-domain X is the
sum of feature weights that match the document text, normalized to
[0, 1].

The sub-domain with the highest normalized score wins — provided the
score exceeds the confidence threshold of **0.5**. If no sub-domain
exceeds 0.5, the document falls back to `generic-fallback`, which runs
only the v1 LAUNCH_RULES and the v3 core rules (no v4 sub-domain rules).

### Feature file location

```
dkb/v4/sub-domain-features.json
```

The file is a JSON object keyed by sub-domain code (A–P). Each value is
an array of `{ phrase: string; weight: number }` objects. Phrases are
matched case-insensitively against the full extracted text.

## Stage 2 — family scoring within the sub-domain

Once a sub-domain is selected, the classifier scores the document
against each family within that sub-domain using the same weighted-
phrase approach, but with family-specific features drawn from the
playbook's `classifier_hints` field (added in v4 playbook JSON).

The family with the highest score is selected. If two families tie, the
alphabetically earlier family id wins (deterministic tiebreak). The
selected family determines which playbook is applied.

## Implementation

The classifier is implemented in:

```
src/extract/v4/classifier.ts
```

It exports two functions:

```typescript
classifySubDomain(text: string): SubDomainCode | "generic-fallback"
classifyFamily(text: string, subDomain: SubDomainCode): FamilyId
```

`classifySubDomain` loads `sub-domain-features.json` (bundled at build
time via Vite's `?raw` import) and returns the winning code or
`"generic-fallback"`. `classifyFamily` is called only when
`classifySubDomain` returned a real sub-domain code.

## Confidence threshold

The threshold of **0.5** was chosen to minimize false-positive playbook
selection (loading a trust-and-estate playbook against an NDA is more
harmful than falling back to generic). Raise the threshold to be more
conservative (more fallback, fewer false positives); lower it to be more
aggressive (fewer fallback cases, more false positives).

## Fallback behavior

When the classifier returns `"generic-fallback"`, the engine runs
LAUNCH_RULES (v1) + V3_RULES (v3 core) only. No v4 sub-domain rules
fire. The report cover notes that sub-domain classification was not
confident and the user may want to select a sub-domain manually (future
UI hook).

## How to retune

1. Edit `dkb/v4/sub-domain-features.json` — add or adjust phrase/weight
   entries for the sub-domain that is mis-classified.
2. Run `npm run test -- --reporter=verbose` and check whether
   `src/extract/v4/classifier.test.ts` passes.
3. If you are adding a brand-new phrase set, regenerate the DKB:
   `npm run dkb:build` and commit the updated snapshot.
4. Adjust `classifier_hints` in the relevant playbook JSON files if the
   family-stage scoring is the problem rather than the sub-domain stage.

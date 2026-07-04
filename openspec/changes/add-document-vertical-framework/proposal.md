# add-document-vertical-framework

## Why

Every mechanism a new legal vertical needs already exists, but the map has holes an expansion would fall through. The v4 classifier scores 16 contract sub-domains (`src/extract/v4/classifier.ts`, `dkb/v4/sub-domain-features.json` keys A–P); a litigation brief, a production set, or a will with no matching family silently falls to `generic-fallback` and gets contract-shaped treatment — the audit's live example was STRUCT-003 reporting "No signature block detected" on an arbitrary text file, a confidently wrong contract finding on a non-contract input. Rule isolation exists (`Rule.applies_to_playbooks`, `src/engine/finding.ts:104-109`) and is proven by the v3 DPA/BAA packs, but nothing states the contract every future pack must honor: how a vertical declares itself, how its rules stay off other document types, how its scope-of-review is disclosed, and how a document that matches *no* vertical is reported honestly. This change writes that contract down and closes the fallback-honesty hole — the prerequisite for the filing-compliance, production-QA, and estate changes behind it.

## What Changes

- **Fallback honesty.** When classification falls to `generic-fallback` (matcher below `MATCH_THRESHOLD`, no v4 sub-domain ≥ its calibrated floor), every report surface carries an explicit banner: the document did not match any known type, contract-lint rules were applied anyway, and findings may not be meaningful for a non-contract document. The banner is part of the hashed report (not render-only), so a generic-fallback receipt is distinguishable forever.
- **Vertical pack contract, documented and enforced.** A vertical = one classifier family (feature entry in the sub-domain data), one or more playbook/profile JSON files, one rule pack whose every rule sets `applies_to_playbooks` to that vertical's ids, one rule-ID namespace, and one scope-of-review statement ("reviewed for: X; not reviewed for: Y") rendered on every report where the pack ran. A guard test enforces the gate: no rule outside the v1/v2 launch set may omit `applies_to_playbooks`.
- **Cross-hash safety pinned.** A property test asserts that adding a vertical pack leaves every existing golden `result_hash` byte-identical when the active playbook is not in the pack's list — turning the informal "additive packs don't disturb hashes" invariant into a gate.
- **Vertical registry doc** (`docs/verticals.md`): the pack contract, the namespace table (existing: STRUCT/FIN/TEMP/…, DPA/BAA, v4 domains; reserved for this wave: FILE, CITE, DDL, PROD, PNOT; estate deepening extends the existing EST namespace), and the honesty posture each pack inherits (presence-only never issues a clean bill; tiers stay attorney-gated via the legal-basis ledger).

## Impact

- Affected specs: `document-verticals` (new capability spec)
- Affected code: `src/ui/pipeline.ts` + `tools/cli/run.ts` + report builders (fallback banner), new guard + property tests, `docs/verticals.md`; no engine behavior changes for matched documents
- Risk: the fallback banner enters the hashed report → goldens for generic-fallback fixtures re-baseline once; all matched-playbook hashes are provably unchanged (that is the point of the new property test).

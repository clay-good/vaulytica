# Vertical Packs

A **vertical** is one document family Vaulytica knows how to review — a
litigation filing, a data-processing agreement, a will. Every mechanism a new
vertical needs already exists; this document writes down the contract each pack
must honor so an expansion cannot fall through a gap. The machine-checkable half
lives in [`src/verticals/registry.ts`](../src/verticals/registry.ts) and is
enforced by [`src/verticals/registry.test.ts`](../src/verticals/registry.test.ts).

## What a vertical pack is

A pack is five things, each with a single home:

| Part | Where it lives |
| --- | --- |
| **Classifier family** | a feature entry in `dkb/v4/sub-domain-features.json` (or a v2 playbook match) |
| **Playbook(s)/profile(s)** | one or more JSON files under `src/playbooks/` |
| **A gated rule pack** | rules whose every member declares a gate (see below) |
| **A reserved rule-ID namespace** | one prefix, listed in the table below |
| **A scope-of-review statement** | an entry in `SCOPE_OF_REVIEW`, rendered on every report the pack ran on |

## The gate: every non-launch rule is gated to its family

The v1/v2 launch rules (`LAUNCH_RULES`) are the general contract-lint set; they
always run. **Every rule outside that set must declare exactly one gate** so it
never fires on a document type it was not written for:

- **`applies_to_playbooks`** — a non-empty list of playbook ids. The rule runs
  only when one of them is the active playbook. This is how the DPA and BAA
  packs are gated today.
- **A registered assertion gate (`assertion_gate`)** — the rule runs only when
  the user asserts a named flag/toggle (e.g. a deadline-computation profile or
  `--estate-checks`). The gate name must appear in `REGISTERED_ASSERTION_GATES`.
  Used by packs that deepen an already-shipped playbook or attach to opt-in
  machinery, where a playbook gate does not fit.

A guard test fails the suite naming any non-launch rule that declares neither
gate, or an assertion gate that is not registered.

### Assertion-gate registry

| Assertion | Pack | Status |
| --- | --- | --- |
| _(none yet)_ | — | The first assertion-gated pack registers its gate here. |

## Namespace reservation

Every finding id is `PREFIX-NNN`. Each prefix has one owner, so ids stay
collision-free across packs. `NAMESPACE_OWNERS` is the source of truth; the
guard test asserts no prefix is claimed twice and that every shipped non-launch
rule uses a registered prefix.

| Prefix | Owner |
| --- | --- |
| STRUCT, FIN, TEMP, OBLI, RISK, CHOICE, TERM, IPDATA, PERS, DARK | launch contract-lint |
| BAA | HIPAA business associate |
| DPA | GDPR data processing |
| USDPA | US state data processing |
| TRANSFER | cross-border transfer |
| ADDENDA | addenda |
| MSA, NDA | deep MSA / NDA packs |
| BNK, CON, EMP, EQT, EST, GOV, HC, INS, IPL, MNA, POL, PRV, RE, REG, SET | v4 sub-domain families |
| **FILE** | filing-format lint *(reserved)* |
| **CITE** | authority-citation lint *(reserved)* |
| **DDL** | deadline computation *(reserved)* |
| **PROD** | production QA *(reserved)* |
| **PNOT** | privacy notice *(reserved)* |

The estate pack deepens the already-owned **EST** prefix rather than reserving a
new one.

## Honesty posture every pack inherits

- **Presence-only.** A pack reports what it *found*, never what it *did not
  find* as a clean bill of health (`src/delivery/types.ts`). A pack that runs
  and finds nothing renders its scope statement and reports "no findings from
  the checks listed" — never "compliant" or "clean."
- **Scope of review, always rendered.** Each pack declares what it checked and
  what it did not (`reviewed_for` / `not_reviewed_for`). That statement appears
  on every report surface the pack ran on (DOCX, HTML, JSON, Markdown, and the
  tab).
- **Tiers stay attorney-gated.** A legal-confidence tier appears on a finding
  only after a credentialed attorney signs the rule's legal-basis ledger entry.
  A pack never mints its own tier.
- **Unmatched is reported as unmatched.** When classification falls to the
  generic fallback, the run carries a `classification_notice` stating that no
  known family matched and contract-lint rules were applied anyway. The notice
  is inside the hashed run, so a generic-fallback receipt is distinguishable
  forever.

## Adding a pack cannot change existing hashes

Activating a pack narrows the candidate rules through `selectActiveRules`: a
rule whose playbook gate excludes the active playbook, or whose assertion gate
is not asserted, is selected *out* before the engine runs. A property test
proves that registering a synthetic pack leaves every launch golden's
`result_hash` byte-identical when the active playbook is outside the pack's gate
— and, for assertion-gated rules, whenever the assertion is not made. See
[`src/verticals/registry.test.ts`](../src/verticals/registry.test.ts).

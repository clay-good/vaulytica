# Vaulytica v45 — The US Catalog (105 More American Document Families, Column-First)

> **Status:** **Shipped (9.42.0).** v4 took the catalog from "contracts" to "every logically-operative legal document" by adding sixteen sub-domains — and stopped one layer short of the documents an American practice actually handles all day. A firm that reviews an MSA also reviews the purchase order underneath it, the franchise disclosure document, the QDRO, the WARN notice, the preliminary lien notice, the stipulated protective order. Each of those is a distinct instrument with its own governing text and its own short list of terms that decide whether it works. v45 adds **105** of them inside the same sixteen sub-domains, with **605** new checks, and it does so **column-first**: the catalog was designed as compliance-matrix columns, and each column ships as exactly one check. It continues the global step numbering after v44's Step 224, beginning at **Step 225**.
> **Scope:** one idea — go **deep on one jurisdiction** rather than wide across more. Every family is US, and every citation is US law: the UCC as the states enacted it, an FTC trade regulation rule, the FAR, ERISA, the Bayh-Dole Act, a state mechanic's lien statute. This is not a new engine, a new rule shape, a new report surface, or a new gate. It is 105 playbooks, 605 rules built from the three existing v4 rule builders, one new pack shorthand, and two new bundle chunks.
> **Posture (unchanged, non-negotiable):** deterministic (every check is a pure regex read of the document text; no float, no clock, no network), no AI, no server, citable (every check names the authority behind the expectation, and says plainly when the authority is customary practice rather than a rule that compels the clause), presence-only (a check reports what it found, never certifies a document compliant), and **additive** — every v5 rule is gated to exactly one v5 playbook, so no document the engine could already classify changes its `result_hash`.
> **Cousin docs:** [`spec-v4.md`](spec-v4.md) (the sixteen sub-domains this deepens), [`verticals.md`](verticals.md) (the pack contract every wave honors), [`adding-a-rule.md`](adding-a-rule.md), [`bundle-splitting.md`](bundle-splitting.md). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

The catalog's weakness after v4 was not breadth. It was that breadth had been bought at one document per family: one lease, one loan agreement, one settlement agreement. Real practice is denser than that. The lease has a sublease, a work letter, an LOI, an estoppel, and a listing agreement around it. The loan agreement has a forbearance, a control agreement, and a factoring facility beside it. The settlement has a covenant not to sue, a stipulated dismissal, a consent judgment, and a protective order.

Those satellites are where the drafting defects actually live, because they are the documents that get produced from a template under time pressure and reviewed least. A preliminary lien notice that omits the statutory warning forfeits the lien outright. A QDRO that omits the no-increased-benefit recital is rejected by the plan administrator. A first-party special needs trust without the Medicaid payback is not an exempt trust at all. None of those is a judgment call; each is a term that is either in the document or is not.

That is exactly the shape this engine is good at, and it is the shape v4 had not been pointed at.

## §2. What v45 is and is not

**It is:**

- **105 new US document families**, each a playbook under `src/playbooks/v5/` with title keywords, distinguishing phrases, negative features, expected defined terms, a regulator frame, and a compliance matrix.
- **605 new checks**, one per compliance-matrix column, gated to exactly one family each.
- **A column-first authoring discipline.** The catalog was designed as matrices first and rules second, and a guard test asserts the two never diverge: a family's column count must equal its check count, and its description must state its own rule range.
- **A new pack shorthand** (`src/engine/rules/v5/_pack.ts`) that turns one column into one rule, supplying the boilerplate and leaving the four fields that carry the legal content: the citation, the patterns, why it matters, and what to add.
- **Two new bundle chunks** (`v5-rules-corp`, `v5-rules-reg`), for the same reason v4 split into two: keeping every chunk under the 600 KB threshold.

**It is not:**

- **Not a new rule shape.** Every v5 rule is `buildV4PresenceRule` under a different name. The one addition is conjunction semantics (§5), which is a pattern-composition choice, not a new builder.
- **Not a widening of jurisdiction.** Every family is US. Where a body of law varies by state, the citation says so and the check reads for the term, never for the state's version of it.
- **Not a claim of completeness.** 105 families is a large fraction of what a US general practice touches and nowhere near all of it. The catalog is a list of what Vaulytica knows, published in full on the front page, precisely so a reader can see what is missing.
- **Not a change to any existing document's output.** See §7.

## §3. The posture filter

1. **Deterministic** — each check is a set of regexes tested against the document's own text. No ordering by score, no threshold, no clock.
2. **Honest about authority** — a check that rests on a statute cites the statute; a check that rests on how the document is customarily drafted says so in the citation itself (`practice()` renders "Customary US drafting practice — … (no single controlling authority)"). The engine never dresses a drafting convention as a legal requirement.
3. **Presence-only** — a check reports a term as not found. It never reports the document as compliant, adequate, or effective.
4. **No server** — the rules are pure functions in the same bundle as every other rule.
5. **Additive** — §7.

---

# Part I — The catalog

## §4. Sixteen sub-domains, 105 families

| Sub-domain | Families | Checks | Rule range |
| --- | --- | --- | --- |
| Commercial — UCC and FTC | 16 | 88 | `COMM-101..188` |
| Commercial — digital and consumer | 8 | 47 | `COMM-201..247` |
| Entity governance and nonprofit | 7 | 38 | `GOV-101..138` |
| Equity compensation and secondaries | 5 | 30 | `EQT-101..130` |
| M&A deliverables and investment | 5 | 28 | `MNA-101..128` |
| Real estate satellites and conveyancing | 9 | 50 | `RE-101..150` |
| Employment and labor | 9 | 53 | `EMP-101..153` |
| Settlement and litigation-adjacent | 8 | 43 | `SET-101..143` |
| IP transfers and collaboration | 6 | 33 | `IPL-101..133` |
| Consent instruments and data sharing | 4 | 23 | `PRV-101..123` |
| Health care contracting | 5 | 32 | `HC-101..132` |
| Insurance policy and coverage review | 3 | 18 | `INS-101..118` |
| Lending and consumer credit | 7 | 43 | `BNK-101..143` |
| Design services and lien notices | 3 | 17 | `CON-101..117` |
| Trusts, benefits orders, cohabitation | 5 | 30 | `EST-401..430` |
| Enterprise compliance policies | 5 | 32 | `POL-101..132` |

Ranges are disjoint from every shipped v4 rule: v4 stops at or below `-080` in each sub-domain prefix, so v5 starts at `-101`; the estate prefix additionally carries the assertion-gated `EST-1xx/2xx/3xx` deepening, so v5 starts at `EST-401`.

## §5. One column, one check

Each family's playbook carries a `compliance_matrix_columns` list. Each column names a term the document is expected to carry, and ships as one rule:

```ts
{
  id: "EST-421",
  name: "No increased-benefit requirement",
  cite: usc("29", "1056", "ERISA § 206(d)(3)(D) — limitations on qualified orders"),
  pat: [/(shall\s+not\s+require\s+the\s+plan\s+to\s+provide|does\s+not\s+require)/i,
        /(any\s+type\s+or\s+form\s+of\s+benefit.{0,60}not\s+otherwise\s+provided|increased\s+benefits)/i],
  all: true,
  why:  "§ 1056(d)(3)(D) disqualifies an order that requires a benefit form the plan does not offer …",
  fix:  "Recite that the order does not require the plan to provide any type or form of benefit …",
  sev:  "critical",
}
```

Two deliberate departures from the v4 presence spec:

- **Default severity is `warning`, not `critical`.** A v4 presence rule defaults to `critical` because those packs check terms a regulator enumerates. A catalog column is a drafting expectation. Rules whose absence is independently actionable — an unlawful clause, a statutory disclosure, a benefits-qualification condition — pass `sev: "critical"` explicitly.
- **`all` conjoins the patterns.** The v4 builder treats `present_patterns` as alternatives, which is right for synonym sets and wrong for pillar sets. `all: true` compiles the patterns into one anchored lookahead conjunction, so every pillar must appear. §13 explains why this had to exist.

## §6. Applicability gates

A column that applies only to a sub-shape of the family carries `when`. A residential purchase contract for new construction is not missing a lead-based paint disclosure; a third-party special needs trust is not missing a Medicaid payback; a civilian-agency FAR rider is not missing a DFARS cybersecurity flow-down. Reporting an absence the document itself shows is irrelevant is a false positive, and this wave has 24 such gates.

---

# Part II — Additivity

## §7. Adding v5 cannot change any existing hash

Every v5 rule declares `applies_to_playbooks` naming exactly one v5 playbook. `selectActiveRules` filters a rule out before the engine runs whenever the active playbook is outside its gate, so for any document that matched a pre-v5 family the whole wave is selected out and the `EngineRun` — including its `execution_log` and `result_hash` — is byte-identical to before. This is the contract [`verticals.md`](verticals.md) states for every pack; `src/verticals/registry.test.ts` proves it on every launch golden, and `src/engine/rules/v5/ruleset.test.ts` proves no v5 rule names a pre-v5 playbook.

The golden corpus is the empirical half of the same claim: all 1,074 golden assertions pass unchanged with 105 new playbooks registered in the matcher, which is the evidence that no corpus document was re-classified into a v5 family.

---

# Part III — Delivery

## §8. Bundle

The v5 catalog is ~285 KB raw. Left in the shared `rules-core` chunk it pushed that chunk to 883 KB, past the 600 KB per-chunk cap. It now splits into `v5-rules-corp` (218 KB) and `v5-rules-reg` (173 KB) on the same corporate/regulatory line v4 uses, with a v5 file joining the regulatory bucket by default. Nothing moves onto the first-paint path: like every rule chunk, both load behind the file-drop gesture.

## §9. Front page

The document-type index names all 250 families and states the count in three places, all guarded by `tests/integration/site-document-types.test.ts`, which reads the playbook directory off disk. A new family fails that test until the page lists it.

---

# Part IV — Verification

## §10. What ships green

- `src/engine/rules/v5/ruleset.test.ts` — 14 structural assertions: the count, id uniqueness, no collision with any earlier wave, registered namespace prefixes, the numbering floor, exactly one playbook gate per rule, every family covered, no rule reaching a pre-v5 family, `applicable_jurisdictions === ["US"]`, one column per check, and each description stating its own rule range.
- `src/engine/rules/v5/behavior.test.ts` — 21 representative checks pinned in **both** directions, plus five applicability-gate probes.
- `src/engine/rules/v5/title-vacuity.test.ts` — §13.
- `src/verticals/registry.test.ts` — the gate contract, extended to cover `V5_RULES`.
- `tests/integration/readme-rule-count-drift.test.ts` — the published totals, extended to include the v5 addend.

## §11. Counts

| | Before | After |
| --- | --- | --- |
| Document families | 145 | 250 |
| Single-document rules | 1,111 | 1,716 |
| Test suite | 6,638 | 6,701 |

---

# Part V — What this cost, and what it taught

## §12. The pack shorthand earns its keep

605 rules written longhand in the v4 spec shape would be roughly 9,000 lines in which the legal content — the authority, the reason, the fix — is a minority of the text. `pack()` supplies the invariant half and leaves four fields. The result is that a reviewer reads 605 citations and 605 explanations rather than 605 object literals.

## §13. The title-vacuity defect

A presence rule fires when **none** of its patterns match. So a rule whose pattern is a word from its own family's title can never fire.

That is not a hypothetical. The first run of the probe found **27 real instances**, including:

- the irrevocability recital (`EST-401`), satisfied by the words "Irrevocable Trust" in the title;
- the UCC § 9-104 control language (`BNK-127`), satisfied by the word "Control" in "Deposit Account Control Agreement";
- the BIPA written release (`PRV-101`), satisfied by the word "Consent" in the family name;
- the cohabitation non-marital recital (`EST-426`), satisfied by "Cohabitation";
- the FCRA written authorization (`EMP-150`), satisfied by the word "signature" in an ordinary signature block;
- the separate-property clause (`EST-427`), satisfied by the word "Title:" in a signature block.

Each of those would have shipped a column the compliance matrix shows as reviewed and that reports nothing on any document, forever — which is worse than no column at all, because the matrix asserts coverage that does not exist.

The fix was two-part: conjunction semantics (`all`) where the patterns were distinct pillars, and pattern tightening where a pillar was too generic. The guard is permanent: `title-vacuity.test.ts` runs every ungated check against a document that is only its family's title plus execution boilerplate, and requires all of them to fire. Gated rules are excluded from the probe, and the gated set is *derived* by `pack()` rather than hand-maintained, so a stale id can never quietly widen the exclusion.

**The general lesson, worth carrying into any future wave:** in a presence-rule catalog, the adversarial direction is not "does it fire on a bad document" — it is "*can* it fire at all." A rule that never fires is invisible in review, invisible in the goldens, and invisible in the finding counts. It is only visible to a probe that deliberately hands the rule the emptiest document its family admits.

---

# Part VI — Open questions

1. **Per-state overlays.** Several checks read for a term whose content varies by state (mechanic's lien warnings, physician non-competes, automatic-renewal notice windows). The check reads for the term; it does not yet know which state's version applies. The `--state` assertion machinery the estate pack uses is the natural home for that, and is deliberately out of scope here.
2. **Language-quality rules.** This wave is entirely clause-presence. Several families have obvious language-quality checks behind them — an unenforceable liquidated-damages formula, a conduct exclusion triggered by allegation rather than adjudication — and those need the adversarial false-accusation discipline the v4 packs went through over several sessions before they can ship.
3. **Corpus fixtures.** The wave ships without golden fixtures of its own. The structural, behavioral, and vacuity guards constrain it; a labeled corpus per family would constrain classification accuracy, which they do not.

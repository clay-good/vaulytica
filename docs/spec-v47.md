# Vaulytica v47 — Legal Currency (Keeping 1,808 Citations From Quietly Going Stale)

> **Status:** **Shipped (9.42.0)** — the guard and the first repair. The review cadence in Part III is a **process commitment**, not code. v47 is not a feature. It is the answer to a failure mode the catalog acquired the moment it got large: a citation that was good law when it was written and is not any more. There is no rule count attached to it. It continues the global step numbering after v46's Step 226, beginning at **Step 227**.
> **Scope:** one idea — the catalog's honesty claim decays with time unless something forces it not to. Every other spec in this repo adds capability. This one protects the capability already shipped.
> **Cousin docs:** [`verticals.md`](verticals.md) (the honesty posture this defends), [`data-sources.md`](data-sources.md) (how the DKB is built and dated), [`spec-v45.md`](spec-v45.md) and [`spec-v46.md`](spec-v46.md) (the two waves that took the catalog to 1,808 checks).

---

# Part 0 — The failure mode

## §1. What went wrong

Vaulytica's whole argument is that every finding names the authority behind it. That argument has a decay function nobody had accounted for.

A rule is written when its authority is good law. Nothing about the rule changes when the authority is vacated. It keeps firing, keeps citing, and keeps reading — to an attorney, in a Word report, with a URL — as confident, sourced advice. It is invisible in a diff, because no line changed. It is invisible in the goldens, because the output is byte-identical to what it was when it was right. And it is invisible in the finding counts, because the count is the same.

It had already happened twice:

- **The FTC's "click-to-cancel" rule.** The 2024 amendments to the Negative Option Rule were vacated in their entirety by the Eighth Circuit on July 8, 2025, never took effect, and 16 C.F.R. Part 425 has since been recodified to its pre-2024 text, which reaches prenotification plans only. Six surfaces presented it as governing a SaaS subscription — including a v3 rule *named* "FTC Click-to-Cancel alignment" whose explanation told the reader the rule "requires that cancellation be at least as easy as signup."
- **The FTC Non-Compete Clause Rule.** Set aside nationwide in *Ryan LLC v. FTC* and since removed from the CFR. The employment and personnel packs had been updated correctly and said so. The M&A restrictive-covenant playbook had not, and still framed itself as covenants "under the FTC NCR sale-of-business exception (16 C.F.R. § 910.2(a)(2))."

The second is the more instructive one: **the repo already knew.** Three files said "vacated nationwide … never took effect," and a fourth, in a different directory, did not. Knowing is not the same as having a mechanism.

## §2. Why the existing guards did not catch it

The repo has an unusually dense drift-guard layer: rule counts, README totals, playbook names on the landing page, CLI flags, coverage floors, DKB integrity, bundle sizes. Every one of them compares **the repo against itself**. A citation going stale is a change in the world, and no self-consistency check can see it.

That is a real limit, and worth stating plainly rather than pretending a test can close it. What a test *can* do is make a repair permanent.

---

# Part I — The guard

## §3. `tests/integration/vacated-authority.test.ts`

A registry of authorities that have been vacated, set aside, or withdrawn. Each entry pairs `mentions` (how the repo names the authority) with `disclaimer` (the vocabulary that makes a mention honest — *vacated*, *set aside*, *never took effect*, *withdrawn*, *recodified*, *would likewise have*).

Two assertions per entry:

1. **No rule** — across the launch set, v3, v4, v5, and v6 — has a name, description, or citation that names the authority without a disclaimer.
2. **No repaired prose file** mentions it without a disclaimer within a six-line window. The window matters: a disclaimer is usually the next sentence of the same comment or the next clause of a formatter-wrapped string literal, so line-by-line matching reports correct prose as a violation.

Plus one assertion that the repair kept the substance: ADDENDA-019 still checks cancellation parity, and its version is no longer `1.0.0`.

**What the guard does and does not do.** It cannot know what gets vacated next; that is research, not a test. Its value is that a repair cannot be silently undone, and that the next such discovery has an obvious place to land — one registry entry, and the assertions come free.

## §4. The repair pattern

When an authority falls, the check usually survives it. Cancellation parity is still required — by ROSCA § 8403 and the state automatic-renewal laws, which the vacatur did not touch. Sale-of-business covenants are still enforceable — under the state goodwill doctrine that governed before the FTC rule and governs now.

So the pattern is:

1. **Keep the logic.** The patterns, the gate, and the severity stay.
2. **Re-cite to the authority that actually imposes the obligation**, and bump the rule version.
3. **Rename if the name carried the dead authority.** A rule named "FTC Click-to-Cancel alignment" is wrong in the findings index, in the compliance matrix, and in the execution log — places the explanation never reaches.
4. **Annotate the DKB entry inline**, so a reader who follows the citation gets the current posture. The Part 910 entry already did this; Part 425 now does too.
5. **Add the registry entry**, and regenerate the goldens the text change moves.

---

# Part II — What this costs

A citation repair is a text change inside a `Finding`, so it changes `result_hash`. The click-to-cancel repair moved **340 golden files** across the v2, v3, and v4 corpora. That is the correct price: the report *did* change, the provenance *should* say so, and a repair that did not move the hash would mean the corrected text never reached a reader.

Both golden families need regenerating, by two different mechanisms — `VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/` for v3/v4 and the same variable over `tests/integration/golden-output.test.ts` for the v2 set. Missing the second is an easy way to leave the suite red after a citation fix.

---

# Part III — The cadence (a process commitment, not code)

The guard is retrospective by construction. Finding the *next* vacated authority is a review task, and the honest thing is to write down when it happens rather than to imply a test covers it.

**Each release, re-verify the authorities most exposed to change:**

| Class | Why it moves | Examples in the catalog |
| --- | --- | --- |
| FTC trade regulation rules | Vacated on APA grounds twice in two years | Negative Option / Part 425, Non-Compete / Part 910, Endorsement Guides, CARS |
| Agency rules under active challenge | Post-*Loper Bright* litigation volume | SEC climate and cyber rules, DOL rules, CFPB rules |
| Federal Rules of Civil Procedure | Amended on a December 1 cycle | FRCP 16, 26, 30(b)(6), 34, 45; FRE 702, 502 |
| State analog statutes | New states enact each session | automatic-renewal laws, privacy statutes, physician non-compete bans, mini-WARN acts |
| Uniform acts and model rules | Amended by the ULC and the ABA | UCC amendments, RULLCA, UTC, Model Rules |
| Standard forms | Revised on a publisher's cycle | AIA, NVCA, LSTA, IAB, AAA/JAMS rules |

**Where a repair lands:** the registry entry in the guard, the rule's own text and version, the DKB entry, the CHANGELOG, and the goldens.

---

# Part IV — Open questions

1. **Machine-readable currency.** The DKB already carries `retrieved_at` per citation. A check that flags any citation not re-verified within N months would convert the cadence above from a commitment into a gate. It needs a review ledger the DKB does not have yet, and the `docs/legal-basis/` queue is the obvious place to grow one.
2. **Positive verification, not just vacatur.** The guard catches presenting dead law as live. It does not catch a rule that is *silent* about an authority that has since become live — the mirror failure, and the harder one.
3. **Scope of the registry.** Two entries today. It should grow only from real discoveries, never speculatively: an entry for an authority that was never cited is noise, and noise in a guard is how guards get ignored.

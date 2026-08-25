# Vaulytica v46 — The Lawyer's Own Documents (Engagement, Discovery, Pleadings)

> **Status:** **Shipped (9.42.0).** Every wave through v45 reads a document the lawyer's **client** is a party to. v46 turns the same engine on the documents the **practice itself** produces — the engagement letter, the requests for production, the answer. That is a different legal use case, not a wider contract catalog: it is the first time Vaulytica reads a document the lawyer signs, and the first time the governing text is a rule the lawyer is *personally* bound by rather than a statute governing the deal. Three packs, 15 families, 92 checks, three reserved namespaces (`ENG`, `DISC`, `PLDG`). It continues the global step numbering after v45's Step 225, beginning at **Step 226**.
> **Scope:** one idea — point the linter at the practice, not the transaction. Engagement and fee agreements against the ABA Model Rules; discovery instruments against the FRCP; pleadings against Rules 8, 9, 10, 11, and 38. No new engine, no new rule shape, no new report surface: it reuses the v45 `pack()` shorthand unchanged.
> **Posture (unchanged, and here at its strictest):** deterministic, no AI, no server, presence-only, additive — plus two caveats this wave forces into every citation it emits, because the alternative is a tool that tells a lawyer their state requires something it does not (§3).
> **Cousin docs:** [`spec-v45.md`](spec-v45.md) (the shorthand and the title-vacuity guard this reuses), [`verticals.md`](verticals.md) (the pack contract, including the scope-of-review obligation these packs lean on hardest), [`spec-v4.md`](spec-v4.md). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

The engine's premise is that a large share of legal risk lives in whether a document says a specific thing, and that checking for it is mechanical work a computer should do. Nothing in that premise is specific to contracts.

The documents a practice produces for itself are, if anything, a better fit than contracts. They are more standardized, they are governed by rules with enumerated elements, and their failure modes are unusually binary:

- An interrogatory response served without the answering party's verification is not evidence.
- A discovery response that omits the Rule 34(b)(2)(C) statement of whether material is being withheld is unreviewable, which is why the 2015 amendment added it.
- A request for admission not answered in 30 days is **deemed admitted** — the only discovery device with an automatic, case-dispositive default.
- An affirmative defense omitted from an answer is generally waived, and Rule 12(h)(1) waives personal jurisdiction, venue, and process defenses omitted from the first response.
- A jury demand not served within 14 days waives the jury trial.
- A contingent fee agreement that does not say whether expenses come off before or after the fee is the most-litigated term in contingency practice, and Model Rule 1.5(c) requires it in terms.

Every one of those is a term that is either present or is not. None requires judgment about the merits. They are exactly what this engine does, and until now it was pointed somewhere else.

## §2. What v46 is and is not

**It is:**

- **Three packs.** Law-practice engagement documents (`ENG`, 36 checks over 6 families), discovery instruments (`DISC`, 40 checks over 7 families), and pleadings (`PLDG`, 16 checks over 2 families).
- **Three reserved namespaces**, registered in `NAMESPACE_OWNERS` alongside every other pack.
- **Three scope-of-review statements**, rendered on every report these packs run on. They carry more weight here than anywhere else in the catalog, and §3 explains why.

**It is not:**

- **Not an ethics opinion.** No check asserts that a lawyer has satisfied or breached a duty. A guard test asserts that no rule *name* in the wave contains a conclusion word (`violat`, `breach…dut`, `unethical`, `malpractice`, `sanctionable`).
- **Not a merits review.** The pleading pack reads form. Whether a claim is plausible, a defense available, or a Rule 9(b) allegation particular *enough* is the drafter's judgment, and the scope statement says so in those words.
- **Not a substitute for the local rules.** §3.
- **Not a change to any existing document's output.** Every rule is gated to exactly one v6 playbook.

## §3. Two caveats this wave forces into the citation itself

Most of the catalog cites law that binds. This wave largely does not, and burying that in a footnote would make the tool actively misleading. So both caveats are rendered into the citation text, which travels with the finding onto every report surface — DOCX, HTML, JSON, Markdown, and the tab.

**The ABA Model Rules bind nobody.** Every state adopts its own version, and several differ materially on the exact points this pack checks: whether a fee agreement must be in writing at all, whether an advance flat fee may be deposited in the operating account, what "the file" means on termination. `modelRule()` renders every citation as *"ABA Model Rule of Professional Conduct 1.5(c) — … (model text; each state adopts its own version)"*. A finding says a term the Model Rules contemplate was not found. It never says the lawyer's jurisdiction requires it.

**Local rules and standing orders outrank the national rule.** Discovery response formats, privilege-log contents, deposition practice, caption format, and jury-demand placement are all routinely modified by local rule or by the assigned judge's own standing order. `localRule()` renders that as *"… (varies by district, division, and judge; the assigned court's own rules govern)"*, and each discovery and pleading scope statement lists it under **not reviewed for**.

---

# Part I — The packs

## §4. Families and namespaces

| Pack | Families | Checks | Namespace |
| --- | --- | --- | --- |
| Law-practice engagement | engagement letter · contingency fee · flat fee · joint-representation waiver · limited-scope representation · closing letter | 36 | `ENG-001..036` |
| Discovery instruments | requests for production · interrogatories · requests for admission · responses and objections · privilege log · Rule 26(f) report · deposition notice | 40 | `DISC-001..040` |
| Pleadings | complaint · answer | 16 | `PLDG-001..016` |

## §5. Law-practice engagement (`ENG`)

Anchored in Model Rules 1.0(e), 1.2(a) and (c), 1.3, 1.5(b) and (c), 1.7, 1.9, 1.13, 1.15(c) and (d), 1.16(d), and 3.3.

The checks concentrate where the rule text is enumerated rather than evaluative. Rule 1.5(c) is the clearest example: it names four things a contingent fee agreement must state, and each ships as a check — the percentage method by stage, whether expenses are deducted before or after the fee, the expenses owed if there is no recovery, and the closing statement. Rule 1.5(a)'s reasonableness standard, by contrast, ships as nothing, because it is a judgment about the matter and the market.

Two checks are worth calling out as the ones most likely to surface a real problem:

- **`ENG-006` — advance fees and where they are held.** Rule 1.15(c) requires advance fees in a client trust account, withdrawn as earned. Treating an advance as the firm's money on receipt is among the most common disciplinary findings in the country. Gated on the document actually taking an advance.
- **`ENG-019` — refund of the unearned portion.** Rule 1.16(d) requires refunding any unearned advance whatever the agreement calls the fee, so a "non-refundable" flat fee is unenforceable to that extent everywhere.

## §6. Discovery instruments (`DISC`)

Anchored in FRCP 5(d)(1)(B), 16(b)(3), 26(b)(1) and (b)(5), 26(f), 26(g), 30(b), 33, 34, and 36, and FRE 502(d) and 901.

The pack's center of gravity is the **2015 amendments**, which changed what a compliant response looks like and which practice has been slow to absorb:

- **`DISC-017`** — objections stated with specificity; boilerplate lists are increasingly treated as waived.
- **`DISC-018`** — whether responsive material is being withheld. The single most-missed requirement in modern discovery practice, and the one whose absence makes an objection unreviewable.
- **`DISC-019`** — the "subject to and without waiving" formulation, which leaves the requesting party unable to tell what was produced and what was held back, and which a growing number of courts treat as a waiver of the objections it purports to preserve. Gated on the formulation actually appearing.
- **`DISC-020`** — a stated production completion date, which Rule 34(b)(2)(B) requires and "will produce responsive documents" does not supply.

`DISC-032` requests an FRE 502(d) order at the Rule 26(f) stage — the only mechanism that protects against waiver in other federal and state proceedings, free to ask for, and routinely forgotten.

## §7. Pleadings (`PLDG`)

Anchored in FRCP 8(a), 8(b), 8(c), 9(b), 10(a) and (b), 11(a), 12(b) and (h), and 38(b).

The pack is deliberately small and reads only structure. Its highest-value checks are the four irreversible ones — the omissions that cannot be cured later:

- **`PLDG-008`** — the Rule 38(b) jury demand, waived under Rule 38(d) if not served in time. The easiest right in civil procedure to lose by omission.
- **`PLDG-012`** — Rule 8(c)(1) affirmative defenses, generally waived if omitted from the answer.
- **`PLDG-013`** — the Rule 12(b)(2)-(5) defenses that Rule 12(h)(1) waives if omitted from the first response, whatever their merit.
- **`PLDG-011`** — the Rule 8(b)(5) lack-of-knowledge formulation, whose loose paraphrases have been read as admissions.

---

# Part II — Verification

## §8. Additivity

Every v6 rule declares `applies_to_playbooks` naming exactly one v6 playbook, so `selectActiveRules` filters the whole wave out for any document that matched an earlier family. All 1,074 golden assertions pass unchanged with 15 new playbooks registered in the matcher.

## §9. Bundle

The three packs are ~45 KB raw and ship as one `v6-rules` chunk: they are small, they change together, and they are the only rules in the catalog that read a document the lawyer signs. Behind the file-drop gesture like every other rule chunk; nothing moves onto the first-paint path.

## §10. What ships green

- `src/engine/rules/v6/ruleset.test.ts` — structure (count, uniqueness across every prior wave, the three reserved prefixes, one playbook gate per rule, every family covered, one matrix column per check), the honesty posture (a registered scope statement for every family; no conclusion word in any rule name), and the title-vacuity guard.
- `src/engine/rules/v6/behavior.test.ts` — 20 representative checks pinned in both directions, plus six gate probes including the `DISC-019` boilerplate detector in both directions.
- `src/verticals/registry.test.ts` — the gate contract, extended to `V6_RULES`.

## §11. Counts

| | Before | After |
| --- | --- | --- |
| Document families | 250 | 265 |
| Single-document rules | 1,716 | 1,808 |
| Test suite | 6,701 | 6,757 |

---

# Part III — Open questions

1. **State rules of professional conduct.** The `ENG` pack reads for the term; it does not know which state's rule applies. The `--state` assertion machinery is the natural home for a per-state overlay, and the differences that matter most (fee-agreement writing requirements, advance-fee handling, file-return scope) are well documented enough to encode.
2. **Local rules as a court profile.** The filing-format pack already models courts as versioned, cited data (`src/filing/profiles/*.json`). Discovery response formats and privilege-log requirements fit the same shape, and would let `DISC` and `PLDG` read the assigned court's rule rather than the national default.
3. **Paragraph-level answer reconciliation.** `PLDG-010` reads for a paragraph-by-paragraph structure. Reconciling an answer's responses against a complaint's paragraph count is a genuine cross-document check — the shape the consistency engine already handles — and is the obvious next step.
4. **State-court procedure.** Every check in `DISC` and `PLDG` is federal. State practice differs in every state, and the scope statements say so rather than papering over it.

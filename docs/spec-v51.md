# Vaulytica v51 — The Drafting Loop (Lint, Revise, Re-Lint, and Know When to Stop)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v50.md`](spec-v50.md), beginning at **Step 318**.
> **Scope:** one idea — an agent or a person revising a draft should be able to ask "what did my change fix, what did it cause, and what did it remove?" and get a deterministic answer. Most of the machinery exists; v51 fixes what running the loop exposed and defines where it ends.
> **Posture (unchanged):** deterministic, presence-only, no AI in the engine. **A clean lint is a floor, not a review.** The tool never says a draft is good; it says which named checks no longer fire.
> **Cousin docs:** [`spec-v8.md`](spec-v8.md) Part XVIII (where the clause redline is recorded as built), [`spec-v48.md`](spec-v48.md) (the MCP tools that carry this), [`posture-for-attorneys.md`](posture-for-attorneys.md).

---

# Part 0 — What exists, measured

## §1. `compare` already answers the first question — in JSON

`vaulytica compare base revised` matches findings by `rule_id` (the engine emits one finding per rule per run) and reports **resolved**, **introduced**, and **unchanged**. On two NDA drafts: 2 resolved, 0 introduced, 12 unchanged.

But the 4 KB Markdown names only the _introduced_ findings; which two were resolved appears only in the 41 KB JSON. And `compare` takes two file paths and nothing else. v51 does not rebuild the comparison; it makes its answer readable and safe to loop on.

## §2. What running the loop for real found

Every specimen was analyzed; each finding's own quoted advice was added to the document; the document was analyzed again.

| Measured over 327 specimens, 1,389 findings                       | Result                                                         |
| ----------------------------------------------------------------- | -------------------------------------------------------------- |
| Criticals and warnings that carry a recommendation                | 531 of 532                                                     |
| `info` findings that carry one                                    | 117 of 857                                                     |
| `info` findings with none that nonetheless **report a gap**       | About 129 — "No venue / forum clause detected," for one        |
| Findings whose recommendation quotes language to add (`Add: '…'`) | 28                                                             |
| Of those, cleared by adding the quoted language                   | 23                                                             |
| New findings caused by adding it                                  | 6 — all `info` observations about the added clause, no defects |

Four defects fall out of that table and the review of it:

1. **Rules their own advice cannot satisfy.** `NDA-D-019` recommends "not intended to create, and shall not be construed as creating, a precedent" and looks for `not (create|constitute) a precedent`. `ADDENDA-007` recommends "…is classified as Confidential…" and looks for `data classification` and three variants, none of which is "is classified as." In both, the sentence the reader is told to add does not match.
2. **The guard for exactly this has been looking at 15 rules.** `recommendation-satisfies-check.test.ts` extracts quotes with a double-quote pattern; the v3 and v4 rules quote with single quotes. It has never probed a v3, v4, or v6 rule, though its header says "every ungated presence check."
3. **The loop has no stopping point, and severity is not it.** Most `info` findings are observations ("Force majeure clause present"); an agent told to reach zero findings would delete the clause. But about 250 `info` findings are gaps a drafter should close — `NDA-D-019` itself is `info`.
4. **The redline misreads an insertion.** Adding one numbered clause to the NDA produced "4 rewritten · 1 added": the clause number is part of the match key, so every renumbered clause looked changed, and changed clauses are paired by position — "7. Governing Law" against "7. Return or Destruction." This happens on all 255 specimens with sequential numbering.

---

# Part I — The loop

## §3. One call per round

Over MCP, `compare_documents` takes `base` and `revised` as paths or as text, and returns the compact form. On the CLI, `compare --format markdown` gains the same sections.

- **`fixed`** — actionable findings (§4) that no longer fire.
- **`introduced`** — findings the revision caused.
- **`remaining`** — actionable findings still firing, with their location in the revised draft.
- **`no_longer_present`** — observations that disappeared. Listed separately, because they disappear when a clause is **deleted**.
- **`removed`** — clauses removed and the net word change, from the clause diff. A round that fixes by removal says so in one line.
- Both result hashes, the comparison hash, and the revised input's SHA-256, so a person handed the final draft can reproduce the last round.

Today `compare` refuses a pair whose drafts match **different families**, and a heavy rewrite can flip the match, making every family rule look resolved or introduced. From the second round the revised draft is analyzed under the base draft's document type instead.

## §4. "Actionable" has one definition

**A finding is actionable when it carries a recommendation.** Everything else is an **observation**: a fact about the document that needs no change.

- Severity stays what it is. `--fail-on warning` remains the CI gate; `actionable` is what a drafter works through. On the corpus the two differ by the 117 `info` findings that carry advice and the one warning that carries none.
- **The ten rules that report a gap without advice get advice** — `RISK-011`, `CHOICE-003`, `TEMP-007`, `STRUCT-009`, `OBLI-003`, `IPDATA-005`, `STRUCT-004`, `IPDATA-004`, `TEMP-009`, `TEMP-002` — so the definition matches what the findings mean. Each is a rule-text change with a version bump.
- **The fix list agrees.** `--format md` renders every finding as a checkbox today, observations included. Observations move under their own heading without one, reading "Present in the document. No change needed; do not remove the clause to clear this."

The field is computed in one place and appears in the compact projection, `brief-json`, and the fix list.

## §5. When to stop

The tool is stateless; the stop rule is stated in the tool description and enforced by the agent:

1. `remaining` is empty; or
2. a round fixes nothing; or
3. the revised `result_hash` equals one from an earlier round (the draft is oscillating); or
4. five rounds.

Then hand the person the draft, the last comparison, and the hashes.

## §6. Draft with the checklist, not against it

Iterating to clean is the slow path. `describe_document_type` returns what a family will be checked for, so an agent drafts once and lints to confirm.

The site data it would read is not enough. `tools/site/doc-types.json` lists each type's **family** checks and gives the general rules as a single number — and 87% of findings on the specimens (1,204 of 1,389) come from general rules. Authorities are per type, and 246 of 265 types list none.

So the tool needs new data: the general rules that run on a family, each with id, description, and recommendation; and type-level sources where they exist. It returns a rule's **description**, never its pattern — the difference between telling a drafter what a clause must do and telling them which words to type.

## §7. Say what a clean result means

Every loop result carries one fixed line, owned by `src/report/disclaimers.ts`:

> No actionable findings remain. This means the named checks no longer fire. It does not mean the document is complete, balanced, or enforceable.

An agent can write text that satisfies a pattern and says nothing. The engine cannot detect that and does not claim to. What it can do is §3's `removed` line: show when a round's progress came from deleting.

---

# Part II — The fixes the loop needs

## §8. Advice that works

- The guard extracts single-quoted drafting and the `Add: e.g., '…'` form, and walks every rule family. Expect it to fail on `NDA-D-019` and `ADDENDA-007`. Fix both patterns, bump both versions.
- About fifteen v4 rules fail a single-quote probe. Most quote a section title, which the probe misreads; `GOV-044`, `EMP-044`, and `SET-019` look like real drafting and are read by hand.
- `language()` rules, which flag a bad clause instead of a missing one, need the advice placed **inside** the paragraph the rule reads. `MSA-023` fails a naive probe for that reason and is not a defect.

## §9. A redline that survives renumbering

Two changes, both prototyped against the specimens (the prototype is not committed; Step 320's test replaces it):

- **Strip a leading clause number from the match key** (`7.`, `7.1`, `(a)`, `Section 7.`); the displayed text keeps it. A clause whose only change is its number is **renumbered**, a fifth status.
- **Pair changed clauses by token similarity,** not position. With the key fix alone, one specimen still paired an inserted clause with its neighbor.

**The relation that holds it,** over the 255 specimens with sequential top-level numbering: insert one single-paragraph clause with unique text and renumber the headings — the diff shows exactly 1 added and 0 rewritten (255 of 255 in the prototype; 0 of 255 today). When cross-references are renumbered too, every rewritten pair is equal except for digits.

The new status reaches the comparison JSON, the DOCX comparison, and the browser's comparison view. The comparison hash does not move.

---

# Part III — Steps

| Step | Work                                                                                                        | Verify                                                                                                                          |
| ---- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 318  | §4: the `actionable` field; advice for the ten gap rules; the fix list's observations heading               | The field is identical across `brief-json`, the fix list, and the comparison for every specimen; golden diff is those ten rules |
| 319  | §8: widen the advice guard; fix `NDA-D-019` and `ADDENDA-007`; read the v4 hits                             | Guard fails before each fix and passes after                                                                                    |
| 320  | §9: number-free key, similarity pairing, `renumbered`                                                       | The insertion relation at 255 of 255                                                                                            |
| 321  | §3, §6: compact comparison, text inputs, the pin, `removed`; general-rule data for `describe_document_type` | Comparison hash equals today's; a deletion-only revision is reported as removal                                                 |

---

# Part IV — What this deliberately does not do

1. **No auto-fix.** The engine never writes clause text into a document. 28 of 1,389 findings quote language at all; generating the rest is authorship, and authorship is the agent's or the lawyer's.
2. **No score.** A percentage invites optimizing it. The loop reports named checks.
3. **No pattern disclosure through the tool.** §6.

# Part V — Open questions

1. **Recording a person's verdict.** "This finding is wrong for this document" has a home already: a custom playbook's `rule_overrides`. Whether the loop should write one is a product decision; until then the agent is told and remembers.
2. **Should more recommendations quote language?** Quoted advice clears on the first try and is testable. Each quote is also a drafting position the project would be taking, and needs a practice source like any rule.
3. **Same defect, moved.** Matching by `rule_id` reports "unchanged" when a revision fixes a defect in one section and creates it in another. Rare on the corpus; unmeasured on real revisions.

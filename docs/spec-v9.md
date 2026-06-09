# Vaulytica v9 — The Last Look

> **Status:** **Thrust A (Clean to Send) implemented — Steps 148–154 shipped (8.1.0).** This spec defines v9 and continues the global step numbering after v8's Step 147, beginning at **Step 148**. Thrust A's container read-surface ([`src/delivery/`](../src/delivery/) — `container.ts`, `sensitive.ts`, `handoff.ts`, `report.ts`), the `HANDOFF-001…005` family, the `DeliveryReport` artifact with its own `delivery_hash`, the adversarial-container fixtures, and the totality + masking-invariant gates are live and wired into the JSON report (`delivery` block), the CLI (`--delivery`), and the tab (a "Clean to send?" section). Thrusts **B (Ready to Sign, Steps 155–159)** and **C (Tracked to Its Dates, Steps 160–164)** and the close (Step 165) remain **proposed — not yet implemented**. The `Status` lines of the prior specs are unchanged by it.
> **Scope:** one coherent thesis, three interlocking thrusts — *the last look a lawyer takes before a document leaves their hands, and the first thing they track once it is signed.* v8 made the engine unbreakable, citable everywhere, and reachable from the CLI. v9 makes it answer the three questions every practitioner asks by hand, every time, on every document, regardless of practice area: **is it clean to send, is it ready to sign, and what dates does it put on my calendar?** Each is a pure, deterministic function of the document; none needs a model, a server, or a single byte of attorney-gated legal authority — the document is its own proof.
> - **(A) Clean to Send** — a *pre-disclosure scan* over the document's **original container bytes**, not its flattened text: residual tracked changes, live comments, hidden/non-printing content, authoring metadata that leaks privilege or a prior client, and sensitive-data patterns (SSN/EIN/account/card/DOB) that should have been redacted. The ingest layer throws all of this away today ([`src/ingest/docx.ts`](../src/ingest/docx.ts) uses `mammoth.convertToHtml`, which never surfaces `w:ins`/`w:del`, `word/comments.xml`, or `docProps/core.xml`), so no rule can see it. Uniquely enabled by the no-server posture: the one document you must never upload to a cloud scrubber is exactly the one this catches, in the tab.
> - **(B) Ready to Sign** — *execution readiness*, deepening the `STRUCT-*` family from *detection* to *reconciliation*: every preamble/defined party matched to a signature line, every referenced Exhibit/Schedule/Annex matched to a present section, every notary/witness/attestation block the document **itself** calls for matched to a fillable block, and every unfilled blank consolidated into one readiness view — emitted as a deterministic **Closing Checklist** export.
> - **(C) Tracked to Its Dates** — a *computed critical-dates register*. The date extractor already pulls absolute, relative, and named-anchor dates ([`src/extract/dates.ts`](../src/extract/dates.ts)); v9 resolves a relative term against its anchor and computes the **absolute** derived deadline (notice-before-renewal, cure window, opt-out window, survival end, auto-renewal trigger), producing a sorted register and deepening the v6 `.ics`/fix-list exports — with the wall-clock posture trap closed explicitly.
> **Posture (unchanged, non-negotiable):** deterministic (same input → identical bytes, on any machine, forever), no AI / no probabilistic path, no server (the document, every scan, and every artifact stay on the user's machine; the tab makes zero cross-origin requests; the CLI opens no socket beyond the local DKB it ships with), citable (every finding traces to a numbered rule and a source — and v9's findings cite **the document itself**, the strongest source there is), lints / references / now *inspects-for-handoff* — but never drafts, and never renders a legal conclusion. Every step passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative legal documents), [`spec-v5.md`](spec-v5.md) (Ground Truth — accuracy & validation), [`spec-v6.md`](spec-v6.md) (Workflow), [`spec-v7.md`](spec-v7.md) (Depth & Proof), [`spec-v8.md`](spec-v8.md) (Hardening & Reach). Companions: [`v9/pre-disclosure-scan.md`](v9/pre-disclosure-scan.md) (the container-extraction surface, threat model, and honesty contract) and [`v9/critical-dates.md`](v9/critical-dates.md) (the date-derivation contract). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

By v8 the engine is correct on inputs an author wrote down (v7), survives hostile ones (v8 Thrust A), cites its sources in every format (v8 Thrust B), and runs from the CLI (v8 Thrust C). Once the v5 corpus lands it will also be *legally measured*. What the product still does not do is sit in the two moments that bracket a lawyer's relationship with a document: the moment **before it goes out**, and the moment **after it comes back signed**. Both are deterministic. Neither is served today.

1. **The product cannot see the thing most likely to end a career.** The recurring legal-malpractice headline is not a missing indemnity cap — it is a redline sent with opposing counsel's comments still attached, a "final" Word file whose metadata names the prior client it was templated from, or a tracked-change that reveals a number the sender meant to bury. Vaulytica is blind to every one of these, by construction: the DOCX ingest converts to flattened HTML and drops the revision marks, the comment store, the hidden runs, and the document properties before a single rule runs. The information the lawyer most needs a second pair of eyes on is the information the engine deletes on the way in. And because Vaulytica uploads nothing, it is the *only* kind of tool a lawyer can safely point at a privileged, unredacted, comment-laden draft — a cloud scrubber would require the very disclosure the scrub is meant to prevent.

2. **"Has a signature block" is not "ready to sign."** `STRUCT-003` detects *whether a signature block exists*; it does not reconcile the parties named in the preamble against the parties who actually have a line to sign, notice a referenced "Exhibit C" that was never attached, or catch a document that recites "sworn before me, a Notary Public" yet ships with no notary block. Execution readiness is the checklist a closing paralegal runs by hand on every deal. It is pure document-internal reconciliation — exactly the deterministic, self-citing work the engine is built for — and it stops one layer short of where the value is.

3. **The engine extracts dates and then drops them on the floor.** v7 deepened date-extraction recall and v6 exports a `.ics`, but no step *computes the deadline the terms imply*. "Sixty (60) days prior to each anniversary of the Effective Date" plus a resolved Effective Date of 2026-01-01 is, deterministically, "give notice by 2025-11-02." The arithmetic is pure; the anchor resolution already exists in the definitions extractor; the only thing missing is the step that joins them and writes the answer onto a calendar.

These interlock as a single use case. A lawyer does not finish a document and stop — they *clean it, complete it, and calendar it*. v9 is the spec for that last look.

## §2. What v9 is and is not

**It is:**
- A **new read surface**: a pure, deterministic pass over the **original uploaded bytes** (the DOCX/PDF container, before mammoth/pdf.js flatten them) that extracts the revision, comment, hidden-content, and metadata facts the engine currently discards — feeding a new `HANDOFF-*` finding family and a `DeliveryReport` artifact. Specified in [`v9/pre-disclosure-scan.md`](v9/pre-disclosure-scan.md).
- A **reconciliation deepening** of the `STRUCT-*` family — party↔signature, reference↔attachment, recited-formality↔block, and a consolidated blank sweep — plus a deterministic Closing Checklist export.
- A **derivation step** that turns extracted temporal terms into absolute computed dates and a sorted critical-dates register, deepening the existing `.ics` and fix-list exports.
- A pass that **strengthens** the posture, not strains it: every v9 finding cites the document itself, so v9 needs *no* new DKB authority and is wholly outside the v5 attorney-gate.

**It is not:**
- A **drafting tool.** v9 inspects, reconciles, and computes. It never writes a clause, redacts a value, removes a tracked change, or strips metadata — it *reports* them and tells the user precisely where they are. The v4 line stands: it lints, it does not draft. Removing what it finds is the user's deliberate act in their own editor.
- A **renderer of legal conclusions.** v9 never asserts a document is "validly executed," "properly notarized," "ESIGN/UETA-compliant," "privilege-clean," or "fully redacted." Those are jurisdiction- and fact-dependent legal judgments — precisely the attorney-gated territory v5/v7 defer. v9 reports *internal facts* ("the document recites notarization but contains no notary block"; "patterns matching SSN format appear in 3 locations"), and is scrupulous about the difference. See §3 corollary 2 and the §[deferrals] note.
- An **assertion of absence.** A pattern scan that finds nothing has found *nothing it can match*, not *nothing there*. Every v9 surface that reports the presence of something is forbidden from reporting its absence as a clean bill of health. The honesty contract is the v5 contract, restated for a new surface (§3 corollary 3).
- A **model, a server, or a wall-clock dependency.** No probabilistic component. Nothing leaves the tab. And — the v9-specific trap — **no computed date in the hashed result depends on "today"** (§3 corollary 4).
- A **UI rebuild.** The four document states, the drop zone, the theme toggle, and the inline-diagram architecture stay. New surfaces are additive: a Delivery section in the report, a readiness summary, a Closing Checklist export button, and a critical-dates view.

## §3. The posture filter (the gate every step passes)

Identical to v6/v7/v8 §3, restated because v9 opens a brand-new read surface (the raw container) and a brand-new output category (handoff/readiness) — the two places posture is easiest to erode by accident:

```
Deterministic?  same input → identical bytes, on any machine, forever.
No AI?          no probabilistic component anywhere in the path.
No server?      the document, every scan, and every artifact stay on the user's machine;
                the browser tab makes zero cross-origin requests; the CLI opens no socket
                except to read the local DKB it ships with.
Citable?        every finding traces to a numbered rule and a source — for v9, the source
                is the document's own bytes (a revision mark, a metadata field, a clause).
Lints, not drafts?  finds, reconciles, computes, references, explains — never writes,
                removes, redacts, or renders a legal conclusion.
```

Four v9-specific corollaries:
- **1. The new read surface is pure.** Parsing a zip member, an OOXML element, or a PDF Info dictionary is a pure function of the input bytes. The container scan introduces no clock, no network, no randomness — it is the v8 §6 "bounds, not timeouts" discipline applied to a new parser, and it inherits every v8 Thrust A guard (byte caps, decompression-ratio ceiling, depth limits) before it reads a single member.
- **2. Report the fact, never the conclusion.** A handoff or readiness finding states what is *in* the document ("a tracked insertion is present at §4.2"; "the preamble names 4 parties; 3 have signature lines"). It must never state what the fact *legally means* ("this document is not validly executed"; "privilege is waived"). The bright line is the same one that separates the existing `STRUCT-*` rules from the v5-gated enforceability data.
- **3. Presence-only honesty.** A scan may report what it *found*. It may never report what it *did not find* as assurance. The Delivery report says "found N items of these types"; it never says "this document is clean / contains no PII / is safe to send." This is the v5 honesty contract on a new surface, and §[honesty] makes it an executable test.
- **4. No wall-clock in the hash.** A *derived* date is absolute arithmetic over the document's own terms and anchors — `result_hash`-stable forever. A *relative-to-today* view ("due in 12 days", "overdue") depends on the current date and is therefore **render-only**, computed at display time, never entering the `result_hash` or any export's canonical body — exactly as v8 Step 137 handled citation freshness (show the date, never a computed elapsed age in the hashed artifact).

## §4. How the three thrusts sequence

Dependency-first, mirroring v7/v8 §4. **Clean to Send (A) lands first** because it opens the new container read-surface and the `HANDOFF-*` family that the Delivery report and the CLI's `--delivery` mode both consume; it also reuses the v8 Thrust A input guards directly, so it must sit on top of a hardened ingest. **Ready to Sign (B) lands second**, deepening the existing `STRUCT-*` rules and reusing A's container surface for the signature/attachment reconciliation. **Tracked to Its Dates (C) lands last** because its register and exports compose the readiness output and the existing findings into one artifact. Within each thrust the measurement/fixture step lands before the gate, exactly as v5 §IX #4 and v7/v8 §4 require: **build the adversarial-container corpus and read what the parser actually surfaces before writing each handoff rule; pin the readiness reconciliation against fixtures before gating it; prove the date arithmetic with property tests before wiring the register to a calendar.**

---

# THRUST A — CLEAN TO SEND

These steps add a deterministic read over the document's **original container**, recovering the revision, comment, hidden-content, metadata, and sensitive-data facts the ingest layer discards — and surfacing them as a new `HANDOFF-*` finding family and a `DeliveryReport`. Each finding cites the exact container element it came from. The full surface, threat model, format-applicability matrix, and honesty contract live in [`v9/pre-disclosure-scan.md`](v9/pre-disclosure-scan.md); this section specifies the engine-side shape.

## Part I — The container-read contract

### §5. What it does

Defines a new module `src/ingest/container.ts` (alongside, not inside, the existing `ingestDocx`/`ingestPdf`) that takes the **original uploaded bytes** and returns a typed `ContainerFacts` record: revision marks, comments, hidden runs, metadata fields, and the raw text spans the sensitive-data scan reads. It runs *in parallel* to normalization, never mutating the `DocumentTree`. It is format-aware: DOCX (the rich case — OOXML zip), PDF (Info dictionary + annotations/markup via pdf.js), and a documented no-op for pasted text and image-only inputs (which carry no container to inspect — and the report says so honestly, per §3 corollary 3).

### §6. The gap and the fix

The gap is structural: [`src/ingest/docx.ts`](../src/ingest/docx.ts) calls `mammoth.convertToHtml`, whose entire job is to *flatten* a DOCX to clean prose — it resolves tracked changes to their accepted state, drops comments, and ignores `docProps`. By the time the bytes reach the engine, the handoff-relevant facts are gone. The fix is to read the **same `ArrayBuffer`** the ingest already holds (`ingestDocxBuffer` has it) a second time, through `fflate` (already in the bundle for `.zip` ingest) into the OOXML parts, with the v8 Thrust A guards applied first. This is additive: a text-only or metadata-free document yields empty `ContainerFacts` and zero findings, so no existing golden moves.

## Part II — Tracked changes & comments

### §7. What it does

`HANDOFF-001` (tracked changes present) and `HANDOFF-002` (comments present): parse `word/document.xml` for `w:ins`/`w:del`/`w:moveFrom`/`w:moveTo` revision elements and `word/comments.xml` for the comment store; for PDF, parse text-markup and `Text` (sticky-note) annotations. Each finding reports the count, the author (from the revision/comment `w:author`/PDF annotation author — itself a metadata leak the user should see), and the section it sits in (resolved against the outline the extractor already builds). It cites the revision/comment element itself.

### §8. The honest fix

A "final" document with live revision marks or comments is the single most common pre-disclosure accident. The finding is **critical** severity. It reports presence and location; it never removes them (that is the user's act in Word) and never asserts what the comment's *content* means. The author name is surfaced precisely because it is the leak — "this comment is attributed to *a name from the prior matter*" is the fact the lawyer needs.

## Part III — Hidden & non-printing content

### §9. What it does

`HANDOFF-003`: surface content that is present in the bytes but absent from the rendered/flattened view — DOCX hidden runs (`w:vanish`), text in deleted-but-retained revision ranges, and (reported as a lower-confidence signal, never an assertion) runs whose color matches the page background. The point is the gap between *what the engine read* (the flattened tree) and *what a recipient's tooling could recover* (the full container). Where the two diverge, the recipient can see something the sender may believe is gone.

### §10. The gap

This is the subtlest leak and the one a flattening ingest is structurally blind to. v9 reports the *presence and location* of hidden/non-printing content and the recovered text span, so the user can decide; it does not judge intent and does not claim to find *all* concealment techniques — §3 corollary 3 governs the wording.

## Part IV — Authoring metadata

### §11. What it does

`HANDOFF-004`: parse `docProps/core.xml` (`dc:creator`, `cp:lastModifiedBy`, `dcterms:created`/`modified`, `cp:revision`) and `docProps/app.xml` (`Company`, `Manager`, `Template`, total-edit-time); for PDF, the Info dictionary (`Author`, `Creator`, `Producer`, `Title`) and any `XMP` packet. Report each populated field verbatim. The leak is concrete and routine: a document templated from a prior client's agreement that still names that client in `Company` or the template path, or a `lastModifiedBy` that reveals who really drafted the "client's own" markup.

### §12. The fix

Verbatim reporting, never alteration. Severity scales with sensitivity: a `Company`/`Manager`/`Template`-path field naming an entity that does **not** appear in the document's own party set is **high** (a likely cross-matter leak — and the cross-check is deterministic against the parties the extractor already pulls); a bare author name is **medium**; an absent field is silent.

## Part V — Sensitive-data patterns

### §13. What it does

`HANDOFF-005`: a deterministic pattern scan over the extracted text for data that is routinely meant to be redacted before disclosure — US SSN (`NNN-NN-NNNN` with structural validation), EIN, bank-routing/account runs, payment-card numbers (**Luhn-validated** to suppress the obvious false positives), dates of birth in `DOB:`-style context, and (lower-confidence, context-gated) email and phone. Each hit reports its type, location, and a **masked** excerpt (the value is never echoed in full into any artifact — the report that warns about exposed PII must not itself reproduce it). The matchers and their confidence tiers are pinned in [`v9/pre-disclosure-scan.md`](v9/pre-disclosure-scan.md).

### §14. The honest fix

This is the corollary-3 step where the temptation to overclaim is highest. The finding is phrased as *"3 spans match SSN format"*, never *"contains 3 SSNs"* and never *"no PII found."* A Luhn-valid 16-digit run is a card-number *candidate*, surfaced for human confirmation. The scan reduces the chance of an unredacted disclosure; it cannot and does not certify a clean one — and the report says exactly that.

## Part VI — The Delivery report & the gate

### §15. What it does

A `DeliveryReport` artifact aggregates the `HANDOFF-*` findings into one surface: a report section (DOCX/HTML/JSON), a one-line summary on the complete state ("Delivery: 1 tracked change, 2 comments, metadata names 'Acme LLP' — review before sending"), a CLI `--delivery` mode and a SARIF mapping (handoff findings are first-class results, reusing the v8 Step 141 surface), and a `delivery` block in the JSON report. **Hashing decision:** the `HANDOFF-*` findings are deterministic over the original bytes and so carry their own `delivery_hash` over the `ContainerFacts`; they are *additive* to and *namespaced apart from* the engine `result_hash`, so the rule-finding `result_hash` is byte-unchanged and no existing golden re-baselines (the rationale is the v8 Step 146 clause-evidence "field outside the run" precedent).

### §16. The fuzz & completeness gate

Build the adversarial-container corpus first (deterministic builders, per v8 Step 127 / §[deferrals]): a DOCX with a comment store but no `comments.xml` part, a malformed `core.xml`, a revision element with no author, a zip whose `document.xml` is truncated, a 50 MB comment store. Prove `container.ts` is **total** — resolves to typed facts or a typed rejection, never throws, never hangs — under the v8 fuzz harness, and add a completeness meta-test that every `HANDOFF-*` finding survives into the Delivery section, the JSON `delivery` block, and the SARIF output.

---

# THRUST B — READY TO SIGN

These steps deepen the `STRUCT-*` family from *detection* to *reconciliation*, and emit a deterministic Closing Checklist. No new authority; every finding cites the document's own structure. Each reuses the parties, outline, crossref, and definitions facts the extractors already produce.

## Part VII — Signature-block completeness

### §17. What it does

`STRUCT-017` (continuing the existing structural numbering): reconcile the party set the engine already extracts (preamble parties + defined party roles, [`src/extract/parties.ts`](../src/extract/parties.ts)) against the signature lines `STRUCT-003` locates. Report each named party with **no** corresponding signature line, and each signature line attributable to **no** named party. This is the paralegal's first closing check, made deterministic.

### §18. The gap and the fix

`STRUCT-003` answers "is there a signature block?" — a yes/no. The deal-killing failure is subtler: a four-party agreement with three signature lines. The fix reuses two existing fact sets and a deterministic name-match (the same normalization the cross-document defined-term-drift check already uses); it adds no new extractor. Severity **high** — an unsignable party is a closing blocker.

## Part VIII — Attachment completeness

### §19. What it does

`STRUCT-018`: reconcile every Exhibit/Schedule/Annex/Appendix/Attachment **reference** the crossref extractor resolves ([`src/extract/crossrefs.ts`](../src/extract/crossrefs.ts)) against the set of attachments **present** as sections/headings in the document (or, in bundle mode, present as sibling files). A reference to "Exhibit C — Data Processing Terms" with no Exhibit C in the document — or in the folder — is the second classic closing gap. Reports referenced-but-absent and present-but-unreferenced attachments.

### §20. The fix

This composes cleanly with bundle mode: in a single document, "present" means a heading; in a folder, a referenced exhibit may legitimately be a sibling file, so the check is bundle-aware and only flags an attachment absent from the **entire** dropped set. Reuses the v4 cross-document fact plumbing; adds no extractor.

## Part IX — Recited formalities

### §21. What it does

`STRUCT-019`: where the document's **own text** recites an execution formality — "WITNESS my hand", "sworn before me", "Notary Public", "acknowledged before me", "in the presence of the undersigned witnesses" — check that the corresponding fillable block (notary jurat/acknowledgment, witness lines) is actually present. A document that recites notarization but ships with no notary block is internally inconsistent, and that inconsistency is deterministic and self-evident.

### §22. The honest fix

This is the corollary-2 step in Thrust B. `STRUCT-019` checks *internal consistency only*: the document said it would be notarized/witnessed and then provided nowhere to do so. It does **not** assert that notarization or witnessing is legally *required* (that is jurisdiction- and instrument-dependent — attorney-gated, deferred). The finding reads "the document recites notarization but contains no notary block," never "this document must be notarized."

## Part X — Readiness consolidation & the Closing Checklist

### §23. What it does

A single readiness surface consolidating the unfilled-blank findings (`STRUCT-011`/`STRUCT-013`), the signature/attachment/formality reconciliations (`STRUCT-017`–`019`), and the relevant `HANDOFF-*` items (a draft is not send-ready *or* sign-ready with live tracked changes) into one ordered view — and a **Closing Checklist** export: a deterministic, itemized, checkable list in Markdown, CSV, and DOCX, reusing the v6/v8 export pipeline ([`src/report/exports.ts`](../src/report/exports.ts)). Render-side and manifest-scoped; no rule logic changes, so no `result_hash` moves.

### §24. The fix

The checklist is the artifact a closing lawyer actually wants in hand: "□ Party D has no signature line · □ Exhibit C referenced, not attached · □ 2 tracked changes remain · □ Effective Date blank unfilled." It is a re-projection of findings the engine already produced, so it is free of new correctness risk and inherits the v8 citation-everywhere guarantee.

---

# THRUST C — TRACKED TO ITS DATES

These steps turn the dates the extractor already pulls into the deadlines a lawyer must calendar — absolute arithmetic over the document's own terms and anchors, never wall-clock-relative in the hashed result. The full derivation contract, anchor-resolution rules, and register schema are in [`v9/critical-dates.md`](v9/critical-dates.md).

## Part XI — The date-derivation contract

### §25. What it does

Defines the pure function that takes a relative temporal term (`DateReference` from [`src/extract/dates.ts`](../src/extract/dates.ts)) plus its resolved anchor (an absolute date the definitions extractor maps from "the Effective Date") and returns the **absolute** derived date. Calendar arithmetic only: `anchor ± N calendar days/months/years`, with documented month-end and leap-year handling. Where the anchor is itself unresolved (an undated "Effective Date"), the derived date is **unresolved** and surfaced as "verify manually" — never guessed (the v5 honesty contract; the same posture as the v7 Step 114 "verify-manually" `.ics` events).

### §26. The posture trap, closed

Per §3 corollary 4: the derived **absolute** date is `result_hash`-stable. Anything *relative to today* — "due in 12 days", "overdue", a soonest-deadline sort keyed on now — is **render-only**, computed at display time from the absolute dates, and never enters the hash, the JSON canonical body, or any export's stable content. This step writes that boundary into the type system (the absolute date is a hashed field; the relative view is a derived display value), so the trap cannot be sprung by a later edit.

## Part XII — Derived deadlines

### §27. What it does

`DATE-001`…`DATE-00n`: compute the deadlines the standard temporal clauses imply — **auto-renewal notice** (the date by which non-renewal notice must be given before a term anniversary), **cure window** (the last day to cure a stated default), **opt-out / termination-for-convenience window**, **survival end** (the date a surviving obligation lapses), and **notice-period** deadlines generally. Each is a join of a `DateReference`, a resolved anchor, and the obligation it attaches to ([`src/extract/obligations.ts`](../src/extract/obligations.ts)), surfaced with the clause it came from. Each cites the clause text.

### §28. The fix

These are the dates a missed-deadline malpractice claim is built on, and the document states every input to them — the only missing piece is the arithmetic, which is pure. The computation is fixture-gated with property tests (anchor ± N is monotonic; month-end and leap-year boundaries hold; an unresolved anchor yields an unresolved date) before any of it is wired to a calendar.

## Part XIII — The critical-dates register & exports

### §29. What it does

A deterministic, canonically-sorted **critical-dates register**: one row per derived deadline — computed absolute date, trigger clause, responsible party (from `obligations.ts`), and source citation. It deepens the existing exports: the v6 `.ics` gains the computed deadlines as events (with a render-only lead-time alarm — never a hashed elapsed value); the fix-list groups by date; the JSON report gains a `critical_dates` block; the SARIF and HTML surfaces carry the register. Reuses the v8 citation-everywhere and parity-proven pipeline; the register is a `result_hash`-stable artifact, additive to existing goldens.

### §30. The fix

The register is the bridge from "we read your document" to "here is your calendar," and it is the deterministic counterpart to the thing every other tool does with a language model and cannot reproduce twice. Same document, same engine, same DKB → byte-identical register, on any machine, forever.

---

# Part XIV — Determinism and privacy preservation

v9 opens a new read surface and a new output category; both must clear the same bar the rest of the engine clears, and two are worth stating explicitly:

- **The container scan is build-and-runtime-pure, and runtime-private.** It reads bytes the user already dropped, in the tab, and emits findings to the same report surface; it makes zero network calls and writes nothing off-machine. The one network-touching idea adjacent to this thrust — checking whether a leaked URL in metadata resolves — is **explicitly out of scope** (it would breach the no-server posture); v9 reports the URL's presence, never fetches it.
- **No corpus contamination.** The adversarial-container fixtures are deterministic builders (no real documents committed), and the v5 `accuracy-corpus-guard` is extended to assert `src/` never imports them — identical to the v8 Step 139 discipline. A real document's leaked metadata must never enter the repo as a test artifact.
- **Sensitive data never round-trips.** §13's masking rule is a hard invariant: no `HANDOFF-005` finding, in any format, may contain an unmasked matched value. A completeness test asserts it across DOCX/JSON/CSV/Markdown/SARIF/HTML.

---

# Part XV — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v8's Step 147. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property/completeness gates and the v8 fuzz + citation-completeness gates stay green; from Step 154 on, the container-surface fuzz gate joins; from Step 164 on, the no-wall-clock-in-hash invariant joins as a metamorphic test. Ordered dependency-first: Clean to Send before Ready to Sign before Tracked to Its Dates.

Status legend: **✅ shipped** · ⬜ proposed.

| # | Step | Output | Tier |
|---|------|--------|------|
| 148 ✅ | Container-read contract + adversarial corpus | `src/ingest/container.ts` skeleton + `ContainerFacts` type; the §5 contract and threat model in [`v9/pre-disclosure-scan.md`](v9/pre-disclosure-scan.md); the deterministic adversarial-container builders (malformed/oversized/missing-part OOXML + PDF) as code, mirroring v8 Step 127. Reuses the v8 Thrust A guards before any member is read. | Clean to Send |
| 149 ✅ | Tracked changes & comments | `HANDOFF-001`/`002` — `w:ins`/`w:del`/`w:move*` + `word/comments.xml`; PDF markup/sticky annotations; count + author + section + element citation. Critical severity. Fixtures. | Clean to Send |
| 150 ✅ | Authoring metadata | `HANDOFF-004` — `core.xml`/`app.xml` + PDF Info/XMP, verbatim; cross-matter detection against the extracted party set (high when a metadata entity is absent from the parties). | Clean to Send |
| 151 ✅ | Hidden & non-printing content | `HANDOFF-003` — `w:vanish`, deleted-but-retained ranges, background-color runs as a lower-confidence signal; reports the recovered span; corollary-3 wording. | Clean to Send |
| 152 ✅ | Sensitive-data patterns | `HANDOFF-005` — SSN/EIN/account/Luhn-card/DOB + context-gated email/phone; **masked** excerpts only; confidence tiers pinned in the companion. Presence-only phrasing. | Clean to Send |
| 153 ✅ | Delivery report & surfaces | `DeliveryReport` aggregate: report section (DOCX/HTML), JSON `delivery` block, complete-state summary line, CLI `--delivery`, SARIF mapping; namespaced `delivery_hash` outside `result_hash` (zero golden churn). | Clean to Send |
| 154 ✅ | Container fuzz + completeness gate | `container.ts` proven total under the v8 fuzz harness over the adversarial corpus; completeness meta-test (every `HANDOFF-*` survives into Delivery section + JSON + SARIF); masking invariant test (§Part XIV). | Clean to Send |
| 155 ⬜ | Signature-block completeness | `STRUCT-017` — party set ↔ signature lines reconciliation; deterministic name-match reusing defined-term-drift normalization; high severity; positive + negative fixtures. | Ready to Sign |
| 156 ⬜ | Attachment completeness | `STRUCT-018` — resolved Exhibit/Schedule/Annex references ↔ present attachments; bundle-aware (sibling file counts as present); reuses v4 cross-document plumbing. | Ready to Sign |
| 157 ⬜ | Recited formalities | `STRUCT-019` — recited notary/witness/acknowledgment text ↔ presence of a fillable block; internal-consistency only (corollary 2); never asserts legal requirement. | Ready to Sign |
| 158 ⬜ | Readiness consolidation | A single ordered readiness view composing `STRUCT-011`/`013`/`017`/`018`/`019` + relevant `HANDOFF-*`; render-side, no logic change, no `result_hash` move. | Ready to Sign |
| 159 ⬜ | Closing Checklist export | Deterministic itemized checklist in Markdown/CSV/DOCX via the v6/v8 export pipeline; inherits citation-everywhere; structure-tested. | Ready to Sign |
| 160 ⬜ | Date-derivation contract | The pure `anchor ± N` function + anchor resolution from the definitions extractor; month-end/leap-year/unresolved-anchor rules; the contract in [`v9/critical-dates.md`](v9/critical-dates.md). Property tests (monotonicity, boundaries). | Tracked to Dates |
| 161 ⬜ | Derived deadlines | `DATE-001…00n` — auto-renewal notice, cure window, opt-out window, survival end, notice-period; each a join of `DateReference` + anchor + obligation; clause citation; fixtures + properties. | Tracked to Dates |
| 162 ⬜ | Critical-dates register | Canonically-sorted register (computed date · trigger · responsible party · citation); `result_hash`-stable; JSON `critical_dates` block; additive. | Tracked to Dates |
| 163 ⬜ | Calendar & fix-list deepening | `.ics` gains computed deadlines (render-only lead-time alarm); fix-list groups by date; HTML/SARIF carry the register; reuses parity-proven pipeline + citation-everywhere. | Tracked to Dates |
| 164 ⬜ | No-wall-clock invariant gate | Metamorphic test: the same document re-run under two different "today" values yields a byte-identical `result_hash`, JSON canonical body, and every export's stable content; relative-to-today view is render-only and excluded by construction. | Tracked to Dates |
| 165 ⬜ | v9 docs + threat-model + version bump | `docs/v9/README.md` overview; threat-model "v9 — handoff & delivery surface" note (the container read-surface and its privacy invariants); bump to 9.0.0; reconcile spec statuses; README posture/test-count + Thrust surface refresh. | Close |

Total work: **18 build steps (148–165).** Thrust A (148–154, seven steps) opens the only genuinely new read-surface in v9 and is measure-first (build the adversarial container corpus and read what the parser surfaces before writing each guard/rule); it is additive — text-only and metadata-clean documents yield empty `ContainerFacts`, so the engine `result_hash` never moves. Thrust B (155–159, five steps) deepens the existing `STRUCT-*` family with two new reconciliation rules, one internal-consistency rule, and two render-side surfaces — the new rules re-baseline only the structural goldens they touch (mechanical, reviewed). Thrust C (160–164, five steps) is pure arithmetic over already-extracted facts plus render-side export deepening, gated by property tests and the no-wall-clock metamorphic invariant. Step 165 closes. The highest-leverage steps are **149/150/152** (the leaks that end careers, now visible) and **161/162** (the deadlines a missed-date claim is built on, now computed).

---

# Part XVI — Principled deferrals

v9 ships the deterministic, honesty-clean, posture-passing work and defers, with reasons, the steps that would compromise honesty, posture, or the green-build contract:

- **Any legal-sufficiency conclusion (execution, notarization, e-signature, redaction adequacy, privilege).** Whether a document is *validly* executed, whether notarization is *required*, whether an e-signature *satisfies* ESIGN/UETA, whether a redaction is *legally adequate*, or whether privilege is *waived* are jurisdiction- and fact-dependent legal judgments — the attorney-gated territory v5/v7 already defer. v9 reports the internal facts (`STRUCT-017`–`019`, `HANDOFF-*`) and stops at the bright line of §3 corollary 2. Closing these would require the same credentialed legal review v5 specifies and has not yet sourced.
- **Removing or scrubbing what the scan finds.** v9 reports tracked changes, comments, metadata, and PII; it never strips, accepts, or redacts them. A scrub tool *writes* the document, which crosses the v4 lint-not-draft line and creates a far worse failure mode (silently destroying content the user wanted). The fix stays the user's deliberate act in their own editor; v9 tells them exactly where to look.
- **Fetching a URL found in metadata or a clause.** Checking whether a leaked or incorporated URL resolves would breach the no-server posture at runtime. v9 reports the URL's presence; the build-only reachability checker (v8 Step 139) remains the only place a URL is ever fetched, and never from `src/`.
- **Negotiation posture ladders.** Extending the v6 bring-your-own-playbook into tiered ideal/acceptable/walk-away positions (and reporting which tier a clause meets) is a genuinely valuable, posture-clean *workflow* feature — but it sits on the v6 use-case axis, not the v9 "last look" axis, and folding it in would dilute the thesis. Noted here as the strongest candidate for a future spec.
- **OCR'd and image-only inputs in the container scan.** A scanned PDF has no recoverable revision/comment/metadata structure, and a flattened image carries no OOXML. v9's container scan is a documented no-op for these (the report says so, per §3 corollary 3) rather than pretending to inspect them.

---

# Part XVII — Open questions for the maintainer

1. **Delivery hashing (Step 153).** Carry the `HANDOFF-*` findings in a separate `delivery_hash` outside the engine `result_hash` (zero golden churn, but two hashes a consumer must track), or fold them into a single combined hash (one number, but every existing golden re-baselines)? Recommendation: **separate `delivery_hash`** — the handoff facts are a property of the *container*, not the *findings*, the engine's finding set is genuinely unchanged, and the v8 Step 146 clause-evidence "field outside the run" precedent already establishes the pattern.
2. **Sensitive-data scan default-on vs. opt-in (Step 152).** Run `HANDOFF-005` on every document, or gate it behind a "scan for sensitive data" affordance? Recommendation: **default-on with masked output** — the cost is a deterministic regex pass, the masking invariant means it can never itself leak, and a pre-disclosure check the user has to remember to enable is one they will forget on the document that matters. Surface a count, not the values.
3. **Closing Checklist scope (Step 159).** Should the checklist include the substantive engine findings too (a full pre-send review sheet), or only the readiness/handoff items (a focused closing list)? Recommendation: **readiness/handoff only by default, with a flag to merge** — the closing list's value is its focus; the full findings already have the main report.
4. **Recited-formality breadth (Step 157).** Limit `STRUCT-019` to notary/witness recitals (high precision), or extend to corporate-authority recitals ("duly authorized by resolution of the Board"), apostille, and consular legalization (broader, more false positives)? Recommendation: **notary/witness in v9, the rest deferred** — they are the highest-frequency, highest-precision recitals; the broader set needs its own fixture pass.
5. **Two-digit-year and ambiguous-anchor dates in derivation (Step 160).** When the anchor's own date is ambiguous (a two-digit year past the `dates.ts` pivot, or an "Effective Date" defined only as "the date of last signature"), derive a best-effort date or mark it unresolved? Recommendation: **mark unresolved, surface "verify manually"** — a guessed deadline is worse than an honest gap, and this is the v5 honesty contract on the date surface.
6. **Cross-matter metadata detection threshold (Step 150).** Flag a metadata entity as a likely cross-matter leak whenever it is absent from the party set (simple, some false positives for outside-counsel firm names that legitimately drafted the doc), or maintain a per-run allowlist of the user's own firm/entities? Recommendation: **absent-from-parties flag in v9, render the entity verbatim so the user adjudicates in one glance**; an allowlist is a configurability the §3-adjacent simplicity rule disfavors until a user asks for it.

---

# Part XVIII — What this gives the user

- **The leak you can't see, made visible — without uploading a thing.** Drop the redline you're about to send and Vaulytica tells you, in the tab, that two tracked changes and a comment from the other side are still live, that the metadata names the client you templated it from, and that an exhibit references an SSN that should have been redacted. The one document you could never hand to a cloud scrubber is the one this was built for.
- **A closing checklist that runs itself.** Every party reconciled to a signature line, every referenced exhibit reconciled to an attachment, every recited notarization reconciled to a block, every blank found — as a deterministic, citable list you can work down before the deal closes, instead of a manual read at midnight.
- **Your calendar, computed from the contract.** "Sixty days before the anniversary of the Effective Date" becomes "give notice by 2025-11-02," on a register and in a calendar file you can import — the same arithmetic every time, reproducible to the byte, where every other tool gives you a confident guess that changes on the next run.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v9 passes the §3 gate. The new read-surface is pure and private; every finding cites the document's own bytes; not one computed date depends on what day you run it; and the thing the lawyer most fears handing to a server is precisely the thing this checks without one.

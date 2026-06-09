# v9 companion — The pre-disclosure scan

> Companion to [`spec-v9.md`](../spec-v9.md) Thrust A (Clean to Send). This document specifies the **container-read surface**: what it reads, from where, what it is forbidden to do, and the honesty contract that governs every word it emits. It is the v9 analog of [`v8/robustness-and-fuzzing.md`](../v8/robustness-and-fuzzing.md) and [`v8/citation-standard.md`](../v8/citation-standard.md) — the precise contract behind a thrust the main spec summarizes.

---

## 1. The premise

The engine reads a *flattened* document. [`src/ingest/docx.ts`](../../src/ingest/docx.ts) converts a DOCX to clean HTML via `mammoth.convertToHtml`, whose explicit purpose is to discard everything that is not final prose: it resolves tracked changes to their accepted text, drops the comment store, ignores hidden runs, and never touches `docProps`. [`src/ingest/pdf.ts`](../../src/ingest/pdf.ts) extracts the text layer and discards the Info dictionary and annotations. By the time bytes reach the `DocumentTree`, the handoff-relevant facts are gone.

The pre-disclosure scan reads the **same original bytes a second time**, through a path that *preserves* what mammoth/pdf.js discard, and reports the facts the lawyer needs before the document leaves their hands. It never alters the document and never feeds the `DocumentTree` — it is a parallel, additive read.

## 2. The read surface

A new module `src/ingest/container.ts`, called with the original `ArrayBuffer` the ingest path already holds, returns a typed `ContainerFacts`:

```
ContainerFacts {
  format: "docx" | "pdf" | "none"      // "none" = paste / image-only: nothing to inspect
  revisions:   RevisionMark[]          // tracked insertions/deletions/moves
  comments:    CommentMark[]           // comment store entries
  hidden:      HiddenSpan[]            // vanish runs, deleted-but-retained ranges, bg-color runs
  metadata:    MetadataField[]         // core.xml / app.xml / PDF Info / XMP, verbatim
  textSpans:   TextSpan[]              // the spans the §5 sensitive-data scan reads
}
```

Every record carries the container element it came from (the OOXML part + element, or the PDF object) so the finding can cite its exact source. The scan applies the **v8 Thrust A input guards first** — byte cap, decompression-ratio ceiling, member-count and depth limits — before reading a single zip member; a hostile container is rejected with a typed error exactly as a hostile document is, and never expanded.

### DOCX (the rich case)

A DOCX is a zip (`fflate`, already bundled). The relevant parts:

| Part | Reads | Yields |
|---|---|---|
| `word/document.xml` | `w:ins`, `w:del`, `w:moveFrom`, `w:moveTo` (+ `w:author`, `w:date`); `w:vanish` runs | revisions, hidden |
| `word/comments.xml` | comment entries (+ author, initials, date) | comments |
| `docProps/core.xml` | `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`/`modified`, `cp:revision` | metadata |
| `docProps/app.xml` | `Company`, `Manager`, `Template`, `TotalTime` | metadata |

### PDF

Via the pdf.js instance ingest already loads: `getMetadata()` (Info dictionary — `Author`, `Creator`, `Producer`, `Title` — and any XMP packet) and per-page annotations (`getAnnotations()` — text-markup and `Text`/sticky-note annotations are the PDF analog of comments). PDFs have no tracked-change model, so `revisions` is empty for PDF and the report says so.

### Paste / image-only

No container exists. `format: "none"`, all arrays empty, and the Delivery report states plainly that there was nothing to inspect — it does **not** imply the content is clean (honesty contract, §4).

## 3. The threat model — what leaks, and how

The scan exists because each of these is a documented, recurring pre-disclosure accident:

1. **Live tracked changes.** A "final" sent with revision marks intact exposes negotiating history, rejected terms, and numbers the sender meant to settle. `HANDOFF-001`, **critical**.
2. **Live comments.** Internal notes ("push back hard on this", "client won't pay more than X") shipped to the counterparty. `HANDOFF-002`, **critical**. The comment *author* is itself surfaced — it is often a second leak.
3. **Hidden / non-printing content.** `w:vanish` runs and text inside deleted-but-retained revision ranges are absent from the rendered view but trivially recoverable by the recipient. `HANDOFF-003`. Background-color-matched runs are a **lower-confidence** signal, never an assertion.
4. **Authoring metadata.** `lastModifiedBy` revealing who really drafted the "client's" markup; `Company`/`Template` naming the *prior client* a template was cloned from. `HANDOFF-004`. **High** when the named entity is absent from the document's own party set (a likely cross-matter leak); **medium** for a bare author name.
5. **Unredacted sensitive data.** SSNs, account numbers, card numbers, DOBs left in an exhibit meant to be redacted before production. `HANDOFF-005`.

## 4. The honesty contract (non-negotiable)

This surface is where overclaiming is most tempting and most dangerous. Three hard rules, each an executable test:

- **Presence, never absence.** Every finding states what was *found* ("2 comments present", "3 spans match SSN format"). No finding, summary, or export may state or imply the converse — never "no PII", "clean", "safe to send", or "fully redacted." A scan that matches nothing has matched nothing; it has not certified the document. The Delivery summary for an empty result reads "No tracked changes, comments, or metadata leaks detected by the patterns checked" — scoped to the patterns, never absolute.
- **Fact, never legal conclusion.** The scan reports container facts. It never renders the legal meaning of those facts (waiver, admissibility, adequacy of redaction). That bright line is [`spec-v9.md`](../spec-v9.md) §3 corollary 2.
- **Never echo the secret.** A report warning about exposed sensitive data must not itself reproduce it. Every `HANDOFF-005` excerpt is **masked** (`123-45-6789` → `•••-••-6789`) in every format — DOCX, JSON, CSV, Markdown, SARIF, HTML. The masking invariant is asserted by a completeness test across all six.

## 5. Sensitive-data matchers and confidence tiers

Deterministic patterns, each with a fixed confidence tier. Tier governs severity and wording, never suppression — a low-tier match is still surfaced, phrased as a candidate.

| Type | Matcher | Validation | Tier |
|---|---|---|---|
| US SSN | `NNN-NN-NNNN` | area ≠ 000/666/9xx; group ≠ 00; serial ≠ 0000 | high |
| EIN | `NN-NNNNNNN` | valid prefix set | medium |
| Payment card | 13–19 digit run | **Luhn** checksum | high (Luhn-valid) / drop (invalid) |
| Bank account/routing | routing `NNNNNNNNN` + ABA checksum; account in context | ABA checksum; `account`/`acct` context gate | medium |
| Date of birth | date in `DOB`/`born`/`d.o.b.` context | context-gated | medium |
| Email | RFC-ish local@domain | context-gated (suppresses notice-block addresses) | low |
| Phone | NANP forms | context-gated | low |

Every matcher is a bounded, ReDoS-safe regex (the [`src/extract/`](../../src/extract/) hardening from the recent ReDoS sweep applies here verbatim). Email and phone are **context-gated** because a contract's notice block legitimately contains both — an ungated match would bury the signal in noise.

## 6. Hashing and privacy

- **`delivery_hash`, separate from `result_hash`.** The `HANDOFF-*` findings are a deterministic function of the *container*, not the *findings*; they carry their own hash over `ContainerFacts` and are namespaced apart, so the engine's `result_hash` is byte-unchanged and no existing golden re-baselines. Precedent: the v8 Step 146 clause-evidence "field outside the run."
- **No corpus contamination.** The adversarial-container fixtures are deterministic builders — a function that emits a DOCX zip with a malformed `core.xml` or a truncated `document.xml`, never a committed real document. The v5 `accuracy-corpus-guard` is extended to assert `src/` never imports them.
- **Runtime-private.** The scan reads bytes already in the tab and writes findings to the same report; zero network calls. A URL found in metadata is *reported*, never *fetched* — fetching it would breach the no-server posture ([`spec-v9.md`](../spec-v9.md) Part XVI).

## 7. Termination guarantee

`container.ts` is **total**: for any input bytes it returns typed `ContainerFacts` or throws a typed rejection (`InputTooLargeError`, `ArchiveTooLargeError`, `MalformedContainerError`) — it never throws an untyped error and never hangs. This is proven under the v8 fuzz harness ([`tests/integration/fuzz-boundary.test.ts`](../../tests/integration/fuzz-boundary.test.ts) family) over the adversarial corpus: malformed zip, missing `comments.xml` referenced by `document.xml`, revision element with no author, truncated `document.xml`, 50 MB comment store, deeply nested parts. The boundary property — *resolves-or-typed-rejects, never throws, never hangs* — is the API-boundary analog of the v8 Step 134 gate, extended to the container surface.

/**
 * Universal scope-of-review statement (add-attorney-review-ledger, task 4).
 *
 * A fixed, versioned block rendered near the disclaimer on **every** report,
 * framing Vaulytica the way an attorney frames a limited-scope engagement:
 * what the review covered and — just as important — what it did not. This is
 * distinct from the per-pack "Scope of Review — <pack>" block (which lists what
 * a specific regulated pack checked); this one is tool-wide and always present.
 *
 * Fixed text, versioned so a change is auditable. Rendered on the human report
 * surfaces (HTML/DOCX) alongside the disclaimer; it is engagement framing, not
 * a machine field, so it does not enter `run` or `result_hash`.
 */

export const ENGAGEMENT_SCOPE_VERSION = "1.0.0";

export const ENGAGEMENT_SCOPE = {
  version: ENGAGEMENT_SCOPE_VERSION,
  intro:
    "Vaulytica performs a limited-scope, mechanical review — the scope below and no more. A clean check means the reviewed language was present, never that the document is sound, complete, or a good deal.",
  reviewed_for: [
    "presence of the clauses and structural elements the matched playbook enumerates",
    "the specific red flags the fired rules encode",
    "internal consistency of the terms the engine could extract from the text you provided",
  ],
  not_reviewed_for: [
    "commercial adequacy — whether the terms are a good deal for you",
    "tax, accounting, or regulatory treatment",
    "local-counsel matters and jurisdiction-specific requirements beyond the cited authorities",
    "anything outside the submitted text — side letters, course of dealing, or oral terms",
  ],
} as const;

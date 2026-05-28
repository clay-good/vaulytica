# Two-document (consistency-check) mode

v3 accepts up to four documents in a single drop. When two or more
documents are loaded together, the cross-document consistency engine
(`src/engine/consistency/`) runs after each document's own playbook and
emits findings that cite **every** contributing document and quote the
conflicting text from each.

This page covers when to use it, what the rules check, and how the
findings are surfaced.

> **v4 readers:** v4 lifts the 4-document cap and adds the CROSS-*
> families (party / jurisdiction / defined-term / date / amount /
> missing / precedence). The v3 CC-001..CC-007 rules below ship in
> the same registry (`ALL_CONSISTENCY_RULES`) and run on every v4
> bundle that satisfies their `requires: DocKind[]`. See
> [`docs/v4/cross-document-rules.md`](../v4/cross-document-rules.md)
> for the v4 surface.

## When to use it

The canonical pairings are:

| Bundle | What consistency catches |
|---|---|
| MSA + BAA | BAA permitted uses broader than MSA service scope; BAA term silently diverges from MSA |
| MSA + DPA | DPA processing purpose open-ended relative to MSA services; DPA data categories not anchored to MSA services |
| MSA + SOW | order-of-precedence inversion (MSA controls but operative terms live only in the SOW) |
| Any pair | governing-law mismatch; notice-clause mismatch |
| BAA + Subcontractor BAA | flow-down completeness; permitted-uses parity |

The user drops the documents at the same time. Up to four is the
hard limit per [`MAX_DOCUMENTS`](../../src/ui/v3/multi-doc.ts).

## What it checks

The shipped consistency rules are
(see [`src/engine/consistency/rules/rules.ts`](../../src/engine/consistency/rules/rules.ts)):

| Id | Title | Severity | Requires |
|---|---|---|---|
| CC-001 | BAA permitted uses no broader than MSA service scope | critical | msa + baa |
| CC-002 | DPA processing purpose matches MSA services | warning | msa + dpa |
| CC-003 | DPA data categories not broader than MSA's services | warning | msa + dpa |
| CC-004 | BAA term aligns with MSA (or extension is explicit) | warning | msa + baa |
| CC-005 | Governing-law alignment across the bundle | warning | any |
| CC-006 | Notice-clause alignment | info | any |
| CC-007 | Order-of-precedence consistent with where operative terms live | warning | msa |

Each rule declares which document kinds it requires; if any required
kind is missing, the runner records a `ran: false` log entry and the
rule emits nothing.

## How findings are shaped

A `ConsistencyFinding` carries:

```ts
{
  id, rule_id, rule_version,
  severity: "critical" | "warning" | "info",
  title, description, explanation,
  recommendation?,
  source_citations: SourceCitation[],
  excerpts: Array<{
    doc_id, source_file_name,
    text, section_id?,
    start_offset, end_offset,
  }>,
}
```

The `excerpts` array is what makes a consistency finding readable: each
entry quotes the conflicting text from one contributing document, so
the reader sees the conflict in both documents side by side.

## How it shows up in the report

Spec §59 describes the two-document consistency appendix. The DOCX
report includes the appendix only when a `ConsistencyRun` is passed to
[`buildDocxReport`](../../src/report/docx.ts):

```ts
const result = await runEngineMulti({ documents, dkb });
const docx = await buildDocxReport(
  result.per_document[0].run,
  ingest,
  dkb,
  playbook,
  {
    consistency: result.consistency,
    matrix, transfers, subprocessor, insurance,
    dkb_build_date: "2026-05-16T00:00:00Z",
  },
);
```

The appendix renders a finding-count table followed by per-finding
heading + severity + description + explanation + recommendation +
per-document excerpts, and closes with the `result_hash` of the
consistency run.

## Determinism

The consistency engine carries the same determinism contract as the v2
runner:

- Rules are sorted lexicographically by id before execution.
- Findings are sorted by `(severity, rule_id, doc_id, start_offset)`.
- `result_hash` is `sha256` over the canonicalized run JSON with
  `result_hash`, `executed_at`, and per-entry `elapsed_ms` blanked.
- Repeat runs produce identical hashes.

The same bundle re-run on a different machine, at a different time,
with the same DKB build produces a byte-identical
`ConsistencyRun.result_hash`.

## How to add a new consistency rule

A consistency rule is a pure function that takes a `ConsistencyContext`
(documents + DKB) and returns `ConsistencyFinding[]`. The rule declares
the document kinds it requires (`requires: DocKind[]`) so the runner
can skip it cleanly when the bundle is missing one.

```ts
import type { ConsistencyRule } from "../types.js";
import { findByKind, findParagraph } from "../_helpers.js";
import { paragraphExcerpt, makeConsistencyFinding } from "./_finding.js";

export const CC_008_MY_RULE: ConsistencyRule = {
  id: "CC-008",
  version: "1.0.0",
  name: "My new cross-document check",
  category: "consistency",
  default_severity: "warning",
  description: "Plain-language description of the conflict.",
  requires: ["msa", "dpa"],
  check(ctx) {
    const msa = findByKind(ctx.documents, "msa");
    const dpa = findByKind(ctx.documents, "dpa");
    if (!msa || !dpa) return [];
    // ... find the conflict, return [makeConsistencyFinding({...})]
    return [];
  },
};
```

Then add it to the registry at
[`src/engine/consistency/rules/rules.ts`](../../src/engine/consistency/rules/rules.ts)'s
exported `CONSISTENCY_RULES` array.

## What it does not check

- It does not redline. The output is a finding, not a fix.
- It does not verify that the documents were executed by the same
  parties — the v3 engine takes the document text at face value.
- It does not run document-pair consistency across more than four
  documents at once. Four is the user-facing UX limit.

For the consistency engine's full design, see
[`spec-v3.md`](../../spec-v3.md) §§27, 59.

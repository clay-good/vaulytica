/**
 * The v5 rule-pack shorthand (spec-v45.md §4).
 *
 * Every v5 rule is one **compliance-matrix column** of one playbook: the
 * catalog was designed column-first, and each column names a term the
 * document is expected to carry. Writing 600 of those out longhand in the
 * v4 spec shape would bury the legal content — the authority, the reason
 * the term matters, and the fix — under boilerplate that is identical
 * every time. `pack()` supplies the boilerplate and leaves the four
 * fields that are not: the citation, the patterns that recognize the
 * clause, why it matters, and what to add.
 *
 * Two deliberate departures from the v4 presence builder:
 *
 *  - **Default severity is `warning`, not `critical`.** A v4 presence rule
 *    defaults to `critical` because those packs check terms a regulator
 *    enumerates. A catalog column is a drafting expectation; calling every
 *    missing one critical would make the severity axis meaningless. Rules
 *    that check a term whose absence is independently actionable — an
 *    unlawful clause, a statutory disclosure, a benefits-eligibility
 *    condition — pass `sev: "critical"` explicitly.
 *  - **`applicable_if` is encouraged.** A column that only applies to a
 *    sub-shape of the family ("first-party SNT payback", "pre-1978
 *    residential") must gate on evidence that the sub-shape is present,
 *    or it reports an absence the document itself shows is irrelevant.
 */

import type { Rule, Severity } from "../../finding.js";
import type { SourceCitation } from "../../../dkb/types.js";
import { presenceRule } from "./_helpers.js";

/** One compliance-matrix column, expressed as a check. */
export type ColumnSpec = {
  /** `PREFIX-NNN`, unique across the whole catalog. */
  id: string;
  /**
   * Defaults to `1.0.0`. Bumped when a shipped column's behavior changes,
   * so a reader comparing two reports can tell a re-run from a repair —
   * the version travels with every finding the rule emits.
   */
  ver?: string;
  /** The column, phrased as the thing the document should carry. */
  name: string;
  /** The authority behind the expectation. */
  cite: SourceCitation;
  /**
   * Patterns that recognize the clause. By default any one of them
   * satisfies the column (they are synonyms for the same term). Set
   * {@link ColumnSpec.all} when they are distinct *pillars* that must all
   * be present.
   */
  pat: RegExp[];
  /**
   * Require every pattern to match rather than any one.
   *
   * The default OR is right for synonym sets and wrong for pillar sets,
   * and getting it wrong is invisible: a rule whose first pattern is a
   * word from the document's own title ("control" in a Deposit Account
   * Control Agreement, "irrevocab" in an Irrevocable Trust) is satisfied
   * by the title page and never fires. `title-vacuity.test.ts` proves no
   * rule has that shape, gated or not.
   *
   * The conjunction is evaluated pattern by pattern, so each keeps its own
   * flags. Composing the pillars into one anchored lookahead regex — the
   * first implementation — could not: it dropped every source flag, so a
   * pillar written `/^\s*\d+\.\s/m` to find a numbered paragraph became a
   * start-of-DOCUMENT match, and PLDG-004 reported a properly numbered
   * complaint as carrying no numbered paragraphs, at `critical`.
   */
  all?: boolean;
  /** Why an attorney cares that this term is present. */
  why: string;
  /** What to add when it is not. */
  fix: string;
  /** Defaults to `warning`. */
  sev?: Severity;
  /** Gate: skip the check entirely unless the document shows this shape. */
  when?: RegExp[];
  /**
   * Express-denial frames, built with `expressDenial(topic)`.
   *
   * A presence check reads the document for the words the required clause
   * would use, so a document that AFFIRMATIVELY DISCLAIMS the term — "the
   * Company performs no restricted-party screening" — is silent: every topic
   * word is there, and the column scores as satisfied. That is backwards. An
   * express denial is strictly worse than an omission, because the omission
   * may be an oversight and the denial is a decision.
   *
   * Keep the topic SPECIFIC. A bare topic swallows the governing law: with
   * `consent` alone, "strictly necessary cookies do not require consent"
   * reads as a denial of the consent clause.
   */
  denied?: readonly RegExp[];
  /** Overrides the generated `missing_description` when the default is too thin. */
  missing?: string;
};

/**
 * Rule ids whose spec carries an applicability gate (`when`), across every
 * wave built on this shorthand (v5 and v6). Those rules
 * are *supposed* to be silent on a document that does not show the shape
 * they check for — a residential contract for new construction is not
 * missing a lead-based paint disclosure — so the title-vacuity guard
 * excludes them. Populated as `pack()` builds each ruleset.
 */
export const GATED_PACK_RULE_IDS = new Set<string>();

/**
 * Every column spec this shorthand has built, by rule id, with the two
 * fields that decide whether the check can fire at all: its recognizer
 * patterns and their conjunction mode. The reachability guards read this
 * so they can probe a rule's patterns DIRECTLY, which is the only way to
 * reach a rule whose applicability gate would otherwise short-circuit the
 * check before the patterns are ever consulted.
 */
export const PACK_SPECS = new Map<string, { playbook: string; pat: RegExp[]; all: boolean }>();

/**
 * Build one playbook's ruleset from its compliance-matrix columns. Every
 * rule is gated to `playbook` alone, which is what keeps the whole v5 wave
 * hash-neutral for every pre-v5 document (`docs/verticals.md`).
 */
export function pack(playbook: string, category: string, specs: readonly ColumnSpec[]): Rule[] {
  for (const s of specs) {
    if (s.when) GATED_PACK_RULE_IDS.add(s.id);
    PACK_SPECS.set(s.id, { playbook, pat: [...s.pat], all: s.all === true });
  }
  return specs.map((s) =>
    presenceRule({
      id: s.id,
      version: s.ver,
      name: s.name,
      category,
      description: `${s.name} — a compliance-matrix column of the ${playbook} playbook.`,
      citation: s.cite,
      playbooks: [playbook],
      missing_title: `${s.name} — not found`,
      missing_description:
        s.missing ?? `No clause addressing "${s.name.toLowerCase()}" was found in this document.`,
      explanation: s.why,
      recommendation: s.fix,
      present_patterns: [...s.pat],
      require_all_present: s.all,
      applicable_if: s.when,
      denied_if: s.denied,
      // A denial is a different finding from an absence and has to say so:
      // the title is what reaches the findings index, the compliance matrix,
      // and the execution log, where the description never does.
      ...(s.denied
        ? {
            denied_title: `${s.name} — expressly disclaimed`,
            denied_description: `This document states that ${s.name.toLowerCase()} does not apply, is not required, or will not be provided. An express disclaimer is not an omission: the term is absent by decision, and the sentence below is where the document says so.`,
          }
        : {}),
      default_severity: s.sev ?? "warning",
    }),
  );
}

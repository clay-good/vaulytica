/**
 * The documents a package is missing.
 *
 * A reviewer's first question about a stack of paper is not only "is each of
 * these sound" but "is this all of it". `Playbook.companion_playbooks` — the
 * catalog's only cross-reference field, "suggested two-document pairings" —
 * already encodes the answer for 205 of the 267 shipped families: a Complaint
 * pairs with an Answer, a Document Request with the Discovery Responses that
 * reply to it, an Engagement Letter with the fee agreement that prices it.
 *
 * The field was declared, populated across 335 references, schema-validated,
 * and read by **nothing**. This is where it does work, because a bundle is the
 * one surface that can tell whether the companion is in the room: it knows
 * every family the package contains, so a named pairing that is absent is a
 * fact about the package rather than a guess about the deal.
 *
 * Deliberately **not a finding**. A finding is an assertion about the text of
 * a document the user gave us; "you did not give us the Answer" is an
 * observation about the package, and the reasons a document is absent are
 * usually good ones (it does not exist yet, it is not in scope, it is
 * privileged). It renders as a reference block and enters no `result_hash`.
 */

/** The subset of a `Playbook` this module reads. */
export type CompanionCatalogEntry = {
  id: string;
  name: string;
  companion_playbooks?: string[];
};

/** One companion family the package names but does not contain. */
export type CompanionGap = {
  /** Playbook id of the absent document. */
  missing_playbook_id: string;
  /** Its display name, resolved from the catalog — never synthesized from the id. */
  missing_playbook_name: string;
  /** Ids of the families present in the package that name it, sorted. */
  expected_by: readonly string[];
};

/**
 * `generic-fallback` is the matcher's "no family won" placeholder, not a
 * document anyone can be asked to produce. No playbook names it as a companion
 * today; excluding it means one that starts to cannot produce the absurd note
 * "this package is missing a Generic Fallback".
 */
const NOT_A_DOCUMENT = new Set(["generic-fallback"]);

/**
 * Companion documents named by the families in `present` that `present` does
 * not itself contain.
 *
 * Returns `[]` — never a partial answer — when the package names no absent
 * companion, so a caller can gate rendering on emptiness.
 *
 * Honesty rules, both load-bearing:
 *
 *  - a companion id the catalog cannot resolve is **dropped**, never rendered
 *    under a name derived from its id. `playbook-cross-references.test.ts`
 *    makes an unresolvable id impossible in the shipped catalog, but this
 *    function is also handed user-supplied catalogs and must not invent a
 *    document that does not exist;
 *  - a family present in the package is never reported as missing from it,
 *    including when a second copy of the same family is what names it.
 *
 * Deterministic: sorted by `missing_playbook_id`, with `expected_by` sorted
 * and de-duplicated, so two runs over the same package render byte-identically.
 */
export function missingCompanions(
  present: ReadonlyArray<{ playbook_id: string }>,
  catalog: ReadonlyArray<CompanionCatalogEntry>,
): CompanionGap[] {
  const byId = new Map(catalog.map((p) => [p.id, p]));
  const inPackage = new Set(present.map((d) => d.playbook_id));

  /** missing id → the present ids that named it. */
  const named = new Map<string, Set<string>>();
  for (const id of inPackage) {
    const entry = byId.get(id);
    if (!entry) continue;
    for (const companion of entry.companion_playbooks ?? []) {
      if (inPackage.has(companion)) continue;
      if (NOT_A_DOCUMENT.has(companion)) continue;
      if (!byId.has(companion)) continue;
      const who = named.get(companion) ?? new Set<string>();
      who.add(id);
      named.set(companion, who);
    }
  }

  return (
    [...named.entries()]
      .map(([missing, who]) => ({
        missing_playbook_id: missing,
        missing_playbook_name: byId.get(missing)!.name,
        expected_by: [...who].sort(),
      }))
      // Codepoint order, not `localeCompare`: playbook ids are ASCII kebab-case,
      // and an unpinned collator sorts differently depending on the machine's
      // locale — which `determinism-guard.test.ts` exists to catch, and did.
      .sort((a, b) => (a.missing_playbook_id < b.missing_playbook_id ? -1 : 1))
  );
}

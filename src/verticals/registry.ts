/**
 * Vertical registry — the single source of truth behind
 * `add-document-vertical-framework`.
 *
 * A "vertical" is one document family Vaulytica knows how to review: one
 * classifier family, one or more playbooks, one gated rule pack under a
 * reserved rule-id prefix, and one scope-of-review statement. This module
 * pins the three machine-checkable halves of that contract:
 *
 * 1. {@link NAMESPACE_OWNERS} — which pack owns each rule-id prefix, so two
 *    packs can never silently claim one namespace (guarded by a test).
 * 2. {@link REGISTERED_ASSERTION_GATES} — the opt-in flags/toggles a pack may
 *    gate its rules behind instead of `applies_to_playbooks`. A non-launch
 *    rule must declare one gate or the other; a gate name absent from this
 *    list fails the guard test.
 * 3. {@link SCOPE_OF_REVIEW} — the "reviewed for X; not reviewed for Y"
 *    statement each regulated pack renders on every report it runs on,
 *    following the presence-only doctrine (never a clean bill of health).
 *
 * The prose companion (the pack contract, the honesty posture, the full
 * namespace table) lives in `docs/verticals.md`.
 */

/**
 * Rule-id prefix → the pack that owns it. Every rule id is `PREFIX-NNN`; the
 * guard test asserts no two owners share a prefix and that every shipped
 * non-launch rule uses a registered prefix. Reserved-but-unused prefixes for
 * the current expansion wave are listed so a new pack cannot collide with a
 * planned one.
 */
export const NAMESPACE_OWNERS: Readonly<Record<string, string>> = {
  // v1/v2 launch contract-lint families.
  STRUCT: "launch",
  FIN: "launch",
  TEMP: "launch",
  OBLI: "launch",
  RISK: "launch",
  CHOICE: "launch",
  TERM: "launch",
  IPDATA: "launch",
  PERS: "launch",
  DARK: "launch",
  // v3 regulated / deep packs.
  BAA: "baa",
  DPA: "dpa-gdpr",
  USDPA: "dpa-us-state",
  TRANSFER: "cross-border-transfer",
  ADDENDA: "addenda",
  MSA: "msa-deep",
  NDA: "nda-deep",
  // v4 sub-domain packs (classifier families A–P).
  BNK: "banking-finance",
  CON: "construction",
  EMP: "employment",
  EQT: "equity-comp",
  EST: "trust-estate",
  GOV: "government",
  HC: "healthcare",
  INS: "insurance",
  IPL: "ip-licensing",
  MNA: "m-and-a",
  POL: "policy",
  PRV: "privacy",
  RE: "real-estate",
  REG: "regulated",
  SET: "settlement",
  // Reserved for the current expansion wave (docs/verticals.md). Not yet
  // shipped — listed so a pack in progress cannot collide with a planned one.
  FILE: "filing-format-lint",
  CITE: "authority-citation-lint",
  DDL: "deadline-computation",
  PROD: "production-qa",
  PNOT: "privacy-notice",
} as const;

/**
 * Opt-in assertion gates a non-launch rule may declare instead of
 * `applies_to_playbooks` — the user must assert the named flag/toggle for the
 * rule to run. Empty until the first assertion-gated pack ships (e.g.
 * deadline-computation profiles or `--estate-checks`); a rule naming a gate
 * absent from this list fails the guard test.
 */
export const REGISTERED_ASSERTION_GATES: readonly string[] = [];

/** A pack's honesty-bounded statement of what it did and did not review. */
export type ScopeStatement = {
  /** Human label for the pack, e.g. "HIPAA Business Associate Agreement". */
  pack: string;
  /** The concrete things the pack's rules check for. */
  reviewed_for: readonly string[];
  /** Material things a reader might assume were checked but were not. */
  not_reviewed_for: readonly string[];
};

/**
 * Scope statements for the shipped regulated packs, keyed by playbook id.
 * Rendered on every report where the pack ran. The DPA and BAA families are
 * the two regulated verticals live today; future packs register here.
 */
export const SCOPE_OF_REVIEW: Readonly<Record<string, ScopeStatement>> = {
  ...scopeForIds(["baa", "baa-subcontractor"], {
    pack: "HIPAA Business Associate Agreement",
    reviewed_for: [
      "presence of the required BAA safeguards, breach-notification, and subcontractor flow-down terms",
      "permitted-use and return-or-destruction language a HIPAA business-associate agreement is expected to carry",
    ],
    not_reviewed_for: [
      "whether the parties are in fact covered entities or business associates",
      "the sufficiency of the safeguards described under the HIPAA Security Rule",
      "any determination of HIPAA compliance",
    ],
  }),
  ...scopeForIds(
    [
      "dpa-controller-processor",
      "dpa-processor-subprocessor",
      "scc-module-2",
      "scc-module-3",
      "dpa-multi-state-us",
      "dpa-ccpa-service-provider",
      "uk-idta-addendum",
    ],
    {
      pack: "Data Processing Agreement",
      reviewed_for: [
        "presence of the GDPR Article 28 processor terms, sub-processor controls, and international-transfer mechanisms",
        "return-or-deletion, audit, and breach-notification language a data-processing agreement is expected to carry",
      ],
      not_reviewed_for: [
        "whether a valid transfer mechanism actually applies to the parties' data flows",
        "the adequacy of the technical and organizational measures described",
        "any determination of GDPR, UK GDPR, or state-privacy-law compliance",
      ],
    },
  ),
};

/** Scope statement for the active playbook, or `undefined` if none is registered. */
export function scopeForPlaybook(playbookId: string): ScopeStatement | undefined {
  return SCOPE_OF_REVIEW[playbookId];
}

/**
 * The canonical "which rules does this run include" filter — how activating a
 * vertical pack narrows the candidate rules. A rule is included when:
 *
 * - it has no `applies_to_playbooks`, or the active playbook is in that list; AND
 * - it has no `assertion_gate`, or the named assertion is in `assertions`.
 *
 * Selecting a pack's rules *out* here (rather than letting the engine run and
 * skip-log them) is what makes pack addition hash-neutral for documents
 * outside the pack's gate — the property test proves this on every launch
 * golden. Kept generic over the rule shape so the engine's `Rule` type need
 * not be imported here.
 */
export function selectActiveRules<
  R extends { applies_to_playbooks?: readonly string[]; assertion_gate?: string },
>(rules: readonly R[], playbookId: string, assertions: readonly string[] = []): R[] {
  return rules.filter((r) => {
    if (r.applies_to_playbooks && r.applies_to_playbooks.length > 0) {
      if (!r.applies_to_playbooks.includes(playbookId)) return false;
    }
    if (r.assertion_gate !== undefined) {
      if (!assertions.includes(r.assertion_gate)) return false;
    }
    return true;
  });
}

/** The rule-id prefix (the part before the first `-`), e.g. `STRUCT-003` → `STRUCT`. */
export function rulePrefix(ruleId: string): string {
  const i = ruleId.indexOf("-");
  return i > 0 ? ruleId.slice(0, i) : ruleId;
}

/** Helper: attach one statement to several playbook ids. */
function scopeForIds(
  ids: readonly string[],
  statement: ScopeStatement,
): Record<string, ScopeStatement> {
  const out: Record<string, ScopeStatement> = {};
  for (const id of ids) out[id] = statement;
  return out;
}

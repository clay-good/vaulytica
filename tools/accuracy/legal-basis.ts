/**
 * v5 Ground Truth — the legal-basis ledger (spec-v5 Part III §12–§15, Step 75).
 *
 * Build-and-CI-only. Like the rest of `tools/accuracy/`, this module is
 * **never** imported by `src/` (the corpus-privacy guard asserts it). The
 * ledger is a *trust artifact*, not runtime logic: it records, per rule, the
 * legal authority the rule rests on and a credentialed attorney's sign-off,
 * so a third party can audit which rules a lawyer actually blessed and which
 * are still author-asserted.
 *
 * Measurement (Part II) tells us whether a rule matches human annotations; the
 * ledger tells us whether the rule's *legal premise* is sound. The two are
 * orthogonal and both required before a finding is fully defensible.
 *
 * ## Source of truth and the machine mirror
 *
 * The human-readable ledger is markdown under `docs/legal-basis/`; the machine
 * mirror this module loads is `docs/legal-basis/ledger.json` — a flat array of
 * {@link LegalBasisEntry}. `tests/integration/legal-basis-ledger.test.ts`
 * enforces that every entry validates, references a real rule and real DKB
 * nodes, and that any `tier` a rule carries inline (`Rule.tier`) is backed by a
 * matching signed entry here. The ledger is **honestly empty** until Steps
 * 76/77 (attorney review) land real sign-offs — no fabricated verdicts.
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
export const LEDGER_PATH = join(REPO_ROOT, "docs", "legal-basis", "ledger.json");

/**
 * One cited authority backing a rule's claim (spec-v5 §12). Extends the v1
 * "every rule cites ≥1 DKB entry" invariant from "has a citation" to "the
 * citation actually supports the claim, confirmed by a human" — so every
 * authority is pinned to a DKB node the engine already carries.
 */
export const LegalAuthoritySchema = z.object({
  /** The authority, e.g. "45 C.F.R. § 164.410" or "UCC § 2-207". */
  authority: z.string().min(1),
  /** Pinpoint within the authority, e.g. "(a)(1)". Optional for short cites. */
  pinpoint: z.string().optional(),
  /** Id of the DKB node that materializes this authority. Must exist in the DKB. */
  dkb_node: z.string().min(1),
});
export type LegalAuthority = z.infer<typeof LegalAuthoritySchema>;

/**
 * The reviewer's verdict on a rule's legal premise (spec-v5 §12/§14):
 * - `sound` — the premise holds as stated.
 * - `sound-but-narrow` — holds, but narrower than the rule's trigger; tighten.
 * - `disputed` — contestable; may ship only downgraded to `opinion` tier.
 * - `unsound` — the premise does not hold; triggers retirement (§14).
 */
export const LegalVerdictSchema = z.enum(["sound", "sound-but-narrow", "disputed", "unsound"]);
export type LegalVerdict = z.infer<typeof LegalVerdictSchema>;

/** Confidence tier, mirrors `RuleTier` in `src/engine/finding.ts` (spec-v5 §12). */
export const LedgerTierSchema = z.enum(["established", "prevailing-practice", "opinion"]);
export type LedgerTier = z.infer<typeof LedgerTierSchema>;

/**
 * The sign-off block. A rule is not `sound`-signed by the person who authored
 * it (§13: author ≠ reviewer) — the bar number is recorded for the
 * maintainer's audit, never published verbatim, so the schema stores an opaque
 * `credential` string the maintainer fills with the redacted form.
 */
export const LegalReviewSchema = z.object({
  /** Opaque reviewer id, e.g. "att-007". Not the person's name. */
  reviewer: z.string().min(1),
  /** Redacted credential, e.g. "JD, licensed NY bar (number on file)". */
  credential: z.string().min(1),
  /** ISO 8601 review date. A fixed date, never wall-clock. */
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD"),
  verdict: LegalVerdictSchema,
  tier: LedgerTierSchema,
});
export type LegalReview = z.infer<typeof LegalReviewSchema>;

/** One ledger record per rule (spec-v5 §12). */
export const LegalBasisEntrySchema = z
  .object({
    rule_id: z.string().min(1),
    /** Plain-language statement of what the rule asserts about the law. */
    claim: z.string().min(1),
    /** Non-empty, DKB-linked (spec-v5 §12: "must be non-empty and DKB-linked"). */
    legal_basis: z.array(LegalAuthoritySchema).min(1),
    review: LegalReviewSchema,
    notes: z.string().optional(),
  })
  .strict();
export type LegalBasisEntry = z.infer<typeof LegalBasisEntrySchema>;

export const LegalBasisLedgerSchema = z.array(LegalBasisEntrySchema);
export type LegalBasisLedger = z.infer<typeof LegalBasisLedgerSchema>;

/**
 * Load and validate the machine-mirror ledger. Returns `[]` (the honest empty
 * state) when the file is absent or holds an empty array — no attorney has
 * signed yet (Steps 76/77 are human-gated), and an empty ledger is correct,
 * not an error. Throws on a malformed file so a bad edit fails CI loudly.
 */
export async function loadLegalBasisLedger(path: string = LEDGER_PATH): Promise<LegalBasisLedger> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return [];
  }
  const parsed: unknown = JSON.parse(raw);
  return LegalBasisLedgerSchema.parse(parsed);
}

/** Index a ledger by `rule_id`. Asserts no duplicate rule_id (§12: one record per rule). */
export function indexLedger(ledger: LegalBasisLedger): Map<string, LegalBasisEntry> {
  const byRule = new Map<string, LegalBasisEntry>();
  for (const entry of ledger) {
    if (byRule.has(entry.rule_id)) {
      throw new Error(`legal-basis ledger: duplicate rule_id "${entry.rule_id}"`);
    }
    byRule.set(entry.rule_id, entry);
  }
  return byRule;
}

/**
 * The confidence tier a rule may carry inline (`Rule.tier`), derived from its
 * signed ledger entry. A `disputed` verdict caps the tier at `opinion`
 * (spec-v5 §14: disputed may ship "only if downgraded to tier: opinion");
 * `unsound` yields `undefined` because the rule must be retired, not surfaced.
 */
export function tierForRule(
  ledger: LegalBasisLedger | Map<string, LegalBasisEntry>,
  ruleId: string,
): LedgerTier | undefined {
  const entry =
    ledger instanceof Map ? ledger.get(ruleId) : ledger.find((e) => e.rule_id === ruleId);
  if (!entry) return undefined;
  if (entry.review.verdict === "unsound") return undefined;
  if (entry.review.verdict === "disputed") return "opinion";
  return entry.review.tier;
}

/** Coverage rollup for the SCOREBOARD / ledger README — honest signed/total. */
export function ledgerCoverage(
  ledger: LegalBasisLedger,
  totalRules: number,
): {
  total_rules: number;
  signed: number;
  by_verdict: Record<LegalVerdict, number>;
  by_tier: Record<LedgerTier, number>;
} {
  const by_verdict: Record<LegalVerdict, number> = {
    sound: 0,
    "sound-but-narrow": 0,
    disputed: 0,
    unsound: 0,
  };
  const by_tier: Record<LedgerTier, number> = {
    established: 0,
    "prevailing-practice": 0,
    opinion: 0,
  };
  for (const entry of ledger) {
    by_verdict[entry.review.verdict] += 1;
    by_tier[entry.review.tier] += 1;
  }
  return { total_rules: totalRules, signed: ledger.length, by_verdict, by_tier };
}

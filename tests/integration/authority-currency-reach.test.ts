/**
 * Can the "verify currency" label REACH the authorities read by hand?
 *
 * `fix-legal-authority-currency` promises that a finding resting on a reading
 * older than the horizon says so: the report layer computes
 * "verify currency (retrieved <date>)" over every finding's
 * `source_citations` (`src/report/json.ts`, and the SARIF, HTML and export
 * paths beside it).
 *
 * 🚨 Measured at 9.1005.0, that promise was true only for the part of the
 * product whose authorities live in the DKB. `resolveCitations` looks an id up
 * in the DKB and nothing else, so a rule resting on a statute read by hand
 * into a source module could not produce a structured citation at all — it
 * could only name the statute in prose and bake the read date into a
 * sentence. `READ-001`'s `source_citations` was `[]` while a DKB-backed
 * finding in the same run carried a dated citation. Nothing could ever label
 * the readability statutes or the mandated texts stale, however old the
 * reading got.
 *
 * ⚠️ This is a RUNTIME test on purpose. Two static scans over rule source were
 * written first and both were wrong: a rule that builds its citation from a
 * data table contains no literal statute string, so a prose scan cannot see
 * it; and `source_citations: []` passed straight to `makeFinding` matches any
 * pattern looking for a literal `citations: [`. The question "does this
 * finding carry an authority the currency machinery can read?" is only
 * answerable by firing the rule and looking at the finding.
 */
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { currencyLabel } from "../../src/report/citations.js";
import { MANDATED_TEXTS } from "../../src/engine/rules/text/mandated-texts.js";
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import type { Finding } from "../../src/engine/finding.js";

/** A policy far below every statute's minimum, so READ-001 fires. */
const DENSE_POLICY = `HOMEOWNERS INSURANCE POLICY

The insurer's obligation to indemnify the insured for consequential, incidental, or derivative losses occasioned by the occurrence of any peril enumerated in the declarations, notwithstanding any contrary provision of any endorsement, rider, or supplementary documentation incorporated by reference, shall be determined exclusively in accordance with the provisions of the applicable valuation methodology and the limitations, conditions, and exclusions specified in this policy.
`;

const HOLDER = MANDATED_TEXTS.find((r) => r.id === "ftc-holder-notice")!;

/** A credit contract carrying the Holder Rule notice with a word changed. */
const ALTERED_NOTICE_CONTRACT = `RETAIL INSTALLMENT CONTRACT

Seller: Harbour Lane Appliances, Inc.  Buyer: Nadia Osei

1. Price. The cash price is $1,480, payable at $62 a month for twenty-four months.

2. Notice.

${HOLDER.variants[0]!.text.replace("ALL CLAIMS AND DEFENSES", "ANY CLAIMS AND DEFENSES")}

3. Governing Law. This contract is governed by the law of the State of Ohio.
`;

/** Inside and far outside a twelve-month horizon, anchored to a fixed date. */
const FRESH = { as_of: "2026-11-23T00:00:00Z", horizon_months: 12 };
const LATER = { as_of: "2030-11-23T00:00:00Z", horizon_months: 12 };

function assertCurrencyReaches(f: Finding, expectCitation: RegExp): void {
  expect(
    f.source_citations.length,
    `${f.rule_id} rests on a statute and carries NO structured citation, so no "verify currency" label can ever apply to it`,
  ).toBeGreaterThan(0);
  const c = f.source_citations.find((x) => expectCitation.test(x.source));
  expect(c, `${f.rule_id}: no citation matching ${expectCitation}`).toBeDefined();
  // The date must be one the currency machinery can actually read.
  expect(Number.isNaN(Date.parse(c!.retrieved_at)), `${c!.retrieved_at} is unparseable`).toBe(
    false,
  );
  expect(currencyLabel(c!, FRESH), "a fresh reading must not be labelled").toBeUndefined();
  expect(currencyLabel(c!, LATER), "a four-year-old reading must be labelled").toContain(
    "verify currency",
  );
}

describe("the currency label reaches the hand-read authorities", () => {
  it("labels a readability statute's own reading", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE_POLICY, "policy.txt", { deps, readability: "fl" });
    const f = r.run.findings.find((x) => x.rule_id === "READ-001");
    expect(f, JSON.stringify(r.run.findings.map((x) => x.rule_id))).toBeDefined();
    assertCurrencyReaches(f!, /Fla\. Stat\. § 627\.4145/);
  });

  it("labels a mandated text's own reading", async () => {
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(ALTERED_NOTICE_CONTRACT, "contract.txt", { deps });
    const f = r.run.findings.find((x) => x.rule_id === "TEXT-001");
    expect(f, JSON.stringify(r.run.findings.map((x) => x.rule_id))).toBeDefined();
    assertCurrencyReaches(f!, /16 C\.F\.R\. § 433\.2/);
  });

  it("carries the row's own url, not a guess", async () => {
    // The citation must point where the text was actually read, so a reader
    // following it sees the words the rule measured against.
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(DENSE_POLICY, "policy.txt", { deps, readability: "fl" });
    const f = r.run.findings.find((x) => x.rule_id === "READ-001")!;
    const std = READABILITY_STANDARDS.find((s) => s.id === "fl")!;
    expect(f.source_citations[0]!.source_url).toBe(std.source_url);
    expect(f.source_citations[0]!.retrieved_at).toContain(std.retrieved_at);
  });

  it("gives every row in both hand-read tables what a citation needs", () => {
    // The static half, and the only part a scan can honestly answer: a row
    // that lacks a url or a read date cannot become a citation at all, so the
    // rule above would silently go back to carrying none.
    const rows = [
      ...READABILITY_STANDARDS.map((s) => ({ what: s.id, ...s })),
      ...MANDATED_TEXTS.map((t) => ({ what: t.id, ...t })),
    ];
    expect(rows.length, "no authority rows found — this would be vacuous").toBeGreaterThan(10);
    for (const row of rows) {
      expect(row.citation.length, row.what).toBeGreaterThan(5);
      expect(() => new URL(row.source_url), `${row.what}: bad source_url`).not.toThrow();
      expect(row.retrieved_at, row.what).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});

/**
 * What is still outside the currency check, and why — measured, not assumed.
 *
 * `TEXT-003` rests on U.C.C. § 2-316(2) and § 1-201(b)(10), and carries no
 * structured citation. That is deliberate and the reason is a licence one: the
 * DKB holds § 2-201, § 2-304 and § 1-201(b)(20) but not these two
 * subsections, and the U.C.C. is a Uniform Law Commission model code whose
 * official text is ULC-copyrighted — unlike a state's enacted version. Minting
 * a "public domain (government edict)" citation for it would be a false claim
 * about the source, so the honest state is no citation until the two
 * subsections enter the DKB with their real licence.
 *
 * This case is pinned so the debt is visible and so adding those nodes makes
 * the test fail and be deleted, rather than sitting unnoticed.
 *
 * ⚠️ The REST of the rules that declare no DKB citation — 97 of 1,946 — were
 * audited at 9.1007.0 and are correct as they are. Most are drafting-quality
 * rules resting on no law at all ("this clause sets no notice period"), which
 * is why `STRUCT`, `RISK`, `TEMP`, `TERM`, `OBLI` and `PROOF` are nearly all
 * uncited. The handful that DO name a statute name it for a reason that is not
 * a single supporting authority:
 *
 *   - `PERS-007` weighs FOUR separate tests (the IRS 20-factor test, the DOL
 *     economic-realities test, Cal. Lab. Code § 2775, M.G.L. c. 149 § 148B).
 *     The finding does not rest on one of them, and minting one citation would
 *     misrepresent which authority it depends on.
 *   - `IPDATA-002` names Cal. Lab. Code § 2870 in a CODE COMMENT, never in
 *     user-facing text.
 *
 * A wrong citation is worse than none: it would put a confident
 * "verify currency" label on a statute the finding does not actually rest on.
 * So the rule is to cite where ONE hand-read authority backs the finding, and
 * to stay silent where several do or where none does.
 */
describe("the authorities deliberately left outside it", () => {
  it("TEXT-003 carries no citation, and the U.C.C. nodes it needs are not in the DKB", async () => {
    const { LAUNCH_RULES, V3_RULES, V4_RULES, V5_RULES, V6_RULES, V7_RULES } =
      await import("../../src/engine/index.js");
    const all = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES, ...V7_RULES];
    const text003 = all.find((r) => r.id === "TEXT-003");
    expect(text003, "TEXT-003 is not registered").toBeDefined();
    expect(text003!.dkb_citations, "if TEXT-003 gained a DKB node, delete this case").toEqual([]);
  });
});

/**
 * Per-fixture sanity guards. Pin down which rules **must** fire for
 * each fixture so a regression that silently drops a finding gets
 * caught even when the result_hash drifts (rules added, severity
 * shifted, etc.). The golden-output test catches byte-level drift;
 * this test catches *semantic* drift in the bad-* fixtures' intended
 * coverage.
 *
 * Add a new entry to `EXPECTED_RULE_IDS` for each fixture you want
 * to lock down. Use the subset of rules whose failure-to-fire would
 * be a regression — not the full set, because the full set is the
 * golden test's job.
 */

import { describe, expect, it } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

/**
 * For each fixture, the rule IDs that MUST appear in `findings`.
 * Adding to this list = adding a regression guard. Removing from it
 * is a deliberate scope change — say why in the PR.
 */
const EXPECTED_RULE_IDS: Record<string, string[]> = {
  // Clean NDA — the structural rules silently pass; we don't assert
  // any specific finding for this one.
  "mutual-nda.docx": [],

  // bad-nda.docx carries 5 intentional violations. The engine now
  // catches all 5: impossible date, hanging cross-reference, uncapped
  // liability, `[insert party name]` placeholder, AND the word/numeral
  // mismatch. FIN-001 is no longer skipped by the mutual-nda playbook
  // — it has a narrow pattern (`<words> (<numeral>)`) and zero
  // false-positive cost on clean NDAs without monetary terms.
  "bad-nda.docx": [
    "TEMP-001", // impossible date "February 30, 2026"
    "STRUCT-007", // hanging cross-reference to "Section 9.4"
    "STRUCT-013", // `[insert party name]` placeholder
    "FIN-001", // "fifty thousand dollars ($75,000)" mismatch
    "RISK-009", // "liable for all damages…without limitation"
  ],

  // bad-saas.docx exercises the saas-customer / saas-vendor playbook
  // surface. Locked down: auto-renewal detected, indemnity asymmetry
  // flagged, indemnity procedural elements missing.
  "bad-saas.docx": [
    "TEMP-004", // auto-renewal language
    "OBLI-002", // asymmetric obligation
    "RISK-011", // incomplete indemnity procedure
  ],

  // Paste path mirrors the clean NDA — same structural pass.
  "pasted-mutual-nda.txt": [],

  // bad-employment.docx carries 7 intentional violations targeting the
  // employment-at-will-us playbook + the personnel/dark-pattern rules
  // added post-1.0. All 7 fire; this guard locks them in.
  "bad-employment.docx": [
    "DARK-005", // class-action waiver
    "PERS-005", // California non-compete (void under Cal. B&P §16600)
    "PERS-006", // non-disparagement without NLRA / SEC carve-outs
    "TERM-009", // asymmetric termination-for-convenience
    "CHOICE-010", // one-sided jury-trial waiver
    "OBLI-008", // `best efforts` undefined
    "TEMP-012", // survival clause silent on confidentiality + IP
  ],

  // bad-lease.docx (lease-commercial-multitenant playbook) carries 7
  // intentional violations; all fire.
  "bad-lease.docx": [
    "STRUCT-013", // `[Premises Address]` placeholder
    "CHOICE-010", // one-sided jury-trial waiver
    "DARK-006", // asymmetric pre-suit notice gate
    "FIN-009", // 3%/month late fee (36%/year)
    "RISK-015", // indemnification without aggregate cap
    "RISK-016", // insurance requirement without coverage minimum
    "TEMP-011", // auto-renewal with 10-day non-renewal window
  ],

  // bad-contractor.docx (independent-contractor playbook). The
  // "misclassification" dark pattern surfaces through PERS / TERM /
  // DARK rules rather than a dedicated misclassification rule —
  // none exists yet in the catalog.
  "bad-contractor.docx": [
    "DARK-005", // class-action waiver
    "STRUCT-013", // `[insert contractor name]` placeholder
    "PERS-005", // California non-compete
    "PERS-006", // non-disparagement
    "TERM-009", // asymmetric termination
  ],

  // bad-unilateral-nda.docx (unilateral-nda playbook). Intentional
  // violations: uncapped damages, survival silent on confidentiality,
  // and a `[insert recipient name]` placeholder.
  "bad-unilateral-nda.docx": [
    "STRUCT-013", // `[insert recipient name]` placeholder
    "RISK-009", // "damages without limitation"
    "TEMP-012", // survival silent on confidentiality
  ],

  // bad-residential-lease.docx (lease-residential-us playbook).
  // Intentional violations: 7-day non-renewal, 5%/month late fee,
  // asymmetric pre-suit notice, browsewrap modification clause,
  // tenant-only non-disparagement, `[Property Address]` placeholder.
  "bad-residential-lease.docx": [
    "STRUCT-013", // `[Property Address]` placeholder
    "DARK-006", // asymmetric pre-suit notice
    "DARK-007", // browsewrap modification ("continued occupancy")
    "FIN-009", // 5%/month late fee = 60%/year
    "PERS-006", // non-disparagement
    "TEMP-011", // auto-renewal with 7-day non-renewal window
  ],

  // bad-msa.docx (msa-general playbook). Intentional violations: MAC
  // clause present, indemnity without cap, insurance without minimum,
  // governing-law / venue mismatch, asymmetric termination, undefined
  // `reasonable efforts`, `[Effective Date]` placeholder.
  "bad-msa.docx": [
    "STRUCT-013", // `[Effective Date]` placeholder
    "OBLI-007", // material adverse change clause
    "OBLI-008", // `reasonable efforts` undefined
    "RISK-015", // indemnification without cap
    "RISK-016", // insurance without coverage minimum
    "CHOICE-009", // Delaware law / Texas venue mismatch
    "TERM-009", // asymmetric termination
  ],

  // bad-saas-vendor.docx — vendor-side SaaS contract with aggressive
  // commitments. The matcher prefers saas-customer over saas-vendor
  // for this fixture (both playbooks share most features for a
  // generic SaaS doc); the sanity guard is playbook-agnostic and
  // locks in the rules that fire regardless of which side wins.
  "bad-saas-vendor.docx": [
    "STRUCT-013", // `[TBD methodology]` placeholder
    "FIN-009", // 2.5%/month late fee = 30%/year
    "IPDATA-007", // data retention period unspecified (DPA ref only)
    "RISK-015", // indemnification carved out of cap
    "OBLI-008", // `best efforts` undefined
  ],

  // bad-consulting.docx — hybrid IC + advisory engagement.
  // Misclassification signals fire (PERS-007 — new this round) plus
  // the standard IC-style violations.
  // bad-consulting.docx: STRUCT-013 was previously firing on
  // signature-line underscore false positives; with that fixed,
  // this fixture no longer trips STRUCT-013. The substantive rules
  // below remain locked in.
  "bad-consulting.docx": [
    "PERS-005", // California non-compete
    "PERS-006", // non-disparagement
    "PERS-007", // IC misclassification signals
    "OBLI-008", // `best efforts` undefined
  ],

  // bad-sow.docx (sow playbook). Child-of-MSA contract with
  // intentionally under-defined deliverables, scope-creep clause,
  // late fee, placeholder.
  "bad-sow.docx": [
    "STRUCT-013", // `[TBD]` placeholder
    "FIN-009", // 2%/month late fee (24%/year)
    "OBLI-008", // `best efforts` undefined
  ],

  // --- 2026-05-12 research-driven fixtures ---

  // bad-nda-residuals.docx (mutual-nda playbook). Surfaces the new
  // OBLI-009 residuals rule + the standard NDA placeholder guard.
  "bad-nda-residuals.docx": [
    "OBLI-009", // residuals clause / `unaided memory`
    // STRUCT-013 previously matched signature-line underscores
    // (false positive); fixed.
  ],

  // bad-nda-no-dtsa.docx (unilateral-nda playbook). No dedicated DTSA
  // rule exists yet (potential PERS-009 / IPDATA-010 follow-up);
  // for now we lock in OBLI-005 (boilerplate confidentiality scope)
  // and the placeholder.
  // STRUCT-013 previously matched signature-line underscores (false
  // positive); fixed. OBLI-005 remains the substantive guard.
  "bad-nda-no-dtsa.docx": ["OBLI-005"],

  // bad-employment-trap.docx (employment-at-will-us playbook).
  // Showcases the new PERS-008 TRAP rule alongside class-action waiver,
  // forced-arbitration choice-of-forum, and one-sided jury waiver.
  "bad-employment-trap.docx": [
    "PERS-008", // training-repayment / stay-or-pay
    "DARK-005", // class-action waiver
    "CHOICE-010", // one-sided jury-trial waiver
    // STRUCT-013 dropped — previously firing on signature underscores.
  ],

  // bad-employment-choice-of-law.docx (employment-at-will-us playbook).
  // Showcases the new CHOICE-011 rule (DE law on a CA-based employee)
  // plus PERS-005 (CA non-compete).
  "bad-employment-choice-of-law.docx": [
    "CHOICE-011", // out-of-state choice-of-law on California worker
    "PERS-005", // California non-compete
    // STRUCT-013 dropped — previously firing on signature underscores.
  ],

  // bad-contractor-leaseback.docx (independent-contractor playbook).
  // Exercises misclassification surface — PERS-007 does NOT fire here
  // because the explicit "independent contractor" label is paired with
  // signals not all yet covered by PERS-007's pattern set; STRUCT-013,
  // FIN-005, RISK-011 are the durable guards.
  // STRUCT-013 dropped — previously firing on signature underscores.
  "bad-contractor-leaseback.docx": ["FIN-005", "RISK-011"],

  // bad-saas-data-hostage.docx (saas-customer playbook). Showcases the
  // new IPDATA-009 rule (AI/ML training on Customer Data) alongside
  // FIN-009 (predatory late fee) and IPDATA-004/005 (deletion / SCC).
  "bad-saas-data-hostage.docx": [
    "IPDATA-009", // AI/ML training rights
    "FIN-009", // late fee
    "IPDATA-004", // data deletion / portability silent
    // STRUCT-013 dropped — previously firing on signature underscores.
  ],

  // bad-saas-suspension.docx (saas-customer playbook). Showcases the
  // new DARK-008 rule (unilateral suspension without notice/cure).
  "bad-saas-suspension.docx": [
    "DARK-008", // unilateral suspension
    "OBLI-006", // SLA token / weasel-word
    // STRUCT-013 dropped — previously firing on signature underscores.
  ],

  // bad-saas-vendor-uncapped-ip.docx — vendor-side contract; the
  // matcher prefers msa-general for this title pattern. Guard the
  // durable rules.
  "bad-saas-vendor-uncapped-ip.docx": [
    // STRUCT-013 dropped — previously firing on signature underscores.
    "IPDATA-007", // data retention period unspecified
    "RISK-011", // indemnity procedural elements missing
  ],

  // bad-msa-mfn.docx (msa-general playbook). MFN doesn't have a
  // dedicated rule yet (potential FIN-010 follow-up); the guard locks
  // in the durable rules that fire across the doc.
  "bad-msa-mfn.docx": [
    // OBLI-001 dropped — previously firing on "EACH PARTY'S TOTAL
    // CUMULATIVE LIABILITY…" which is a clear mutual obligor, not an
    // ambiguous one. STRUCT-013 dropped — previously firing on
    // signature underscores.
    "FIN-005", // payment terms ambiguity
  ],

  // bad-lease-cam.docx (lease-commercial-multitenant playbook).
  // Uncapped CAM gross-up + asymmetric insurance surface.
  // STRUCT-013 dropped — previously firing on signature underscores.
  "bad-lease-cam.docx": ["RISK-016", "RISK-011"],

  // bad-residential-lease-deposit.docx (lease-residential-us playbook).
  // Overcollection + Javins waiver. No dedicated security-deposit rule
  // exists yet — the durable guards are STRUCT-013 + FIN-005.
  // STRUCT-013 dropped — previously firing on signature underscores.
  "bad-residential-lease-deposit.docx": ["FIN-005"],

  // bad-consulting-success-fee.docx (consulting-agreement playbook).
  // Success-fee + conflict + IP sweep + non-solicit. RISK-015 fires
  // for uncapped indemnity; OBLI-008 fires for `best efforts`.
  "bad-consulting-success-fee.docx": [
    "RISK-015", // indemnification without cap
    "OBLI-008", // `best efforts` undefined
    "OBLI-004", // conflict-of-interest silent
    // STRUCT-013 dropped — previously firing on signature underscores.
  ],
};

describe("fixture sanity guards", () => {
  for (const [name, required] of Object.entries(EXPECTED_RULE_IDS)) {
    if (required.length === 0) {
      it.skip(`${name}: no sanity guard (baseline clean fixture)`, () => {});
      continue;
    }
    it(`${name}: every required rule fires`, async () => {
      const { run } = await runFixture(join(CONTRACTS, name));
      const fired = new Set(run.findings.map((f) => f.rule_id));
      const missing = required.filter((id) => !fired.has(id));
      expect(
        missing,
        `expected these rules to fire but they did not: ${missing.join(", ")}`,
      ).toEqual([]);
    });
  }
});

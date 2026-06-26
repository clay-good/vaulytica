/**
 * v4 two-stage classifier tests (spec-v4.md §9, Step 42).
 *
 * Covers:
 *
 *   - Sub-domain detection for B (governance), C (equity), D (M&A),
 *     E (real estate), F (employment), G (settlement), K (insurance),
 *     L (banking), M (construction), N (trust/estate), O (compliance
 *     policy), and P (regulatory prose) — one positive case each, with
 *     a synthetic body that hits two title keywords + a few
 *     distinguishing phrases.
 *   - The 0.5 sub-domain threshold (a low-signal body returns null).
 *   - The v3 high-confidence short-circuit (a confident v3 detection
 *     maps directly to its v4 sub-domain without re-scoring).
 *   - `rankedAlternatives` ordering (winner first, runner-up second).
 *   - Determinism (two runs over the same input produce identical
 *     classifications).
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildContext } from "../../../src/engine/_test-fixtures.js";
import {
  classifyV4,
  classifyV4SubDomain,
  rankedAlternatives,
  type SubDomainFeatures,
} from "../../../src/extract/v4/index.js";
import type { V3Detection } from "../../../src/ui/v3/auto-detect.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFeatures(): SubDomainFeatures {
  const path = join(__dirname, "..", "..", "..", "dkb", "v4", "sub-domain-features.json");
  return JSON.parse(readFileSync(path, "utf8")) as SubDomainFeatures;
}

const FEATURES = loadFeatures();

function classifyFromBody(title: string, body: string, v3?: V3Detection) {
  const ctx = buildContext([title, body]);
  return classifyV4(ctx.extracted, `${title}\n${body}`, FEATURES, v3);
}

/* ---------------- per-sub-domain positive cases ---------------- */

describe("classifyV4 — sub-domain detection", () => {
  it("B-governance fires on bylaws + board of directors", () => {
    const r = classifyFromBody(
      "BYLAWS OF ACME CORP",
      "These Bylaws of the Corporation govern the Board of Directors. The registered agent for the Corporation is named below. Annual meeting of stockholders shall occur each year per the Delaware General Corporation Law.",
    );
    expect(r.sub_domain).toBe("B-governance");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("C-equity fires on SAFE + vesting + 409A", () => {
    const r = classifyFromBody(
      "Simple Agreement for Future Equity",
      "This Simple Agreement for Future Equity is between Company and Investor. The post-money valuation cap is $10,000,000. Conversion event includes a qualified financing. Vesting commencement date is the Effective Date. IRC Section 409A compliance is required.",
    );
    expect(r.sub_domain).toBe("C-equity");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("D-m-and-a fires on stock purchase + closing + representations", () => {
    const r = classifyFromBody(
      "Stock Purchase Agreement",
      "This Stock Purchase Agreement contemplates the Closing on the Closing Date. The Purchase Price shall be paid in cash. Representations and warranties of the Seller survive the Closing. Indemnification basket and indemnification cap are set in Section 9.",
    );
    expect(r.sub_domain).toBe("D-m-and-a");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("E-real-estate fires on lease + premises + landlord", () => {
    const r = classifyFromBody(
      "Commercial Lease Agreement",
      "This Commercial Lease Agreement is between Landlord and Tenant. The Premises are described in Exhibit A. Monthly Rent and Security Deposit are set forth herein. Common Area and CAM charges are paid by Tenant.",
    );
    expect(r.sub_domain).toBe("E-real-estate");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("F-employment fires on employment agreement + at-will + base salary", () => {
    const r = classifyFromBody(
      "Executive Employment Agreement",
      "This Executive Employment Agreement is between Employer and Employee. Employment is at-will. The Employee's base salary is $300,000. Termination for cause is defined herein. Section 409A and Section 280G compliance.",
    );
    expect(r.sub_domain).toBe("F-employment");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("G-settlement fires on settlement + 1542 + release", () => {
    const r = classifyFromBody(
      "Settlement Agreement and Mutual Release",
      "This Settlement Agreement and Mutual Release is a general release of claims. California Civil Code Section 1542 is expressly waived. The Parties shall release all claims. No admission of liability is intended.",
    );
    expect(r.sub_domain).toBe("G-settlement");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("K-insurance fires on ACORD 25 + named insured", () => {
    const r = classifyFromBody(
      "Certificate of Liability Insurance — ACORD 25",
      "Certificate of Liability Insurance. Named Insured: Acme Corp. Policy Period: 2026-01-01 to 2027-01-01. Form Number: CG 20 10. Additional Insured endorsement attached. Waiver of subrogation included.",
    );
    expect(r.sub_domain).toBe("K-insurance");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("L-banking fires on promissory note + maker + payee", () => {
    const r = classifyFromBody(
      "Promissory Note",
      "Promissory Note. For value received, Maker promises to pay Payee the principal amount of $1,000,000. The interest rate is fixed at 6%. UCC § 9-203 attachment is satisfied. Reg Z disclosures attached.",
    );
    expect(r.sub_domain).toBe("L-banking");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("M-construction fires on AIA + owner + contractor + scope of work", () => {
    const r = classifyFromBody(
      "AIA Document A101 — Standard Form of Agreement Between Owner and Contractor",
      "The Owner and the Contractor agree to the Scope of Work described in Exhibit A. General Conditions of the Contract for Construction shall apply. Progress payment and final payment terms apply. Miller Act protections apply.",
    );
    expect(r.sub_domain).toBe("M-construction");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("N-trust-estate fires on last will + testator + executor", () => {
    const r = classifyFromBody(
      "Last Will and Testament",
      "I, John Doe, the Testator, declare this to be my Last Will and Testament. I appoint Jane Doe as my Executor and personal representative. The trustee of any trust created hereunder shall act in the interest of the beneficiary.",
    );
    expect(r.sub_domain).toBe("N-trust-estate");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("O-compliance-policy fires on insider trading policy", () => {
    const r = classifyFromBody(
      "Insider Trading Policy",
      "This Insider Trading Policy prohibits trading on material non-public information. Rule 10b-5 and Rule 10b5-1 plans are described. The Code of Conduct applies. Anti-retaliation provisions per Dodd-Frank are included.",
    );
    expect(r.sub_domain).toBe("O-compliance-policy");
    expect(r.confidence).toBeGreaterThan(0.5);
  });

  it("P-regulatory-prose fires on Form D + Regulation D + Rule 506", () => {
    const r = classifyFromBody(
      "Form D — Notice of Exempt Offering of Securities",
      "Form D filed under Regulation D. This is a Rule 506 exempt offering. Blue Sky filings are described. The Issuer's offering is private.",
    );
    expect(r.sub_domain).toBe("P-regulatory-prose");
    expect(r.confidence).toBeGreaterThan(0.5);
  });
});

/* ---------------- threshold + fallback ---------------- */

describe("classifyV4 — threshold + fallback", () => {
  it("returns null sub-domain when no signals match", () => {
    const r = classifyFromBody(
      "Notes",
      "This document is entirely unrelated to any of the catalogued legal families.",
    );
    expect(r.sub_domain).toBeNull();
    expect(r.confidence).toBe(0);
  });

  it("returns null sub-domain on a body below the confidence floor", () => {
    // One distinguishing phrase only (~0.143) — should not clear the
    // calibrated 0.4 threshold.
    const r = classifyFromBody("Notes", "Tenant.");
    expect(r.sub_domain).toBeNull();
  });
});

/* ---------------- v3 short-circuit ---------------- */

describe("classifyV4 — v3 high-confidence short-circuit", () => {
  it("routes a v3 BAA detection to I-privacy / I.1 directly", () => {
    const v3: V3Detection = {
      family: "baa",
      suggested_playbook: "baa",
      confidence: 0.92,
      signals: [
        { source: "definition", evidence: "Business Associate", weight: 3 },
        { source: "phrase", evidence: "45 CFR § 164.504", weight: 2 },
      ],
    };
    const r = classifyFromBody("Generic", "Unrelated body text.", v3);
    expect(r.sub_domain).toBe("I-privacy");
    expect(r.family_id).toBe("I.1");
    expect(r.confidence).toBeCloseTo(0.92, 2);
  });

  it("does not short-circuit on v3 unknown / low confidence", () => {
    const v3: V3Detection = {
      family: "unknown",
      suggested_playbook: null,
      confidence: 0,
      signals: [],
    };
    // No body signals either → null sub-domain
    const r = classifyFromBody("Notes", "Unrelated.", v3);
    expect(r.sub_domain).toBeNull();
  });

  it("falls through to the v4 stage-1 scorer when v3 confidence < 0.6", () => {
    const v3: V3Detection = {
      family: "baa",
      suggested_playbook: "baa",
      confidence: 0.3,
      signals: [],
    };
    const r = classifyFromBody(
      "BYLAWS OF ACME CORP",
      "These Bylaws of the Corporation govern the Board of Directors. The registered agent is named below. Annual meeting of stockholders per the Delaware General Corporation Law.",
      v3,
    );
    // v4 scorer should pick B-governance regardless of the weak v3 signal.
    expect(r.sub_domain).toBe("B-governance");
  });
});

/* ---------------- alternatives ---------------- */

describe("rankedAlternatives", () => {
  it("returns the winner first and runners-up after", () => {
    const ctx = buildContext([
      "Stock Purchase Agreement",
      "This Stock Purchase Agreement contemplates the Closing on the Closing Date. The Purchase Price is set. Representations and warranties of the Seller survive. Voting Agreement is referenced.",
    ]);
    const alts = rankedAlternatives(
      {
        extracted: ctx.extracted,
        body_text: "Stock Purchase Agreement ... Voting Agreement is referenced.",
        features: FEATURES,
      },
      3,
    );
    expect(alts.length).toBeLessThanOrEqual(3);
    expect(alts[0]!.sub_domain).toBe("D-m-and-a");
  });
});

/* ---------------- determinism ---------------- */

describe("classifyV4 — determinism", () => {
  it("produces an identical classification on two runs over the same input", () => {
    const r1 = classifyFromBody(
      "Commercial Lease Agreement",
      "Landlord and Tenant. The Premises are described. Monthly Rent is set. Security Deposit retained.",
    );
    const r2 = classifyFromBody(
      "Commercial Lease Agreement",
      "Landlord and Tenant. The Premises are described. Monthly Rent is set. Security Deposit retained.",
    );
    expect(r1).toEqual(r2);
  });
});

/* ---------------- registry contract ---------------- */

describe("sub-domain-features.json — registry contract", () => {
  it("ships exactly the 16 sub-domains enumerated in spec §6", () => {
    const ids = Object.keys(FEATURES.sub_domains).sort();
    expect(ids).toEqual(
      [
        "A-commercial",
        "B-governance",
        "C-equity",
        "D-m-and-a",
        "E-real-estate",
        "F-employment",
        "G-settlement",
        "H-ip-licensing",
        "I-privacy",
        "J-healthcare",
        "K-insurance",
        "L-banking",
        "M-construction",
        "N-trust-estate",
        "O-compliance-policy",
        "P-regulatory-prose",
      ].sort(),
    );
  });

  it("every sub-domain has at least one title keyword and one distinguishing phrase", () => {
    for (const [id, entry] of Object.entries(FEATURES.sub_domains)) {
      expect(entry.title_keywords.length, `${id}.title_keywords`).toBeGreaterThan(0);
      expect(entry.distinguishing_phrases.length, `${id}.distinguishing_phrases`).toBeGreaterThan(
        0,
      );
    }
  });

  it("declares the calibrated thresholds", () => {
    // Sub-domain floor calibrated from 0.5 → 0.4 against the golden
    // corpus (spec-v4 Part VII open question #8; see
    // classifier-calibration.test.ts). Family floor stays 0.5.
    expect(FEATURES.thresholds.sub_domain_min_confidence).toBe(0.4);
    expect(FEATURES.thresholds.family_min_confidence).toBe(0.5);
  });

  it("declares the v2-aligned scoring weights", () => {
    expect(FEATURES.scoring_weights.title_keyword).toBe(0.3);
    expect(FEATURES.scoring_weights.distinguishing_phrase).toBe(0.2);
    expect(FEATURES.scoring_weights.negative_feature).toBe(-0.1);
  });
});

void classifyV4SubDomain; // typecheck reference

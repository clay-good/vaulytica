/**
 * The guard against over-suppression.
 *
 * A long campaign of false-positive fixes teaches every rule to stay quiet on
 * a clause that only LOOKS like a defect. The risk that campaign creates is the
 * opposite and worse error: a rule taught to ignore the compliant form that
 * also stops seeing the real one. A linter that misses a genuine defect is more
 * dangerous than one that over-reports, because silence reads as a clean bill.
 *
 * This document is adversarial by construction. Every clause in it is the
 * GENUINE version of something a guard elsewhere in the engine suppresses:
 *
 *   - a California settlement with no § 1542 waiver (SET-003's gate is
 *     satisfied — California law governs and the release covers unknown claims)
 *   - a settlement of a sexual-harassment charge with no § 162(q) recital
 *     (SET-010's nexus is present)
 *   - a one-sided, uncapped commercial indemnity (RISK-002, RISK-015 — not the
 *     statutory D&O or neutral-agent forms those rules learned to skip)
 *   - a real class-action waiver (DARK-005 — not "nothing herein waives")
 *   - a lowercase use of an expressly defined term (STRUCT-009 / STRUCT-014 —
 *     not a statutory idiom, entity type, or parenthetical noun)
 *   - a dangling internal cross-reference (STRUCT-007 — not a statutory cite,
 *     an ARTICLE heading, or another instrument's numbering)
 *   - a genuine cross-border transfer with no Article 46 safeguard (IPDATA-008
 *     — not "no transfers occur")
 *   - a truly unidentified obligor and a bare ambiguous trigger (OBLI-001,
 *     OBLI-003 — not a named passive agent or a stated statutory mechanism)
 *   - no signature block at all (STRUCT-003 — no conformed signature,
 *     certification, adoption recital, delivery recital, or publication stamp)
 *
 * If a future guard is written too broadly, one of these assertions fails and
 * says exactly which defect went blind.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { runEngine } from "../runner.js";
import { LAUNCH_RULES } from "./index.js";
import { V3_RULES } from "./v3/index.js";
import { V4_RULES } from "./v4/index.js";
import type { Playbook, RuleContext } from "../finding.js";

const SRC = { name: "adversarial.docx", sha256: "0".repeat(64), size_bytes: 100 };
const SETTLEMENT_PB: Playbook = { id: "confidential-settlement", version: "1.0.0" };
const ALL_RULES = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES];

const ADVERSARIAL: [string, ...string[]][] = [
  [
    "Confidential Settlement Agreement and Release",
    'This Confidential Settlement Agreement (this "Agreement") is entered into as of May 4, 2027, between Sablecrest Media LLC, a California limited liability company ("Company"), and Dana Whitfield ("Claimant"), resolving Claimant\'s charge of workplace sexual harassment filed with the DFEH.',
  ],
  [
    "Definitions",
    '"Confidential Information" means all non-public information of the Company disclosed to Claimant during employment.',
  ],
  [
    "Settlement Payment",
    "Company shall pay Claimant $250,000. Claimant shall protect the confidential information of the Company at all times.",
  ],
  [
    "Release",
    "Claimant releases the Company from all claims, known and unknown, arising from Claimant's employment and the harassment charge.",
  ],
  [
    "Indemnification",
    "Claimant shall indemnify and hold harmless the Company from any and all claims, damages, losses, and expenses arising out of any breach of this Agreement by Claimant. Claimant shall indemnify the Company against any third-party claim relating to Claimant's statements. Claimant shall indemnify the Company for any tax liability arising from the settlement payment.",
  ],
  [
    "Class-Action Waiver",
    "Claimant waives any right to participate in a class action, collective action, or representative action against the Company.",
  ],
  [
    "Data Transfer",
    "Company may transfer Claimant's personnel data to its processing affiliate outside the EEA for administration.",
  ],
  [
    "Administration",
    "The appropriate party shall provide notice from time to time as needed. Any dispute shall be resolved as set forth in Section 19 of this Agreement.",
  ],
  ["Governing Law", "This Agreement is governed by the laws of the State of California."],
];

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

/** Each planted defect, with the clause that plants it. */
const PLANTED: [string, string][] = [
  ["SET-003", "California release of unknown claims with no § 1542 waiver"],
  ["SET-010", "sexual-harassment settlement with no § 162(q) recital"],
  ["RISK-002", "indemnity borne by one party only"],
  ["RISK-015", "commercial indemnity with no aggregate cap"],
  ["DARK-005", "an actual class-action waiver"],
  ["STRUCT-003", "no signature block of any form"],
  ["STRUCT-007", "a reference to a Section 19 that does not exist"],
  ["STRUCT-009", "lowercase use of the defined Confidential Information"],
  ["STRUCT-014", "lowercase use of the defined Confidential Information"],
  ["IPDATA-008", "transfer outside the EEA with no Article 46 safeguard"],
  ["OBLI-001", "'the appropriate party' as obligor"],
  ["OBLI-003", "'from time to time as needed' as a trigger"],
];

describe("suppression regression — every guarded rule still sees the real defect", () => {
  it.each(PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...ADVERSARIAL), SETTLEMENT_PB);
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});

/**
 * The consumer dark-pattern rules were each written to a narrower phrasing than
 * the pattern takes, so the textbook form of the clause the rule polices went
 * unreported. This adversarial "Vendor Terms of Service" carries the genuine
 * version of each, and pins that they all fire — a future narrowing of any of
 * these patterns fails here by name.
 */
const CONSUMER_ADVERSARIAL: [string, ...string[]][] = [
  ["Vendor Terms of Service", "By continuing to use the Service, you agree to these Terms."],
  [
    "Renewal",
    "The subscription renews automatically for successive twelve (12) month terms unless you provide written notice of non-renewal at least ninety (90) days before the end of the then-current term.",
  ],
  [
    "Suspension",
    "Vendor may suspend or terminate your access immediately, without notice and without any cure period, for any reason.",
  ],
  [
    "Disputes",
    "Any dispute shall be resolved by binding individual arbitration. You waive any right to a jury trial and any right to participate in a class action. If Vendor prevails in any dispute, you shall pay Vendor's attorneys' fees.",
  ],
];

const CONSUMER_PLANTED: [string, string][] = [
  ["DARK-002", "'renews automatically' with a (90)-day non-renewal window"],
  ["DARK-003", "'you shall pay Vendor's attorneys' fees'"],
  ["DARK-004", "binding individual arbitration + class waiver in consumer terms"],
  ["DARK-008", "suspend or terminate your access without notice or cure"],
  ["CHOICE-008", "'waive any right to a jury trial'"],
  ["DARK-005", "'you waive any right to … participate in a class action'"],
];

describe("false-negative regression — consumer dark patterns still fire", () => {
  it.each(CONSUMER_PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...CONSUMER_ADVERSARIAL), {
      id: "saas-vendor",
      version: "1.0.0",
    });
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});

/**
 * The BAA defect rules flag HIPAA-noncompliant clauses. Each was written to a
 * narrower phrasing than the defect takes: an over-long breach window written
 * "ninety (90) days", an open-ended "when feasible" return obligation, and a
 * choice-of-law clause overriding federal HIPAA. This adversarial BAA carries
 * all three and pins that they fire — while the statutory "if infeasible"
 * condition (correct drafting) stays out of the return-obligation defect.
 */
const BAA_ADVERSARIAL: [string, ...string[]][] = [
  [
    "Business Associate Agreement",
    "Effective Date: June 1, 2027. This Business Associate Agreement is entered into between Covered Entity and Business Associate.",
  ],
  [
    "Breach Notification",
    "Business Associate shall notify Covered Entity of any breach of unsecured PHI within ninety (90) days after discovery of the breach.",
  ],
  [
    "Return or Destruction",
    "Upon termination, Business Associate shall return or destroy all PHI when feasible.",
  ],
  [
    "Governing Law",
    "This Agreement is governed by the laws of the State of Texas, which shall control over any conflicting federal requirement.",
  ],
];

const BAA_PLANTED: [string, string][] = [
  ["BAA-020", "breach window of 'ninety (90) days'"],
  ["BAA-024", "open-ended 'when feasible' return obligation"],
  ["BAA-042", "choice-of-law overriding federal HIPAA"],
];

describe("false-negative regression — BAA defect rules still fire", () => {
  it.each(BAA_PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...BAA_ADVERSARIAL), { id: "baa", version: "1.0.0" });
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});

/**
 * The GDPR Art. 28 defect rules flag a processor DPA that violates the
 * controller's mandatory protections. Each was written to a narrower phrasing
 * than the violation takes: the deletion choice handed to the processor via
 * "sole discretion" rather than "option/choice", the audit right eliminated by
 * a generic certification report "in lieu of any audit" rather than a named
 * SOC 2, and the processor arrogating instruction-amendment power via
 * "unilaterally amend" rather than "deviate/depart". This adversarial DPA
 * carries all three and pins that they fire.
 */
const DPA_ADVERSARIAL: [string, ...string[]][] = [
  [
    "Data Processing Agreement",
    "This Data Processing Agreement is entered into pursuant to Article 28 GDPR between Controller and Processor, effective June 1, 2027.",
  ],
  [
    "Deletion or Return",
    "Upon termination, Processor shall, at the Processor's sole discretion, either delete or return the Personal Data.",
  ],
  [
    "Instructions",
    "Processor may unilaterally amend or supplement the Controller's instructions where Processor deems it operationally necessary.",
  ],
  [
    "Audit",
    "In lieu of any audit or inspection rights, Controller shall rely solely on a third-party certification report, and Controller shall have no right to conduct or mandate an audit.",
  ],
];

const DPA_PLANTED: [string, string][] = [
  ["DPA-035", "deletion choice handed to the processor's sole discretion"],
  ["DPA-036", "audit eliminated by a report 'in lieu of any audit'"],
  ["DPA-037", "processor may unilaterally amend the controller's instructions"],
];

describe("false-negative regression — GDPR DPA defect rules still fire", () => {
  it.each(DPA_PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...DPA_ADVERSARIAL), {
      id: "dpa-controller-processor",
      version: "1.0.0",
    });
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});

/**
 * The separation-agreement defect rules police McLaren Macomb overbreadth. Each
 * missed the dominant phrasing: the non-disparagement written "shall not MAKE
 * any disparaging statement" (not "shall not disclose/disparage"), the
 * confidentiality written "keep the terms … of this Agreement confidential"
 * (not the exact "terms of this agreement"), and — worse — the protected-rights
 * carve-out counted as present whenever "government agency" appeared, even in
 * the prohibition ("shall not disclose … to any government agency") the
 * carve-out is supposed to undo. This adversarial separation agreement carries
 * the overbroad clauses with no genuine carve-out and pins that both fire.
 */
const SEPARATION_ADVERSARIAL: [string, ...string[]][] = [
  [
    "Separation Agreement and General Release",
    "This Separation Agreement is between Company and Employee, effective July 1, 2027, and pays Employee severance over and above accrued amounts.",
  ],
  [
    "Confidentiality",
    "Employee shall keep the terms, amount, and existence of this Agreement strictly confidential and shall not disclose them to any person, including any government agency.",
  ],
  [
    "Non-Disparagement",
    "Employee shall not make any disparaging, negative, or critical statement about the Company, its officers, or its products, in any forum, at any time.",
  ],
];

const SEPARATION_PLANTED: [string, string][] = [
  ["EMP-020", "overbroad confidentiality and non-disparagement (McLaren Macomb)"],
  ["EMP-021", "protected-rights carve-out that is actually a prohibition"],
];

describe("false-negative regression — separation defect rules still fire", () => {
  it.each(SEPARATION_PLANTED)("%s still fires on %s", async (ruleId) => {
    const ctx = withPb(buildContext(...SEPARATION_ADVERSARIAL), {
      id: "separation-agreement",
      version: "1.0.0",
    });
    const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
  });
});

/**
 * The highest-stakes defect fixes of the session — a discriminatory covenant, a
 * cognovit clause, and broad-form / anti-indemnity clauses in their canonical
 * wording. Each was invisible to the engine (or the rule that should catch it)
 * until an adversarial document surfaced it. These are the defects where a
 * false negative is gravest — a title reviewer missing a racially restrictive
 * covenant, or a lender's confession-of-judgment slipping past — so they get a
 * permanent guard: narrow the pattern and one of these fails by name.
 */
const HIGH_STAKES: { rule: string; playbook: string; sections: [string, ...string[]][] }[] = [
  {
    rule: "RE-038",
    playbook: "ccrs",
    sections: [
      [
        "Covenant",
        "The premises shall not be conveyed to or occupied by persons of African descent.",
      ],
    ],
  },
  // The residential tenant-protection rules — each flags a void lease term that
  // a landlord imposes on a consumer tenant. A false negative here lets an
  // illegal clause pass unremarked, so they get the same permanent guard.
  {
    rule: "DARK-010",
    playbook: "lease-residential-us",
    sections: [["Lease", "Tenant hereby waives the implied warranty of habitability."]],
  },
  {
    rule: "DARK-011",
    playbook: "lease-residential-us",
    sections: [["Lease", "Landlord may change the locks and remove the tenant without notice."]],
  },
  {
    rule: "DARK-012",
    playbook: "lease-residential-us",
    sections: [["Lease", "The security deposit is non-refundable."]],
  },
  {
    rule: "DARK-013",
    playbook: "lease-residential-us",
    sections: [
      ["Lease", "Tenant hereby waives all rights and remedies under the landlord-tenant act."],
    ],
  },
  {
    rule: "BNK-051",
    playbook: "promissory-note",
    sections: [
      [
        "Note",
        "Maker irrevocably authorizes any attorney to appear and confess judgment against Maker for the unpaid balance, without prior notice or a hearing.",
      ],
    ],
  },
  {
    rule: "INS-015",
    playbook: "indemnification-agreement",
    sections: [
      [
        "Indemnity",
        "Contractor shall indemnify Owner from all liability caused in whole or in part by the negligence of the Owner.",
      ],
    ],
  },
  {
    rule: "MSA-010",
    playbook: "msa-vendor-deep",
    sections: [
      [
        "Indemnity",
        "Governed by New York law. Vendor shall indemnify Customer for all claims caused in whole or in part by the negligence of Customer.",
      ],
    ],
  },
  {
    rule: "MSA-009",
    playbook: "msa-vendor-deep",
    sections: [["Liability", "Vendor exempts itself from liability for its own fraud."]],
  },
];

describe("false-negative regression — the highest-stakes defects still fire", () => {
  it.each(HIGH_STAKES.map((h) => [h.rule, h] as const))(
    "%s still fires on its canonical clause",
    async (ruleId, h) => {
      const ctx = withPb(buildContext(...h.sections), { id: h.playbook, version: "1.0.0" });
      const run = await runEngine({ rules: ALL_RULES, ctx, source_file: SRC });
      expect(run.findings.map((f) => f.rule_id)).toContain(ruleId);
    },
  );
});

import { describe, expect, it } from "vitest";
import { buildTree } from "../../../src/extract/_fixtures.js";
import {
  classifyRoles,
  extractAuditRights,
  extractBreachTimings,
  extractDataCategories,
  extractDtsaNotice,
  extractInsuranceSchedule,
  extractSecurityMeasures,
  extractSubprocessorInventory,
  extractTransferMechanisms,
  extractAllV3,
} from "../../../src/extract/v3/index.js";

describe("v3 role classifier", () => {
  it("detects roles from quoted definitions", () => {
    const tree = buildTree([
      "Definitions",
      `"Processor" means the entity that processes Personal Data on behalf of the Controller.`,
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "processor" && r.evidence === "definition")).toBe(true);
  });

  it("detects role from parenthetical alias", () => {
    const tree = buildTree([
      "Preamble",
      `Acme Corp. (the "Business Associate") shall protect PHI.`,
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "business-associate")).toBe(true);
  });

  it("detects role via CCPA clause usage", () => {
    const tree = buildTree([
      "Body",
      "As a Service Provider under the CCPA, Recipient shall not retain Personal Information.",
    ]);
    const roles = classifyRoles(tree);
    expect(roles.some((r) => r.role === "service-provider-ccpa")).toBe(true);
  });

  it("is empty when no role language appears", () => {
    const tree = buildTree(["Body", "The Effective Date is January 1, 2026."]);
    expect(classifyRoles(tree)).toEqual([]);
  });

  it("is deterministic across runs", () => {
    const tree = buildTree([
      "Body",
      `"Controller" means the entity. "Processor" means the entity that processes.`,
    ]);
    expect(JSON.stringify(classifyRoles(tree))).toEqual(JSON.stringify(classifyRoles(tree)));
  });
});

describe("v3 data-category extractor", () => {
  it("detects HIPAA identifiers", () => {
    const tree = buildTree([
      "PHI",
      "Categories include names, telephone numbers, email addresses, social security numbers, and IP addresses.",
    ]);
    const cats = extractDataCategories(tree);
    const slugs = cats.map((c) => c.slug);
    expect(slugs).toContain("hipaa-names");
    expect(slugs).toContain("hipaa-phone");
    expect(slugs).toContain("hipaa-email");
    expect(slugs).toContain("hipaa-ssn");
    expect(slugs).toContain("hipaa-ip");
  });

  it("detects GDPR special categories and flag", () => {
    const tree = buildTree([
      "Annex I.B",
      "The data includes special categories of personal data: racial or ethnic origin and data concerning health.",
    ]);
    const cats = extractDataCategories(tree);
    expect(cats.some((c) => c.slug === "special-categories-flag")).toBe(true);
    expect(cats.some((c) => c.group === "gdpr-special")).toBe(true);
  });

  it("returns nothing on clean text", () => {
    const tree = buildTree(["Body", "The parties agree to terms."]);
    expect(extractDataCategories(tree)).toEqual([]);
  });
});

describe("v3 transfer-mechanism extractor", () => {
  it("classifies SCC Module 2 and locates the annex", () => {
    const tree = buildTree([
      "Cross-border",
      "The parties incorporate Module 2 of the Standard Contractual Clauses, attached as Annex A.",
    ]);
    const mechs = extractTransferMechanisms(tree);
    expect(mechs.some((m) => m.kind === "scc-module-2")).toBe(true);
    expect(mechs.find((m) => m.kind === "scc-module-2")?.location).toBe("annex");
  });

  it("detects UK IDTA, Addendum, and Adequacy Decision", () => {
    const tree = buildTree([
      "Body",
      "Pursuant to the International Data Transfer Agreement (IDTA) and the UK Addendum, transfers rely on an adequacy decision.",
    ]);
    const mechs = extractTransferMechanisms(tree);
    const kinds = mechs.map((m) => m.kind);
    expect(kinds).toContain("uk-idta");
    expect(kinds).toContain("uk-addendum");
    expect(kinds).toContain("adequacy-decision");
  });

  it("reads adequacy 'finding' and UK adequacy 'regulations' as the adequacy basis", () => {
    for (const text of [
      "Transfers are permitted under an adequacy finding by the Commission.",
      "Transfers rely on the UK adequacy regulations.",
    ]) {
      const kinds = extractTransferMechanisms(buildTree(["Transfers", text])).map((m) => m.kind);
      expect(kinds, text).toContain("adequacy-decision");
    }
  });

  it("returns empty when no transfer language is present", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    expect(extractTransferMechanisms(tree)).toEqual([]);
  });
});

describe("v3 security-measures extractor", () => {
  it("detects measures and cadence", () => {
    const tree = buildTree([
      "Annex II",
      "Vendor shall maintain encryption at rest, encryption in transit, multi-factor authentication, and conduct annual penetration testing.",
    ]);
    const measures = extractSecurityMeasures(tree);
    const slugs = measures.map((m) => m.slug);
    expect(slugs).toContain("encryption-at-rest");
    expect(slugs).toContain("encryption-in-transit");
    expect(slugs).toContain("mfa");
    expect(slugs).toContain("penetration-testing");
    const pen = measures.find((m) => m.slug === "penetration-testing");
    expect(pen?.cadence).toBe("annual");
  });

  it("detects spelled two-factor and passive/hyphenated encryption phrasings", () => {
    const expect_slug = (text: string, slug: string) => {
      const slugs = extractSecurityMeasures(buildTree(["Security", text])).map((m) => m.slug);
      expect(slugs, text).toContain(slug);
    };
    expect_slug("Vendor requires two-factor authentication for administrative access.", "mfa");
    expect_slug("Vendor enforces two-step verification for remote logins.", "mfa");
    expect_slug("All data at rest is encrypted using AES-256.", "encryption-at-rest");
    expect_slug(
      "Vendor maintains data-at-rest encryption across all databases.",
      "encryption-at-rest",
    );
    expect_slug("All data in transit is encrypted.", "encryption-in-transit");
  });

  it("returns empty on clean text", () => {
    const tree = buildTree(["Body", "The Term begins on the Effective Date."]);
    expect(extractSecurityMeasures(tree)).toEqual([]);
  });
});

describe("v3 breach-timing extractor", () => {
  it("normalizes hours and days", () => {
    const tree = buildTree([
      "Notification",
      "In the event of a personal data breach, Processor shall notify the Controller within 48 hours of discovery.",
    ]);
    const t = extractBreachTimings(tree);
    const first = t[0];
    expect(first).toBeDefined();
    expect(first!.max_delay_hours).toBe(48);
    expect(first!.addressee).toBe("controller");
    expect(first!.trigger).toBe("discovery");
  });

  it("captures vague phrases", () => {
    const tree = buildTree([
      "Notification",
      "Business Associate shall report any security incident to Covered Entity without unreasonable delay.",
    ]);
    const t = extractBreachTimings(tree);
    const first = t[0];
    expect(first).toBeDefined();
    expect(first!.max_delay_phrase).toBe("without unreasonable delay");
    expect(first!.max_delay_hours).toBeNull();
  });

  it("reads the numeral in the 'word (numeral)' drafting form", () => {
    // "within seventy-two (72) hours" is the dominant breach-clause form; the
    // parenthesized numeral is authoritative. It previously parsed to null.
    for (const [text, hours] of [
      [
        "Processor shall notify Controller of any personal data breach within seventy-two (72) hours of discovery.",
        72,
      ],
      [
        "Vendor shall notify Customer of a security incident within twenty-four (24) hours of confirmation.",
        24,
      ],
      [
        "Processor shall inform Controller of any personal data breach within two (2) business days.",
        48,
      ],
      [
        "Processor shall notify Controller of any personal data breach within sixty (60) days of discovery.",
        1440,
      ],
    ] as const) {
      const t = extractBreachTimings(buildTree(["Notification", text]));
      expect(
        t.some((x) => x.max_delay_hours === hours),
        `${text} -> ${JSON.stringify(t.map((x) => x.max_delay_hours))}`,
      ).toBe(true);
    }
  });

  it("matches a plural breach noun ('report Breaches')", () => {
    // A BAA states its duty in the plural; `\bbreach\b` never matched "Breaches"
    // so the whole clause was dropped.
    const t = extractBreachTimings(
      buildTree([
        "Breach Reporting",
        "Business Associate shall report Breaches to Covered Entity within sixty (60) days of discovery.",
      ]),
    );
    expect(t.some((x) => x.max_delay_hours === 1440 && x.addressee === "controller")).toBe(true);
  });
});

describe("v3 audit-rights extractor", () => {
  it("captures frequency, notice, methods", () => {
    const tree = buildTree([
      "Audit",
      "Customer may audit Processor once per year upon 30 days' prior written notice; onsite audits and SOC 2 substitution are permitted under confidentiality obligations.",
    ]);
    const a = extractAuditRights(tree);
    const first = a[0];
    expect(first).toBeDefined();
    expect(first!.frequency_per_year).toBe(1);
    expect(first!.notice_days).toBe(30);
    expect(first!.methods).toContain("onsite");
    expect(first!.methods).toContain("soc2-substitution");
    expect(first!.confidentiality_required).toBe(true);
  });

  it("reads the notice period in the 'word (numeral)' form", () => {
    const a = extractAuditRights(
      buildTree([
        "Audit",
        "Customer may audit Processor once per year upon thirty (30) days' prior written notice.",
      ]),
    );
    expect(a[0]?.notice_days).toBe(30);
  });

  it("reads annual and twelve-month audit-frequency forms as once per year", () => {
    for (const text of [
      "Customer may audit Processor once annually upon reasonable notice.",
      "Customer may audit Processor no more than once in any twelve (12) month period.",
      "Customer may audit Processor no more than once per twelve-month period.",
      "Customer may audit Processor once every twelve months.",
      "Processor shall be audited annually by an independent auditor.",
    ]) {
      const a = extractAuditRights(buildTree(["Audit", text]));
      expect(a[0]?.frequency_per_year, text).toBe(1);
    }
    const twice = extractAuditRights(
      buildTree(["Audit", "Customer may audit Processor twice annually."]),
    );
    expect(twice[0]?.frequency_per_year).toBe(2);
  });
});

describe("v3 subprocessor extractor", () => {
  it("captures consent form, list location, notice, objection, flow-down", () => {
    const tree = buildTree([
      "Subprocessors",
      "Processor has general written authorization to engage sub-processors listed in Annex III, subject to 30 days' prior written notice; Controller may object on reasonable grounds, and Processor shall impose the same data protection obligations on sub-processors.",
    ]);
    const s = extractSubprocessorInventory(tree);
    expect(s).not.toBeNull();
    expect(s?.consent_form).toBe("general-written");
    expect(s?.list_location).toBe("annex");
    expect(s?.notice_days).toBe(30);
    expect(s?.objection_right).toBe(true);
    expect(s?.flow_down_required).toBe(true);
  });

  it("returns null when no subprocessor language appears", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    expect(extractSubprocessorInventory(tree)).toBeNull();
  });

  it("reads the notice period in the 'word (numeral)' form", () => {
    const s = extractSubprocessorInventory(
      buildTree([
        "Subprocessors",
        "Processor may engage sub-processors listed in Annex III, subject to thirty (30) days' prior written notice; Controller may object on reasonable grounds.",
      ]),
    );
    expect(s?.notice_days).toBe(30);
  });
});

describe("v3 insurance extractor", () => {
  it("captures lines, amounts, endorsements, AM Best, notice", () => {
    const tree = buildTree([
      "Insurance",
      "Vendor shall maintain commercial general liability insurance of $2,000,000 per occurrence and $4,000,000 aggregate, professional liability of $5,000,000, and cyber liability of $5,000,000. Each policy shall be written with an A.M. Best rating of A-VII or better. Required endorsements: CG 20 10 and CG 20 37. Vendor shall provide 30 days' prior written notice of cancellation.",
    ]);
    const sched = extractInsuranceSchedule(tree);
    const lines = new Set(sched.amounts.map((a) => a.line));
    expect(lines.has("commercial-general-liability")).toBe(true);
    expect(lines.has("professional-liability")).toBe(true);
    expect(lines.has("cyber-liability")).toBe(true);
    const cgl = sched.amounts.find(
      (a) => a.line === "commercial-general-liability" && a.per_occurrence_usd === 2_000_000,
    );
    expect(cgl).toBeDefined();
    const forms = sched.endorsements.map((e) => e.form_number);
    expect(forms).toContain("CG 20 10");
    expect(forms).toContain("CG 20 37");
    expect(sched.required_am_best_rating).toBe("A-VII");
    expect(sched.notice_of_cancellation_days).toBe(30);
  });

  it("reads the notice period in the 'word (numeral)' drafting form", () => {
    // "thirty (30) days' notice of cancellation" previously parsed to null.
    for (const [text, days] of [
      ["Insurer shall provide thirty (30) days' prior written notice of cancellation.", 30],
      ["Insurer shall give ten (10) days notice of cancellation for non-payment.", 10],
      ["Sixty (60) days' notice of non-renewal is required.", 60],
    ] as const) {
      const sched = extractInsuranceSchedule(buildTree(["Insurance", text]));
      expect(sched.notice_of_cancellation_days, text).toBe(days);
    }
  });

  it("reads limits stated with a currency code instead of a leading '$'", () => {
    for (const text of [
      "Vendor shall carry commercial general liability insurance of 1,000,000 USD per occurrence.",
      "Vendor shall carry commercial general liability insurance of USD 1,000,000 per occurrence.",
      "Vendor shall carry commercial general liability insurance of 1,000,000 dollars per occurrence.",
    ]) {
      const sched = extractInsuranceSchedule(buildTree(["Insurance", text]));
      const cgl = sched.amounts.find(
        (a) => a.line === "commercial-general-liability" && a.per_occurrence_usd === 1_000_000,
      );
      expect(cgl, text).toBeDefined();
    }
  });

  it("captures per-claim and each-accident limit qualifiers", () => {
    const sched = extractInsuranceSchedule(
      buildTree([
        "Insurance",
        "Consultant shall maintain professional liability (errors and omissions) insurance of $5,000,000 per claim.",
        "Consultant shall maintain employers' liability insurance of $1,000,000 each accident.",
      ]),
    );
    const eo = sched.amounts.find((a) => a.line === "professional-liability");
    expect(eo?.per_occurrence_usd).toBe(5_000_000);
    expect(eo?.raw_text).toContain("per claim");
    const el = sched.amounts.find((a) => a.line === "employers-liability");
    expect(el?.per_occurrence_usd).toBe(1_000_000);
    expect(el?.raw_text).toContain("each accident");
  });

  it("does not treat a bare number without a currency marker as a limit", () => {
    const sched = extractInsuranceSchedule(
      buildTree([
        "Insurance",
        "Under Section 25, the Contractor shall maintain Commercial General Liability insurance for a period of 3 years covering 2 locations.",
      ]),
    );
    expect(sched.amounts).toHaveLength(0);
  });
});

describe("v3 DTSA notice extractor", () => {
  it("detects substantively-complete notice", () => {
    const tree = buildTree([
      "DTSA",
      "Notice pursuant to the Defend Trade Secrets Act: An individual shall not be held criminally or civilly liable under any federal or state trade secret law for the disclosure of a trade secret that is made in confidence to a federal, state, or local government official or to an attorney solely for the purpose of reporting a suspected violation of law, or that is filed under seal in a lawsuit or other proceeding. This notice extends to employees, contractors, and consultants.",
    ]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(true);
    expect(d.covers_government_disclosure).toBe(true);
    expect(d.covers_under_seal).toBe(true);
    expect(d.covers_contractors).toBe(true);
    expect(d.substantively_complete).toBe(true);
  });

  it("detects incomplete notice", () => {
    const tree = buildTree([
      "DTSA",
      "Notice under 18 U.S.C. § 1833: employees may disclose trade secrets in some circumstances.",
    ]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(true);
    expect(d.substantively_complete).toBe(false);
  });

  it("returns absent when no notice present", () => {
    const tree = buildTree(["Body", "Effective Date: 2026-01-01."]);
    const d = extractDtsaNotice(tree);
    expect(d.present).toBe(false);
    expect(d.substantively_complete).toBe(false);
  });
});

describe("v3 aggregate extractAllV3", () => {
  it("produces a fully-populated V3ExtractedData and is deterministic", () => {
    const tree = buildTree([
      "Body",
      `"Processor" means the entity that processes Personal Data on behalf of the Controller. Module 2 of the Standard Contractual Clauses is incorporated. Encryption at rest is required. Notify Controller within 72 hours of any personal data breach upon discovery. Customer may audit Processor once per year upon 30 days' prior written notice.`,
    ]);
    const a = extractAllV3(tree);
    expect(a.roles.length).toBeGreaterThan(0);
    expect(a.transfer_mechanisms.length).toBeGreaterThan(0);
    expect(a.security_measures.length).toBeGreaterThan(0);
    expect(a.breach_timings.length).toBeGreaterThan(0);
    expect(a.audit_rights.length).toBeGreaterThan(0);
    expect(a.dtsa_notice.present).toBe(false);
    expect(JSON.stringify(a)).toEqual(JSON.stringify(extractAllV3(tree)));
  });
});

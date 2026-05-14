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

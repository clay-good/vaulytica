import { describe, expect, it } from "vitest";

import { ADDENDA_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const SEC: Playbook = { id: "vendor-security-addendum", version: "1.0.0" };
const AI: Playbook = { id: "ai-addendum", version: "1.0.0" };
const EULA: Playbook = { id: "eula", version: "1.0.0" };
const TOS: Playbook = { id: "saas-tos", version: "1.0.0" };
const PRIVACY: Playbook = { id: "privacy-policy-lint", version: "1.0.0" };
const SRC = { name: "addendum.docx", sha256: "0".repeat(64), size_bytes: 1 };

const withPb = (ctx: RuleContext, p: Playbook): RuleContext => ({ ...ctx, playbook: p });

const COMPLIANT_SECURITY: [string, ...string[]][] = [
  ["Vendor Security Addendum", "This Addendum sets out Vendor's security controls."],
  [
    "Access Control",
    "Vendor enforces multi-factor authentication (MFA) and least-privilege access control for all production systems.",
  ],
  [
    "Encryption",
    "All Customer Data is encrypted at rest using AES-256 and in transit using TLS 1.2 or TLS 1.3. FIPS 140-3 validated modules are used where applicable.",
  ],
  [
    "Vulnerability Management",
    "Vendor maintains a vulnerability management program with continuous scanning, patching, and configuration management.",
  ],
  [
    "Audit Rights",
    "Customer may audit Vendor's security controls annually with reasonable notice; in lieu of an audit Vendor will deliver a current SOC 2 Type II report renewed annually.",
  ],
  [
    "Incident Response",
    "Vendor shall notify Customer within 48 hours of confirming a security incident affecting Customer Data.",
  ],
  [
    "Vulnerability Disclosure",
    "Vendor maintains a coordinated vulnerability disclosure (VDP) program and acknowledges reports within 5 business days.",
  ],
  [
    "Secure Development",
    "Vendor operates a secure-development-lifecycle (SDLC) including SAST, DAST, and peer code review prior to production deployment.",
  ],
  [
    "Data Classification",
    "Customer Data containing personal data is classified as Confidential and receives the controls in Schedule A. Data classification is mapped to control tiers.",
  ],
  [
    "Penetration Testing",
    "Vendor commissions an independent penetration test annually and remediates critical findings within 30 days.",
  ],
];

const COMPLIANT_AI: [string, ...string[]][] = [
  ["AI Addendum", "This Addendum governs Generative AI features."],
  [
    "Definitions",
    "'Generative AI' means a foundation model that produces Output. 'Foundation Model' shall mean a large language model. 'Output' means the data produced by the model. 'Training Data' means data used to train models.",
  ],
  [
    "Permitted and Prohibited Uses",
    "Vendor will not train its models on Customer Data without an explicit opt-in by Customer. Opt-out is insufficient.",
  ],
  [
    "Transparency",
    "AI features in the Service are listed in Schedule B and are opt-in by default. The underlying foundation model is hosted by a third-party provider (OpenAI) or on-prem where indicated.",
  ],
  [
    "Intellectual Property",
    "As between the parties, Customer owns Outputs to the extent permitted by law; Vendor retains its models and tooling.",
  ],
  [
    "Warranties and Disclaimers",
    "Outputs are provided as-is and may contain inaccuracies (hallucination risk). Customer is responsible for human review prior to use for legal, medical, or financial decisions.",
  ],
  [
    "Subprocessors",
    "AI subprocessors include OpenAI, Anthropic, and Google Vertex; the current list is maintained at the URL in Schedule C.",
  ],
  [
    "Data Handling",
    "On termination, Vendor shall delete all fine-tuning data derived from Customer Data within 30 days; trained model weights derived from Customer Data shall be deleted within 90 days.",
  ],
];

describe("Addenda ruleset — registry contract", () => {
  it("exports exactly 20 rules with stable ADDENDA-NNN ids", () => {
    expect(ADDENDA_RULES.length).toBe(20);
    const ids = ADDENDA_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(20);
    for (const r of ADDENDA_RULES) {
      expect(r.id).toMatch(/^ADDENDA-\d{3}$/);
      expect(r.category).toBe("addenda");
      expect((r.applies_to_playbooks ?? []).length).toBeGreaterThan(0);
    }
  });

  it("does not run when no addenda playbook is active", async () => {
    const ctx = buildContext([
      "Agreement",
      "Generic services agreement, no addenda playbook active.",
    ]);
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
  });

  it("security rules don't fire on the AI playbook", async () => {
    const ctx = withPb(buildContext(["Some Addendum", "Generative AI features."]), AI);
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const securityIds = run.findings
      .map((f) => f.rule_id)
      .filter((id) => /ADDENDA-00[1-9]/.test(id));
    expect(securityIds).toHaveLength(0);
  });
});

describe("Addenda ruleset — compliant fixtures", () => {
  it("compliant Vendor Security Addendum produces zero critical findings", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SECURITY), SEC);
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });

  it("compliant AI Addendum produces zero critical findings", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_AI), AI);
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
  });
});

describe("Addenda ruleset — failure modes", () => {
  it("missing incident-response window fires ADDENDA-004", async () => {
    const ctx = withPb(
      buildContext([
        "Vendor Security Addendum",
        "Vendor will notify Customer of incidents promptly without undue delay. MFA in production. AES-256 at rest, TLS 1.3 in transit. SOC 2 Type II. SDLC with SAST and DAST. Annual penetration test. VDP. Data classification mapped to controls. Annual SOC 2 review.",
      ]),
      SEC,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "ADDENDA-004")).toBeTruthy();
  });

  it("training on customer data without opt-in fires ADDENDA-011 critical", async () => {
    const ctx = withPb(
      buildContext([
        "AI Addendum",
        "Vendor may use Customer Data to train its models on an opt-out basis. Hallucination disclaimer. Subprocessors: OpenAI.",
      ]),
      AI,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const finding = run.findings.find((f) => f.rule_id === "ADDENDA-011");
    expect(finding).toBeTruthy();
    expect(finding?.severity).toBe("critical");
  });

  it("missing AI definitions fires ADDENDA-010", async () => {
    const ctx = withPb(
      buildContext([
        "AI Addendum",
        "We use AI in the service. Customer owns outputs. Hallucination risk. Subprocessor: OpenAI. Fine-tuning data deleted on termination.",
      ]),
      AI,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "ADDENDA-010")).toBeTruthy();
  });

  it("missing FTC Click-to-Cancel alignment fires ADDENDA-019", async () => {
    const ctx = withPb(
      buildContext([
        "Terms of Service",
        "You may cancel by phone only by calling our office during business hours.",
      ]),
      TOS,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "ADDENDA-019")).toBeTruthy();
  });

  it("missing EU consumer-law minimums fires ADDENDA-018", async () => {
    const ctx = withPb(
      buildContext([
        "EULA",
        "Licensor grants Licensee a non-exclusive, non-transferable, revocable license to use the Software. Licensee may not reverse engineer, decompile, or sublicense the Software.",
      ]),
      EULA,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "ADDENDA-018")).toBeTruthy();
  });

  it("missing CCPA/GDPR/COPPA disclosures fires ADDENDA-020", async () => {
    const ctx = withPb(
      buildContext([
        "Privacy Policy",
        "We respect your privacy and use industry-standard security practices.",
      ]),
      PRIVACY,
    );
    const run = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "ADDENDA-020")).toBeTruthy();
  });
});

describe("Addenda ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_SECURITY), SEC);
    const a = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    const b = await runEngine({
      rules: ADDENDA_RULES,
      ctx,
      executed_at: "2026-05-13T00:00:00Z",
      source_file: SRC,
    });
    expect(a.result_hash).toBe(b.result_hash);
  });
});

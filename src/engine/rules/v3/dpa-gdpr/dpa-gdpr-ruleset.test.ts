import { describe, expect, it } from "vitest";

import { DPA_GDPR_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const DPA_PLAYBOOK: Playbook = { id: "dpa-controller-processor", version: "1.0.0" };
const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 1 };

function withDpa(ctx: RuleContext): RuleContext {
  return { ...ctx, playbook: DPA_PLAYBOOK };
}

/**
 * A near-fully-compliant DPA fixture. Each Art. 28(3) enumerated
 * obligation is represented; Annexes I, II, III are referenced; Article
 * 32 / 33 / 35 / 27 / 37 and Chapter V transfers are named.
 */
const COMPLIANT_DPA_SECTIONS: [string, ...string[]][] = [
  [
    "Data Processing Agreement",
    "Effective Date: January 1, 2026. This DPA is between Controller and Processor in accordance with Article 28 GDPR.",
  ],
  [
    "1. Definitions",
    "Personal Data, Data Subject, Processing, Controller and Processor shall have the meaning given in Article 4 GDPR. Personal Data Breach shall have the meaning given in Article 4(12) GDPR.",
  ],
  [
    "2. Scope and Subject-Matter of Processing",
    "The subject-matter of the processing, duration of processing, nature and purpose of the processing, type of personal data, categories of data subjects, and obligations and rights of the controller are described in Annex I.",
  ],
  [
    "3. Processing on Documented Instructions",
    "Processor shall process Personal Data only on documented instructions from Controller, including with regard to transfers to a third country.",
  ],
  [
    "4. Confidentiality of Personnel",
    "Processor shall ensure that persons authorised to process the Personal Data have committed themselves to confidentiality or are under an appropriate statutory obligation of confidentiality.",
  ],
  [
    "5. Security of Processing",
    "Processor shall implement appropriate technical and organisational measures pursuant to Article 32 GDPR, including pseudonymisation and encryption where appropriate, ongoing confidentiality, integrity, availability and resilience, ability to restore availability after an incident (backup and recovery), and a process for regularly testing the measures (penetration testing). The specific measures are set out in Annex II — Technical and Organisational Measures.",
  ],
  [
    "6. Sub-processors",
    "Processor shall not engage another processor without prior general written authorisation of Controller. Processor shall inform Controller of any intended changes concerning the addition or replacement of Sub-processors, giving Controller the opportunity to object. Where Processor engages a Sub-processor, the same data protection obligations shall be imposed on the Sub-processor by contract. The current list of Sub-processors is set out in Annex III. Processor shall maintain a record of Sub-processors available to Controller on request.",
  ],
  [
    "7. Data Subject Rights and Articles 32–36 Assistance",
    "Processor shall assist Controller, taking into account the nature of processing, in fulfilling its obligation to respond to requests for exercising Data Subject rights. Processor shall assist Controller in ensuring compliance with obligations pursuant to Articles 32 to 36, including security of processing, personal data breach notification, data protection impact assessment (Article 35 DPIA), and prior consultation. Processor shall also assist Controller with its records of processing activities (Article 30 RoPA).",
  ],
  [
    "8. Personal Data Breach Notification",
    "Processor shall notify Controller without undue delay after becoming aware of a Personal Data Breach. The notification shall describe the nature of the breach, the categories of data subjects, likely consequences, and measures taken to address the breach as required by Article 33(3).",
  ],
  [
    "9. Deletion or Return",
    "At the choice of Controller, Processor shall delete or return all Personal Data to Controller after the end of the provision of services relating to processing and delete existing copies, unless retention is required by Union or Member State law.",
  ],
  [
    "10. Audit and Compliance Demonstration",
    "Processor shall make available to Controller all information necessary to demonstrate compliance with Article 28 and shall allow for and contribute to audits, including inspections, conducted by Controller or a mandated auditor.",
  ],
  [
    "11. International Transfers",
    "Where transfers to a third country occur, the parties shall rely on the EU Standard Contractual Clauses (Commission Implementing Decision 2021/914) Module 2 and complete the relevant Annexes. The parties have conducted a Transfer Impact Assessment per Clause 14 and have considered local laws and practices. Onward transfers shall be subject to the same data protection obligations as set out in this Agreement (SCC Clause 8.8). Processor shall notify Controller of any legally-binding request from a public authority and challenge such requests where permitted.",
  ],
  [
    "12. EU Representative and Data Protection Officer",
    "Where required, Processor's EU representative under Article 27 and its Data Protection Officer under Article 37 are identified in Annex I.",
  ],
  [
    "13. Liability",
    "Liability between the parties shall be allocated in accordance with Article 82 GDPR.",
  ],
  [
    "14. Term and Termination",
    "Term of this Agreement is co-terminous with the underlying services agreement. Obligations applicable to retained Personal Data shall survive termination.",
  ],
  [
    "15. Governing Law and Notices",
    "This Agreement is in writing, including in electronic form. It shall be governed by the laws of Ireland. Notices shall be given in writing to the addresses listed below. By: ____________ Name: Jane Doe Title: Chief Privacy Officer Date: 2026-01-01.",
  ],
];

describe("DPA-GDPR ruleset — registry contract", () => {
  it("exports exactly 55 rules with stable DPA-NNN ids", () => {
    expect(DPA_GDPR_RULES.length).toBe(55);
    const ids = DPA_GDPR_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(55);
    for (const r of DPA_GDPR_RULES) {
      expect(r.id).toMatch(/^DPA-\d{3}$/);
      expect(r.applies_to_playbooks).toContain("dpa-controller-processor");
      expect(r.category).toBe("dpa-gdpr");
      expect(r.dkb_citations.length).toBeGreaterThan(0);
    }
  });

  it("does not run when the playbook is not a DPA playbook", async () => {
    const ctx = buildContext(["Agreement", "Generic services agreement with no DPA terminology."]);
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings).toHaveLength(0);
    expect(run.execution_log.every((e) => e.fired === false)).toBe(true);
  });
});

describe("DPA-GDPR ruleset — compliant fixture", () => {
  it("produces zero critical findings against the canonical compliant DPA", async () => {
    const ctx = withDpa(buildContext(...COMPLIANT_DPA_SECTIONS));
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals).toHaveLength(0);
    expect(run.execution_log.filter((e) => e.fired).length).toBeLessThanOrEqual(5);
  });
});

describe("DPA-GDPR ruleset — failure modes", () => {
  it("missing breach notification fires DPA-024", async () => {
    const ctx = withDpa(
      buildContext([
        "DPA",
        "This DPA references personal data and controller and processor but says nothing about breaches.",
      ]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-024")).toBeTruthy();
  });

  it("processor-chooses-delete-or-return fires DPA-035", async () => {
    const ctx = withDpa(
      buildContext(["DPA", "Processor may choose to delete personal data at the end of services."]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-035")).toBeTruthy();
  });

  it("SOC 2 in lieu of audit fires DPA-036", async () => {
    const ctx = withDpa(
      buildContext([
        "DPA",
        "SOC 2 reports shall be the sole means of compliance demonstration in lieu of any audit. Processor shall notify Controller of Personal Data Breaches without undue delay.",
      ]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-036")).toBeTruthy();
  });

  it("controller indemnifies processor for GDPR fines fires DPA-048", async () => {
    const ctx = withDpa(
      buildContext([
        "DPA",
        "Controller shall indemnify Processor for any GDPR fine arising from processing of Personal Data.",
      ]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-048")).toBeTruthy();
  });

  it("'industry-standard security' without annex fires DPA-023", async () => {
    const ctx = withDpa(
      buildContext([
        "DPA",
        "Processor implements industry-standard security to protect Personal Data.",
      ]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-023")).toBeTruthy();
  });

  it("document with no 'personal data' reference fires DPA-050", async () => {
    const ctx = withDpa(
      buildContext([
        "Agreement",
        "Generic services agreement with no privacy terminology whatsoever.",
      ]),
    );
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(run.findings.find((f) => f.rule_id === "DPA-050")).toBeTruthy();
  });
});

describe("DPA-GDPR ruleset — determinism", () => {
  it("two runs over the same input produce the same result_hash", async () => {
    const ctx = withDpa(buildContext(...COMPLIANT_DPA_SECTIONS));
    const a = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    const b = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    expect(a.result_hash).toBe(b.result_hash);
  });
});

describe("DPA-GDPR ruleset — SCC Module 2 playbook scope", () => {
  it("rules also run under the scc-module-2 playbook", async () => {
    const ctx: RuleContext = {
      ...buildContext(...COMPLIANT_DPA_SECTIONS),
      playbook: { id: "scc-module-2", version: "1.0.0" },
    };
    const run = await runEngine({
      rules: DPA_GDPR_RULES,
      ctx,
      executed_at: "2026-05-12T00:00:00Z",
      source_file: SRC,
    });
    // At least one rule should have fired (non-skipped) since playbook matches.
    expect(run.execution_log.filter((e) => e.elapsed_ms === 0).length).toBeLessThan(55);
  });
});

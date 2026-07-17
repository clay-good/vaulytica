/**
 * CLI/API ↔ pipeline parity (spec-v8 §22, Step 143).
 *
 * The whole point of the CLI is that it is the SAME engine as the tab. The
 * v7 parity test (`tools/accuracy/parity.test.ts`) proves `runReport` ≡
 * `runDocument` byte-for-byte; this test extends that chain to the CLI
 * entry point: `analyzeText` (and `analyzeFile` over a temp file) must
 * produce the identical `EngineRun` — same `result_hash`, same findings,
 * same playbook — as the parity-proven `runDocument`.
 *
 * So "the number on your CI dashboard describes shipped behavior" stays
 * true through the headless surface too.
 */

import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { loadAccuracyDeps, runDocument } from "../accuracy/pipeline.js";
import { analyzeText, analyzeFile, runProductionQa } from "./api.js";

const NDA = [
  "Mutual Non-Disclosure Agreement",
  "",
  'This Mutual Non-Disclosure Agreement is between Acme Corp., a Delaware corporation ("Disclosing Party"), and Globex Industries, Inc., a New York corporation ("Receiving Party"), effective 2026-01-01.',
  "",
  '"Confidential Information" means any non-public information disclosed by either party.',
  "",
  "Each party shall protect the Confidential Information for a period of three (3) years. This Agreement shall be governed by the laws of the State of Delaware.",
].join("\n");

describe("CLI/API parity with the parity-proven pipeline (spec-v8 Step 143)", () => {
  it("analyzeText produces a byte-identical EngineRun to runDocument", async () => {
    const deps = await loadAccuracyDeps();
    const direct = await runDocument(NDA, "nda.txt", undefined, deps);
    const api = await analyzeText(NDA, "nda.txt", { deps });

    expect(api.run.playbook_id).toBe(direct.run.playbook_id);
    expect(api.run.result_hash).toBe(direct.run.result_hash);
    expect(api.run.findings).toEqual(direct.run.findings);
  });

  it("analyzeFile over a .txt matches runDocument and exposes the ingest result", async () => {
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-"));
    try {
      const path = join(dir, "nda.txt");
      await writeFile(path, NDA);
      const fromFile = await analyzeFile(path, { deps });
      const direct = await runDocument(NDA, "nda.txt", undefined, deps);

      expect(fromFile.run.result_hash).toBe(direct.run.result_hash);
      expect(fromFile.run.findings).toEqual(direct.run.findings);
      expect(fromFile.ingest.sha256).toBe(direct.run.source_file.sha256);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("auto-resolves size bands from the document's labeled deal value (add-negotiation-ladder-playbooks)", async () => {
    const deps = await loadAccuracyDeps();
    const num = (value: number) => ({
      kind: "numeric_threshold" as const,
      metric: "liability_cap_multiple" as const,
      comparator: "gte" as const,
      value,
    });
    const playbook = {
      schema_version: "1.0" as const,
      catalog_version: "0.1.0",
      id: "banded",
      name: "Banded",
      description: "cap floor scales with the deal",
      mode: "replace" as const,
      negotiation_positions: [
        {
          dimension: "Liability cap",
          ideal: num(3),
          acceptable: num(2),
          size_bands: [
            { min_value: 1_000_000, label: "1M-plus", ideal: num(12), acceptable: num(6) },
          ],
        },
      ],
    };
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-"));
    try {
      // Labeled total → the ≥$1M band applies (floor 6): an 8x cap is acceptable.
      const labeled = join(dir, "labeled.txt");
      await writeFile(
        labeled,
        "MSA\nThe total contract value is $5,000,000.\nThe liability cap is 8x fees.\n",
      );
      const r1 = await analyzeFile(labeled, { deps, posture: true, customPlaybook: playbook });
      const p1 = r1.negotiation_posture!.positions[0]!;
      expect(p1.tier).toBe("acceptable");
      expect(p1.size_band).toContain("1M-plus");
      expect(p1.size_band).toContain("auto-detected");

      // No labeled total → base default (floor 2): the same 8x cap is ideal.
      const unlabeled = join(dir, "unlabeled.txt");
      await writeFile(unlabeled, "MSA\nThe liability cap is 8x fees.\n");
      const r2 = await analyzeFile(unlabeled, { deps, posture: true, customPlaybook: playbook });
      const p2 = r2.negotiation_posture!.positions[0]!;
      expect(p2.tier).toBe("ideal");
      expect(p2.size_band).toBe("default (no --deal-value)");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("forcing a playbook overrides the auto-match", async () => {
    const deps = await loadAccuracyDeps();
    const forced = await analyzeText(NDA, "nda.txt", {
      deps,
      playbookId: deps.launchPlaybooks[0]!.id,
    });
    expect(forced.run.playbook_id).toBe(deps.launchPlaybooks[0]!.id);
  });

  it("--court activates the filing pack on a brief and stays dormant without it", async () => {
    const { getCourtProfile } = await import("../../src/filing/court-profile.js");
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-filing-"));
    try {
      const brief = [
        "IN THE UNITED STATES COURT OF APPEALS FOR THE NINTH CIRCUIT",
        "No. 24-1. Acme v. Globex.",
        "BRIEF FOR APPELLANT",
        "TABLE OF CONTENTS",
        "TABLE OF AUTHORITIES",
        "STATEMENT OF THE ISSUES",
        "SUMMARY OF THE ARGUMENT",
        "ARGUMENT. The standard of review is de novo. Respectfully submitted.",
      ].join("\n\n");
      const path = join(dir, "brief.txt");
      await writeFile(path, brief);

      const dormant = await analyzeFile(path, { deps });
      expect(dormant.run.playbook_id).toBe("appellate-brief");
      expect(dormant.run.filing_profile).toBeUndefined();
      expect(dormant.run.findings.some((f) => f.rule_id.startsWith("FILE-"))).toBe(false);

      const active = await analyzeFile(path, {
        deps,
        filing: { profile: getCourtProfile("frap-default")!, brief_kind: "principal" },
      });
      expect(active.run.filing_profile?.id).toBe("frap-default");
      expect(active.run.findings.some((f) => f.rule_id.startsWith("FILE-"))).toBe(true);
      // The filing pack is inside the hashed run, so the two receipts differ.
      expect(active.run.result_hash).not.toBe(dormant.run.result_hash);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("--deadline-profile resolves a business-days deadline the register otherwise punts", async () => {
    const { getDeadlineProfile } = await import("../../src/deadlines/profile.js");
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-ddl-"));
    try {
      const contract = [
        '"Effective Date" means July 1, 2026.',
        "The breaching party shall cure within 10 business days after the Effective Date.",
      ].join("\n\n");
      const path = join(dir, "contract.txt");
      await writeFile(path, contract);

      const plain = await analyzeFile(path, { deps, criticalDates: true });
      const punted = plain.critical_dates!.register.find((r) => r.anchor === "Effective Date")!;
      expect(punted.resolved).toBe(false); // business-days, no profile

      const resolved = await analyzeFile(path, {
        deps,
        deadline: { profile: getDeadlineProfile("frcp-6")! },
      });
      const row = resolved.critical_dates!.register.find((r) => r.anchor === "Effective Date")!;
      expect(row.resolved).toBe(true);
      expect(row.deadline_profile_id).toBe("frcp-6");
      // Default register hash is unchanged by adding the profile only where it applies.
      expect(resolved.critical_dates!.critical_dates_hash).not.toBe(
        plain.critical_dates!.critical_dates_hash,
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("--court on a non-filing document leaves the hash byte-identical", async () => {
    const { getCourtProfile } = await import("../../src/filing/court-profile.js");
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-filing-nda-"));
    try {
      const path = join(dir, "nda.txt");
      await writeFile(path, NDA);
      const plain = await analyzeFile(path, { deps });
      const withCourt = await analyzeFile(path, {
        deps,
        filing: { profile: getCourtProfile("frap-default")!, brief_kind: "principal" },
      });
      expect(withCourt.run.result_hash).toBe(plain.run.result_hash);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("evaluates negotiation posture from a custom playbook (spec-v10 Step 172)", async () => {
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-"));
    try {
      const path = join(dir, "nda.txt");
      await writeFile(path, NDA);
      const customPlaybook = {
        schema_version: "1.0" as const,
        catalog_version: "0.1.0",
        id: "acme",
        name: "Acme",
        description: "Acme negotiation positions.",
        negotiation_positions: [
          {
            dimension: "Governing law",
            ideal: { kind: "governing_law_in" as const, allowed: ["Delaware"] },
            acceptable: { kind: "governing_law_in" as const, allowed: ["Delaware", "New York"] },
            guidance: { ideal: "Delaware — hold." },
          },
        ],
      };
      const r = await analyzeFile(path, { deps, customPlaybook, posture: true });
      expect(r.negotiation_posture).toBeDefined();
      const row = r.negotiation_posture!.positions.find((p) => p.dimension === "Governing law");
      expect(row?.tier).toBe("ideal"); // the NDA is governed by Delaware
      expect(r.negotiation_posture!.counts.ideal).toBe(1);

      // Without --posture, no posture is computed.
      const noPosture = await analyzeFile(path, { deps, customPlaybook });
      expect(noPosture.negotiation_posture).toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("--regime activates the PNOT pack on a privacy notice and stays dormant without it", async () => {
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-pnot-"));
    try {
      const notice = [
        "PRIVACY POLICY",
        "Last updated: January 1, 2026.",
        "Categories of Personal Information We Collect. We collect identifiers.",
        "Your Privacy Rights. Right to know, delete, opt-out, and correct.",
        "Do Not Sell or Share My Personal Information. We do not sell.",
        "Contact Us. privacy@example.com.",
      ].join("\n\n");
      const path = join(dir, "privacy.txt");
      await writeFile(path, notice);

      const dormant = await analyzeFile(path, { deps });
      expect(dormant.run.playbook_id).toBe("privacy-notice-us");
      expect(dormant.run.asserted_regimes).toBeUndefined();
      expect(dormant.run.findings.some((f) => f.rule_id.startsWith("PNOT-"))).toBe(false);

      const active = await analyzeFile(path, { deps, regimes: ["ccpa"] });
      expect(active.run.asserted_regimes).toEqual(["ccpa"]);
      expect(active.run.findings.some((f) => f.rule_id.startsWith("PNOT-CCPA-"))).toBe(true);
      expect(active.run.result_hash).not.toBe(dormant.run.result_hash);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("--estate-checks activates the EST pack on a will and stays dormant/hash-stable without it", async () => {
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-est-"));
    try {
      const will = [
        "LAST WILL AND TESTAMENT OF JOHN DOE",
        "I, John Doe, being of sound mind, declare this to be my last will and testament, and I revoke all prior wills and codicils.",
        "ARTICLE I. I appoint Jane Doe as Executor of my estate.",
        "ARTICLE II. Residuary Estate. I give the rest, residue and remainder of my estate as follows: 40% to my son Alan, and 50% to my daughter Beth.",
        "ARTICLE III. I direct that my just debts be paid. I make the following specific bequests to my devisees.",
        "IN WITNESS WHEREOF, I have signed my name to this my last will and testament.",
        "_______________________ Testator",
      ].join("\n\n");
      const path = join(dir, "will.txt");
      await writeFile(path, will);

      const dormant = await analyzeFile(path, { deps });
      expect(dormant.run.playbook_id).toBe("last-will-and-testament");
      expect(dormant.run.estate_checks_asserted).toBeUndefined();
      expect(dormant.run.findings.some((f) => /^EST-(1|2|3)\d\d/.test(f.rule_id))).toBe(false);

      const active = await analyzeFile(path, { deps, estateChecks: true });
      expect(active.run.estate_checks_asserted).toBe(true);
      // EST-201 catches the 40%+50%=90% residue split.
      expect(active.run.findings.some((f) => f.rule_id === "EST-201")).toBe(true);
      expect(active.run.result_hash).not.toBe(dormant.run.result_hash);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("runProductionQa reconciles a directory production set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-prod-"));
    try {
      await writeFile(join(dir, "ACME_000001.pdf"), "doc");
      await writeFile(join(dir, "ACME_000002.pdf"), "doc");
      await writeFile(join(dir, "ACME_000004.pdf"), "doc"); // gap at 000003
      await writeFile(
        join(dir, "privlog.csv"),
        "BegBates,EndBates,Privilege,Description\nACME_000002,ACME_000002,Attorney-Client,Email\n",
      );
      const report = await runProductionQa(dir);
      expect(report.member_count).toBe(4);
      expect(report.log_present).toBe(true);
      const codes = report.findings.map((f) => f.code);
      expect(codes).toContain("PROD-001"); // Bates gap
      expect(codes).toContain("PROD-010"); // withheld-but-produced
      expect(report.production_qa_hash).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
    // runProductionQa runs a per-member HANDOFF sweep (ingest + scanDelivery of
    // each .pdf/.docx member); pdfjs worker init is far slower on cold Windows
    // CI than locally, so this multi-member ingest needs a generous timeout.
  }, 30000);
});

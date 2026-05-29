/**
 * Custom-playbook end-to-end harness (spec-v6 Part II, Step 93).
 *
 * Runs every per-use-case contract fixture through the SAME pipeline the
 * live site uses (ingest → extract → engine via `runFixture`), then enforces
 * a use-case-appropriate **custom playbook** on it via `runCustomPlaybook`.
 * This is the honest equivalent of "drop a real doc and run it against your
 * own standard" — real pipeline, repo corpus (network egress is unavailable
 * in this environment, so we use the committed realistic fixtures rather than
 * downloaded filings).
 *
 * The test logs a readable per-fixture report and asserts aggregate
 * invariants (determinism, provenance, that the playbooks actually catch
 * real violations and honestly skip unevaluable metrics).
 */

import { describe, expect, it } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runFixture, listFixtures } from "./_pipeline-helpers.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import {
  runCustomPlaybook,
  validateCustomPlaybook,
  type CustomPlaybook,
  type CustomPlaybookRun,
} from "../../src/playbooks/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

function makePlaybook(raw: Record<string, unknown>): CustomPlaybook {
  const v = validateCustomPlaybook({
    schema_version: "1.0",
    catalog_version: "0.1.0",
    ...raw,
  });
  if (!v.ok) throw new Error(`invalid harness playbook ${String(raw.id)}: ${v.errors.join("; ")}`);
  return v.playbook;
}

// One custom playbook per use case — a team's own positions, exercising all
// six predicate kinds across the set.
const NDA = makePlaybook({
  id: "acme-nda-standard",
  name: "Acme NDA Standard",
  description: "Acme's positions for inbound NDAs.",
  custom_rules: [
    { id: "NDA-CI", title: "Confidential Information must be defined", description: "A defined Confidential Information term is required.", severity: "critical", assert: { kind: "defined_term_present", term: "Confidential Information" }, citation: { reference: "Acme NDA Policy §1" } },
    { id: "NDA-NO-RESIDUALS", title: "No residuals clause", description: "We strike residual-knowledge clauses.", severity: "warning", assert: { kind: "clause_absent", pattern: "residual" } },
    { id: "NDA-GOVLAW", title: "Governing law must be DE or NY", description: "We accept only Delaware or New York governing law.", severity: "warning", assert: { kind: "governing_law_in", allowed: ["Delaware", "New York"] } },
    { id: "NDA-REFS", title: "Cross-references must resolve", description: "Dangling internal references are unacceptable.", severity: "info", assert: { kind: "cross_ref_resolves" } },
  ],
});

const SAAS = makePlaybook({
  id: "acme-saas-buyer",
  name: "Acme SaaS Buyer Standard",
  description: "Acme's positions for inbound SaaS agreements.",
  custom_rules: [
    { id: "SAAS-LOL", title: "Limitation of Liability clause required", description: "A limitation-of-liability clause must be present.", severity: "critical", assert: { kind: "clause_present", pattern: "limitation of liability" }, citation: { reference: "Acme Contracting Policy §4" } },
    { id: "SAAS-CAP", title: "Liability cap at least 12x fees", description: "We do not accept a cap below 12x fees.", severity: "critical", assert: { kind: "numeric_threshold", metric: "liability_cap_multiple", comparator: "gte", value: 12 } },
    { id: "SAAS-NOTICE", title: "Termination notice at most 30 days", description: "We do not accept a termination notice longer than 30 days.", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
    { id: "SAAS-GOVLAW", title: "Governing law must be DE or NY", description: "We accept only Delaware or New York governing law.", severity: "warning", assert: { kind: "governing_law_in", allowed: ["Delaware", "New York"] } },
  ],
});

const VENDOR = makePlaybook({
  id: "acme-vendor-mgmt",
  name: "Acme Vendor Management Standard",
  description: "Acme's positions for MSAs, SOWs, and consulting/contractor agreements.",
  custom_rules: [
    { id: "VND-PAY", title: "Payment terms at least Net 30", description: "We do not accept payment terms shorter than Net 30.", severity: "warning", assert: { kind: "numeric_threshold", metric: "payment_term_days", comparator: "gte", value: 30 } },
    { id: "VND-NOTICE", title: "Termination notice at most 30 days", description: "We do not accept a termination notice longer than 30 days.", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
    { id: "VND-GOVLAW", title: "Governing law must be DE or NY", description: "We accept only Delaware or New York governing law.", severity: "warning", assert: { kind: "governing_law_in", allowed: ["Delaware", "New York"] }, citation: { reference: "Acme Vendor Policy §2" } },
    { id: "VND-REFS", title: "Cross-references must resolve", description: "Dangling internal references are unacceptable.", severity: "info", assert: { kind: "cross_ref_resolves" } },
  ],
});

const EMPLOYMENT = makePlaybook({
  id: "acme-employment",
  name: "Acme Employment Standard",
  description: "Acme's positions for employment agreements.",
  custom_rules: [
    { id: "EMP-GOVLAW", title: "Governing law must be CA", description: "Employment agreements must be governed by California law.", severity: "critical", assert: { kind: "governing_law_in", allowed: ["California"] }, citation: { reference: "Acme Employment Policy §1" } },
    { id: "EMP-NOTICE", title: "Notice period at most 30 days", description: "We do not accept a notice period longer than 30 days.", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
  ],
});

const LEASE = makePlaybook({
  id: "acme-lease",
  name: "Acme Lease Standard",
  description: "Acme's positions for commercial/residential leases.",
  custom_rules: [
    { id: "LEASE-NOTICE", title: "Notice period at most 30 days", description: "We do not accept a notice period longer than 30 days.", severity: "warning", assert: { kind: "numeric_threshold", metric: "notice_period_days", comparator: "lte", value: 30 } },
    { id: "LEASE-GOVLAW", title: "Governing law must be DE or NY", description: "We accept only Delaware or New York governing law.", severity: "info", assert: { kind: "governing_law_in", allowed: ["Delaware", "New York"] } },
  ],
});

function playbookFor(name: string): CustomPlaybook {
  if (name.includes("nda")) return NDA;
  if (name.includes("saas")) return SAAS;
  if (name.includes("employment")) return EMPLOYMENT;
  if (name.includes("lease")) return LEASE;
  return VENDOR; // msa / sow / consulting / contractor and any other
}

type Row = { fixture: string; playbook: string; run: CustomPlaybookRun };

describe("custom-playbook end-to-end harness over the fixture corpus", () => {
  it("enforces a per-use-case custom playbook on every fixture and reports findings", async () => {
    const dkb = loadStarterDkbSync();
    const fixtures = (await listFixtures(CONTRACTS)).filter((f) => f.endsWith(".docx"));
    expect(fixtures.length).toBeGreaterThan(0);

    const rows: Row[] = [];
    for (const fixture of fixtures) {
      const { ingest } = await runFixture(join(CONTRACTS, fixture));
      const extracted = extractAll(ingest.tree, {
        classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
      });
      const playbook = playbookFor(fixture);
      const run = await runCustomPlaybook(playbook, { tree: ingest.tree, extracted });
      rows.push({ fixture, playbook: playbook.id, run });

      // Determinism: a second run is byte-identical.
      const again = await runCustomPlaybook(playbook, { tree: ingest.tree, extracted });
      expect(again.result_hash).toBe(run.result_hash);
    }

    // ---- human-readable report --------------------------------------------
    const lines: string[] = ["", "Custom-playbook enforcement over the fixture corpus:", ""];
    let totalFindings = 0;
    let totalUneval = 0;
    let govLawFindings = 0;
    let uncitedFindings = 0;
    for (const { fixture, playbook, run } of rows) {
      totalFindings += run.findings.length;
      totalUneval += run.unevaluable.length;
      govLawFindings += run.findings.filter((f) => f.rule_id.toLowerCase().includes("govlaw")).length;
      uncitedFindings += run.findings.filter((f) => f.citation_provenance === "uncited (team policy)").length;
      const sev = { critical: 0, warning: 0, info: 0 };
      for (const f of run.findings) sev[f.severity]++;
      lines.push(
        `• ${fixture}  [${playbook}]  → ${run.findings.length} finding(s) ` +
          `(${sev.critical}C/${sev.warning}W/${sev.info}I), ${run.unevaluable.length} unevaluable`,
      );
      for (const f of run.findings) {
        lines.push(`    - [${f.severity}] ${f.rule_id}: ${f.title} (${f.citation_provenance})`);
      }
      for (const u of run.unevaluable) {
        lines.push(`    ~ ${u.rule_id}: not evaluated — ${u.reason}`);
      }
    }
    lines.push("");
    lines.push(
      `Totals: ${totalFindings} findings, ${totalUneval} unevaluable, ` +
        `${govLawFindings} governing-law violations, ${uncitedFindings} uncited findings, across ${rows.length} fixtures.`,
    );
    // eslint-disable-next-line no-console
    console.log(lines.join("\n"));

    // ---- aggregate invariants ---------------------------------------------
    // Every finding is provenance-marked as custom-playbook.
    for (const { run } of rows) {
      for (const f of run.findings) {
        expect(f.source).toBe("custom-playbook");
        expect(["cited", "uncited (team policy)"]).toContain(f.citation_provenance);
      }
    }
    // The playbooks actually catch real violations end-to-end.
    expect(totalFindings).toBeGreaterThan(0);
    // At least one fixture's governing law falls outside an allowed set.
    expect(govLawFindings).toBeGreaterThan(0);
    // The liability_cap_multiple metric is honestly reported unevaluable on
    // fixtures that never state a cap multiple (no fabricated answer).
    expect(totalUneval).toBeGreaterThan(0);
  });
});

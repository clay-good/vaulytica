import { describe, expect, it } from "vitest";
import { TRUST_ESTATE_RULES } from "./trust-estate/rules.js";
import { REAL_ESTATE_RULES } from "./real-estate/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import { runEngine } from "../../runner.js";
import type { Playbook, RuleContext } from "../../finding.js";

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };
const WILL_PB: Playbook = { id: "last-will-and-testament", version: "1.0.0" };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("probe EST-006 childless testator", () => {
  it("does EST-006 fire on a compliant childless will", async () => {
    const ctx = withPb(
      buildContext([
        "Last Will and Testament",
        "I, John Smith, the undersigned, a resident of the State of Texas, being of sound mind, declare this to be my Last Will and Testament.",
        "I revoke all prior wills and codicils.",
        "I nominate my spouse, Jane Smith, as Executor, and if she is unable to serve, I nominate my brother Robert Smith as successor Executor.",
        "No bond shall be required of any Executor serving under this will.",
        "I give the residue of my estate to my spouse, Jane Smith.",
        "I have no children. This will was signed by the testator and attested by two witnesses and notarized.",
      ]),
      WILL_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    const est006 = run.findings.filter((f) => f.rule_id === "EST-006");
    console.log("EST-006 findings:", JSON.stringify(est006, null, 2));
    console.log(
      "all findings:",
      run.findings.map((f) => f.rule_id),
    );
  });
});


const MSA_PB: Playbook = { id: "family-msa", version: "1.0.0" };

describe("probe EST-056 childless MSA", () => {
  it("does EST-056 fire on a compliant childless MSA", async () => {
    const ctx = withPb(
      buildContext([
        "Marital Settlement Agreement",
        "This Marital Settlement Agreement is entered into by Husband and Wife, who have no children together and none are expected.",
        "Date of separation: January 1, 2026.",
        "Division of Property: the parties divide their real property, retirement accounts, and debts as set forth in Exhibit A.",
        "Spousal Support: Husband shall pay Wife $2,000 per month for 36 months, non-modifiable.",
        "Tax Provisions: the parties shall file separately post-TCJA and address dependency exemptions as needed.",
        "Retirement Plan Division: the parties shall obtain a QDRO to divide the 401(k) plan.",
        "Incorporation: this Agreement shall be incorporated but not merged into the judgment of divorce, and is signed and notarized by both parties.",
      ]),
      MSA_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    console.log("all findings:", run.findings.map((f) => `${f.rule_id}:${f.severity}`));
  });
});

import { describe, expect, it } from "vitest";

import { MSA_DEEP_RULES } from "./msa-deep/rules.js";
import { ADDENDA_RULES } from "./addenda/rules.js";
import { NDA_DEEP_RULES } from "./nda-deep/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";

const CLEAN_MSA =
  "Master Services Agreement. Supplier shall indemnify, defend and hold Customer harmless from any third-party claim that the Services infringe any intellectual property right, and shall follow the indemnification procedure of prompt notice, control of defense, and no settlement without consent. " +
  "Service Levels. The Service Level Agreement (SLA) attached as Exhibit A sets the committed service levels and credits. " +
  "Termination. Either party may terminate this Agreement for material breach on thirty days' notice and an opportunity to cure, and either party may terminate for bankruptcy or insolvency. " +
  "Wind-down. Supplier shall provide a ninety-day wind-down period. Data Return. On termination Supplier shall permit export of Customer data and shall provide data return and portability in a machine-readable format.";

const CLEAN_ADDENDA =
  "AI Addendum. AI definitions: Model, Output, Input. Customer data is not used for training without opt-in. " +
  "AI transparency: features, default state, and hosting are described. IP ownership of AI Outputs vests in Customer. " +
  "Provider disclaims warranties as to Output accuracy and Customer shall apply human review. " +
  "AI Subprocessors. Provider discloses each AI subprocessor and model provider on its trust page and notifies Customer of changes. " +
  "Deletion. Provider shall perform deletion of fine-tuning data derived from Customer data on termination. " +
  "License grant scope and prohibited uses are stated. EU consumer-law minimums apply. FTC click-to-cancel alignment. Required privacy disclosures are provided.";

const CLEAN_NDA =
  "Mutual Nondisclosure Agreement. Notice of Immunity. Pursuant to the Defend Trade Secrets Act, 18 U.S.C. § 1833(b), an individual shall not be held criminally or civilly liable for disclosing a trade secret in confidence to a government official solely for the purpose of reporting a suspected violation of law; this whistleblower immunity applies to filings made under seal. " +
  "Confidentiality Term. The obligations continue for five years, and trade secrets remain protected for so long as they remain trade secrets. " +
  "Confidential Information is defined below. Exclusions: publicly available information, information previously known to the recipient, information lawfully obtained from a third party, and independently developed information. " +
  "Permitted use is to evaluate the Purpose. Return or Destroy. On request Recipient shall return or destroy all copies of Confidential Information and certify destruction of confidential material.";

const CASES: [Rule[], string, string, boolean, string][] = [
  [
    MSA_DEEP_RULES,
    "MSA-001",
    CLEAN_MSA,
    true,
    "Supplier does not indemnify Customer for any third-party IP infringement claim.",
  ],
  [
    MSA_DEEP_RULES,
    "MSA-011",
    CLEAN_MSA,
    true,
    "This Agreement does not allocate ownership of background IP or foreground IP created hereunder; ownership remains unresolved.",
  ],
  [
    // A well-drafted MSA says the agreement "does not assign ownership of
    // background IP" — each party keeps its own. Only a refusal to RESOLVE
    // ownership is a denial, so this decoy must stay silent.
    MSA_DEEP_RULES,
    "",
    CLEAN_MSA,
    false,
    "Each party retains its background IP and grants a licence; this Agreement does not assign ownership of background IP to the other party.",
  ],
  [
    MSA_DEEP_RULES,
    "MSA-016",
    CLEAN_MSA,
    true,
    "No service levels apply and Supplier provides no SLA.",
  ],
  [MSA_DEEP_RULES, "MSA-018", CLEAN_MSA, true, "Customer may not terminate for material breach."],
  [
    MSA_DEEP_RULES,
    "MSA-021",
    CLEAN_MSA,
    true,
    "Supplier does not provide data return or portability on termination.",
  ],
  [MSA_DEEP_RULES, "", CLEAN_MSA, false, ""],
  [
    MSA_DEEP_RULES,
    "",
    CLEAN_MSA,
    false,
    "The IP indemnity does not extend to claims arising from Customer's modifications.",
  ],
  [
    MSA_DEEP_RULES,
    "",
    CLEAN_MSA,
    false,
    "Customer may not terminate for material breach without first providing notice and a cure period.",
  ],
  [
    MSA_DEEP_RULES,
    "",
    CLEAN_MSA,
    false,
    "Nothing in this Section limits Customer's data return rights.",
  ],
  [
    ADDENDA_RULES,
    "ADDENDA-015",
    CLEAN_ADDENDA,
    true,
    "Provider does not disclose its AI subprocessors.",
  ],
  [
    ADDENDA_RULES,
    "ADDENDA-016",
    CLEAN_ADDENDA,
    true,
    "Fine-tuning data is not deleted on termination.",
  ],
  [ADDENDA_RULES, "", CLEAN_ADDENDA, false, ""],
  [
    ADDENDA_RULES,
    "",
    CLEAN_ADDENDA,
    false,
    "This Section does not apply to subprocessors that never receive Customer data.",
  ],
  [
    ADDENDA_RULES,
    "",
    CLEAN_ADDENDA,
    false,
    "Provider may not engage an AI subprocessor without notifying Customer.",
  ],
  [
    NDA_DEEP_RULES,
    "NDA-D-001",
    CLEAN_NDA,
    true,
    "This Agreement provides no whistleblower immunity.",
  ],
  [
    NDA_DEEP_RULES,
    "NDA-D-013",
    CLEAN_NDA,
    true,
    "Recipient is not required to return or destroy Confidential Information.",
  ],
  [NDA_DEEP_RULES, "", CLEAN_NDA, false, ""],
  [
    NDA_DEEP_RULES,
    "",
    CLEAN_NDA,
    false,
    "Nothing in this Agreement limits the whistleblower immunity conferred by 18 U.S.C. § 1833(b).",
  ],
  [
    NDA_DEEP_RULES,
    "",
    CLEAN_NDA,
    false,
    "Recipient may not retain Confidential Information without returning or destroying all copies.",
  ],
];

const denied = (rules: Rule[], text: string): string[] =>
  rules
    .filter((r) => {
      const f = r.check(buildContext(["Agreement", text]));
      // "declined" joins the vocabulary with MSA-011. None of the
      // missing-clause titles in these packs use these words, so the filter
      // still proves it was `denied_if` that matched.
      return f !== null && /disclaim|denied|declined/i.test(f.title);
    })
    .map((r) => r.id);

/**
 * Express-denial guards for the MSA-deep, addenda, and NDA-deep packs — the
 * last three v3 families in the sweep.
 *
 * A clause-presence rule fires when NONE of its `present_patterns` match, so a
 * document that AFFIRMATIVELY DISCLAIMS the obligation matches every topic word
 * and the rule stays silent — while one that merely omits the topic is flagged.
 * `denied_if` inverts that. The assertion reads the finding TITLE, because a
 * fixture also trips the ordinary missing-clause branch on unrelated rules.
 *
 * Rules whose required clause is itself a disclaimer, waiver, exclusion, or
 * carve-out carry no guard by design — MSA-015 (implied-warranty disclaimer),
 * MSA-017 (sole-and-exclusive remedy), MSA-025 (no-waiver), MSA-030 (UCC
 * § 2-719 carve-out), ADDENDA-011 (prohibited use), and the NDA exclusion
 * rules. A denial frame there would flag the compliant drafting.
 */
describe("v3 MSA / addenda / NDA presence rules — express denial", () => {
  it.each(CASES.filter(([, , , want]) => want).map(([r, id, base, , tail]) => [id, r, base, tail]))(
    "%s fires on an express disclaimer: %s",
    (id, rules, base, tail) => {
      expect(denied(rules as Rule[], `${base} ${tail}`)).toContain(id);
    },
  );

  it.each(CASES.filter(([, , , want]) => !want).map(([r, , base, , tail]) => [tail, r, base]))(
    "does not read compliant drafting as a denial: %s",
    (tail, rules, base) => {
      expect(denied(rules as Rule[], `${base} ${tail}`)).toEqual([]);
    },
  );
});

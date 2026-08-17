import { describe, expect, it } from "vitest";

import { DPA_GDPR_RULES } from "./dpa-gdpr/rules.js";
import { TRANSFER_RULES } from "./transfer/rules.js";
import { DPA_US_STATE_RULES } from "./dpa-us-state/rules.js";
import { NDA_DEEP_RULES } from "./nda-deep/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";

const ALL: Rule[] = [
  ...DPA_GDPR_RULES,
  ...TRANSFER_RULES,
  ...DPA_US_STATE_RULES,
  ...NDA_DEEP_RULES,
];
const byId = (id: string): Rule => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no ${id}`);
  return r;
};

// These rules had NO behavioral coverage: an audit read them and reasoned
// about their guards, but none had ever been run through `check()`. Reasoning
// about a regex is not evidence, so each is pinned here against the compliant
// drafting it must stay silent on — and, where the rule flags a specific bad
// form, against that form too.
// [id, shouldFire, label, text]
const CASES: [string, boolean, string, string][] = [
  // DPA-027 — no exclude_if at all
  [
    "DPA-027",
    false,
    "compliant",
    "Processor shall notify Controller without undue delay and in any event within 24 hours after becoming aware of a personal data breach.",
  ],
  [
    "DPA-027",
    true,
    "bad-30d",
    "Processor shall notify Controller of a personal data breach within 30 days of becoming aware.",
  ],
  [
    "DPA-027",
    true,
    "bad-spelled",
    "Processor shall report any breach no later than thirty (30) business days after discovery.",
  ],
  [
    "DPA-027",
    false,
    "good-48h",
    "Processor shall notify Controller of a personal data breach within 48 hours of becoming aware.",
  ],
  // DPA-037 — no exclude_if at all
  [
    "DPA-037",
    false,
    "compliant",
    "Processor shall not amend these instructions unilaterally; any change requires Controller's prior written agreement.",
  ],
  [
    "DPA-037",
    false,
    "compliant-never",
    "Processor shall never unilaterally amend the Controller's documented instructions.",
  ],
  // TRANSFER-015 / 017 — no exclude_if
  [
    "TRANSFER-015",
    false,
    "compliant",
    "The parties have completed a transfer impact assessment documenting the laws of the destination country and the supplementary measures adopted.",
  ],
  [
    "TRANSFER-017",
    false,
    "compliant",
    "The importer shall notify the exporter of any binding request from a public authority and shall challenge it where lawful.",
  ],
  // USDPA-020 / 021
  [
    "USDPA-020",
    false,
    "compliant",
    "Service Provider shall not sell or share personal information, and shall not retain, use, or disclose it for any purpose other than the business purposes specified in the Agreement.",
  ],
  [
    "USDPA-021",
    false,
    "compliant",
    "Service Provider certifies that it understands the restrictions in this Addendum and will comply with them.",
  ],
  // NDA-D-010 / 011 / 020 / 024
  [
    "NDA-D-010",
    false,
    "compliant",
    "Nothing in this Agreement restricts either party from making a general solicitation not specifically directed at the other party's employees.",
  ],
  [
    "NDA-D-011",
    false,
    "compliant",
    "Each party shall use the Confidential Information solely for the Purpose and for no other purpose.",
  ],
  [
    "NDA-D-020",
    false,
    "compliant",
    "The obligations of each party under this Agreement are mutual and apply equally to each party as Discloser and as Recipient.",
  ],
  [
    "NDA-D-024",
    false,
    "compliant",
    "Recipient shall return or destroy all Confidential Information upon request and certify such destruction in writing.",
  ],
];

describe("v3 rules that previously had no behavioral coverage", () => {
  it.each(CASES.filter(([, want]) => !want).map(([id, , label, text]) => [id, label, text]))(
    "%s stays silent on compliant drafting (%s)",
    (id, _label, text) => {
      expect(byId(id).check(buildContext(["Agreement", text])), id).toBeNull();
    },
  );

  it.each(CASES.filter(([, want]) => want).map(([id, , label, text]) => [id, label, text]))(
    "%s still fires on the form it targets (%s)",
    (id, _label, text) => {
      expect(byId(id).check(buildContext(["Agreement", text])), id).not.toBeNull();
    },
  );
});

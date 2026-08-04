/**
 * The v4 commercial playbooks (A.8–A.11) are only useful if a real
 * document actually ROUTES to them through the matcher — the ruleset tests
 * pin the playbook manually and so cannot catch a match-feature regression
 * that would send a supply / distribution / referral / marketing agreement
 * to `generic-fallback` (or, for marketing, to the launch `msa-general`).
 * This asserts each routes to its own playbook against the full 145-playbook
 * set (launch + the served extended manifest).
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { matchPlaybook } from "../../src/playbooks/matcher.js";
import { parsePlaybook } from "../../src/playbooks/index.js";
import { EXTENDED_MANIFEST_PATH } from "../../tools/build-extended-playbooks.js";
import { loadAllPlaybooks } from "./_pipeline-helpers.js";
import type { ExtractedData } from "../../src/extract/types.js";

describe("commercial playbook routing", () => {
  it("routes each A.8–A.11 document to its own playbook", async () => {
    const launch = await loadAllPlaybooks();
    const extended = (JSON.parse(readFileSync(EXTENDED_MANIFEST_PATH, "utf8")) as unknown[]).map(
      (p) => parsePlaybook(p),
    );
    const available = [...launch, ...extended];
    const noExtract = { definitions: { entries: [] } } as unknown as ExtractedData;

    const cases: Array<{ want: string; title: string; body: string }> = [
      {
        want: "manufacturing-supply-agreement",
        title: "Master Supply Agreement",
        body: "This Master Supply Agreement governs Seller's supply of the Goods per the delivery schedule and purchase orders. Specifications and lead time apply.",
      },
      {
        want: "distribution-agreement",
        title: "Distribution Agreement",
        body: "Supplier appoints Distributor as exclusive distributor of the Products in the Territory. Minimum purchase and resale terms.",
      },
      {
        want: "channel-referral-agreement",
        title: "Referral Agreement",
        body: "Partner earns a referral fee for each qualified referral introduced. Channel partner terms.",
      },
      {
        want: "marketing-services-agreement",
        title: "Marketing Services Agreement",
        body: "Agency provides marketing services and creative deliverables for the advertising campaign and media buy.",
      },
    ];

    for (const { want, title, body } of cases) {
      const m = matchPlaybook(noExtract, [], available, { title, body_text: body });
      expect(m.playbook_id, `${want}: routed to ${m.playbook_id}`).toBe(want);
      expect(m.confidence, want).toBeGreaterThanOrEqual(0.5);
    }
  });
});

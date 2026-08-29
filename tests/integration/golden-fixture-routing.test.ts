/**
 * A golden fixture routes to the family it was written for.
 *
 * Every golden fixture carries a `.playbook` sidecar that FORCES its family,
 * so the matcher never runs on it and a mis-routing can hide there
 * indefinitely. Routing the same 327 fixtures without the sidecar is a free
 * matcher corpus three times the size of the specimen set, and it found five
 * real defects the day it was written:
 *
 * - `insurance-coi-minimal.txt` was pinned to `coi-policy` — a CONFLICT OF
 *   INTEREST policy — so a certificate of insurance had been audited against
 *   POL-033..036 for years, drawing four findings about recusal and annual
 *   certification. The sidecar was wrong, not the matcher.
 * - `subcontractor-agreement`'s title keyword "subcontract" is a SUBSTRING of
 *   "Subcontractor Business Associate Agreement", so a HIPAA downstream BAA
 *   routed to a construction subcontract at 1.00.
 * - `baa-subcontractor` listed the BASE RATE of every HIPAA document —
 *   "protected health information", "covered entity", "business associate",
 *   "phi" — as distinguishing phrases, so a patient's authorization form
 *   scored 0.6 there.
 * - `phi-authorization` did not list its own statutory caption,
 *   "Authorization for Use and Disclosure of Protected Health Information"
 *   (45 C.F.R. § 164.508).
 * - "UK International Data Transfer Addendum to the EU Standard Contractual
 *   Clauses" title-matches BOTH families head-on; the EU SCC modules now carry
 *   the counter-signal.
 *
 * The exceptions below are DECLARED, each with the reason it is not a defect.
 * They are almost all PERSPECTIVE VARIANTS — `msa-vendor-deep` is the same
 * document as `msa-general` reviewed from the other side of the table, and the
 * user selects it; the matcher is not supposed to guess it.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";

const PLAYBOOK_DIR = join(process.cwd(), "playbooks");
const launch = readdirSync(PLAYBOOK_DIR)
  .filter((f) => f.endsWith(".json") && f !== "extended.json")
  .map((f) => parsePlaybook(JSON.parse(readFileSync(join(PLAYBOOK_DIR, f), "utf8"))));
const extended = parsePlaybooks(
  JSON.parse(readFileSync(join(PLAYBOOK_DIR, "extended.json"), "utf8")),
);
const ALL = [...launch, ...extended];
const dkb = loadStarterDkbSync();

/** declared family → what the matcher picks instead, and why that is correct. */
const DECLARED: Map<string, string> = new Map([
  [
    "msa-vendor-deep",
    "msa-general — the same document from the vendor's side; the user selects it",
  ],
  [
    "msa-customer-deep",
    "msa-general — the same document from the customer's side; the user selects it",
  ],
  ["mutual-nda-deep", "mutual-nda — the deep review of the same document"],
  ["unilateral-nda-deep", "unilateral-nda — the deep review of the same document"],
  [
    "executive-employment",
    "employment-at-will-us — an executive agreement is an employment agreement",
  ],
  ["saas-tos", "saas-customer — the same terms read from the customer's side"],
  ["privacy-policy-lint", "privacy-notice-gdpr — the lint pass over the same notice"],
  ["ai-addendum", "msa-general — an addendum reads as the agreement it amends"],
  ["dpa-multi-state-us", "dpa-controller-processor — the US-state overlay on the same DPA"],
  [
    "dpa-processor-subprocessor",
    "dpa-controller-processor — the downstream leg of the same processing chain",
  ],
  [
    "mutual-release",
    "confidential-settlement — a mutual release is the operative half of a settlement",
  ],
  ["net-lease", "lease-commercial-multitenant — a net lease IS a commercial lease"],
  [
    "copyright-license",
    "generic-fallback — the four-line minimal fixture carries the title and nothing else, and one signal is below the 0.5 threshold by design",
  ],
]);

const CASES: [string, string, string][] = [];
for (const dir of [
  join(process.cwd(), "tests", "golden", "v3", "fixtures"),
  join(process.cwd(), "tests", "golden", "v4", "fixtures"),
]) {
  if (!existsSync(dir)) continue;
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".txt")) continue;
    const sidecar = join(dir, `${file}.playbook`);
    if (!existsSync(sidecar)) continue;
    CASES.push([file, readFileSync(sidecar, "utf8").trim(), join(dir, file)]);
  }
}

describe("a golden fixture routes to the family it was written for", () => {
  it("the fixture corpus is loaded", () => {
    expect(CASES.length).toBeGreaterThan(300);
  });

  it.each(CASES)("%s", async (_file, want, path) => {
    const text = readFileSync(path, "utf8");
    const tree = (await ingestPaste(text)).tree;
    const extracted = extractAll(tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const match = matchPlaybook(extracted, extracted.classified, ALL, {
      title: titleCorpus(tree, _file),
      body_text: text,
    });
    if (match.playbook_id === want) return;
    const reason = DECLARED.get(want);
    expect(
      reason,
      `${_file}: written for ${want}, routes to ${match.playbook_id} (${match.confidence.toFixed(2)}) — declare it here with a reason if that is correct`,
    ).toBeDefined();
    expect(
      reason!.startsWith(match.playbook_id),
      `${want} is declared to route to "${reason}", but it routed to ${match.playbook_id}`,
    ).toBe(true);
  });
});

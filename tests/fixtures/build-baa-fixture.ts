#!/usr/bin/env tsx
/**
 * Binary BAA fixture generator for the v3 Playwright suite.
 *
 * The v3 dropzone validates by file-name suffix and accepts only
 * `.pdf` and `.docx`. The Step 34 golden corpus ships
 * `baa-minimal-pass.txt`; the no-network Playwright spec at
 * `tests/e2e/v3/no-network.spec.ts` skips when the fixture is `.txt`.
 * This script produces a deterministic `.docx` variant with the same
 * substantive content so the e2e spec can drop a real BAA and exercise
 * the v3 BAA ruleset + report writer end-to-end on the offline path.
 *
 * Output: `tests/e2e/v3/baa-minimal-pass.docx`. The Playwright spec
 * lives in the same directory; keeping the fixture beside it
 * deliberately keeps it out of `tests/golden/v3/fixtures/` (which the
 * offline golden harness scans — adding a new fixture there would
 * trigger a result_hash mismatch until a paired golden is baselined).
 *
 * Run: `npm run fixtures:baa`.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Document, Packer, Paragraph, TextRun, HeadingLevel } from "docx";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, "..", "e2e", "v3");

type Block = { heading?: string; paragraphs: string[] };

function buildDocx(blocks: Block[]): Promise<Buffer> {
  const children: Paragraph[] = [];
  for (const b of blocks) {
    if (b.heading) {
      children.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: b.heading, bold: true })],
        }),
      );
    }
    for (const p of b.paragraphs) {
      children.push(new Paragraph({ children: [new TextRun({ text: p })] }));
    }
  }
  const doc = new Document({ sections: [{ properties: {}, children }] });
  return Packer.toBuffer(doc);
}

const baa: Block[] = [
  {
    heading: "Business Associate Agreement",
    paragraphs: [
      `This Business Associate Agreement ("BAA") is entered into pursuant to the requirements of 45 CFR § 164.504(e) between Covered Entity, Acme Health LLC, a Delaware limited liability company ("Covered Entity"), and Business Associate, Globex Services Inc., a New York corporation ("Business Associate"). The Parties acknowledge that Business Associate creates or receives Protected Health Information ("PHI") on behalf of Covered Entity in performing the Services.`,
    ],
  },
  {
    heading: "Permitted Uses and Disclosures",
    paragraphs: [
      `Business Associate may use and disclose PHI only to perform the Services described in the Master Services Agreement between the parties, and as otherwise permitted or required under this BAA, the HIPAA Rules, and applicable law. Business Associate shall not use or disclose PHI other than as permitted or required by this BAA or as required by law.`,
    ],
  },
  {
    heading: "Safeguards",
    paragraphs: [
      `Business Associate shall implement administrative, physical, and technical safeguards that reasonably and appropriately protect the confidentiality, integrity, and availability of Electronic Protected Health Information ("ePHI") that Business Associate creates, receives, maintains, or transmits on behalf of Covered Entity, as required by the Security Rule at 45 CFR §§ 164.308, 164.310, and 164.312. Business Associate shall comply with the Security Rule administrative, physical, and technical safeguards as required by 45 CFR § 164.314(a)(2)(i).`,
    ],
  },
  {
    heading: "Reporting",
    paragraphs: [
      `Business Associate shall report to Covered Entity any Security Incident of which it becomes aware. Business Associate shall report Breaches of Unsecured PHI to Covered Entity without unreasonable delay and in no case later than sixty (60) days following discovery of the Breach, as required by 45 CFR § 164.410.`,
    ],
  },
  {
    heading: "Subcontractor Flow-Down",
    paragraphs: [
      `Business Associate shall ensure that any subcontractor that creates, receives, maintains, or transmits PHI on behalf of Business Associate agrees in writing to the same restrictions, conditions, and requirements that apply to Business Associate under this BAA.`,
    ],
  },
  {
    heading: "Access, Amendment, Accounting",
    paragraphs: [
      `Business Associate shall make PHI available to Covered Entity as necessary to satisfy Covered Entity's obligations under 45 CFR § 164.524 (access), 45 CFR § 164.526 (amendment), and 45 CFR § 164.528 (accounting of disclosures).`,
    ],
  },
  {
    heading: "Books, Records",
    paragraphs: [
      `Business Associate shall make its internal practices, books, and records relating to its use and disclosure of PHI available to the Secretary of Health and Human Services for purposes of determining Covered Entity's compliance with the HIPAA Rules.`,
    ],
  },
  {
    heading: "Return or Destruction",
    paragraphs: [
      `Upon termination of this BAA for any reason, Business Associate shall return to Covered Entity or destroy all PHI received from or created or received by Business Associate on behalf of Covered Entity. If return or destruction is infeasible, Business Associate shall extend the protections of this BAA to such PHI and limit further uses and disclosures to those purposes that make return or destruction infeasible.`,
    ],
  },
  {
    heading: "Minimum Necessary",
    paragraphs: [
      `Business Associate shall, when using or disclosing PHI or requesting PHI from Covered Entity, make reasonable efforts to limit such use or disclosure to the minimum necessary to accomplish the intended purpose.`,
    ],
  },
  {
    heading: "Mitigation",
    paragraphs: [
      `Business Associate shall mitigate, to the extent practicable, any harmful effect that is known to Business Associate of a use or disclosure of PHI by Business Associate in violation of this BAA.`,
    ],
  },
  {
    heading: "Workforce Training",
    paragraphs: [
      `Business Associate shall train members of its workforce on PHI handling and the requirements of this BAA.`,
    ],
  },
  {
    heading: "Encryption",
    paragraphs: [
      `Business Associate shall encrypt PHI in transit and at rest using industry-standard methods consistent with NIST SP 800-66 and FIPS 140-3.`,
    ],
  },
  {
    heading: "Risk Assessment",
    paragraphs: [
      `Business Associate shall conduct a HIPAA Security Risk Assessment at least annually.`,
    ],
  },
  {
    heading: "Sanctions",
    paragraphs: [
      `Business Associate shall apply appropriate sanctions against workforce members who fail to comply with this BAA.`,
    ],
  },
  {
    heading: "Subcontractor List",
    paragraphs: [
      `Business Associate maintains a list of subcontractors that create, receive, maintain, or transmit PHI on behalf of Business Associate.`,
    ],
  },
  {
    heading: "Governing Law",
    paragraphs: [
      `This BAA shall be governed by the laws of the State of Delaware.`,
    ],
  },
  {
    heading: "Notice",
    paragraphs: [
      `Any notice required under this BAA shall be in writing and sent to the Privacy Officer at the address set forth in the Master Services Agreement.`,
    ],
  },
  {
    heading: "Term",
    paragraphs: [
      `This BAA shall be co-terminous with the Master Services Agreement, except that the obligations to return or destroy PHI shall survive.`,
      `Effective Date: January 1, 2026.`,
      `Signed by: ____________________________________`,
      `Title: Authorized Representative`,
      `Date: January 1, 2026`,
    ],
  },
];

async function main(): Promise<void> {
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, "baa-minimal-pass.docx"), await buildDocx(baa));
  process.stdout.write("baa fixture generated\n");
}

void main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});

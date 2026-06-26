#!/usr/bin/env tsx
/**
 * End-to-end sample-document generator.
 *
 * Produces a small, hand-droppable corpus under `tests/e2e/sample-docs/`
 * for exercising the live site (drag-and-drop on https://vaulytica.com or
 * a local `npm run preview`) and the `vaulytica analyze` CLI. Unlike the
 * golden fixtures under `tests/fixtures/contracts/`, these are NOT part of
 * the `result_hash` regression gate — they exist purely so a human (or a
 * Playwright smoke run) can verify the three headline e2e flows the README
 * advertises:
 *
 *   1. Single-document analysis
 *        single/vendor-saas-agreement.docx   — realistic SaaS subscription
 *                                               agreement with several plain
 *                                               issues (auto-renewal, uncapped
 *                                               liability, unilateral change,
 *                                               missing governing law).
 *        single/clean-mutual-nda.docx         — a tidy mutual NDA: the "looks
 *                                               clean, few findings" baseline.
 *
 *   2. Multi-document bundle / cross-document mode (drop the whole folder)
 *        bundle/master-services-agreement.docx
 *        bundle/statement-of-work.docx
 *        bundle/data-processing-addendum.docx
 *      The three disagree on purpose — governing law (DE vs CA), the
 *      definition of "Services", the liability cap, and a referenced
 *      companion doc — so the cross-document consistency pass has something
 *      to find (CROSS-JURIS / CROSS-DEFTERM / CROSS-PRECEDENCE / CROSS-AMOUNT).
 *
 *   3. Pasted-text path
 *        pasted-services-agreement.txt        — paste into the textarea.
 *
 * NOT covered here: the v9 pre-disclosure / "clean to send" scan reads the
 * ORIGINAL container bytes for tracked changes, comments, and authoring
 * metadata. The `docx` library can't emit those constructs, so a faithful
 * HANDOFF-* sample needs a real Word round-trip and is out of scope for a
 * deterministic generator. See the README for how to make one by hand.
 *
 * Run: `npm run e2e:samples`  (or `tsx tests/e2e/sample-docs/build-sample-docs.ts`)
 *
 * These files are generated. Don't hand-edit them — edit this script and
 * re-run.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Document, Packer, Paragraph, TextRun, HeadingLevel } from "docx";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SINGLE = join(__dirname, "single");
const BUNDLE = join(__dirname, "bundle");

mkdirSync(SINGLE, { recursive: true });
mkdirSync(BUNDLE, { recursive: true });

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

function blocksToText(blocks: Block[]): string {
  const lines: string[] = [];
  for (const b of blocks) {
    if (b.heading) lines.push(b.heading, "");
    for (const p of b.paragraphs) lines.push(p, "");
  }
  return lines.join("\n").trimEnd() + "\n";
}

async function main(): Promise<void> {
  // ----------------------------------------------------------------
  // 1a. Single document — realistic vendor SaaS agreement with issues
  // ----------------------------------------------------------------
  const vendorSaas: Block[] = [
    {
      heading: "Software-as-a-Service Subscription Agreement",
      paragraphs: [
        `This Software-as-a-Service Subscription Agreement (this "Agreement") is entered into as of March 1, 2026 (the "Effective Date") between Northwind Cloud, Inc., a Delaware corporation ("Provider"), and Customer identified on the applicable Order Form ("Customer").`,
      ],
    },
    {
      heading: "1. Subscription and Access",
      paragraphs: [
        `Provider grants Customer a non-exclusive, non-transferable right to access and use the hosted services described in the applicable Order Form (the "Services") during the Subscription Term.`,
        `Customer is responsible for all activity occurring under its accounts and for maintaining the confidentiality of its credentials.`,
      ],
    },
    {
      heading: "2. Term and Renewal",
      paragraphs: [
        `The initial Subscription Term is twelve (12) months from the Effective Date. Thereafter, this Agreement will automatically renew for successive twelve (12) month terms unless either party gives written notice of non-renewal at least ten (10) days before the end of the then-current term.`,
      ],
    },
    {
      heading: "3. Fees",
      paragraphs: [
        `Customer shall pay the subscription fee of twenty-five thousand dollars ($20,000) per year, due net thirty (30) days from the invoice date.`,
        `Late payments accrue interest at three percent (3%) per month until paid in full.`,
      ],
    },
    {
      heading: "4. Changes to the Services and Terms",
      paragraphs: [
        `Provider may modify the Services, the applicable fees, or the terms of this Agreement at any time in its sole discretion by posting the updated terms to its website, and Customer's continued use of the Services constitutes acceptance of the modified terms.`,
      ],
    },
    {
      heading: "5. Limitation of Liability",
      paragraphs: [
        `Customer agrees that Provider shall have no liability whatsoever for any direct, indirect, incidental, consequential, special, or punitive damages arising out of or relating to this Agreement, regardless of the theory of liability and even if advised of the possibility of such damages.`,
      ],
    },
    {
      heading: "6. Indemnification",
      paragraphs: [
        `Customer shall indemnify, defend, and hold harmless Provider from and against any and all claims, damages, liabilities, costs, and expenses arising out of Customer's use of the Services. Provider has no corresponding indemnification obligation to Customer.`,
      ],
    },
    {
      heading: "7. Suspension",
      paragraphs: [
        `Provider may suspend or terminate Customer's access to the Services at any time, with or without cause and with or without notice.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Dana Pruitt  Title: VP Sales  Date: March 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(SINGLE, "vendor-saas-agreement.docx"), await buildDocx(vendorSaas));

  // ----------------------------------------------------------------
  // 1b. Single document — clean mutual NDA (the low-noise baseline)
  // ----------------------------------------------------------------
  const cleanNda: Block[] = [
    {
      heading: "Mutual Non-Disclosure Agreement",
      paragraphs: [
        `This Mutual Non-Disclosure Agreement (this "Agreement") is entered into as of February 1, 2026 (the "Effective Date") between Harborview Analytics, Inc., a Delaware corporation, and Cedar Peak Robotics, LLC, a California limited liability company (each a "Party" and together the "Parties").`,
      ],
    },
    {
      heading: "1. Definitions",
      paragraphs: [
        `"Confidential Information" means non-public information disclosed by one Party (the "Discloser") to the other Party (the "Recipient") that is marked confidential or that a reasonable person would understand to be confidential given its nature and the circumstances of disclosure.`,
        `"Permitted Purpose" means evaluating and pursuing a potential business relationship between the Parties.`,
      ],
    },
    {
      heading: "2. Confidentiality Obligations",
      paragraphs: [
        `Each Recipient shall protect the Discloser's Confidential Information using at least the same degree of care it uses to protect its own confidential information of like importance, and in no event less than a reasonable degree of care.`,
        `Each Recipient shall use Confidential Information solely for the Permitted Purpose and shall limit access to those of its employees and advisors who have a need to know and who are bound by confidentiality obligations no less protective than those in this Agreement.`,
      ],
    },
    {
      heading: "3. Exclusions",
      paragraphs: [
        `Confidential Information does not include information that is or becomes publicly available through no fault of the Recipient, was lawfully known to the Recipient before disclosure, is independently developed without use of the Confidential Information, or is lawfully obtained from a third party without restriction.`,
      ],
    },
    {
      heading: "4. Compelled Disclosure",
      paragraphs: [
        `A Recipient may disclose Confidential Information to the extent required by law or court order, provided that, where legally permitted, it gives the Discloser prompt prior notice and reasonable cooperation to seek protective treatment.`,
      ],
    },
    {
      heading: "5. Term and Survival",
      paragraphs: [
        `This Agreement begins on the Effective Date and continues for two (2) years. The confidentiality obligations in Section 2 survive termination and continue for three (3) years after the date of disclosure of the applicable Confidential Information.`,
      ],
    },
    {
      heading: "6. Governing Law",
      paragraphs: [
        `This Agreement is governed by and construed in accordance with the laws of the State of Delaware, without regard to its conflict-of-laws principles.`,
      ],
    },
    {
      heading: "7. Entire Agreement",
      paragraphs: [
        `This Agreement constitutes the entire agreement between the Parties regarding its subject matter and supersedes all prior or contemporaneous understandings.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Priya Raman  Title: General Counsel  Date: February 1, 2026`,
        `By: ____________________  Name: Marcus Hale  Title: Chief Executive Officer  Date: February 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(SINGLE, "clean-mutual-nda.docx"), await buildDocx(cleanNda));

  // ----------------------------------------------------------------
  // 2. Cross-document bundle — three docs that disagree on purpose
  // ----------------------------------------------------------------
  const msa: Block[] = [
    {
      heading: "Master Services Agreement",
      paragraphs: [
        `This Master Services Agreement (this "MSA") is entered into as of January 15, 2026 between Summit Integrations, Inc., a Delaware corporation ("Provider"), and Riverstone Holdings, Inc. ("Customer").`,
      ],
    },
    {
      heading: "1. Structure",
      paragraphs: [
        `This MSA governs all Statements of Work executed by the parties. In the event of a conflict between this MSA and a Statement of Work, the terms of this MSA control.`,
      ],
    },
    {
      heading: "2. Definitions",
      paragraphs: [
        `"Services" means professional implementation and integration services performed by Provider's employees.`,
      ],
    },
    {
      heading: "3. Fees",
      paragraphs: [
        `Customer shall pay Provider the fees set forth in each Statement of Work. The not-to-exceed fee for the initial Statement of Work is one hundred thousand dollars ($100,000).`,
      ],
    },
    {
      heading: "4. Limitation of Liability",
      paragraphs: [
        `Each party's aggregate liability arising out of this MSA is capped at one million dollars ($1,000,000).`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [`This MSA is governed by the laws of the State of Delaware.`],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Olivia Trent  Title: COO  Date: January 15, 2026`,
        `By: ____________________  Name: Samuel Kade  Title: VP Procurement  Date: January 15, 2026`,
      ],
    },
  ];
  writeFileSync(join(BUNDLE, "master-services-agreement.docx"), await buildDocx(msa));

  const sow: Block[] = [
    {
      heading: "Statement of Work No. 1",
      paragraphs: [
        `This Statement of Work No. 1 ("SOW") is issued under and incorporates the Master Services Agreement dated January 15, 2026 between Summit Integrations, Inc. ("Provider") and Riverstone Holdings, Inc. ("Customer"). In the event of a conflict between this SOW and the Master Services Agreement, the terms of this SOW control.`,
      ],
    },
    {
      heading: "1. Definitions",
      paragraphs: [
        `"Services" means the deliverables described in Section 2, together with any maintenance, hosting, and support obligations, whether or not performed by Provider's own employees.`,
      ],
    },
    {
      heading: "2. Scope",
      paragraphs: [
        `Provider will deliver the data-migration and reporting workstreams described in Exhibit A, attached hereto.`,
      ],
    },
    {
      heading: "3. Fees",
      paragraphs: [
        `The total fee for the Services under this SOW is one hundred eighty thousand dollars ($180,000), invoiced monthly.`,
      ],
    },
    {
      heading: "4. Governing Law",
      paragraphs: [`This SOW is governed by the laws of the State of California.`],
    },
    {
      heading: "5. Signatures",
      paragraphs: [
        `By: ____________________  Name: Olivia Trent  Title: COO  Date: January 20, 2026`,
      ],
    },
  ];
  writeFileSync(join(BUNDLE, "statement-of-work.docx"), await buildDocx(sow));

  const dpa: Block[] = [
    {
      heading: "Data Processing Addendum",
      paragraphs: [
        `This Data Processing Addendum ("DPA") supplements the Master Services Agreement dated January 15, 2026 between Summit Integrations, Inc. ("Processor") and Riverstone Holdings, Inc. ("Controller") and governs the processing of personal data in connection with the Services.`,
      ],
    },
    {
      heading: "1. Scope of Processing",
      paragraphs: [
        `Processor shall process personal data only on documented instructions from Controller and solely to provide the Services. Processor shall not sell personal data or use it to train models for any purpose unrelated to the Services.`,
      ],
    },
    {
      heading: "2. Security",
      paragraphs: [
        `Processor shall implement appropriate technical and organizational measures to protect personal data against unauthorized access, disclosure, or loss.`,
      ],
    },
    {
      heading: "3. Sub-processors",
      paragraphs: [
        `Processor shall not engage a sub-processor without Controller's prior written authorization and shall flow down obligations no less protective than those in this DPA.`,
      ],
    },
    {
      heading: "4. International Transfers",
      paragraphs: [
        `Where personal data is transferred outside its country of origin, Processor shall ensure an adequate transfer mechanism is in place before the transfer occurs.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This DPA is governed by the laws of the State of Delaware, consistent with the Master Services Agreement it supplements.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Olivia Trent  Title: COO  Date: January 15, 2026`,
        `By: ____________________  Name: Samuel Kade  Title: VP Procurement  Date: January 15, 2026`,
      ],
    },
  ];
  writeFileSync(join(BUNDLE, "data-processing-addendum.docx"), await buildDocx(dpa));

  // ----------------------------------------------------------------
  // 3. Pasted-text path — a services agreement as plain text
  // ----------------------------------------------------------------
  const pastedServices: Block[] = [
    {
      heading: "Professional Services Agreement",
      paragraphs: [
        `This Professional Services Agreement (this "Agreement") is entered into as of April 1, 2026 between Lakeside Advisory, LLC ("Consultant") and Brightline Manufacturing, Inc. ("Client").`,
      ],
    },
    {
      heading: "1. Services",
      paragraphs: [
        `Consultant will provide the advisory services described in each mutually agreed engagement letter. Consultant will perform the services with reasonable skill and care.`,
      ],
    },
    {
      heading: "2. Fees",
      paragraphs: [
        `Client shall pay Consultant a monthly retainer of ten thousand dollars ($10,000), due net fifteen (15) days from invoice.`,
      ],
    },
    {
      heading: "3. Term",
      paragraphs: [
        `This Agreement continues for one (1) year and renews for successive one-year terms unless either party gives sixty (60) days' written notice of non-renewal.`,
      ],
    },
    {
      heading: "4. Confidentiality",
      paragraphs: [
        `Each party shall protect the other's confidential information and use it only to perform under this Agreement.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [`This Agreement is governed by the laws of the State of New York.`],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Erin Coyle  Title: Managing Partner  Date: April 1, 2026`,
        `By: ____________________  Name: Victor Salas  Title: COO  Date: April 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(__dirname, "pasted-services-agreement.txt"), blocksToText(pastedServices));

  console.log("Sample e2e docs written to tests/e2e/sample-docs/");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

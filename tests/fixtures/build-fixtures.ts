#!/usr/bin/env tsx
/**
 * Synthetic fixture generator (spec §26 step 16). Produces a small,
 * deterministic test corpus under `tests/fixtures/contracts/`:
 *
 *   mutual-nda.docx          — Common-Paper-shaped clean Mutual NDA
 *   bad-nda.docx             — 5 intentional rule violations:
 *                              1. unfilled `[insert]` placeholder
 *                              2. hanging cross-reference to "Section 9.4"
 *                              3. word/numeral amount mismatch
 *                              4. uncapped liability
 *                              5. impossible date "February 30, 2026"
 *   bad-saas.docx            — auto-renewal buried in §13(c) + unilateral
 *                              modification right + asymmetric indemnity
 *   pasted-mutual-nda.txt    — pasted-text variant of the clean NDA
 *
 * The real Common Paper DOCX (`mutual-nda-common-paper.docx`) and a
 * scanned-PDF variant are out of scope for this generator — they
 * require network access for the GitHub download and a print-to-image
 * step for the scan. The golden-output test guards on file presence
 * and skips them gracefully if not present.
 *
 * Run: `npm run fixtures`
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Document, Packer, Paragraph, TextRun, HeadingLevel } from "docx";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "contracts");

mkdirSync(CONTRACTS, { recursive: true });

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

async function main(): Promise<void> {
  // --- 1. Clean Mutual NDA ------------------------------------------
  const mutualNda: Block[] = [
    {
      heading: "Mutual Non-Disclosure Agreement",
      paragraphs: [
        `This Mutual Non-Disclosure Agreement (this "Agreement") is entered into as of January 1, 2026 (the "Effective Date") between Acme Corp., a Delaware corporation ("Discloser"), and Beta LLC, a New York limited liability company ("Recipient").`,
      ],
    },
    {
      heading: "1. Definitions",
      paragraphs: [
        `"Confidential Information" means any non-public information disclosed by Discloser to Recipient.`,
        `"Permitted Purpose" means evaluating a potential business relationship between the parties.`,
      ],
    },
    {
      heading: "2. Confidentiality Obligation",
      paragraphs: [
        `Recipient shall protect Confidential Information using the same degree of care it uses to protect its own confidential information of like importance, but in no event less than a reasonable degree of care.`,
        `Recipient shall use Confidential Information solely for the Permitted Purpose.`,
      ],
    },
    {
      heading: "3. Permitted Disclosures",
      paragraphs: [
        `Recipient may disclose Confidential Information to its employees, advisors, and contractors who have a need to know and who are bound by confidentiality obligations no less protective than those in this Agreement.`,
      ],
    },
    {
      heading: "4. Term",
      paragraphs: [
        `This Agreement shall continue for a term of two (2) years from the Effective Date.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "6. Entire Agreement",
      paragraphs: [
        `This Agreement constitutes the entire agreement between the parties and supersedes all prior agreements and understandings.`,
      ],
    },
    {
      heading: "7. Signatures",
      paragraphs: [
        `By: ____________________  Name: Jane Doe  Title: CEO  Date: January 1, 2026`,
        `By: ____________________  Name: John Roe  Title: President  Date: January 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "mutual-nda.docx"), await buildDocx(mutualNda));

  // --- 2. Bad NDA (5 violations) -----------------------------------
  const badNda: Block[] = [
    {
      heading: "Mutual Non-Disclosure Agreement",
      paragraphs: [
        `This Mutual Non-Disclosure Agreement is entered into as of February 30, 2026 between [insert party name], a Delaware corporation ("Discloser"), and Beta LLC ("Recipient").`,
      ],
    },
    {
      heading: "1. Confidentiality Obligation",
      paragraphs: [
        `Recipient shall protect Confidential Information per Section 9.4 (which does not exist in this Agreement).`,
        `Recipient agrees to pay Discloser fifty thousand dollars ($75,000) as liquidated damages for any breach.`,
      ],
    },
    {
      heading: "2. Liability",
      paragraphs: [
        `Recipient shall be liable for all damages, direct, indirect, consequential, special, and punitive, without limitation, arising from any breach of this Agreement.`,
      ],
    },
    {
      heading: "3. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "4. Signatures",
      paragraphs: [
        `By: ____________________  Name: ____________________  Title: ____________________  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-nda.docx"), await buildDocx(badNda));

  // --- 3. Bad SaaS --------------------------------------------------
  const badSaas: Block[] = [
    {
      heading: "Cloud Service Agreement",
      paragraphs: [
        `This Cloud Service Agreement is entered into as of January 1, 2026 between MegaSoft, Inc., a Delaware corporation ("Vendor"), and Customer.`,
      ],
    },
    {
      heading: "1. The Service and Subscription Term",
      paragraphs: [
        `Vendor will provide the Service to Customer for the Subscription Term. Customer Data uploaded to the Service is processed under the DPA.`,
      ],
    },
    {
      heading: "2. Fees and Payment",
      paragraphs: [
        `Customer shall pay an annual subscription fee of $25,000.00 due net-thirty (30) days from invoice.`,
      ],
    },
    {
      heading: "13. Miscellaneous",
      paragraphs: [
        `(a) Notices. Notices shall be in writing.`,
        `(b) Severability. If any provision is held unenforceable, the remainder continues.`,
        `(c) Renewal. This Agreement shall automatically renew for successive one-year terms unless Customer provides written notice of non-renewal at least ninety (90) days before the end of the then-current Subscription Term.`,
        `(d) Modifications. Vendor may modify the terms of this Agreement at any time by posting a revised version on its website; continued use of the Service constitutes acceptance.`,
      ],
    },
    {
      heading: "14. Indemnification",
      paragraphs: [
        `Customer shall indemnify, defend, and hold Vendor harmless from any third-party claim arising from Customer's use of the Service. Vendor shall not have any reciprocal indemnification obligation.`,
      ],
    },
    {
      heading: "15. Limitation of Liability",
      paragraphs: [
        `In no event shall Vendor's aggregate liability exceed the fees paid by Customer to Vendor in the three (3) months preceding the claim.`,
      ],
    },
    {
      heading: "16. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "17. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Vendor  Title: COO  Date: January 1, 2026`,
        `By: ____________________  Name: Sam Buyer  Title: CFO  Date: January 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-saas.docx"), await buildDocx(badSaas));

  // --- 4. Bad Employment Agreement -----------------------------------
  // Targets the employment-at-will-us playbook + personnel/dark-pattern
  // rules. Intentional violations:
  //   1. California non-compete (void under Cal. Bus. & Prof. Code §16600)
  //      — PERS-005
  //   2. Non-disparagement without NLRA / SEC carve-outs — PERS-006
  //   3. Asymmetric termination-for-convenience (Employer free, Employee
  //      bound) — TERM-009
  //   4. One-sided jury-trial waiver (Employee only) — CHOICE-010
  //   5. `Best efforts` undefined — OBLI-008
  //   6. Mandatory class-action waiver — DARK-005
  //   7. Survival clause silent on confidentiality + IP — TEMP-012
  const badEmployment: Block[] = [
    {
      heading: "Employment Agreement",
      paragraphs: [
        `This Employment Agreement is entered into as of January 1, 2026 between MegaCo, Inc., a Delaware corporation ("Employer"), and Alex Smith ("Employee"), an exempt at-will employee based in San Francisco, California.`,
      ],
    },
    {
      heading: "1. Position and Duties",
      paragraphs: [
        `Employee shall use best efforts to perform the duties of Senior Engineer.`,
      ],
    },
    {
      heading: "2. Compensation",
      paragraphs: [
        `Base salary: $180,000 per year, paid bi-weekly.`,
      ],
    },
    {
      heading: "3. Confidentiality",
      paragraphs: [
        `Employee agrees to protect Employer's Confidential Information during and after employment.`,
      ],
    },
    {
      heading: "4. Intellectual Property",
      paragraphs: [
        `All work product created by Employee in the course of employment is hereby assigned to Employer as a work for hire.`,
      ],
    },
    {
      heading: "5. Non-Competition",
      paragraphs: [
        `For a period of twelve (12) months following termination of employment for any reason, Employee shall not directly or indirectly compete with Employer within the State of California or any other state where Employer conducts business.`,
      ],
    },
    {
      heading: "6. Non-Disparagement",
      paragraphs: [
        `Employee shall not disparage Employer, its officers, directors, products, or services in any forum at any time.`,
      ],
    },
    {
      heading: "7. Termination",
      paragraphs: [
        `Employer may terminate this Agreement at any time in its sole discretion.`,
        `Employee shall terminate this Agreement only after providing 60 days written notice of any material breach following a cure period.`,
      ],
    },
    {
      heading: "8. Dispute Resolution",
      paragraphs: [
        `All disputes shall be resolved on an individual basis only and not as part of any class action or representative action.`,
        `Employee hereby waives any right to trial by jury in any action arising from this Agreement.`,
      ],
    },
    {
      heading: "9. Survival",
      paragraphs: [
        `The provisions of Section 2 (Compensation) shall survive termination of this Agreement.`,
      ],
    },
    {
      heading: "10. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
        `Exclusive venue shall be in the federal courts located in San Francisco, California.`,
      ],
    },
    {
      heading: "11. Signatures",
      paragraphs: [
        `By: ____________________  Name: Riley Lead  Title: CEO  Date: January 1, 2026`,
        `By: ____________________  Name: Alex Smith  Date: January 1, 2026`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-employment.docx"), await buildDocx(badEmployment));

  // --- 5. Bad Commercial Lease (multi-tenant office) ----------------
  // Targets the lease-commercial-multitenant playbook. Intentional
  // violations:
  //   1. Insurance requirement without coverage minimum — RISK-016
  //   2. Unlimited "additional rent" via Operating Expenses without cap
  //      — picks up indirectly via STRUCT-013 placeholders
  //   3. One-sided jury-trial waiver — CHOICE-010
  //   4. `[Premises Address]` placeholder — STRUCT-013
  //   5. Asymmetric notice-before-suit gate — DARK-006
  //   6. Auto-renewal with 10-day non-renewal window — TEMP-011
  //   7. Late fee 3% per month (36%/year) — FIN-009
  const badLease: Block[] = [
    {
      heading: "Office Lease",
      paragraphs: [
        `This Office Lease is entered into between BigReit, Inc., a Delaware corporation ("Landlord"), and SmallCo, LLC, a California limited liability company ("Tenant").`,
      ],
    },
    {
      heading: "1. Premises and Term",
      paragraphs: [
        `Landlord leases to Tenant the premises located at [Premises Address] (the "Premises"), comprising 5,000 Rentable Square Feet.`,
        `The initial Term is three (3) years, with automatic renewal for successive one-year terms unless either party provides written notice of non-renewal at least 10 days before the end of the then-current Term.`,
      ],
    },
    {
      heading: "2. Rent",
      paragraphs: [
        `Base Rent: $20,000 per month, payable in advance on the first of each month.`,
        `Additional Rent: Tenant shall pay its proportionate share of Operating Expenses, real estate taxes, and Common Area charges.`,
        `Late Payment: A late fee of 3% per month shall apply to amounts not paid when due.`,
      ],
    },
    {
      heading: "3. Insurance",
      paragraphs: [
        `Tenant shall maintain commercial general liability insurance during the Term.`,
      ],
    },
    {
      heading: "4. Indemnification",
      paragraphs: [
        `Tenant shall indemnify and hold Landlord harmless from any claim arising from Tenant's occupancy of the Premises.`,
      ],
    },
    {
      heading: "5. Dispute Resolution",
      paragraphs: [
        `Tenant shall provide Landlord at least 60 days written notice of any claim before initiating suit.`,
        `Tenant hereby waives any right to trial by jury in any action arising from this Lease.`,
      ],
    },
    {
      heading: "6. Governing Law",
      paragraphs: [
        `This Lease shall be governed by the laws of the State of New York.`,
      ],
    },
    {
      heading: "7. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Property  Title: VP Leasing  Date: ____________________`,
        `By: ____________________  Name: Sam Smallco  Title: Managing Member  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-lease.docx"), await buildDocx(badLease));

  // --- 6. Bad Independent Contractor (misclassification dark pattern)
  // Targets the independent-contractor playbook. The dark pattern is
  // calling someone a "contractor" while imposing employee-style
  // controls (set hours, exclusive engagement, company-supplied tools).
  // Intentional violations:
  //   1. Non-compete in California (PERS-005)
  //   2. Fixed hours / location language (DARK-001 / OBLI-002 surfacing)
  //   3. Asymmetric termination (TERM-009)
  //   4. Class-action waiver (DARK-005)
  //   5. Non-disparagement without carve-out (PERS-006)
  //   6. `[insert]` placeholder (STRUCT-013)
  const badContractor: Block[] = [
    {
      heading: "Independent Contractor Agreement",
      paragraphs: [
        `This Independent Contractor Agreement is entered into between Hirer, Inc. ("Company") and [insert contractor name] ("Contractor"). Contractor is engaged as an independent contractor and not as an employee.`,
      ],
    },
    {
      heading: "1. Services",
      paragraphs: [
        `Contractor shall perform the Services during regular business hours (9:00 a.m. to 5:00 p.m., Monday through Friday) at Company's offices located in San Francisco, California.`,
        `Contractor shall use Company-supplied equipment and shall report daily to Company's designated supervisor.`,
      ],
    },
    {
      heading: "2. Compensation",
      paragraphs: [
        `Company shall pay Contractor a flat monthly fee of $8,000, payable on the first of each month.`,
      ],
    },
    {
      heading: "3. Exclusivity / Non-Compete",
      paragraphs: [
        `During the Term and for twelve (12) months thereafter, Contractor shall not directly or indirectly compete with Company or perform services for any other party within California.`,
      ],
    },
    {
      heading: "4. Non-Disparagement",
      paragraphs: [
        `Contractor shall not disparage Company, its officers, or its products at any time.`,
      ],
    },
    {
      heading: "5. Termination",
      paragraphs: [
        `Company may terminate this Agreement at any time in its sole discretion.`,
        `Contractor shall terminate this Agreement only after providing 30 days written notice of any material breach following a cure period.`,
      ],
    },
    {
      heading: "6. Dispute Resolution",
      paragraphs: [
        `All disputes shall be resolved on an individual basis only and not as part of any class action.`,
      ],
    },
    {
      heading: "7. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Ralph Hirer  Title: COO  Date: ____________________`,
        `By: ____________________  Name: [Contractor Name]  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-contractor.docx"), await buildDocx(badContractor));

  // --- 7. Bad One-Way / Unilateral NDA ------------------------------
  // Targets the unilateral-nda playbook. Intentional violations:
  //   1. Indefinite confidentiality period (no end-date)
  //   2. Permitted-purpose missing
  //   3. Liability uncapped (RISK-009)
  //   4. Survival silent on confidentiality (TEMP-012)
  //   5. `[insert]` placeholder (STRUCT-013)
  const badUnilateralNda: Block[] = [
    {
      heading: "One-Way Non-Disclosure Agreement",
      paragraphs: [
        `This One-Way Non-Disclosure Agreement is entered into between Big Co. ("Disclosing Party") and [insert recipient name] ("Receiving Party").`,
      ],
    },
    {
      heading: "1. Confidential Information",
      paragraphs: [
        `"Confidential Information" means any non-public information disclosed by the Disclosing Party to the Receiving Party.`,
      ],
    },
    {
      heading: "2. Obligations",
      paragraphs: [
        `The Receiving Party shall not disclose Confidential Information for an indefinite period and shall be liable for all damages without limitation.`,
      ],
    },
    {
      heading: "3. Survival",
      paragraphs: [
        `The notice provisions of this Agreement shall survive termination.`,
      ],
    },
    {
      heading: "4. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "5. Signatures",
      paragraphs: [
        `By: ____________________  Name: Big Boss  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: ____________________  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-unilateral-nda.docx"), await buildDocx(badUnilateralNda));

  // --- 8. Bad Residential Lease -------------------------------------
  // Targets the lease-residential-us playbook. Intentional violations:
  //   1. Auto-renewal with 7-day notice window (TEMP-011)
  //   2. 5%/month late fee (60%/year — usurious) (FIN-009)
  //   3. Tenant `as is` waiver — captured by general structural rules
  //   4. `[Property Address]` placeholder (STRUCT-013)
  //   5. Asymmetric pre-suit notice (DARK-006)
  //   6. Browsewrap-style modification (DARK-007)
  //   7. Non-disparagement (PERS-006-ish surface)
  const badResidentialLease: Block[] = [
    {
      heading: "Residential Rental Agreement",
      paragraphs: [
        `This Residential Rental Agreement is entered into between Property Owner LLC ("Landlord") and Renter ("Tenant"), for the premises located at [Property Address] (the "Premises").`,
      ],
    },
    {
      heading: "1. Term",
      paragraphs: [
        `Initial Term: 12 months. Automatically renews for successive 12-month terms unless Tenant provides 7 days written notice before the end of the then-current Term.`,
      ],
    },
    {
      heading: "2. Rent",
      paragraphs: [
        `Base Rent: $2,500 per month, due on the first of each month.`,
        `Late fee: 5% per month on any past-due rent.`,
      ],
    },
    {
      heading: "3. Premises and Condition",
      paragraphs: [
        `Tenant accepts the Premises "as is" and waives all habitability warranties to the maximum extent permitted by law.`,
      ],
    },
    {
      heading: "4. Modifications",
      paragraphs: [
        `Landlord may update these Terms at any time. By continued occupancy of the Premises, Tenant is deemed to have agreed to all updated Terms.`,
      ],
    },
    {
      heading: "5. Dispute Resolution",
      paragraphs: [
        `Tenant shall provide Landlord at least 30 days written notice of any claim before initiating suit.`,
      ],
    },
    {
      heading: "6. Non-Disparagement",
      paragraphs: [
        `Tenant shall not disparage Landlord, the Premises, or other tenants in any public forum.`,
      ],
    },
    {
      heading: "7. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of New York.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Property Owner  Date: ____________________`,
        `By: ____________________  Name: ____________________  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-residential-lease.docx"),
    await buildDocx(badResidentialLease),
  );

  // --- 9. Bad Master Services Agreement -----------------------------
  // Targets the msa-general playbook. Intentional violations:
  //   1. `Reasonable efforts` undefined (OBLI-008)
  //   2. MAC clause (OBLI-007)
  //   3. Indemnification without cap (RISK-015)
  //   4. Insurance without minimum (RISK-016)
  //   5. Governing law / venue mismatch (CHOICE-009)
  //   6. Asymmetric termination (TERM-009)
  //   7. `[Effective Date]` placeholder (STRUCT-013)
  const badMsa: Block[] = [
    {
      heading: "Master Services Agreement",
      paragraphs: [
        `This Master Services Agreement is entered into as of [Effective Date] between Provider Co. ("Provider") and Customer Inc. ("Customer"). Each Statement of Work executed under this Master Agreement is governed by its terms.`,
      ],
    },
    {
      heading: "1. Services",
      paragraphs: [
        `Provider shall use reasonable efforts to deliver the Services described in each SOW.`,
      ],
    },
    {
      heading: "2. Fees",
      paragraphs: [
        `Customer shall pay all fees on Net 30 terms.`,
      ],
    },
    {
      heading: "3. Conditions to Continued Performance",
      paragraphs: [
        `Provider's obligation to continue providing the Services is conditioned on the absence of any material adverse change in Customer's financial condition.`,
      ],
    },
    {
      heading: "4. Insurance",
      paragraphs: [
        `Customer shall maintain commercial general liability insurance during the Term.`,
      ],
    },
    {
      heading: "5. Indemnification",
      paragraphs: [
        `Customer shall indemnify, defend, and hold Provider harmless from any third-party claim arising from Customer's use of the Services.`,
      ],
    },
    {
      heading: "6. Termination",
      paragraphs: [
        `Provider may terminate this Agreement at any time in its sole discretion.`,
        `Customer shall terminate this Agreement only after providing 60 days written notice of material breach following a cure period.`,
      ],
    },
    {
      heading: "7. Governing Law and Venue",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
        `Exclusive venue shall be in the state and federal courts located in Texas.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Provider Lead  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Customer Lead  Title: CFO  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-msa.docx"), await buildDocx(badMsa));

  // --- 10. Bad SaaS Vendor Side ------------------------------------
  // Targets the saas-vendor playbook. Vendor-side concerns flipped
  // from saas-customer: aggressive uptime commitments, perpetual
  // licenses, IP indemnity scope without source-code escrow caveats,
  // weak warranty disclaimer (no "as is" framing).
  const badSaasVendor: Block[] = [
    {
      heading: "Master Subscription Agreement",
      paragraphs: [
        `This Master Subscription Agreement is entered into between Vendor Co. ("Provider") and Customer Inc. ("Customer"). Provider grants Customer access to the Service for the Subscription Term.`,
      ],
    },
    {
      heading: "1. The Service",
      paragraphs: [
        `Provider shall use best efforts to deliver the Service with 99.99% uptime each calendar month, measured by [TBD methodology].`,
        `Customer Data uploaded to the Service is processed under the DPA. The Service is provided AS-IS.`,
      ],
    },
    {
      heading: "2. Fees and Subscription Term",
      paragraphs: [
        `Customer shall pay an annual subscription fee of $50,000.00 due Net 30. Late fee: 2.5% per month.`,
      ],
    },
    {
      heading: "3. IP Indemnity",
      paragraphs: [
        `Provider shall indemnify, defend, and hold Customer harmless from any third-party claim that the Service infringes a US patent, copyright, or trade secret.`,
      ],
    },
    {
      heading: "4. Limitation of Liability",
      paragraphs: [
        `Provider's aggregate liability shall not exceed three (3) months of fees paid, except for indemnification obligations.`,
      ],
    },
    {
      heading: "5. Term and Renewal",
      paragraphs: [
        `Subscription Term: one (1) year, renewing automatically for successive one-year terms unless either party provides 20 days written notice of non-renewal.`,
      ],
    },
    {
      heading: "6. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "7. Signatures",
      paragraphs: [
        `By: ____________________  Name: Vince Vendor  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Caryn Customer  Title: COO  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-saas-vendor.docx"), await buildDocx(badSaasVendor));

  // --- 11. Bad Consulting Agreement --------------------------------
  // Targets the consulting-agreement playbook. Hybrid IC + advisory
  // with the same misclassification dark pattern as bad-contractor
  // but bigger fees + explicit deliverables (consulting-typical).
  const badConsulting: Block[] = [
    {
      heading: "Consulting Agreement",
      paragraphs: [
        `This Consulting Agreement is entered into between Hirer Inc. ("Customer") and Casey Consultant ("Consultant"), an independent contractor providing advisory services to Customer.`,
      ],
    },
    {
      heading: "1. Consulting Services",
      paragraphs: [
        `Consultant shall provide the Consulting Services during regular business hours, on-site at Customer's offices located in San Francisco, California.`,
        `Consultant shall use Customer-supplied equipment and shall report daily to Customer's designated supervisor.`,
      ],
    },
    {
      heading: "2. Compensation",
      paragraphs: [
        `Customer shall pay Consultant a flat monthly retainer of $15,000.00.`,
      ],
    },
    {
      heading: "3. Deliverables and Best Efforts",
      paragraphs: [
        `Consultant shall use best efforts to produce the Deliverables described in each Statement of Work.`,
      ],
    },
    {
      heading: "4. Intellectual Property",
      paragraphs: [
        `All work product produced by Consultant shall be work for hire owned exclusively by Customer.`,
      ],
    },
    {
      heading: "5. Exclusivity / Non-Compete",
      paragraphs: [
        `During the Term and for twelve (12) months thereafter, Consultant shall not directly or indirectly compete with Customer or perform services for any other party within the State of California.`,
      ],
    },
    {
      heading: "6. Non-Disparagement",
      paragraphs: [
        `Consultant shall not disparage Customer, its officers, or its products in any public or private communication.`,
      ],
    },
    {
      heading: "7. Termination",
      paragraphs: [
        `Customer may terminate this Agreement at any time in its sole discretion.`,
        `Consultant shall terminate this Agreement only after providing 60 days written notice of any material breach following a cure period.`,
      ],
    },
    {
      heading: "8. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "9. Signatures",
      paragraphs: [
        `By: ____________________  Name: Henry Hirer  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Casey Consultant  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-consulting.docx"), await buildDocx(badConsulting));

  // --- 12. Bad Statement of Work ------------------------------------
  // Targets the sow playbook (child of msa-general). Intentional
  // violations: undefined deliverables (best efforts language only),
  // scope creep clause, late fee, placeholder, no termination terms.
  const badSow: Block[] = [
    {
      heading: "Statement of Work #1",
      paragraphs: [
        `This SOW is entered into under the Master Agreement dated [TBD] between Provider and Customer.`,
      ],
    },
    {
      heading: "1. Services",
      paragraphs: [
        `Provider shall use best efforts to deliver the Deliverables described below.`,
      ],
    },
    {
      heading: "2. Deliverables and Milestones",
      paragraphs: [
        `Deliverables: as further detailed by Customer from time to time at Customer's sole discretion.`,
        `Milestones: TBD.`,
      ],
    },
    {
      heading: "3. Fees",
      paragraphs: [
        `Customer shall pay Provider $25,000 per milestone.`,
        `Late fee: 2% per month on past-due amounts.`,
      ],
    },
    {
      heading: "4. Scope Changes",
      paragraphs: [
        `Customer may unilaterally modify the scope of Services at any time without additional consideration.`,
      ],
    },
    {
      heading: "5. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Provider  Title: VP Delivery  Date: ____________________`,
        `By: ____________________  Name: Sam Sponsor  Title: VP Procurement  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-sow.docx"), await buildDocx(badSow));

  // ====================================================================
  // Research-driven fixture variants (added 2026-05-12 after a 3-agent
  // swarm surfaced common real-world drafting pitfalls). Each fixture
  // exercises a *distinct* pattern at the playbook level so users can
  // see specific dark patterns and rule reviewers can debug detection.
  // ====================================================================

  // --- 13. Mutual NDA — residuals + compelled-disclosure variant ----
  // Patterns: residuals clause that swallows the obligation; broad
  // compelled-disclosure carve-out with no notice mechanism; perpetual
  // confidentiality without trade-secret bifurcation.
  const badNdaResiduals: Block[] = [
    {
      heading: "Mutual Non-Disclosure Agreement",
      paragraphs: [
        `This Mutual Non-Disclosure Agreement is entered into between Acme Holdings, a Delaware corporation ("Discloser"), and Beta Capital ("Recipient"). The parties wish to discuss a potential business combination.`,
      ],
    },
    {
      heading: "1. Confidential Information",
      paragraphs: [
        `"Confidential Information" means any information disclosed by Discloser to Recipient, in any form, regardless of whether marked as confidential, regardless of the manner of disclosure, including all information learned through observation of Discloser's operations, personnel, or facilities.`,
      ],
    },
    {
      heading: "2. Residuals",
      paragraphs: [
        `Notwithstanding anything herein to the contrary, Recipient and its Representatives shall be free to use for any purpose the Residuals resulting from access to or work with Confidential Information, where "Residuals" means information in non-tangible form which may be retained in the unaided memory of persons who have had access to the Confidential Information.`,
      ],
    },
    {
      heading: "3. Compelled Disclosure",
      paragraphs: [
        `Recipient may disclose Confidential Information if required by law, court order, subpoena, or governmental request, or to its Affiliates, advisors, agents, and other representatives who have a need to know, without further obligation to Discloser.`,
      ],
    },
    {
      heading: "4. Term",
      paragraphs: [
        `The obligations of confidentiality set forth herein shall continue in perpetuity.`,
      ],
    },
    {
      heading: "5. Remedies",
      paragraphs: [
        `Recipient acknowledges that any breach will cause Discloser irreparable harm and Discloser shall be entitled to immediate injunctive relief without the necessity of proving actual damages or posting bond, and to liquidated damages of $250,000 per breach.`,
      ],
    },
    {
      heading: "6. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "7. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Acquirer  Title: SVP Corp Dev  Date: ____________________`,
        `By: ____________________  Name: Sam Target  Title: General Counsel  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-nda-residuals.docx"), await buildDocx(badNdaResiduals));

  // --- 14. Unilateral NDA — missing DTSA + SEC carve-out ------------
  // Patterns: confidentiality binding the recipient with no DTSA
  // 18 U.S.C. §1833(b) whistleblower notice and an express bar on
  // government-agency communication (SEC Rule 21F-17 risk).
  const badNdaNoDtsa: Block[] = [
    {
      heading: "One-Way Non-Disclosure Agreement",
      paragraphs: [
        `This One-Way NDA is entered into between MegaCorp Inc. ("Disclosing Party") and Jamie Engineer ("Receiving Party"). The Receiving Party will receive Confidential Information in connection with consulting services.`,
      ],
    },
    {
      heading: "1. Confidential Information",
      paragraphs: [
        `"Confidential Information" means all non-public information disclosed by the Disclosing Party.`,
      ],
    },
    {
      heading: "2. Obligations",
      paragraphs: [
        `The Receiving Party agrees to maintain in strict confidence all Confidential Information and shall not disclose any such information to any third party, including any governmental agency or regulatory body, without the prior written consent of the Disclosing Party.`,
      ],
    },
    {
      heading: "3. Term",
      paragraphs: [
        `The Receiving Party's obligations under this Agreement shall continue indefinitely.`,
      ],
    },
    {
      heading: "4. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of New York.`,
      ],
    },
    {
      heading: "5. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Manager  Title: Director  Date: ____________________`,
        `By: ____________________  Name: Jamie Engineer  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-nda-no-dtsa.docx"), await buildDocx(badNdaNoDtsa));

  // --- 15. Employment — TRAP + AMN-style non-solicit ----------------
  // Patterns: "stay-or-pay" training repayment (NLRB GC Memo 25-01),
  // California employee non-solicit (AMN Healthcare 2018), arbitration
  // ignoring mass-arb fee rules.
  const badEmploymentTrap: Block[] = [
    {
      heading: "Employment Agreement",
      paragraphs: [
        `This Employment Agreement is entered into between TechCo, a Delaware corporation ("Company"), and Alex Recruit, an exempt at-will employee based in Los Angeles, California.`,
      ],
    },
    {
      heading: "1. Compensation",
      paragraphs: [
        `Base salary: $140,000 per year, paid bi-weekly.`,
      ],
    },
    {
      heading: "2. Training Repayment",
      paragraphs: [
        `In consideration of the specialized training provided by Company (valued at $15,000), Employee agrees that if Employee voluntarily terminates employment or is terminated for cause within twenty-four (24) months of completion of training, Employee shall repay the full training cost to Company within thirty (30) days of separation.`,
      ],
    },
    {
      heading: "3. Non-Solicitation",
      paragraphs: [
        `For a period of twelve (12) months following the termination of Employee's employment with the Company for any reason, Employee shall not, directly or indirectly, solicit, recruit, induce, or otherwise encourage any employee of the Company to terminate his or her employment with the Company.`,
      ],
    },
    {
      heading: "4. Arbitration",
      paragraphs: [
        `Any dispute, claim, or controversy arising out of or relating to Employee's employment shall be resolved exclusively by final and binding arbitration before a single arbitrator administered by JAMS pursuant to its Employment Arbitration Rules then in effect. Employee waives any right to bring or participate in any class, collective, or representative action.`,
        `Employee hereby waives any right to a trial by jury in any action arising from this Agreement.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Riley Hr  Title: Head of People  Date: ____________________`,
        `By: ____________________  Name: Alex Recruit  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-employment-trap.docx"), await buildDocx(badEmploymentTrap));

  // --- 16. Employment — Delaware-law-on-CA-employee + IP overreach --
  // Patterns: choice-of-law evasion (Cal. Lab. Code §925 / §16600.5),
  // invention-assignment overreach beyond §2870 + holdover trailer,
  // non-compete in California.
  const badEmploymentChoiceOfLaw: Block[] = [
    {
      heading: "Employment Agreement",
      paragraphs: [
        `This Employment Agreement is entered into between WidgetCo, a Delaware corporation ("Company"), and Sam Inventor, an exempt at-will employee based in San Francisco, California.`,
      ],
    },
    {
      heading: "1. Invention Assignment",
      paragraphs: [
        `Employee hereby irrevocably assigns to the Company all right, title, and interest in any and all inventions, discoveries, improvements, and works of authorship conceived, developed, or reduced to practice by Employee, alone or with others, during the term of Employee's employment and for a period of one (1) year thereafter, whether or not during working hours or with use of Company resources.`,
      ],
    },
    {
      heading: "2. Non-Competition",
      paragraphs: [
        `For a period of twelve (12) months following termination, Employee shall not directly or indirectly compete with Company anywhere within North America.`,
      ],
    },
    {
      heading: "3. Governing Law and Venue",
      paragraphs: [
        `This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware, without regard to its conflict of laws principles.`,
        `Any dispute arising hereunder shall be litigated exclusively in the state or federal courts located in New Castle County, Delaware, and Employee hereby waives any objection to such venue.`,
      ],
    },
    {
      heading: "4. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Ceo  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Sam Inventor  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-employment-choice-of-law.docx"),
    await buildDocx(badEmploymentChoiceOfLaw),
  );

  // --- 17. IC — equipment leaseback + pre-existing IP sweep ---------
  // Patterns: forced equipment leaseback (FMCSA / ABC prong-C
  // analysis), IP sweep over pre-existing methodologies, hourly fee +
  // timesheets resembling wages.
  const badContractorLeaseback: Block[] = [
    {
      heading: "Independent Contractor Agreement",
      paragraphs: [
        `This Independent Contractor Agreement is entered into between FastShip Logistics ("Company") and Driver Owner-Operator ("Contractor"). Contractor is engaged as an independent contractor.`,
      ],
    },
    {
      heading: "1. Equipment Leaseback",
      paragraphs: [
        `Contractor shall lease the delivery vehicle and handheld scanner from Company at a weekly rate of $325, which Company shall deduct from each weekly settlement. Contractor may not use any vehicle or device not leased from or pre-approved by Company. Failure to maintain the lease in good standing shall constitute material breach of this Agreement.`,
      ],
    },
    {
      heading: "2. Compensation",
      paragraphs: [
        `Company shall pay Contractor an hourly rate of $22.00 for all hours worked, payable bi-weekly on the same schedule as Company's regular payroll. Contractor shall submit timesheets each Friday.`,
      ],
    },
    {
      heading: "3. Intellectual Property",
      paragraphs: [
        `Contractor hereby irrevocably assigns to Company all right, title, and interest, including all intellectual property rights, in and to any and all works, inventions, methods, processes, software, and materials created, conceived, developed, or used by Contractor in connection with the Services, whether developed before, during, or after the term of this Agreement.`,
      ],
    },
    {
      heading: "4. Indemnification",
      paragraphs: [
        `Contractor shall defend, indemnify, and hold harmless Company, its officers, directors, employees, agents, and affiliates from and against any and all claims, damages, losses, liabilities, costs, and expenses (including reasonable attorneys' fees) arising out of or relating in any way to the Services or this Agreement, regardless of the cause thereof, including claims caused in whole or in part by Company's own acts or omissions.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Operator  Title: VP Operations  Date: ____________________`,
        `By: ____________________  Name: Driver Owner-Operator  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-contractor-leaseback.docx"),
    await buildDocx(badContractorLeaseback),
  );

  // --- 18. SaaS Customer — data-hostage + AI training rights --------
  // Patterns: data-hostage termination, AI/model training over
  // Customer Data including PII, IP indemnity with combination
  // carve-out swallowing the rule.
  const badSaasDataHostage: Block[] = [
    {
      heading: "Cloud Service Agreement",
      paragraphs: [
        `This Cloud Service Agreement is entered into between AggressiveSaaS, Inc. ("Vendor") and Customer Co. Vendor provides the Service for the Subscription Term.`,
      ],
    },
    {
      heading: "1. Customer Data and Termination",
      paragraphs: [
        `Upon termination, Vendor may, at its discretion and upon Customer's payment of all amounts then due (including amounts subject to good-faith dispute), provide Customer with an export of Customer Data in a format selected by Vendor. Vendor's obligation to retain Customer Data shall expire seven (7) days after the effective date of termination.`,
      ],
    },
    {
      heading: "2. AI / Model Training Rights",
      paragraphs: [
        `Customer grants Vendor a perpetual, irrevocable, worldwide, royalty-free license to use, reproduce, and create derivative works from Customer Data (including any Personal Data therein) for the purposes of operating, improving, training, and developing Vendor's services, machine-learning models, and related products.`,
      ],
    },
    {
      heading: "3. IP Indemnity",
      paragraphs: [
        `Vendor shall have no obligation to indemnify Customer to the extent a claim arises from (i) use of the Services in combination with any software, hardware, data, or services not furnished by Vendor; or (ii) any modification of the Services not made by Vendor.`,
      ],
    },
    {
      heading: "4. Fees",
      paragraphs: [
        `Annual subscription fee: $40,000. Net 30 from invoice. Late fee: 2% per month on past-due amounts.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Vince Vendor  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Caryn Customer  Title: CFO  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-saas-data-hostage.docx"), await buildDocx(badSaasDataHostage));

  // --- 19. SaaS Customer — unilateral suspension + SLA credit token -
  // Patterns: vendor can suspend without notice; SLA failure remedied
  // by token credit declared exclusive; audit rights gated on vendor
  // consent (illusory).
  const badSaasSuspension: Block[] = [
    {
      heading: "Subscription Agreement",
      paragraphs: [
        `This Subscription Agreement is entered into between LeverageSaaS, Inc. ("Vendor") and Customer Inc.`,
      ],
    },
    {
      heading: "1. Suspension Rights",
      paragraphs: [
        `Vendor may suspend Customer's access to the Services, in whole or in part, immediately and without notice if Vendor determines in its sole discretion that Customer has breached this Agreement or that continued access poses a risk to Vendor or its other customers.`,
      ],
    },
    {
      heading: "2. Service Levels",
      paragraphs: [
        `If Vendor fails to meet the Monthly Uptime Commitment, Customer's sole and exclusive remedy shall be a service credit equal to five percent (5%) of the monthly fee for the affected month, not to exceed in the aggregate one (1) month of fees per calendar year. Customer expressly waives all other rights and remedies, including termination and damages.`,
      ],
    },
    {
      heading: "3. Audit",
      paragraphs: [
        `Customer may, no more than once per twenty-four (24) month period and subject to Vendor's prior written consent (not to be unreasonably withheld), request that Vendor provide its then-current SOC 2 Type II report in lieu of any on-site audit. No on-site or third-party audit shall be permitted without Vendor's prior written approval.`,
      ],
    },
    {
      heading: "4. Term and Renewal",
      paragraphs: [
        `Subscription Term: one (1) year, renewing automatically for successive one-year terms unless Customer provides written notice of non-renewal by certified mail to Vendor's General Counsel no fewer than ninety (90) days prior to the renewal date. Upon each renewal, Fees shall increase by the greater of seven percent (7%) or CPI-U.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of New York.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Vince Vendor  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Caryn Customer  Title: VP Procurement  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-saas-suspension.docx"), await buildDocx(badSaasSuspension));

  // --- 20. SaaS Vendor — uncapped IP indemnity + impossible portability
  // Patterns: uncapped IP indemnity with no modification covenant,
  // operationally impossible data portability, beta features rolled
  // into Service with no AS-IS.
  const badSaasVendorUncappedIp: Block[] = [
    {
      heading: "SaaS Vendor Agreement",
      paragraphs: [
        `This Agreement is entered into between NewVendor Co. ("Provider") and Customer Inc. ("Customer"). Provider grants Customer access to the Service.`,
      ],
    },
    {
      heading: "1. IP Indemnity",
      paragraphs: [
        `Provider shall defend, indemnify, and hold harmless Customer from any claim that the Services infringe any third-party intellectual property right, and shall pay all damages and costs awarded. The foregoing obligation shall not be subject to any limitation of liability set forth in this Agreement.`,
      ],
    },
    {
      heading: "2. Data Portability",
      paragraphs: [
        `Within thirty (30) days of any termination, Vendor shall, at no additional cost to Customer, deliver Customer Data in such file formats and schemas as Customer may reasonably request and provide such transition assistance as Customer deems necessary.`,
      ],
    },
    {
      heading: "3. The Service",
      paragraphs: [
        `"Services" means all features, modules, and functionality made available by Vendor through the platform, including any new features released during the term.`,
        `Provider guarantees 99.99% Monthly Uptime for the Services. "Downtime" means any period in which the Services are not available to Customer for any reason.`,
      ],
    },
    {
      heading: "4. Audit",
      paragraphs: [
        `Customer and its representatives may, upon five (5) business days' notice, enter Vendor's premises and inspect Vendor's systems, books, and records to verify compliance with this Agreement.`,
      ],
    },
    {
      heading: "5. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "6. Signatures",
      paragraphs: [
        `By: ____________________  Name: Vince Vendor  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Caryn Customer  Title: COO  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-saas-vendor-uncapped-ip.docx"),
    await buildDocx(badSaasVendorUncappedIp),
  );

  // --- 21. MSA — MFN pricing + change-of-control ratchet ------------
  // Patterns: MFN pricing, customer's unilateral scope-change right,
  // payment-on-acceptance with sole-discretion rejection,
  // anti-assignment ratchet on minority investment.
  const badMsaMfn: Block[] = [
    {
      heading: "Master Services Agreement",
      paragraphs: [
        `This Master Services Agreement is entered into between Provider LLC ("Provider") and AcquirerCo. ("Customer").`,
      ],
    },
    {
      heading: "1. Most-Favored-Nation Pricing",
      paragraphs: [
        `Provider represents and warrants that the fees charged hereunder are, and shall at all times during the Term remain, no less favorable than those offered to any other customer of Provider for substantially similar services. If Provider offers more favorable pricing to any other customer, Customer's pricing shall automatically be reduced to match, retroactive to the date such pricing was offered.`,
      ],
    },
    {
      heading: "2. Scope Changes",
      paragraphs: [
        `Customer may, in its sole discretion and upon written notice to Provider, modify the scope, specifications, or deliverables of any SOW. Provider shall implement such modifications at no additional cost and within the originally scheduled delivery date.`,
      ],
    },
    {
      heading: "3. Payment and Acceptance",
      paragraphs: [
        `Provider shall not invoice for any Deliverable until Customer has provided written acceptance of such Deliverable. Acceptance shall be in Customer's sole and absolute discretion. Customer may reject any Deliverable for any reason or no reason.`,
      ],
    },
    {
      heading: "4. Assignment / Change of Control",
      paragraphs: [
        `Customer shall not assign this Agreement, nor undergo any direct or indirect change of control (including any merger, consolidation, sale of substantially all assets, or any transaction resulting in any third party acquiring more than twenty percent (20%) of Customer's equity), without Provider's prior written consent, which may be withheld in Provider's sole discretion.`,
      ],
    },
    {
      heading: "5. Limitation of Liability",
      paragraphs: [
        `EACH PARTY'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT, WHETHER IN CONTRACT, TORT, OR OTHERWISE, SHALL NOT EXCEED THE FEES PAID BY CUSTOMER TO PROVIDER IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO THE CLAIM. THE FOREGOING LIMITATION SHALL APPLY NOTWITHSTANDING THE FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.`,
      ],
    },
    {
      heading: "6. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of Delaware.`,
      ],
    },
    {
      heading: "7. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Provider  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Sam Acquirer  Title: VP Procurement  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-msa-mfn.docx"), await buildDocx(badMsaMfn));

  // --- 22. Commercial Lease — uncapped CAM + gross-up + relocation -
  // Patterns: uncapped Operating Expenses with illusory audit
  // (Big-Four-only, 30-day, no contingent), asymmetric gross-up,
  // relocation at landlord discretion, never-sunsetting personal
  // guaranty.
  const badLeaseCam: Block[] = [
    {
      heading: "Office Lease",
      paragraphs: [
        `This Office Lease is entered into between Big Reit, Inc. ("Landlord") and Small Co, LLC ("Tenant"), for the premises located at 100 Building Way (the "Premises"), comprising 8,500 Rentable Square Feet.`,
      ],
    },
    {
      heading: "1. Term and Rent",
      paragraphs: [
        `Initial Term: five (5) years. Base Rent: $30,000 per month.`,
      ],
    },
    {
      heading: "2. Operating Expenses",
      paragraphs: [
        `Tenant shall pay its Proportionate Share of all Operating Expenses, which shall include without limitation all costs of any kind incurred by Landlord in connection with the ownership, operation, maintenance, repair and replacement of the Building. Tenant may, at Tenant's sole cost using a nationally recognized "Big Four" accounting firm engaged on a non-contingent basis, inspect Landlord's records within thirty (30) days of receipt of the annual statement, after which Tenant's audit rights shall be deemed irrevocably waived.`,
      ],
    },
    {
      heading: "3. Gross-Up",
      paragraphs: [
        `For any Comparison Year during which the Building is less than 100% occupied, Landlord shall gross up variable Operating Expenses to the amount that would have been incurred had the Building been 100% occupied. The Base Year Operating Expenses shall reflect actual Operating Expenses for the calendar year in which the Lease commences, regardless of occupancy.`,
      ],
    },
    {
      heading: "4. Landlord Relocation Right",
      paragraphs: [
        `Landlord may, upon thirty (30) days' written notice, relocate Tenant to any other space within the Building or any other building owned or managed by Landlord. Tenant shall execute an amendment confirming such relocation, and Landlord's determination of comparability shall be final and binding.`,
      ],
    },
    {
      heading: "5. Holdover",
      paragraphs: [
        `If Tenant remains in possession after expiration, Tenant shall pay holdover rent equal to two hundred percent (200%) of the Base Rent in effect immediately prior to expiration, and Tenant shall further indemnify Landlord for all direct, indirect and consequential damages arising from the holdover, including without limitation lost rent and liability to any successor tenant.`,
      ],
    },
    {
      heading: "6. Personal Guaranty",
      paragraphs: [
        `Guarantor absolutely, unconditionally and irrevocably guarantees the full and timely payment and performance of all obligations of Tenant under the Lease, including all extensions, renewals, holdover periods, and amendments hereto (whether or not Guarantor receives notice of the same). This Guaranty shall continue in full force regardless of any assignment, sublease, or change in control of Tenant.`,
      ],
    },
    {
      heading: "7. Insurance",
      paragraphs: [
        `Tenant shall maintain commercial general liability insurance during the Term.`,
      ],
    },
    {
      heading: "8. Governing Law",
      paragraphs: [
        `This Lease shall be governed by the laws of the State of New York.`,
      ],
    },
    {
      heading: "9. Signatures",
      paragraphs: [
        `By: ____________________  Name: Pat Property  Title: VP Leasing  Date: ____________________`,
        `By: ____________________  Name: Sam Smallco  Title: Managing Member  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(join(CONTRACTS, "bad-lease-cam.docx"), await buildDocx(badLeaseCam));

  // --- 23. Residential Lease — overcollected deposit + Javins waiver
  // Patterns: 2-month deposit (illegal in CA under AB 12 / NY GOL
  // §7-108), waiver of implied warranty of habitability (Javins),
  // any-time-no-notice entry (overrides Cal. Civ. §1954 / state
  // statutes), penalty-style early-termination fee.
  const badResidentialLeaseDeposit: Block[] = [
    {
      heading: "Residential Lease",
      paragraphs: [
        `This Residential Lease is entered into between Owner LLC ("Landlord") and Renter ("Tenant"), for the premises at 123 Main St, Apt 4B, Oakland, California (the "Premises").`,
      ],
    },
    {
      heading: "1. Rent and Term",
      paragraphs: [
        `Initial Term: 12 months. Base Rent: $2,500 per month.`,
      ],
    },
    {
      heading: "2. Security Deposit",
      paragraphs: [
        `Tenant shall deposit with Landlord two months' rent ($5,000) as a security deposit, plus an additional non-refundable cleaning fee of $500 and a non-refundable pet deposit of $750.`,
      ],
    },
    {
      heading: "3. Condition of Premises",
      paragraphs: [
        `Tenant accepts the Premises in "AS-IS, WHERE-IS" condition and waives any warranty of habitability, fitness for a particular purpose, or compliance with any housing code. Tenant's obligation to pay rent is absolute and not subject to setoff, abatement, or withholding for any reason, including alleged defects.`,
      ],
    },
    {
      heading: "4. Landlord Entry",
      paragraphs: [
        `Landlord and Landlord's agents may enter the Premises at any time, without prior notice, to inspect, make repairs, show the unit to prospective tenants or buyers, or for any other reasonable purpose.`,
      ],
    },
    {
      heading: "5. Early Termination",
      paragraphs: [
        `If Tenant terminates this Lease prior to the expiration date for any reason, Tenant shall pay an early termination fee equal to two months' rent in addition to all rent accruing through the original expiration date, and Landlord shall have no obligation to re-rent the Premises.`,
      ],
    },
    {
      heading: "6. Late Fees",
      paragraphs: [
        `If rent is not received by the 1st of the month, Tenant shall pay a late fee of $150, plus an additional $25 per day until paid in full.`,
      ],
    },
    {
      heading: "7. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Property Owner  Date: ____________________`,
        `By: ____________________  Name: Renter  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-residential-lease-deposit.docx"),
    await buildDocx(badResidentialLeaseDeposit),
  );

  // --- 24. Consulting — success fee + conflict waiver + IP sweep ----
  // Patterns: transaction-based success fee suggesting unregistered
  // broker-dealer activity (FINRA Rule 2040), advance blanket conflict
  // waiver, work-for-hire over pre-existing methodologies, broad post-
  // engagement non-solicit.
  const badConsultingSuccessFee: Block[] = [
    {
      heading: "Consulting and Advisory Agreement",
      paragraphs: [
        `This Consulting and Advisory Agreement is entered into between Capital Co. ("Client") and Casey Advisor ("Advisor"), an independent contractor providing M&A and capital-raising advisory services.`,
      ],
    },
    {
      heading: "1. Services",
      paragraphs: [
        `Advisor shall use best efforts to provide strategic, capital-raising, and M&A advisory services on a non-exclusive basis. Advisor shall also identify and introduce potential investors.`,
      ],
    },
    {
      heading: "2. Compensation",
      paragraphs: [
        `Client shall pay Advisor a monthly retainer of $10,000. In addition to the monthly retainer, upon the closing of any equity or debt financing introduced or facilitated by Advisor, Client shall pay Advisor a success fee equal to five percent (5%) of the gross proceeds raised.`,
      ],
    },
    {
      heading: "3. Conflicts of Interest",
      paragraphs: [
        `Client acknowledges that Advisor may, from time to time, provide services to other parties whose interests may be adverse to Client, including in transactions in which Client is or may become a counterparty, and Client hereby waives any actual or potential conflict of interest arising therefrom.`,
      ],
    },
    {
      heading: "4. Intellectual Property",
      paragraphs: [
        `All deliverables, work product, methodologies, frameworks, tools, templates, and any improvements, derivatives, or modifications thereto (whether pre-existing or developed during the engagement) shall be deemed "works made for hire" and the sole and exclusive property of Client. Advisor hereby irrevocably assigns all right, title, and interest therein to Client.`,
      ],
    },
    {
      heading: "5. Indemnification and Confidentiality",
      paragraphs: [
        `Advisor shall indemnify, defend and hold harmless Client from any claim arising out of or related to the Services. Advisor shall hold all Confidential Information in strict confidence and shall not disclose it to any third party for any reason whatsoever, including in connection with any legal proceeding, without Client's prior written consent.`,
      ],
    },
    {
      heading: "6. Non-Solicitation",
      paragraphs: [
        `For a period of three (3) years following termination of this Agreement for any reason, Advisor shall not, directly or indirectly, solicit, contact, accept business from, or perform services for any client, prospective client, employee, or contractor of Client, regardless of who initiates the contact and regardless of geographic location.`,
      ],
    },
    {
      heading: "7. Governing Law",
      paragraphs: [
        `This Agreement shall be governed by the laws of the State of California.`,
      ],
    },
    {
      heading: "8. Signatures",
      paragraphs: [
        `By: ____________________  Name: Hank Founder  Title: CEO  Date: ____________________`,
        `By: ____________________  Name: Casey Advisor  Date: ____________________`,
      ],
    },
  ];
  writeFileSync(
    join(CONTRACTS, "bad-consulting-success-fee.docx"),
    await buildDocx(badConsultingSuccessFee),
  );

  // --- 25. Pasted-text Mutual NDA ----------------------------------
  const pastedNda = mutualNda
    .map((b) => (b.heading ? `${b.heading}\n${b.paragraphs.join("\n")}` : b.paragraphs.join("\n")))
    .join("\n\n");
  writeFileSync(join(CONTRACTS, "pasted-mutual-nda.txt"), pastedNda);

  process.stdout.write("fixtures generated\n");
}

void main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});

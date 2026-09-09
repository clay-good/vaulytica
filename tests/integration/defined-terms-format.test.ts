/**
 * What a defined TERM is must not depend on where the line breaks fall.
 *
 * The defined-term table is its own surface: it reaches the DOCX appendix and
 * `report/definitions.ts`, which classifies each term as used, unused,
 * used-before-defined, or duplicated. No relation compared it, and the
 * extractor is the most layout-dependent thing in the tree — a "field block"
 * is recognized partly by how SHORT its paragraph is, and a paragraph's length
 * is a fact about the layout rather than about the document.
 *
 * Running the five format transforms over the corpus found 77 movers. Two were
 * real defects and are fixed:
 *
 *  - the smart-quotes transform renamed "Sellers' Representative" to
 *    "Sellers’ Representative", which is the same term — the usage matcher
 *    compared the apostrophe literally, so a document that defines a term with
 *    one and uses it with the other recorded `used_at: []`, and the report says
 *    of that: "defined but never used" (9.493.0);
 *  - a signature block read as a glossary, 21 terms across 16 specimens —
 *    "NORTHGATE RETAIL PARTNERS LLC By" is not a term any document defines
 *    (9.494.0).
 *  - a form's ROUTING INSTRUCTION read as a glossary entry, 7 terms — "TO THE
 *    OWNER", "AFTER RECORDING RETURN TO", "SEND ACKNOWLEDGMENT TO" (9.538.0).
 *
 * The 56 below are what is left, and they are two shapes:
 *
 *  - **junk GAINED** when a transform splits a signature or notice block into
 *    its own paragraphs — "Chief Executive Officer Date", "Marisol Trent
 *    Name". These are the `Date`/`Name`/`Title` labels deliberately left out of
 *    9.494.0's suppression set, because "Effective Date" and "Trade Name" are
 *    ordinary terms the corpus defines and suppressing them would cost far more
 *    than it saved;
 *  - **legitimate terms LOST** when the blank lines go, which is what a PDF
 *    copy-paste produces — a Schumer box loses "Penalty APR" and "Minimum
 *    Interest Charge" once its rows join into one paragraph.
 *
 * The second one has an obvious fix, and it is measured and wrong. The cause
 * is not the length cap (the joined box carries five labels and clears the
 * three-label branch) but the PREFIX test: the box's first row, "Annual
 * Percentage Rate (APR) for Purchases:", carries parentheses and a lowercase
 * connector, so `FIELD_LABEL` cannot capture it and everything up to the
 * SECOND label reads as prose. Accepting a run of three or more labels
 * whatever the paragraph opens with — which is the same reasoning the length
 * cap already accepts — recovers those two terms and **gains 112 others,
 * almost all signature-block junk**: a signature block joined into one
 * paragraph carries `By:`, `Name:`, `Title:` and `Date:`, which is a run of
 * four. The prefix test is load-bearing for exactly that, and the Schumer box
 * is the price.
 *
 * Neither is a finding: `format-invariance.test.ts` holds the finding set at
 * zero movers under these same transforms, and its debt lists are empty. This
 * surface is downstream of that one and is not yet at zero.
 *
 * Asserted by EQUALITY, so the list can only shrink on purpose: a new
 * divergence fails, and so does a repair that is not recorded.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

const stripBlankLines = (t: string): string =>
  t
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .join("\n");
const crlf = (t: string): string => t.replace(/\n/g, "\r\n");
const doubleSpaced = (t: string): string => t.split("\n").join("\n\n");

function hardWrap(text: string, width = 62): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim().length === 0) {
      out.push("");
      continue;
    }
    let rest = line.trim();
    while (rest.length > width) {
      const slice = rest.slice(0, width + 1);
      const cut = Math.max(slice.lastIndexOf(" "), slice.lastIndexOf("-"));
      if (cut <= 0) break;
      out.push(rest.slice(0, cut + (slice[cut] === "-" ? 1 : 0)).trimEnd());
      rest = rest.slice(cut + 1).trimStart();
    }
    out.push(rest);
  }
  return out.join("\n");
}

/** Word's paired curly quotes. It RENAMES a term that carries an apostrophe,
 * which is a real change to the text and so a legitimate divergence. */
function smartQuotes(text: string): string {
  let open = true;
  let out = "";
  for (const ch of text) {
    if (ch === '"') {
      out += open ? "\u201C" : "\u201D";
      open = !open;
    } else if (ch === "'") {
      out += "\u2019";
    } else {
      out += ch;
      if (ch === "\n") open = true;
    }
  }
  return out;
}

const TRANSFORMS: Array<[string, (t: string) => string]> = [
  ["blank lines stripped", stripBlankLines],
  ["CRLF", crlf],
  ["double-spaced", doubleSpaced],
  ["hard-wrapped", hardWrap],
  ["smart quotes", smartQuotes],
];

async function terms(text: string): Promise<string[]> {
  const ingest = await ingestPaste(text);
  return extractAll(ingest.tree)
    .definitions.entries.map((e) => e.term)
    .sort();
}

const TERM_FORMAT_DEBT: readonly string[] = [
  "83b-election.txt [blank lines stripped] lost:Elena Marie Vasquez Address gained:-",
  "83b-election.txt [double-spaced] lost:Elena Marie Vasquez Address gained:-",
  "advertising-insertion-order.txt [double-spaced] lost:Advertiser Advertiser,Brightwater Media Group LLC Agency,Spring Trail Series Flight Dates gained:Flight Dates,Media Company",
  "ca-employment-arbitration.txt [double-spaced] lost:- gained:Chief Executive Officer Date",
  "change-order.txt [double-spaced] lost:Building C Project Number,Change Order,LLC Contractor gained:Project Number",
  "channel-referral-agreement.txt [double-spaced] lost:- gained:Chief Revenue Officer Title,Marisol Trent Name",
  "coi.txt [blank lines stripped] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
  "coi.txt [double-spaced] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
  "commercial-indemnity-agreement.txt [double-spaced] lost:- gained:Manager Title,Marisol Trent Name",
  "commission-plan.txt [blank lines stripped] lost:Print Name gained:-",
  "credit-card.txt [blank lines stripped] lost:Minimum Interest Charge,Penalty APR gained:-",
  "cyber-policy.txt [double-spaced] lost:Named Insured Retroactive Date gained:Retroactive Date",
  "demand-for-inspection.txt [blank lines stripped] lost:PROPOUNDING PARTY,RESPONDING PARTY gained:-",
  "demand-letter.txt [double-spaced] lost:- gained:Our Client",
  "do-liability-policy.txt [double-spaced] lost:- gained:Named Insured,Policy Period",
  // 9.637.0 — the sixth clean document, and the same Annex shape the list
  // already carries: "Competent Supervisory Authority: the Irish Data
  // Protection Commission" is a FIELD BLOCK in Annex I, and once the blank
  // lines go its rows join into prose the field-label reader cannot see.
  "dpa-complete.txt [blank lines stripped] lost:Competent Supervisory Authority gained:-",
  "earnout.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
  "equipment-finance-lease.txt [blank lines stripped] lost:LLC LESSEE gained:-",
  "escrow-agreement-indemnity.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
  "fdd.txt [blank lines stripped] lost:Print Name gained:-",
  "fdd.txt [double-spaced] lost:- gained:TOTAL ESTIMATED INITIAL INVESTMENT",
  "fiscal-sponsorship.txt [double-spaced] lost:- gained:Executive Director Title,Rosalind Achebe Kwan Name",
  "hipaa-npp.txt [double-spaced] lost:Amaru Telephone gained:-",
  "il-employment-noncompete.txt [double-spaced] lost:- gained:Chief Executive Officer Date",
  "independent-contractor.txt [double-spaced] lost:- gained:Chief Executive Officer Date",
  "information-security-policy.txt [double-spaced] lost:Chief Information Security Officer Version gained:Policy Owner",
  "insurance-endorsement-additional-insured.txt [blank lines stripped] lost:Authorized Representative gained:-",
  "insurance-endorsement-additional-insured.txt [double-spaced] lost:- gained:Named Insured",
  "litigation-funding.txt [smart quotes] lost:Claimant's Counsel gained:Claimant’s Counsel",
  "marketing-services-agreement.txt [double-spaced] lost:- gained:Chief Marketing Officer Title,Marisol Trent Name",
  "option-grant.txt [blank lines stripped] lost:Expiration Date,Grant Date,Stock Exercise Price Per Share gained:-",
  "option-grant.txt [double-spaced] lost:Stock Exercise Price Per Share gained:Exercise Price Per Share",
  "order-form.txt [blank lines stripped] lost:Effective Date gained:-",
  "order-form.txt [double-spaced] lost:- gained:Named Users",
  "payment-performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
  "performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
  "ppm-narrative.txt [double-spaced] lost:- gained:Minimum Investment",
  "privacy-notice-multistate.txt [blank lines stripped] lost:Effective Date,Last Updated gained:-",
  "quitclaim-deed.txt [blank lines stripped] lost:Parcel Number gained:-",
  "requests-for-admission.txt [blank lines stripped] lost:DIAZ RESPONDING PARTY,PROPOUNDING PARTY gained:-",
  "requests-for-admission.txt [double-spaced] lost:DIAZ RESPONDING PARTY gained:RESPONDING PARTY",
  "residential-purchase.txt [blank lines stripped] lost:ESCROW AGENT ACKNOWLEDGMENT gained:-",
  "rsu-grant.txt [double-spaced] lost:- gained:Grant Date,Vesting Commencement Date",
  "saas-order-form-fields.txt [blank lines stripped] lost:Total Annual Fee,Total Order Value gained:-",
  "saas-order-form-fields.txt [double-spaced] lost:Start Date Subscription Start Date,USD Payment Terms gained:Annual Fee,Devon Achebe Name,Payment Terms",
  "secondary-stock-transfer.txt [double-spaced] lost:- gained:Priya Venkataraman Name",
  "security-incident-response-plan.txt [double-spaced] lost:Chief Information Security Officer Version gained:Plan Owner",
  "sow-numbered.txt [blank lines stripped] lost:Client Contact,Effective Date,Engagement Lead MSA Reference gained:-",
  "sow-numbered.txt [double-spaced] lost:Engagement Lead MSA Reference,Metering Supplier Contact gained:MSA Reference,Supplier Contact",
  "sow-under-msa.txt [double-spaced] lost:- gained:Managing Member Title,Marcus Ellery Doyle Name",
  "sub-processing-agreement.txt [double-spaced] lost:- gained:Director Title,Rosalind Achebe Kwan Name",
  "subscription-agreement.txt [double-spaced] lost:- gained:Aggregate Purchase Price",
  "term-sheet.txt [blank lines stripped] lost:Governing Law,Lead Investor,Other Investors gained:Founder Vesting",
  "ucc-1.txt [blank lines stripped] lost:IL POSTAL CODE gained:-",
  "uk-facility-agreement.txt [blank lines stripped] lost:Facility Amount,Governing Law gained:-",
  "us-state-privacy-addendum.txt [double-spaced] lost:- gained:General Counsel Title,Marisol Trent Name",
  "warrant.txt [blank lines stripped] lost:Issue Date gained:-",
];

describe("a defined term is not a function of the layout", () => {
  it("moves a term on only the specimens still owed", async () => {
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const base = await terms(text);
      if (base.length === 0) continue;
      probed++;
      for (const [label, fn] of TRANSFORMS) {
        const mutated = fn(text);
        if (mutated === text) continue;
        const after = await terms(mutated);
        if (after.join("|") === base.join("|")) continue;
        const B = new Set(base);
        const A = new Set(after);
        const lost = base.filter((t) => !A.has(t));
        const gained = after.filter((t) => !B.has(t));
        broken.push(
          `${name} [${label}] lost:${lost.slice(0, 3).join(",") || "-"} gained:${gained.slice(0, 3).join(",") || "-"}`,
        );
      }
    }
    expect(probed, "no specimen defines a term — the probe is vacuous").toBeGreaterThan(200);
    expect(broken).toEqual([...TERM_FORMAT_DEBT]);
  }, 600_000);
});

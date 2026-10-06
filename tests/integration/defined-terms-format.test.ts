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

// 9.831.0 — 57 → 47. Pasted text now keeps a form's "Label: value" lines
// apart, as a DOCX does, so the original reads "Subscription Start Date",
// "Payment Terms" and "Exercise Price Per Share" where it read "Start Date
// Subscription Start Date", "USD Payment Terms" and "Stock Exercise Price Per
// Share" — and most of the old entries were exactly that glue. What remains
// is the inverse: a rewrite that breaks the line structure (blank lines
// stripped, hard-wrapped) still glues.
const TERM_FORMAT_DEBT: readonly string[] = [
  "advertising-insertion-order.txt [blank lines stripped] lost:Flight Dates gained:-",
  "coi.txt [blank lines stripped] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
  "coi.txt [double-spaced] lost:INSURERS AFFORDING COVERAGE Insurer A gained:Insurer A",
  "construction-lien-waiver.txt [blank lines stripped] lost:Through Date gained:-",
  "credit-card.txt [blank lines stripped] lost:Minimum Interest Charge gained:-",
  "cta.txt [blank lines stripped] lost:- gained:Chief Executive Officer ACKNOWLEDGED",
  "cyber-policy.txt [blank lines stripped] lost:Continuity Date gained:-",
  "cyber-policy.txt [hard-wrapped] lost:Retroactive Date gained:Named Insured Retroactive Date",
  "demand-for-inspection.txt [blank lines stripped] lost:PROPOUNDING PARTY gained:-",
  "demand-letter.txt [blank lines stripped] lost:Our Client gained:-",
  "demand-letter.txt [hard-wrapped] lost:Our Client gained:-",
  "do-liability-policy.txt [hard-wrapped] lost:Policy Period gained:-",
  "earnout.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
  "employment-arbitration.txt [blank lines stripped] lost:- gained:Chief People Officer EMPLOYEE",
  "equipment-finance-lease.txt [blank lines stripped] lost:LLC LESSEE gained:-",
  "escrow-agreement-indemnity.txt [smart quotes] lost:Sellers' Representative gained:Sellers’ Representative",
  "fdd.txt [double-spaced] lost:- gained:TOTAL ESTIMATED INITIAL INVESTMENT",
  "information-security-policy.txt [double-spaced] lost:Thornapple Instruments Corporation Policy Owner gained:Policy Owner",
  "insurance-endorsement-additional-insured.txt [blank lines stripped] lost:Authorized Representative gained:-",
  "insurance-endorsement-additional-insured.txt [hard-wrapped] lost:Named Insured gained:-",
  "lease-loi.txt [blank lines stripped] lost:- gained:Managing Member ACKNOWLEDGED AND AGREED",
  "litigation-funding.txt [smart quotes] lost:Claimant's Counsel gained:Claimant’s Counsel",
  "option-grant.txt [blank lines stripped] lost:Expiration Date gained:-",
  "option-grant.txt [hard-wrapped] lost:Exercise Price Per Share,Expiration Date gained:-",
  "order-form.txt [blank lines stripped] lost:Effective Date gained:-",
  "partnership-agreement.txt [blank lines stripped] lost:- gained:Manager LIMITED PARTNERS",
  "payment-performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
  "performance-bond.txt [blank lines stripped] lost:Penal Sum gained:-",
  "ppm-narrative.txt [double-spaced] lost:- gained:Minimum Investment",
  "privacy-notice-multistate.txt [blank lines stripped] lost:Last Updated gained:-",
  "quitclaim-deed.txt [blank lines stripped] lost:Parcel Number gained:-",
  "remote-work.txt [blank lines stripped] lost:- gained:Chief People Officer EMPLOYEE",
  "requests-for-admission.txt [blank lines stripped] lost:PROPOUNDING PARTY gained:-",
  "rofr-co-sale.txt [blank lines stripped] lost:- gained:Chief Executive Officer KEY HOLDER",
  "ropa-art-30.txt [hard-wrapped] lost:Data Protection Officer,EU Representative gained:-",
  "saas-order-form-fields.txt [hard-wrapped] lost:Subscription Start Date gained:Start Date Subscription Start Date",
  "secondary-stock-transfer.txt [double-spaced] lost:- gained:Priya Venkataraman Name",
  "security-incident-response-plan.txt [double-spaced] lost:Thornapple Instruments Corporation Plan Owner gained:Plan Owner",
  "side-letter.txt [blank lines stripped] lost:- gained:Managing Member ACKNOWLEDGED AND AGREED",
  "sow-numbered.txt [blank lines stripped] lost:SOW Number gained:-",
  "stockholders-agreement.txt [blank lines stripped] lost:- gained:General Partner KEY HOLDER",
  "trademark-assignment.txt [blank lines stripped] lost:- gained:Managing Member ACCEPTED",
  "tx-conditional-lien-waiver.txt [blank lines stripped] lost:Through Date gained:-",
  "ucc-1.txt [blank lines stripped] lost:IL POSTAL CODE gained:-",
  "uk-facility-agreement.txt [blank lines stripped] lost:Facility Amount,Governing Law gained:-",
  "vc-side-letter.txt [blank lines stripped] lost:- gained:Executive Officer ACKNOWLEDGED AND AGREED",
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

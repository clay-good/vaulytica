/**
 * What the document SAYS is not a function of where its lines break.
 *
 * `extractAll` returns nine surfaces and only one of them — the defined-term
 * table — had a relation over it. Four of the others carry the document's
 * substance rather than its structure, and none of them should move when the
 * layout does: WHO the agreement is between, WHICH law governs it, HOW MUCH
 * money it names, and WHEN its clocks run. (`outline`, `crossrefs` and
 * `obligations` are deliberately absent: a section outline IS the layout, and
 * a transform that makes every line its own paragraph changes it correctly.)
 *
 * Running the five format transforms over the corpus found the extractor
 * reading past the end of a value wherever ingest joins a field block into one
 * paragraph. Three shapes were real and are fixed:
 *
 *  - a party named for two entities at once, because the name ran through the
 *    next field's label — "Ridgeline Constructors LLC Issued by: Cascadia
 *    Surety and Casualty Company", five specimens;
 *  - a party named twice, from a conformed signature block's `/s/` line joined
 *    to its printed-name line — "Anneke Vosberg Anneke Vosberg", five more;
 *  - a per-unit qualifier that read four words of ordinary prose, which the
 *    DOCX extracted-data appendix prints verbatim: "$2,000,000 per occurrence
 *    and", "$4,500 per month, payable in advance". 60 amounts across the
 *    corpus carried one; **none does now, and this relation holds amounts at
 *    ZERO movers.**
 *
 * What is left is recorded below by EQUALITY, so the lists can only shrink on
 * purpose.
 *
 * The SECOND of the two parties shapes is now fixed. A heading swallowed into
 * the name it sits above — "BOARD OF DIRECTORS OF HALCYON INSTRUMENTS",
 * "ARTICLES OF ORGANIZATION OF LAUREL RIDGE PROVISIONS" — turned out not to
 * need the title `matcher.ts` computes, and this comment used to say it did.
 * It needed only what the name itself shows: an ALL-CAPS run whose leading
 * phrase carries a noun that names a paper or a corporate body is a heading,
 * and the party is what follows its last connector. See `HEADING_NOUN` in
 * `src/extract/parties.ts` for why both signals are required and neither
 * alone. **34 junk party records left the corpus and no legitimate name did**;
 * the debt below fell from 124 lines to 114, and the signature-window fix
 * below took it to 57.
 *
 * The FIRST shape is now fixed too, and its cause was not the extractor's
 * reading of a signature block but WHERE it looked for one. The signature
 * window was the last 15% of PARAGRAPHS — a fraction of the paragraph count,
 * which measures how finely a document happens to be chunked and not how far
 * into it you are, which is exactly what these transforms change.
 * `option-grant.txt`'s "By: /s/ Rosalind Achebe" sits at index 17 of 21 as
 * written and at index 25 of 32 with every line its own paragraph, so a signer
 * vanished from a document whose text had not changed by one character. The
 * window is now floored in CHARACTERS, the way the preamble window at the
 * other end of the same function already was. **Six specimens gained a real
 * signer in their NATURAL layout** — each one a name a transformed variant was
 * already finding, and each pushed out of the naive fraction by the notary
 * acknowledgement or exhibit that follows the block. Debt 114 → 57.
 *
 * A third strip, the same ingest join one step further down: a field label
 * SHOUTED on its own line above the name it labels — "PRODUCER" over "Ashgrove
 * Insurance Brokers, LLC" on an ACORD certificate, "CONTRACTOR" over "Bramble
 * Construction Group, Inc." on a change order. `LEADING_ROLE` cannot reach
 * those either, for the same reason it could not reach a caption's role word:
 * it requires a comma that a field block does not write. Debt 57 → 53.
 *
 * And a fourth, the join read from the other side: a PERSON's name absorbed
 * into the FIRM's on the line below it — "Devarshi Nandakumar HOLLOWAY &
 * NANDAKUMAR", an attorney and their firm published as one entity. A legal
 * name does not switch out of Title Case into SHOUTING part-way through;
 * where it appears to, the shouted run is a different line. Debt 53 → 44.
 *
 * Four shapes, ONE cause: `ingestPaste` joins a short line to the line beneath
 * it, so anything a document stacks ABOVE a party's name is read as part of
 * that name. In every one of the four, CASE — not a vocabulary — is what marks
 * where the join happened.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import type { ExtractedData } from "../../src/extract/types.js";

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

/** Word's paired curly quotes. */
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

/**
 * Each surface projected to the VALUES it asserts, never to a position or to
 * the clause text a transform legitimately rewrites.
 */
const SURFACES: Record<string, (d: ExtractedData) => string[]> = {
  parties: (d) =>
    d.parties
      .map((p) =>
        [p.name, p.role ?? "", p.entity_type ?? "", p.jurisdiction_of_formation ?? ""].join("|"),
      )
      .sort(),
  jurisdictions: (d) =>
    d.jurisdictions.map((j) => [j.clause_kind, j.jurisdiction_id ?? ""].join("|")).sort(),
  amounts: (d) =>
    d.amounts
      .map((a) =>
        [a.currency, a.amount, a.word_form ? "w" : "n", a.range_max ?? "", a.per_unit ?? ""].join(
          "|",
        ),
      )
      .sort(),
  dates: (d) =>
    d.dates
      .map((x) =>
        [x.type, x.iso ?? "", x.anchor ?? "", x.offset_days ?? "", x.offset_days_max ?? ""].join(
          "|",
        ),
      )
      .sort(),
};

const PARTY_DEBT: readonly string[] = [
  "83b-election.txt [double-spaced] lost:- gained:Elena Marie Vasquez|||",
  "answer.txt [blank lines stripped] lost:- gained:WHEREFORE, Defendant Halloran Precision Castings||LLC|",
  "architect-agreement.txt [double-spaced] lost:- gained:Teodoro Vessel, AIA|||",
  "assignment-of-claim.txt [double-spaced] lost:- gained:Wexley DO GP II, LLC, its general partner|||",
  "baa.txt [double-spaced] lost:- gained:Ruth Okonjo, M.D|||",
  "bylaws-corporation.txt [double-spaced] lost:WREXHAM ANALYTICS, INC||corporation|Delaware gained:WREXHAM ANALYTICS||INC|",
  "cba.txt [double-spaced] lost:RIDGELINE AEROSPACE COMPONENTS, INC|Employer|INC| gained:RIDGELINE AEROSPACE COMPONENTS||INC|",
  "charter-incorporation.txt [blank lines stripped] lost:Corvid Optical Systems, Inc||corporation| gained:CORVID OPTICAL SYSTEMS, INC. Corvid Optical Systems||Inc|,Corvid Optical Systems||Inc|",
  "conflict-of-interest-policy.txt [double-spaced] lost:Pemberton Ridge Land Conservancy||corporation|Colorado gained:-",
  "convertible-note.txt [blank lines stripped] lost:VALUE RECEIVED, Northgate Instrument Company|Company|corporation|Delaware gained:Delaware FOR VALUE RECEIVED, Northgate Instrument Company|Company|corporation|Delaware",
  "demand-letter.txt [blank lines stripped] lost:Larkspur Timber Supply LLC|Client|LLC| gained:Larkspur Timber Supply|Larkspur|LLC|",
  "dissolution-plan.txt [double-spaced] lost:Alderbrook Instruments, Inc|Company|corporation|Delaware gained:Alderbrook Instruments|Company|Inc|",
  "escrow-agreement.txt [blank lines stripped] lost:- gained:Tallgrass Industrial GP LLC, its general partner|||",
  "escrow-agreement.txt [double-spaced] lost:- gained:Tallgrass Industrial GP LLC, its general partner|||",
  "expert-retention.txt [double-spaced] lost:Anneke Vosberg, Ph.D., P.E. Vosberg Forensic Engineering||LLC| gained:-",
  "fdd.txt [blank lines stripped] lost:TIDEWATER BOWL COMPANY, LLC||company|Virginia gained:TIDEWATER BOWL COMPANY||LLC|",
  "fdd.txt [double-spaced] lost:TIDEWATER BOWL COMPANY, LLC||company|Virginia gained:TIDEWATER BOWL COMPANY||LLC|",
  "flat-fee-agreement.txt [double-spaced] lost:Ravi Chandrasekaran-Boyd Chandrasekaran Robotics||LLC| gained:-",
  "healthcare-poa.txt [double-spaced] lost:- gained:Tobias Osgood-Reyes|||",
  "insurance-endorsement-additional-insured.txt [blank lines stripped] lost:Ridgeline Constructors LLC|Named Insured|LLC| gained:Ridgeline Constructors||LLC|",
  "joint-development.txt [double-spaced] lost:- gained:Annika Sjöberg|||",
  "joint-representation-waiver-founders.txt [double-spaced] lost:Raghunathan Mr. Daniel Ostrowski Kestrel Grove Bakery||LLC| gained:-",
  "lease-assignment-retail.txt [double-spaced] lost:- gained:Adaeze Nwachukwu, D.D.S|||",
  "lease-loi.txt [double-spaced] lost:Alina Fenwick Chief Operating Officer Northgate Diagnostics||Inc| gained:-",
  "minutes.txt [blank lines stripped] lost:Harborlight Analytics, Inc|Company|corporation|Delaware gained:HARBORLIGHT ANALYTICS, INC|Board|corporation|Delaware",
  "mutual-nda-letter.txt [double-spaced] lost:- gained:Desmond Achterberg|||,Ingeborg Fjeldstad|||",
  "notice-of-furnishing.txt [blank lines stripped] lost:- gained:This is a Notice of Furnishing under Ohio Revised Code § 1311.05. It is given to|Lender||",
  "operating-agreement.txt [blank lines stripped] lost:HARBOR POINT VENTURES LLC|Company|company|Delaware gained:HARBOR POINT VENTURES|Company|LLC|",
  "operating-agreement.txt [double-spaced] lost:HARBOR POINT VENTURES LLC|Company|company|Delaware gained:HARBOR POINT VENTURES|Company|LLC|",
  "payer-provider.txt [double-spaced] lost:- gained:Aaron Whitcombe, M.D|||",
  "physician-employment.txt [double-spaced] lost:- gained:Harold Lindstrom, M.D|||",
  "prenup.txt [smart quotes] lost:Party's||individual| gained:Party’s||individual|",
  "protective-order.txt [double-spaced] lost:- gained:Priya Raghunathan|||,Tobias Denholm|||",
  "saas-order-form-fields.txt [blank lines stripped] lost:ORDER FORM Northbridge Cloud||Inc| gained:Northbridge Cloud||Inc|",
  "saas-order-form-fields.txt [double-spaced] lost:ORDER FORM Northbridge Cloud||Inc| gained:Northbridge Cloud||Inc|",
  "secondary-stock-transfer.txt [double-spaced] lost:Marcus Ellery Doyle Priya Venkataraman||| gained:-",
  "side-letter.txt [double-spaced] lost:- gained:Kestrel Deepwater GP III, LLC, its general partner|||,Océane Lefèvre|||",
  "snda.txt [double-spaced] lost:- gained:Ignatius Mbeki-Sørheim|||",
  "sow-numbered.txt [double-spaced] lost:- gained:Ines Bhattacharya-Kovács|||",
  'sow.txt [smart quotes] lost:Halewood Data Systems LLC ("Supplier")|MSA|| gained:Halewood Data Systems LLC (“Supplier”)|MSA||',
  "sublease-office.txt [double-spaced] lost:- gained:Anneli Kiruna-Bergström|||",
  "term-sheet.txt [double-spaced] lost:- gained:Kestrel Deepwater GP III, LLC, its general partner|||,Océane Lefèvre|||",
  "trial-motion.txt [double-spaced] lost:Dashiell Tsukamoto Dashiell Tsukamoto Halloran & Tsukamoto||PLLC| gained:Dashiell Tsukamoto|||,Halloran & Tsukamoto||PLLC|",
  "uk-idta-addendum.txt [blank lines stripped] lost:- gained:Sable Notification Services||GmbH|",
];

const JURISDICTION_DEBT: readonly string[] = [
  "form-d-narrative.txt [double-spaced] lost:- gained:venue|",
];

/** The amount surface owes nothing. A new divergence here is a regression. */
const AMOUNT_DEBT: readonly string[] = [];

const DATE_DEBT: readonly string[] = [
  "saas-order-form-fields.txt [double-spaced] lost:- gained:relative||Subscription Start Date|720|",
];

const DEBT: Record<string, readonly string[]> = {
  parties: PARTY_DEBT,
  jurisdictions: JURISDICTION_DEBT,
  amounts: AMOUNT_DEBT,
  dates: DATE_DEBT,
};

describe("the extracted substance is not a function of the layout", () => {
  it("moves a value on only the specimens still owed", async () => {
    const seen: Record<string, string[]> = {
      parties: [],
      jurisdictions: [],
      amounts: [],
      dates: [],
    };
    const baseline: Record<string, number> = { parties: 0, jurisdictions: 0, amounts: 0, dates: 0 };
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const base = extractAll((await ingestPaste(text)).tree);
      for (const [surface, project] of Object.entries(SURFACES)) {
        baseline[surface] = (baseline[surface] ?? 0) + project(base).length;
      }
      for (const [label, fn] of TRANSFORMS) {
        const mutated = fn(text);
        if (mutated === text) continue;
        const got = extractAll((await ingestPaste(mutated)).tree);
        for (const [surface, project] of Object.entries(SURFACES)) {
          const before = project(base);
          const after = project(got);
          if (before.join("\n") === after.join("\n")) continue;
          const lost = before.filter((v) => !after.includes(v));
          const gained = after.filter((v) => !before.includes(v));
          seen[surface]!.push(
            `${name} [${label}] lost:${lost.join(",") || "-"} gained:${gained.join(",") || "-"}`,
          );
        }
      }
    }

    // Anti-vacuity: a green over an empty baseline proves nothing. Every
    // surface must actually be carrying values across the corpus.
    expect(baseline.parties).toBeGreaterThan(800);
    expect(baseline.jurisdictions).toBeGreaterThan(200);
    expect(baseline.amounts).toBeGreaterThan(600);
    expect(baseline.dates).toBeGreaterThan(1000);

    for (const surface of Object.keys(SURFACES)) {
      expect({ surface, moved: seen[surface]!.sort() }).toEqual({
        surface,
        moved: [...DEBT[surface]!],
      });
    }
  }, 180_000);
});

/**
 * A folder built to be awkward (spec-v52 §2).
 *
 * None of the 327 specimens is unmatched, unreadable, empty or tracked: the
 * corpus was written from the catalog, so every file in it reads cleanly and
 * matches a family. A folder page sorts exactly the files the corpus lacks, so
 * its tiers need fixtures of their own. Built on demand rather than committed:
 * three of them are binary, and each is a few lines of generator.
 *
 *   corrupt.docx        not a zip — cannot be read
 *   scan.pdf            pages with no text layer — read, and nothing in it
 *   empty.txt           zero bytes
 *   blank.txt           whitespace only
 *   tracked.docx        tracked insertions and deletions
 *   advance.txt         a merchant cash advance: no family, and none close
 *   advisor.txt         an advisor agreement: no family, one close (0.4)
 *   recipe.txt          not a legal document at all
 *   french.txt          a contract, not in English
 *   nda.txt             a complete mutual NDA — the ordinary case
 *   2023/msa.txt, 2024/msa.txt   one name in two folders
 *   copies/nda-copy.txt byte-identical to nda.txt
 *   logo.png            a type this tool does not read
 *   .DS_Store, .git/config        hidden, and said to be
 */
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { trackedChangesDocx } from "../../src/delivery/_fixtures.js";
import { scannedPdf } from "../integration/_mcp/pdf.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

export const MERCHANT_CASH_ADVANCE = `MERCHANT CASH ADVANCE AGREEMENT

This Merchant Cash Advance Agreement is entered into on March 3, 2026 between Harbor Funding LLC ("Funder") and Tidewater Bakery Inc. ("Merchant").

1. Purchase of Receivables. Funder purchases $80,000 of Merchant's future receivables for a purchase price of $60,000.

2. Specified Percentage. Merchant authorizes Funder to debit 12% of Merchant's daily card receipts from Merchant's bank account by ACH until the purchased amount has been delivered.

3. Confession of Judgment. Merchant irrevocably authorizes any attorney to appear for Merchant in any court and confess judgment against Merchant for the unpaid balance, without notice.

4. Personal Guaranty. The owner of Merchant personally guarantees Merchant's performance of this Agreement.
`;

export const ADVISOR_AGREEMENT = `ADVISOR AGREEMENT

This Advisor Agreement is between Kestrel Labs, Inc. (the "Company") and Priya Raman (the "Advisor").

1. Services. Advisor will advise the Company on product strategy for about four hours a month.

2. Equity. The Company will grant Advisor an option to purchase 10,000 shares of common stock, vesting monthly over two years.

3. Confidentiality. Advisor will keep the Company's confidential information confidential.

4. Assignment of Inventions. Advisor assigns to the Company all inventions made in the course of the services.
`;

export const RECIPE = `Sourdough, the slow way

Mix 500 grams of flour with 350 grams of water and leave it for an hour. Add 100 grams of starter and 10 grams of salt. Fold the dough every thirty minutes for three hours, shape it, and leave it in the refrigerator overnight. Bake in a covered pot at 250 degrees for twenty minutes, then uncovered for twenty more.
`;

export const FRENCH = `CONTRAT DE PRESTATION DE SERVICES

Le présent contrat est conclu entre la société Lumière SAS et la société Rivage SARL. Le prestataire s'engage à fournir les services décrits en annexe, et le client s'engage à en payer le prix dans un délai de trente jours à compter de la réception de la facture. Chaque partie s'engage à préserver la confidentialité des informations de l'autre partie et à ne pas les divulguer à des tiers sans son consentement préalable et écrit. Le présent contrat est régi par le droit français, et tout litige relatif à son exécution sera soumis aux tribunaux compétents de Paris.
`.repeat(3);

/** Every file the folder holds, by the kind of trouble it is. */
export const TRIAGE_FILES = {
  not_read: ["corrupt.docx", "scan.pdf", "empty.txt", "blank.txt"],
  caveat: ["tracked.docx", "french.txt"],
  unmatched: ["advance.txt", "advisor.txt", "recipe.txt"],
  matched: ["nda.txt", join("2023", "msa.txt"), join("2024", "msa.txt")],
  duplicate_of: { [join("copies", "nda-copy.txt")]: "nda.txt" },
  unsupported: ["logo.png"],
  hidden: [".DS_Store", ".git"],
} as const;

export function buildTriageFolder(dir: string): string {
  for (const sub of ["", "2023", "2024", "copies", ".git"]) {
    mkdirSync(join(dir, sub), { recursive: true });
  }
  writeFileSync(join(dir, "corrupt.docx"), "this is not a zip archive");
  writeFileSync(join(dir, "scan.pdf"), scannedPdf());
  writeFileSync(join(dir, "empty.txt"), "");
  writeFileSync(join(dir, "blank.txt"), "   \n\n\t\n");
  writeFileSync(join(dir, "tracked.docx"), new Uint8Array(trackedChangesDocx()));
  writeFileSync(join(dir, "advance.txt"), MERCHANT_CASH_ADVANCE);
  writeFileSync(join(dir, "advisor.txt"), ADVISOR_AGREEMENT);
  writeFileSync(join(dir, "recipe.txt"), RECIPE);
  writeFileSync(join(dir, "french.txt"), FRENCH);
  copyFileSync(join(SPECIMENS, "mutual-nda-complete.txt"), join(dir, "nda.txt"));
  copyFileSync(join(SPECIMENS, "mutual-nda-complete.txt"), join(dir, "copies", "nda-copy.txt"));
  copyFileSync(join(SPECIMENS, "msa-complete.txt"), join(dir, "2023", "msa.txt"));
  copyFileSync(join(SPECIMENS, "physician-employment.txt"), join(dir, "2024", "msa.txt"));
  writeFileSync(join(dir, "logo.png"), "not really an image");
  writeFileSync(join(dir, ".DS_Store"), "x");
  writeFileSync(join(dir, ".git", "config"), "[core]");
  return dir;
}

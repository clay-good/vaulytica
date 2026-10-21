/**
 * Mandated texts (add-mandated-text-conformance): passages a regulation or
 * statute fixes word for word, each as read at its official source.
 *
 * A row carries where it was read and when, so the provenance guard
 * (`mandated-texts.test.ts`) can refuse a row with none. Rows enter only from
 * an official source; no text is taken from a secondary one. The table lives
 * beside its rules until the scheduled DKB rebuild takes it in, the way the
 * Texas notices live in `regime-data.ts`.
 */

/** One way the mandated passage may be written: the regulation's alternatives are variants of one row. */
export type MandatedVariant = {
  /** The subsection that prescribes it, e.g. "§ 433.2(a)". */
  where: string;
  /** The passage as the authority prints it. */
  text: string;
};

export type MandatedText = {
  id: string;
  /** What the passage is, in a reader's words. */
  name: string;
  /** The authority, as a citation. */
  citation: string;
  /** Where it was read: an official source. */
  source_url: string;
  /** ISO date it was read. */
  retrieved_at: string;
  /** The version read (the amendment history the source prints). */
  version: string;
  variants: readonly MandatedVariant[];
  /** A form the authority requires of the passage. */
  form?: { bold?: boolean; min_points?: number; statement: string };
};

export const MANDATED_TEXTS: readonly MandatedText[] = [
  {
    id: "ftc-holder-notice",
    name: "FTC Holder Rule notice",
    citation: "16 C.F.R. § 433.2",
    source_url:
      "https://www.ecfr.gov/api/versioner/v1/full/2026-10-01/title-16.xml?part=433&section=433.2",
    retrieved_at: "2026-10-20",
    version: "40 FR 53506, Nov. 18, 1975; 40 FR 58131, Dec. 15, 1975",
    variants: [
      {
        where: "§ 433.2(a)",
        text: "NOTICE ANY HOLDER OF THIS CONSUMER CREDIT CONTRACT IS SUBJECT TO ALL CLAIMS AND DEFENSES WHICH THE DEBTOR COULD ASSERT AGAINST THE SELLER OF GOODS OR SERVICES OBTAINED PURSUANT HERETO OR WITH THE PROCEEDS HEREOF. RECOVERY HEREUNDER BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR HEREUNDER.",
      },
      {
        where: "§ 433.2(b)",
        text: "NOTICE ANY HOLDER OF THIS CONSUMER CREDIT CONTRACT IS SUBJECT TO ALL CLAIMS AND DEFENSES WHICH THE DEBTOR COULD ASSERT AGAINST THE SELLER OF GOODS OR SERVICES OBTAINED WITH THE PROCEEDS HEREOF. RECOVERY HEREUNDER BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR HEREUNDER.",
      },
    ],
    form: { bold: true, min_points: 10, statement: "in at least ten point, bold face, type" },
  },
];

/**
 * `titleCorpus` — the matcher's title input (regression).
 *
 * Title keywords are the single largest contributor to a playbook score
 * (0.3, against 0.2 per distinguishing phrase). Three production call
 * sites — the browser pipeline, the bundle pipeline, and the Node/CLI
 * pipeline — plus the parity test that simulates the browser path had each
 * built that input as:
 *
 *     ingest.tree.sections[0]?.heading ?? filename
 *
 * `??` catches null and undefined, not the **empty string** the tree
 * builder produces for a document with no styled heading. So every
 * plain-text or pasted document, and every DOCX whose title is bold body
 * text rather than a Heading style, reached the matcher with an empty
 * title — the largest signal silently unavailable, and not even the
 * filename fallback reached.
 *
 * The observable effect: a short, unambiguous engagement letter scored 0.4
 * against the 0.5 threshold and fell to `generic-fallback`, so none of its
 * family's checks ran. With the title seen it scores 0.7 and routes.
 *
 * Four copies of one line is the pattern worth remembering — the helper now
 * lives beside `matchPlaybook`, which is the only reason a fifth cannot
 * appear.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { titleCorpus, TITLE_PREAMBLE_CHARS, TITLE_SUBJECT_SCAN_PARAGRAPHS } from "./matcher.js";

type Tree = Parameters<typeof titleCorpus>[0];

const tree = (sections: Array<{ heading?: string; paragraphs: string[] }>): Tree =>
  ({
    sections: sections.map((s) => ({
      heading: s.heading,
      paragraphs: s.paragraphs.map((text) => ({ runs: [{ text }] })),
    })),
  }) as Tree;

describe("titleCorpus", () => {
  it("uses the first paragraph when the document has no styled heading", () => {
    // The defect: this returned "" and the filename fallback never fired.
    const t = tree([{ heading: "", paragraphs: ["Engagement Letter", "Dear Client:"] }]);
    expect(titleCorpus(t, "eng.txt")).toContain("Engagement Letter");
  });

  it("treats a whitespace-only heading as absent", () => {
    const t = tree([{ heading: "   \n ", paragraphs: ["Mutual Non-Disclosure Agreement"] }]);
    expect(titleCorpus(t, "doc.txt")).toContain("Mutual Non-Disclosure Agreement");
  });

  it("includes the heading and the preamble together when both are present", () => {
    const t = tree([{ heading: "Purchase Order", paragraphs: ["Terms and Conditions of Sale"] }]);
    const corpus = titleCorpus(t, "po.docx");
    expect(corpus).toContain("Purchase Order");
    expect(corpus).toContain("Terms and Conditions of Sale");
  });

  it("caps the preamble so a long first paragraph cannot outweigh the title", () => {
    // This is a *title* corpus. An unbounded first paragraph would let an
    // incidental mention of another family's title keyword outrank the
    // document's own name.
    const long = "x".repeat(TITLE_PREAMBLE_CHARS * 3);
    const t = tree([{ heading: "Bill of Sale", paragraphs: [long] }]);
    const corpus = titleCorpus(t, "bos.docx");
    expect(corpus.length).toBeLessThanOrEqual("Bill of Sale ".length + TITLE_PREAMBLE_CHARS);
  });

  it("falls back to the filename only when the document supplies nothing", () => {
    expect(titleCorpus(tree([{ heading: "", paragraphs: [""] }]), "fallback.txt")).toBe(
      "fallback.txt",
    );
    expect(titleCorpus(tree([]), "empty.txt")).toBe("empty.txt");
  });
});

describe("titleCorpus — a letter's subject line", () => {
  /**
   * A letter's first paragraph is the sender's letterhead, so the heading +
   * preamble corpus reads the wrong thing entirely. A reservation-of-rights
   * letter reached the matcher as "Meridian Casualty Insurance Company Claims
   * Department 4400 Harbor Point Drive", matched no playbook's title keyword,
   * and fell to `generic-fallback` at 0.4 — while the line the drafter wrote
   * to say what the document IS was four paragraphs down.
   */
  const letter = (subject: string, lead: string[] = []) =>
    tree([
      {
        heading: "",
        paragraphs: [
          "Meridian Casualty Insurance Company",
          "August 14, 2026",
          "Halloran Precision Castings, LLC",
          ...lead,
          subject,
          "Dear Mr. Halloran:",
        ],
      },
    ]);

  it("reads the Re: line as the letter's title", () => {
    expect(
      titleCorpus(letter("Re: Reservation of Rights — Claim No. MC-2026-118447"), "l.txt"),
    ).toContain("Reservation of Rights");
  });

  it("reads the Subject: and In re: conventions too", () => {
    expect(titleCorpus(letter("Subject: WARN Act Notice"), "l.txt")).toContain("WARN Act Notice");
    expect(titleCorpus(letter("In re: Estate of Dermot Halloran"), "l.txt")).toContain(
      "Estate of Dermot Halloran",
    );
  });

  it("still leads with the heading and preamble", () => {
    // The subject is added to the corpus, not substituted for it — a document
    // that has both a title and a subject line keeps both signals.
    const t = tree([
      { heading: "Demand Letter", paragraphs: ["Voss & Iyer LLP", "Re: Unpaid Invoices"] },
    ]);
    const corpus = titleCorpus(t, "d.txt");
    expect(corpus.startsWith("Demand Letter")).toBe(true);
    expect(corpus).toContain("Unpaid Invoices");
  });

  it("does not fire on prose that merely begins with those letters", () => {
    // Anchored to the paragraph start and to the colon, so neither an
    // ordinary sentence nor a defined term ending in "re" can trigger it.
    const t = tree([
      {
        heading: "",
        paragraphs: ["Reference is made to the Credit Agreement.", "Resale: permitted."],
      },
    ]);
    expect(titleCorpus(t, "x.txt")).not.toContain("permitted");
  });

  it("ignores a Re: buried deep in the body", () => {
    // A quoted piece of correspondence or an exhibit is not the document's
    // own subject.
    const filler = Array.from(
      { length: TITLE_SUBJECT_SCAN_PARAGRAPHS + 2 },
      (_, i) => `Paragraph ${i}.`,
    );
    const t = tree([{ heading: "", paragraphs: [...filler, "Re: Some Other Matter"] }]);
    expect(titleCorpus(t, "x.txt")).not.toContain("Some Other Matter");
  });

  it("leaves a document with no subject line byte-identical", () => {
    const t = tree([
      { heading: "Master Services Agreement", paragraphs: ["This Agreement is made…"] },
    ]);
    expect(titleCorpus(t, "msa.docx")).toBe("Master Services Agreement This Agreement is made…");
  });
});

describe("titleCorpus — a court filing's title below the caption", () => {
  /**
   * A filing opens on the court, then the party block, the docket number, and
   * the judge; only then does it say what it is. So the preamble the matcher
   * read was the name of a courthouse — identical for a complaint, an answer,
   * a motion to compel, and a set of interrogatory responses.
   */
  const filing = (title: string) =>
    tree([
      {
        heading: "",
        paragraphs: [
          "IN THE UNITED STATES DISTRICT COURT FOR THE NORTHERN DISTRICT OF ILLINOIS EASTERN DIVISION",
          "RIDGELINE AEROSPACE COMPONENTS, INC.,",
          "Plaintiff,",
          "v. Case No. 1:26-cv-04412 Hon. Marisol Aguirre-Vance HALLORAN PRECISION CASTINGS, LLC, Magistrate Judge Peter Lindqvist",
          "Defendant.",
          title,
          "Pursuant to Rules 26 and 33 of the Federal Rules of Civil Procedure, Defendant responds as follows.",
        ],
      },
    ]);

  it("skips the caption scaffolding and reads the filing's own title", () => {
    const corpus = titleCorpus(
      filing("DEFENDANT'S RESPONSES AND OBJECTIONS TO PLAINTIFF'S FIRST SET OF INTERROGATORIES"),
      "resp.txt",
    );
    expect(corpus).toContain("RESPONSES AND OBJECTIONS");
    expect(corpus).toContain("INTERROGATORIES");
  });

  it("keeps the court line too", () => {
    expect(titleCorpus(filing("COMPLAINT AT LAW AND DEMAND FOR JURY TRIAL"), "c.txt")).toContain(
      "DISTRICT COURT",
    );
  });

  it("does not engage on a document that does not open on a court line", () => {
    // The caption walk is gated on the first paragraph naming a court, so an
    // ordinary agreement is untouched — its second paragraph is body text,
    // not a title.
    const t = tree([
      {
        heading: "",
        paragraphs: [
          "Master Services Agreement",
          "This Agreement is entered into by Acme Inc. and Globex Inc.",
        ],
      },
    ]);
    expect(titleCorpus(t, "msa.txt")).toBe("Master Services Agreement");
  });

  it("does not mistake a sentence mentioning a court for a caption", () => {
    // The court test requires a paragraph with no sentence-ending period, so
    // an indemnity clause naming a court cannot start the caption walk.
    const t = tree([
      {
        heading: "",
        paragraphs: [
          "Any suit shall be brought in a court of competent jurisdiction.",
          "Indemnification. Each party shall indemnify the other.",
        ],
      },
    ]);
    expect(titleCorpus(t, "x.txt")).toBe(
      "Any suit shall be brought in a court of competent jurisdiction.",
    );
  });
});

describe("titleCorpus — the legends above the title", () => {
  /**
   * "EXECUTION VERSION", "CONFIDENTIAL", "PRIVILEGED AND CONFIDENTIAL —
   * ATTORNEY WORK PRODUCT" sit on the first line of a very large share of real
   * deal documents, and the preamble the matcher read was therefore the
   * legend. A mutual NDA carrying "EXECUTION VERSION" over "MUTUAL
   * NON-DISCLOSURE AGREEMENT" routed to `unilateral-nda`: the mutual
   * playbook's title keyword never hit, and the unilateral one won on "the
   * Disclosing Party" / "the Receiving Party", which a mutual NDA uses too
   * because each party is both.
   */
  it("reads past a stack of legends to the document's title", () => {
    const t = tree([
      {
        heading: "",
        paragraphs: [
          "EXECUTION VERSION",
          "CONFIDENTIAL",
          "MUTUAL NON-DISCLOSURE AGREEMENT",
          "This Mutual Non-Disclosure Agreement is entered into as of September 2, 2026.",
        ],
      },
    ]);
    expect(titleCorpus(t, "nda.txt")).toContain("MUTUAL NON-DISCLOSURE AGREEMENT");
  });

  it("reads a compound legend line", () => {
    const t = tree([
      {
        heading: "",
        paragraphs: [
          "PRIVILEGED AND CONFIDENTIAL — ATTORNEY WORK PRODUCT",
          "DRAFT — FOR DISCUSSION PURPOSES ONLY",
          "SETTLEMENT AGREEMENT AND MUTUAL RELEASE",
        ],
      },
    ]);
    expect(titleCorpus(t, "s.txt")).toContain("SETTLEMENT AGREEMENT AND MUTUAL RELEASE");
  });

  it("does not mistake a title that merely contains a legend word", () => {
    // The whole line must be legend tokens. "CONFIDENTIAL" is a legend;
    // "CONFIDENTIALITY AGREEMENT" is a title, and dropping it would lose the
    // only signal the document has.
    const t = tree([{ heading: "", paragraphs: ["CONFIDENTIALITY AGREEMENT", "Body text."] }]);
    expect(titleCorpus(t, "c.txt")).toBe("CONFIDENTIALITY AGREEMENT");
    const draft = tree([{ heading: "", paragraphs: ["DRAFTING CONVENTIONS", "Body text."] }]);
    expect(titleCorpus(draft, "d.txt")).toBe("DRAFTING CONVENTIONS");
  });

  it("reads past a bare container marker", () => {
    // An agreement attached as an exhibit is one of the commonest things a
    // reviewer drops in, and "EXHIBIT A" hid the title exactly as a legend
    // does.
    const t = tree([
      { heading: "", paragraphs: ["EXHIBIT A", "MUTUAL NON-DISCLOSURE AGREEMENT", "Body."] },
    ]);
    expect(titleCorpus(t, "ex.txt")).toContain("MUTUAL NON-DISCLOSURE AGREEMENT");
  });

  it("keeps a container marker that carries the title on the same line", () => {
    const t = tree([
      { heading: "", paragraphs: ["EXHIBIT A — FORM OF MUTUAL NON-DISCLOSURE AGREEMENT", "Body."] },
    ]);
    expect(titleCorpus(t, "ex.txt")).toContain("MUTUAL NON-DISCLOSURE AGREEMENT");
  });

  it("leaves a document that opens on its title byte-identical", () => {
    const t = tree([
      { heading: "", paragraphs: ["Master Services Agreement", "This Agreement is made…"] },
    ]);
    expect(titleCorpus(t, "msa.docx")).toBe("Master Services Agreement");
  });

  it("reads a caption that sits under a legend", () => {
    // The legends are dropped before the caption walk, so a filing stamped
    // "CONFIDENTIAL — SUBJECT TO PROTECTIVE ORDER" still has its title found.
    const t = tree([
      {
        heading: "",
        paragraphs: [
          "CONFIDENTIAL — SUBJECT TO PROTECTIVE ORDER",
          "IN THE UNITED STATES DISTRICT COURT FOR THE DISTRICT OF DELAWARE",
          "ACME INC.,",
          "Plaintiff,",
          "v. Case No. 1:26-cv-00114",
          "Defendant.",
          "PLAINTIFF'S MOTION TO COMPEL",
        ],
      },
    ]);
    expect(titleCorpus(t, "m.txt")).toContain("MOTION TO COMPEL");
  });
});

describe("the title corpus is documented as built", () => {
  /**
   * `docs/adding-a-playbook.md` tells a playbook author what `title_keywords`
   * are matched against, and it states two numbers. Both move with the code,
   * and a playbook authored against a stale cap is a family that silently does
   * not route — so they are pinned here rather than left to drift.
   */
  const DOC = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "adding-a-playbook.md"),
    "utf8",
  );

  it("states the preamble cap and the subject-line scan depth the code uses", () => {
    expect(DOC).toContain("capped at " + TITLE_PREAMBLE_CHARS + " characters");
    expect(DOC).toContain("first twelve paragraphs");
    expect(TITLE_SUBJECT_SCAN_PARAGRAPHS).toBe(12);
  });

  it("names every shape the corpus skips or reaches past", () => {
    // A sixth shape added to the matcher with no row here leaves the author
    // guessing; this is the cheapest thing that makes the omission visible.
    for (const shape of [
      "a letterhead",
      "a court caption",
      "a legend stamp",
      "an exhibit tab",
      "a securities legend",
    ]) {
      expect(DOC, `the shape table has no row for ${shape}`).toContain(shape);
    }
  });
});

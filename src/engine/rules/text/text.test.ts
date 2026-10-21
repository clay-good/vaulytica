/**
 * Mandated texts, slice A (add-mandated-text-conformance): the FTC Holder
 * Rule notice, as 16 C.F.R. § 433.2 prints it (read at eCFR 2026-10-20).
 * The words are checked against the regulation's, and its bold-face form
 * where the file carries formatting.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { ingestPaste } from "../../../ingest/paste.js";
import { ingestDocxBuffer } from "../../../ingest/docx.js";
import { extractAll } from "../../../extract/index.js";
import { buildDocx, documentXml } from "../../../delivery/_fixtures.js";
import type { RuleContext } from "../../finding.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { rule as TEXT_001 } from "./TEXT-001.js";
import { rule as TEXT_002 } from "./TEXT-002.js";

const [A, B] = MANDATED_TEXTS[0]!.variants.map((v) => v.text);
const BODY_A = A!.replace(/^NOTICE /, "");

async function pasted(text: string): Promise<RuleContext> {
  const { tree } = await ingestPaste(text);
  return { ...buildContext(["Agreement"]), tree, extracted: extractAll(tree) };
}

async function docx(
  notice: string,
  bold: boolean,
  opts: { halfPoints?: number; styles?: string } = {},
): Promise<RuleContext> {
  const run = (t: string, b: boolean, sz?: number) => {
    const rPr = `${b ? "<w:b/>" : ""}${sz ? `<w:sz w:val="${sz}"/>` : ""}`;
    return `<w:r>${rPr ? `<w:rPr>${rPr}</w:rPr>` : ""}<w:t xml:space="preserve">${t}</w:t></w:r>`;
  };
  const { tree } = await ingestDocxBuffer(
    buildDocx({
      document: documentXml(
        [
          `<w:p>${run("RETAIL INSTALLMENT SALE CONTRACT", true)}</w:p>`,
          `<w:p>${run("Buyer agrees to pay the Amount Financed in 36 monthly payments.", false)}</w:p>`,
          `<w:p>${run(notice, bold, opts.halfPoints)}</w:p>`,
        ].join(""),
      ),
      ...(opts.styles ? { styles: opts.styles } : {}),
    }),
  );
  return { ...buildContext(["Agreement"]), tree, extracted: extractAll(tree) };
}

const contract = (notice: string) =>
  `RETAIL INSTALLMENT SALE CONTRACT\n\nBuyer agrees to pay the Amount Financed in 36 monthly payments.\n\n${notice}\n`;

describe("TEXT-001 — the Holder Rule notice, altered", () => {
  it("accepts the notice as § 433.2(a) and (b) print it, in capitals or not, with or without its heading", async () => {
    for (const text of [A!, B!, A!.toLowerCase(), `NOTICE:\n\n${BODY_A}`, BODY_A]) {
      expect(TEXT_001.check(await pasted(contract(text))), text.slice(0, 40)).toBeNull();
    }
  });

  it("reports a notice with words dropped, and shows which", async () => {
    const f = TEXT_001.check(
      await pasted(contract(A!.replace("ALL CLAIMS AND DEFENSES", "CLAIMS"))),
    );
    expect(f?.rule_id).toBe("TEXT-001");
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(/16 C\.F\.R\. § 433\.2/);
    expect(f?.description).toContain(`the authority's "ALL … AND DEFENSES" is not in it`);
    expect(f?.excerpt.text).toMatch(/^ANY HOLDER .* HEREUNDER\.$/);
    expect(f?.recommendation).toContain(B!.slice(0, 20));
  });

  it("reports a notice with a word changed", async () => {
    const f = TEXT_001.check(
      await pasted(contract(A!.replace("SHALL NOT EXCEED", "MAY NOT EXCEED"))),
    );
    expect(f?.description).toMatch(/shall/i);
    expect(f?.description).toMatch(/may/i);
  });

  it("names the variant the document is closest to", async () => {
    const f = TEXT_001.check(
      await pasted(contract(B!.replace("RECOVERY HEREUNDER", "ANY RECOVERY HEREUNDER"))),
    );
    expect(f?.description).toMatch(/§ 433\.2\(b\)/);
  });

  it("says nothing about a document with no such notice", async () => {
    expect(
      TEXT_001.check(
        await pasted(contract("The holder of this note may assign it without notice.")),
      ),
    ).toBeNull();
  });
});

describe("TEXT-002 — the Holder Rule notice, not in bold face", () => {
  it("reports a Word file that sets the notice in regular type", async () => {
    const f = TEXT_002.check(await docx(A!, false));
    expect(f?.rule_id).toBe("TEXT-002");
    expect(f?.description).toMatch(/ten point, bold face/);
    expect(f?.description).toMatch(/none of it is bold/);
    expect(f?.description).toMatch(/point size is not stated in the file, so it was not checked/);
  });

  it("accepts the notice in bold", async () => {
    expect(TEXT_002.check(await docx(A!, true))).toBeNull();
  });

  it("says nothing where the file carries no formatting", async () => {
    expect(TEXT_002.check(await pasted(contract(A!)))).toBeNull();
  });
});

describe("the mandated-text table", () => {
  it("names an official source, a date read, and a version for every row", () => {
    for (const row of MANDATED_TEXTS) {
      expect(new URL(row.source_url).hostname, row.id).toMatch(
        /^(?:www\.ecfr\.gov|uscode\.house\.gov|leginfo\.legislature\.ca\.gov|statutes\.capitol\.texas\.gov)$/,
      );
      expect(row.retrieved_at, row.id).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(row.version.trim(), row.id).not.toBe("");
      expect(row.variants.length, row.id).toBeGreaterThan(0);
    }
  });
});

describe("the door-to-door cancellation statement, 16 C.F.R. § 429.1(a)", () => {
  const STATEMENT =
    "You, the buyer, may cancel this transaction at any time prior to midnight of the third business day after the date of this transaction. See the attached notice of cancellation form for an explanation of this right.";

  it("is not held to its exact words, which the rule allows to vary", async () => {
    const reworded = STATEMENT.replace("See the attached", "See the enclosed");
    expect(TEXT_001.check(await pasted(contract(reworded)))).toBeNull();
    expect(
      TEXT_001.check(await pasted(contract(STATEMENT.replace("You, the buyer,", "You")))),
    ).toBeNull();
  });

  it("is held to its bold face in a Word file", async () => {
    const f = TEXT_002.check(await docx(STATEMENT, false));
    expect(f?.title).toMatch(
      /door-to-door cancellation statement is not in the required bold face/,
    );
    expect(f?.description).toMatch(
      /16 C\.F\.R\. § 429\.1\(a\) requires the notice in bold face type of a minimum size of 10 points/,
    );
    expect(TEXT_002.check(await docx(STATEMENT, true))).toBeNull();
  });
});

describe("TEXT-002 — the point size", () => {
  const STYLES = (halfPoints: number) =>
    `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="${halfPoints}"/></w:rPr></w:rPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>`;

  it("reports a bold notice set smaller than ten points", async () => {
    const f = TEXT_002.check(await docx(A!, true, { halfPoints: 16 }));
    expect(f?.title).toMatch(/not in the required size/);
    expect(f?.description).toMatch(/it is set in 8-point type/);
  });

  it("reads the size from the document defaults when the run states none", async () => {
    expect(TEXT_002.check(await docx(A!, true, { styles: STYLES(24) }))).toBeNull();
    const small = TEXT_002.check(await docx(A!, true, { styles: STYLES(18) }));
    expect(small?.description).toMatch(/9-point/);
  });

  it("says both when the notice is neither bold nor large enough", async () => {
    const f = TEXT_002.check(await docx(A!, false, { halfPoints: 14 }));
    expect(f?.title).toMatch(/bold face or size/);
    expect(f?.description).toMatch(/none of it is bold, and it is set in 7-point type/);
  });
});

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { screenLanguage, languageFields } from "./language.js";
import { ingestPaste } from "./paste.js";
import type { DocumentTree } from "./types.js";

/**
 * The defect this file guards. The engine's rules are English regexes, so a
 * translated contract does not fail loudly — it matches almost nothing and
 * returns a short findings list indistinguishable from a clean document. The
 * measurement that motivated the screen: one mutual NDA drew 23 findings in
 * English and 3 in its own Spanish translation, with identical warnings.
 */

const ENGLISH_NDA = `MUTUAL NON-DISCLOSURE AGREEMENT

This Mutual Non-Disclosure Agreement is entered into as of January 1, 2026, by and between Acme Corporation, a Delaware corporation, and Beta Industries LLC, a New York limited liability company.

1. Confidential Information. Each party may disclose to the other certain confidential and proprietary information relating to its business, products, and technology.

2. Obligations. The receiving party shall hold the disclosing party's Confidential Information in strict confidence and shall not disclose it to any third party without the prior written consent of the disclosing party.

3. Term. This Agreement shall commence on the Effective Date and continue for a period of three (3) years, unless earlier terminated by either party upon thirty (30) days' prior written notice.

4. Governing Law. This Agreement shall be governed by and construed in accordance with the laws of the State of New York, without regard to its conflict of laws principles.`;

const SPANISH_NDA = `CONTRATO MUTUO DE CONFIDENCIALIDAD

Este Contrato Mutuo de Confidencialidad se celebra el 1 de enero de 2026, entre Acme Corporation, una sociedad de Delaware, y Beta Industries LLC, una sociedad de responsabilidad limitada de Nueva York.

1. Información Confidencial. Cada parte podrá revelar a la otra cierta información confidencial y de propiedad relativa a su negocio, productos y tecnología.

2. Obligaciones. La parte receptora mantendrá la Información Confidencial de la parte reveladora en estricta confidencialidad y no la revelará a ningún tercero sin el consentimiento previo por escrito de la parte reveladora.

3. Plazo. Este Contrato comenzará en la Fecha de Entrada en Vigor y continuará por un período de tres años, salvo que sea terminado anticipadamente por cualquiera de las partes mediante notificación previa por escrito de treinta días.

4. Ley Aplicable. Este Contrato se regirá e interpretará de conformidad con las leyes del Estado de Nueva York, sin atender a sus principios sobre conflicto de leyes.`;

const FRENCH_NDA = `CONTRAT DE CONFIDENTIALITE

Le présent contrat est conclu entre les parties, et il est convenu que chacune des parties pourra communiquer à l'autre des informations confidentielles relatives à ses activités, à ses produits et à sa technologie.

La partie destinataire conservera les informations confidentielles de la partie divulgatrice dans la plus stricte confidentialité et ne les communiquera à aucun tiers sans le consentement écrit préalable de la partie divulgatrice.

Le présent contrat prend effet à la date d'entrée en vigueur et se poursuit pour une durée de trois ans, sauf résiliation anticipée par l'une ou l'autre des parties moyennant un préavis écrit de trente jours.

Le présent contrat est régi par le droit de l'État de New York.`;

const GERMAN_NDA = `GEHEIMHALTUNGSVEREINBARUNG

Diese Vereinbarung wird zwischen den Parteien geschlossen, und es wird vereinbart, dass jede der Parteien der anderen bestimmte vertrauliche Informationen über ihr Geschäft, ihre Produkte und ihre Technologie offenlegen kann.

Die empfangende Partei wird die vertraulichen Informationen der offenlegenden Partei streng vertraulich behandeln und sie ohne die vorherige schriftliche Zustimmung der offenlegenden Partei nicht an Dritte weitergeben.

Diese Vereinbarung tritt am Tag des Inkrafttretens in Kraft und gilt für einen Zeitraum von drei Jahren, sofern sie nicht von einer der Parteien mit einer Frist von dreißig Tagen schriftlich gekündigt wird.

Diese Vereinbarung unterliegt dem Recht des Staates New York.`;

describe("screenLanguage", () => {
  it("reads English legal prose as English and says nothing", () => {
    expect(screenLanguage(ENGLISH_NDA)).toEqual({ code: "en", notice: null });
  });

  it.each([
    ["Spanish", SPANISH_NDA, "es"],
    ["French", FRENCH_NDA, "fr"],
    ["German", GERMAN_NDA, "de"],
  ])("names %s and warns", (name, text, code) => {
    const screen = screenLanguage(text);
    expect(screen.code).toBe(code);
    expect(screen.notice).toContain(`appears to be ${name}`);
  });

  it("warns without a name when the script is not in the table at all", () => {
    // Chinese does not tokenize into any of the Latin-script function words,
    // so no candidate clears its floor. The document is still not English and
    // still gets the warning — naming is a courtesy, not the point.
    const zh =
      "保密协议。本协议由双方签订，各方可以向另一方披露与其业务、产品和技术有关的某些保密信息。接收方应对披露方的保密信息严格保密，未经披露方事先书面同意，不得向任何第三方披露。本协议自生效之日起生效，有效期为三年，除非任何一方提前三十天书面通知终止。".repeat(
        4,
      );
    const screen = screenLanguage(zh);
    expect(screen.code).toBeUndefined();
    expect(screen.notice).toContain("does not read as English");
    expect(screen.notice).not.toContain("appears to be");
  });

  it("says nothing about a sample too short to judge", () => {
    // A caption, a stub, or an empty paste carries no evidence either way,
    // and a false accusation of foreignness is worse than a missing one.
    expect(screenLanguage("This Agreement is short.")).toEqual({ notice: null });
    expect(screenLanguage("")).toEqual({ notice: null });
  });

  it("warns that a short findings list is not a clean bill of health", () => {
    // The whole point of the notice: the reader must not mistake "nothing
    // matched" for "nothing wrong".
    expect(screenLanguage(SPANISH_NDA).notice).toContain("NOT that the document is sound");
  });

  it("is not fooled by an English title on a foreign body", () => {
    // A translated agreement often keeps an English caption or party names.
    const screen = screenLanguage(`MUTUAL NON-DISCLOSURE AGREEMENT\n\n${SPANISH_NDA}`);
    expect(screen.code).toBe("es");
  });
});

/**
 * The floor is a constant, and a constant with no counter-pressure drifts
 * upward until it starts accusing real documents. Every specimen in the
 * corpus is English legal prose; all of them must screen clean.
 */
describe("the specimen corpus is English", () => {
  const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
  const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

  it("has specimens to check", () => {
    expect(SPECIMENS.length).toBeGreaterThan(300);
  });

  it("screens every specimen as English with no warning", () => {
    const accused: string[] = [];
    for (const f of SPECIMENS) {
      const screen = screenLanguage(readFileSync(join(DIR, f), "utf8"));
      if (screen.code !== "en" || screen.notice !== null) accused.push(f);
    }
    expect(accused).toEqual([]);
  });
});

describe("languageFields", () => {
  const tree = (text: string): DocumentTree => ({
    type: "document",
    sections: [
      {
        id: "s1",
        heading: "",
        level: 1,
        paragraphs: [{ id: "s1.p0", runs: [{ id: "s1.p0.r0", text, start: 0, end: text.length }] }],
        children: [],
      },
    ],
  });

  it("adds nothing to the warnings of an English document", () => {
    const warnings = ["existing"];
    expect(languageFields(tree(ENGLISH_NDA), warnings)).toEqual({ language: "en" });
    expect(warnings).toEqual(["existing"]);
  });

  it("puts the notice FIRST, ahead of every other warning", () => {
    // It reframes everything below it — including the findings list — so a
    // reader who scans one line must see this one.
    const warnings = ["existing"];
    expect(languageFields(tree(SPANISH_NDA), warnings)).toEqual({ language: "es" });
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain("Spanish");
    expect(warnings[1]).toBe("existing");
  });
});

describe("ingest wiring", () => {
  it("declares the language of a pasted English document", async () => {
    const result = await ingestPaste(ENGLISH_NDA);
    expect(result.language).toBe("en");
    expect(result.warnings.some((w) => w.includes("does not read as English"))).toBe(false);
  });

  it("declares — and warns about — a pasted Spanish document", async () => {
    const result = await ingestPaste(SPANISH_NDA);
    expect(result.language).toBe("es");
    expect(result.warnings[0]).toContain("appears to be Spanish");
  });
});

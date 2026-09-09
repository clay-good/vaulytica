/**
 * Verification certificate (add-court-certification-receipt).
 *
 * The certificate is a compliance artifact — the tests pin the three
 * properties that make it safe to attach to a filing: deterministic
 * (pure function of the run, no clock), self-limiting (certifies the
 * tool's operation only, never the filer's compliance; attorney duty
 * stated), and tamper-evident (namespaced certificate_hash re-derivable
 * from the body). It must never embed document text beyond the file
 * name.
 */

import { describe, expect, it } from "vitest";
import {
  buildCertificate,
  buildCertificateDocx,
  buildCertificateJson,
  certificateDocxBlob,
  certificateJsonBlob,
  certificateStatements,
  verifyCertificateHash,
  CERTIFICATE_SCHEMA,
} from "./certificate.js";
import type { EngineRun } from "../engine/finding.js";

const run = {
  version: "9.41.0",
  dkb_version: "v2026-07-04-r2-local",
  playbook_id: "mutual-nda",
  source_file: { name: "nda.docx", sha256: "a".repeat(64), size_bytes: 9667 },
  result_hash: "b".repeat(64),
  findings: [
    {
      rule_id: "FIN-001",
      excerpt: { text: "SECRET CLIENT TEXT THAT MUST NEVER APPEAR" },
      explanation: "x",
    },
  ],
  execution_log: [],
  executed_at: "",
} as unknown as EngineRun;

describe("buildCertificate", () => {
  it("is deterministic and hash-verifiable", async () => {
    const a = await buildCertificateJson(run);
    const b = await buildCertificateJson(run);
    expect(a).toBe(b);
    const cert = await buildCertificate(run);
    expect(cert.schema).toBe(CERTIFICATE_SCHEMA);
    expect(await verifyCertificateHash(cert)).toBe(true);
  });

  it("is tamper-evident: any edited field fails the hash check", async () => {
    const cert = await buildCertificate(run);
    expect(await verifyCertificateHash({ ...cert, result_hash: "c".repeat(64) })).toBe(false);
    expect(
      await verifyCertificateHash({
        ...cert,
        tool: { ...cert.tool, dkb_version: "v9999-forged" },
      }),
    ).toBe(false);
  });

  it("records asserted opt-in packs (present, verifiable, absent by default)", async () => {
    // Plain run: no asserted_packs, byte-identical certificate.
    const plain = await buildCertificate(run);
    expect(plain.asserted_packs).toBeUndefined();

    const withPacks = {
      ...run,
      filing_profile: {
        id: "frap-default",
        version: "2026-07-15",
        court_name: "FRAP",
        brief_kind: "principal",
        authority: [],
      },
      estate_checks_asserted: true,
    } as unknown as EngineRun;
    const cert = await buildCertificate(withPacks);
    expect(cert.asserted_packs?.court_profile).toBe("frap-default");
    expect(cert.asserted_packs?.estate_checks).toBe(true);
    expect(await verifyCertificateHash(cert)).toBe(true);
    // The asserted packs are inside the tamper-evident hash.
    expect(await verifyCertificateHash({ ...cert, asserted_packs: undefined })).toBe(false);
    // And a plain-run certificate hash is unaffected.
    expect(plain.certificate_hash).toBe((await buildCertificate(run)).certificate_hash);
  });

  it("never embeds document text beyond the file name", async () => {
    const json = await buildCertificateJson(run);
    expect(json).toContain("nda.docx");
    expect(json).not.toContain("SECRET CLIENT TEXT");
  });

  it("certifies the tool's operation only — never the filer's compliance", () => {
    const text = certificateStatements(run).join(" ");
    expect(text).toContain("It certifies what this tool did");
    expect(text).toContain("does not certify");
    expect(text).toContain("ABA Formal Opinion 512");
    expect(text).toContain("not legal advice");
    // The privacy-approved claim — never an absolute no-network claim.
    expect(text).toContain("same-origin fetches of the tool's own static assets");
    expect(text).not.toMatch(/zero network|no network calls/i);
  });

  it("carries the exact reproduction command", async () => {
    const cert = await buildCertificate(run);
    expect(cert.reproduce_command).toBe('vaulytica verify <report.json> "nda.docx"');
  });
});

/**
 * The DOCX is the artifact a filer actually hands to a court — and nothing
 * exercised it. `buildCertificateDocx`, the label it prints for the asserted
 * packs, and both Blob wrappers were the only functions in this module no test
 * called, which is the same gap the export Blob wrappers had: the path the
 * product takes is not the path the tests take.
 *
 * What a rendering test has to check here is unusual. The five statements were
 * written to survive a legal review — the scope limit, the no-AI claim, the
 * privacy claim in its approved form, and the attorney's own duty under ABA
 * Formal Opinion 512. A certificate that silently dropped one would still open
 * in Word, still verify its hash, and still be wrong in front of a judge. So
 * the test reads the rendered text and requires every statement, verbatim.
 */
describe("buildCertificateDocx", () => {
  const text = async (blob: Blob): Promise<string> => {
    const { unzipSync, strFromU8 } = await import("fflate");
    const xml = strFromU8(
      unzipSync(new Uint8Array(await blob.arrayBuffer()))["word/document.xml"]!,
    );
    // Word splits a paragraph across runs; the text is what survives the tags,
    // with XML entities read back — the reproduce command contains angle
    // brackets and every statement contains an apostrophe.
    return xml
      .replace(/<[^>]+>/g, "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "\u0027")
      .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
      .replace(/&amp;/g, "&");
  };

  it("renders every field of the certificate model", async () => {
    const cert = await buildCertificate(run);
    const body = await text(await buildCertificateDocx(run));
    for (const [label, value] of [
      ["Tool", `Vaulytica (engine ${cert.tool.engine_version})`],
      ["Knowledge base", cert.tool.dkb_version],
      ["Input file", cert.input.name],
      ["Input SHA-256", cert.input.sha256],
      ["Input size", "9,667 bytes"],
      ["Playbook", cert.playbook_id],
      ["Result hash", cert.result_hash],
      ["Certificate hash", cert.certificate_hash],
      ["Reproduce", cert.reproduce_command],
    ] as const) {
      expect(body, `the DOCX omits ${label}`).toContain(`${label}: `);
      expect(body, `the DOCX omits the value of ${label}`).toContain(value);
    }
  });

  it("carries all five certification statements verbatim", async () => {
    const body = await text(await buildCertificateDocx(run));
    const statements = certificateStatements(run);
    expect(statements).toHaveLength(5);
    for (const s of statements) expect(body, `a certification statement is missing`).toContain(s);
  });

  it("still embeds no document text", async () => {
    expect(await text(await buildCertificateDocx(run))).not.toContain("SECRET CLIENT TEXT");
  });

  it("names the asserted checks, and says nothing when none were asserted", async () => {
    expect(await text(await buildCertificateDocx(run))).not.toContain("Asserted checks");

    const asserted = {
      ...run,
      filing_profile: { id: "nd-cal" },
      asserted_regimes: ["gdpr", "ccpa"],
      estate_checks_asserted: true,
      asserted_state: "us-ca",
    } as unknown as EngineRun;
    const body = await text(await buildCertificateDocx(asserted));
    expect(body).toContain(
      "Asserted checks: court profile nd-cal; privacy regimes gdpr, ccpa; estate checks (state us-ca) (asserted by the user)",
    );
  });

  it("labels estate checks without a state, when no state was asserted", async () => {
    const body = await text(
      await buildCertificateDocx({ ...run, estate_checks_asserted: true } as unknown as EngineRun),
    );
    expect(body).toContain("Asserted checks: estate checks (asserted by the user)");
  });

  it("hands the browser a Word document and a JSON file, not octet-stream", async () => {
    // A wrong MIME is how a download opens in the wrong application.
    expect((await certificateDocxBlob(run)).type).toBe(
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    );
    expect(certificateJsonBlob(await buildCertificateJson(run)).type).toBe("application/json");
  });
});

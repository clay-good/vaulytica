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
  buildCertificateJson,
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

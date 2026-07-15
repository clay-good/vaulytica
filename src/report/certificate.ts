/**
 * Verification certificate (add-court-certification-receipt).
 *
 * Court directives on generative-AI use in filings — 300+ per the
 * Ropes & Gray AI Court Order Tracker; ~113 binding attorney-filing
 * orders per the Legal AI Governance tracker — require filers to
 * disclose AI use, verify AI output, or certify neither occurred.
 * Vaulytica can make that certification PROVABLE: deterministic rule
 * engine, no AI, hash-fingerprinted output. This module renders a
 * one-page compliance artifact stating exactly what the tool did.
 *
 * Scope discipline (the wording that survived the audit's legal
 * review): the certificate certifies THIS TOOL's operation on the
 * identified input — never the filer's overall compliance; it uses the
 * privacy-approved claim (document content is never transmitted; the
 * only network requests are same-origin static-asset fetches), never
 * an absolute "no network transmission"; privilege case law is not
 * asserted; the attorney's own verification duty (ABA Formal Op. 512)
 * is stated, not waived.
 *
 * Deterministic: the certificate is a pure function of the run — no
 * wall clock; the JSON companion carries a namespaced
 * `certificate_hash` re-derivable from its own body, so the artifact
 * is tamper-evident the same way a coherence artifact is.
 */

import { Document, Packer, Paragraph, TextRun, HeadingLevel } from "docx";
import type { EngineRun } from "../engine/finding.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";

export const CERTIFICATE_SCHEMA = "vaulytica.verification-certificate.v1";

export type VerificationCertificate = {
  schema: typeof CERTIFICATE_SCHEMA;
  tool: { name: "Vaulytica"; engine_version: string; dkb_version: string };
  input: { name: string; sha256: string; size_bytes: number };
  playbook_id: string;
  /**
   * The opt-in packs the user asserted for this analysis (add-*-pack). Present
   * only when something was asserted, so a plain-run certificate — and its
   * `certificate_hash` — is byte-identical to before. Records, on the provable
   * receipt, which deterministic checks the filer turned on.
   */
  asserted_packs?: {
    court_profile?: string;
    privacy_regimes?: string[];
    estate_checks?: boolean;
  };
  result_hash: string;
  /** The fixed certification statements, in render order. */
  statements: string[];
  reproduce_command: string;
  /** Namespaced SHA-256 over the canonical body (all fields above). */
  certificate_hash: string;
};

/** The certification statements. Tool scope ONLY — see module doc. */
export function certificateStatements(run: EngineRun): string[] {
  return [
    `Scope. This certificate describes the operation of the Vaulytica document linter (engine ${run.version}, knowledge base ${run.dkb_version}) on the input identified above. It certifies what this tool did. It does not certify, and cannot certify, the filer's overall compliance with any court order, local rule, or rule of professional conduct.`,
    "No generative AI. The analysis was a deterministic rule evaluation. No generative-AI, machine-learning, or other probabilistic component was involved in producing the findings, the report, or this certificate. Given the same input file, engine version, and knowledge-base version, the analysis reproduces byte-identically on any machine.",
    "Local processing. The analysis ran locally on the user's machine (in the browser tab or the headless CLI). No portion of the document's content was transmitted anywhere; the only network requests during a browser analysis are same-origin fetches of the tool's own static assets (rule data, playbooks), none of which carries document content.",
    "Verification. The recorded result hash makes the analysis a checkable receipt: re-running the tool on the same input under the same versions must reproduce it exactly, and a doctored report fails verification.",
    "Attorney responsibility. The reviewing attorney remains responsible for verifying the findings and for compliance with all applicable court orders and professional-conduct rules, including the duties of competence and supervision discussed in ABA Formal Opinion 512. Vaulytica is a software tool, not a lawyer; its output is not legal advice.",
  ];
}

/** Human-readable one-line label for the asserted packs (DOCX field). */
function assertedPacksLabel(p: NonNullable<VerificationCertificate["asserted_packs"]>): string {
  const parts: string[] = [];
  if (p.court_profile) parts.push(`court profile ${p.court_profile}`);
  if (p.privacy_regimes && p.privacy_regimes.length > 0)
    parts.push(`privacy regimes ${p.privacy_regimes.join(", ")}`);
  if (p.estate_checks) parts.push("estate checks");
  return `${parts.join("; ")} (asserted by the user)`;
}

/** The asserted opt-in packs on a run, or undefined when none. */
function assertedPacksOf(run: EngineRun): VerificationCertificate["asserted_packs"] | undefined {
  const packs: NonNullable<VerificationCertificate["asserted_packs"]> = {};
  if (run.filing_profile) packs.court_profile = run.filing_profile.id;
  if (run.asserted_regimes && run.asserted_regimes.length > 0)
    packs.privacy_regimes = run.asserted_regimes;
  if (run.estate_checks_asserted) packs.estate_checks = true;
  return Object.keys(packs).length > 0 ? packs : undefined;
}

async function certificateHash(
  body: Omit<VerificationCertificate, "certificate_hash">,
): Promise<string> {
  // Namespaced apart from result_hash and every other artifact hash, so
  // this fingerprint can never be confused with (or substituted for) one.
  return sha256Hex(`${CERTIFICATE_SCHEMA}\n${stableStringify(body)}`);
}

/** Build the canonical certificate model from a run. Pure — no clock. */
export async function buildCertificate(run: EngineRun): Promise<VerificationCertificate> {
  const body: Omit<VerificationCertificate, "certificate_hash"> = {
    schema: CERTIFICATE_SCHEMA,
    tool: { name: "Vaulytica", engine_version: run.version, dkb_version: run.dkb_version },
    input: {
      name: run.source_file.name,
      sha256: run.source_file.sha256,
      size_bytes: run.source_file.size_bytes,
    },
    playbook_id: run.playbook_id,
    ...(assertedPacksOf(run) ? { asserted_packs: assertedPacksOf(run) } : {}),
    result_hash: run.result_hash,
    statements: certificateStatements(run),
    reproduce_command: `vaulytica verify <report.json> "${run.source_file.name}"`,
  };
  return { ...body, certificate_hash: await certificateHash(body) };
}

/**
 * Re-derive and check a certificate's own hash (the tamper-evidence
 * property). Returns true when the body still matches its fingerprint.
 */
export async function verifyCertificateHash(cert: VerificationCertificate): Promise<boolean> {
  const { certificate_hash, ...body } = cert;
  return (await certificateHash(body)) === certificate_hash;
}

/** Stable JSON companion. */
export async function buildCertificateJson(run: EngineRun): Promise<string> {
  return JSON.stringify(await buildCertificate(run), null, 2);
}

/** One-page DOCX rendering (print to PDF from Word for a PDF copy). */
export async function buildCertificateDocx(run: EngineRun): Promise<Blob> {
  const cert = await buildCertificate(run);
  const field = (label: string, value: string): Paragraph =>
    new Paragraph({
      children: [new TextRun({ text: `${label}: `, bold: true }), new TextRun({ text: value })],
    });
  const children: Paragraph[] = [
    new Paragraph({
      heading: HeadingLevel.HEADING_1,
      children: [new TextRun("Verification Certificate — Deterministic Document Analysis")],
    }),
    field("Tool", `Vaulytica (engine ${cert.tool.engine_version})`),
    field("Knowledge base", cert.tool.dkb_version),
    field("Input file", cert.input.name),
    field("Input SHA-256", cert.input.sha256),
    field("Input size", `${cert.input.size_bytes.toLocaleString("en-US")} bytes`),
    field("Playbook", cert.playbook_id),
    ...(cert.asserted_packs ? [field("Asserted checks", assertedPacksLabel(cert.asserted_packs))] : []),
    field("Result hash", cert.result_hash),
    field("Certificate hash", cert.certificate_hash),
    new Paragraph({ children: [new TextRun("")] }),
    ...cert.statements.map(
      (s) =>
        new Paragraph({
          children: [new TextRun({ text: s })],
          spacing: { after: 160 },
        }),
    ),
    field("Reproduce", cert.reproduce_command),
  ];
  const doc = new Document({ sections: [{ properties: {}, children }] });
  // `Packer.toBlob` works in both the browser and Node ≥ 18 (Blob is
  // global), matching the report builder's own pattern.
  const blob = await Packer.toBlob(doc);
  return new Blob([blob], {
    type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  });
}

/** Blob wrapper for the browser download path. */
export const certificateDocxBlob = buildCertificateDocx;

export function certificateJsonBlob(json: string): Blob {
  return new Blob([json], { type: "application/json" });
}

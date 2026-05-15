/**
 * v3 empty-state and error-state copy (spec-v3.md §63).
 *
 * Centralized strings so the UI hookup, the screen-reader announcements,
 * and the documentation all read the same words. Each entry is keyed by
 * a stable id so the test suite and any future copy review can address
 * it directly.
 */

export const EMPTY_STATE_COPY = {
  headline: "Drop up to four contracts at once — Vaulytica lints them locally.",
  sub: "Vaulytica understands BAAs, DPAs, NDAs, MSAs, EU SCCs, the UK Addendum, vendor security exhibits, AI addenda, and certificates of insurance — and can compare pairs against each other.",
} as const;

export type V3ErrorCode =
  | "baa-no-business-associate"
  | "scc-module-2-empty-annex"
  | "scc-module-3-empty-annex"
  | "acord-25-illegible"
  | "max-documents-exceeded"
  | "duplicate-document"
  | "unsupported-file-type";

export type V3ErrorMessage = {
  title: string;
  detail: string;
};

export const V3_ERROR_COPY: Record<V3ErrorCode, V3ErrorMessage> = {
  "baa-no-business-associate": {
    title: "This looks like a BAA but no 'Business Associate' party is defined.",
    detail:
      "Did you intend to load it as a generic agreement? Toggle the playbook to the right of the chip row to switch.",
  },
  "scc-module-2-empty-annex": {
    title: "This looks like SCC Module 2 but Annex I is empty.",
    detail: "Vaulytica cannot lint an empty annex. Fill in Annex I.A (Parties), I.B (Description of the transfer), and II (TOMs), then re-run.",
  },
  "scc-module-3-empty-annex": {
    title: "This looks like SCC Module 3 but Annex I is empty.",
    detail: "Vaulytica cannot lint an empty annex. Fill in Annex I.A (Parties), I.B (Description of the transfer), and II (TOMs), then re-run.",
  },
  "acord-25-illegible": {
    title: "This looks like an ACORD 25 but the certificate-holder block is illegible.",
    detail: "Try a higher-resolution scan (300 DPI or better), or paste the certificate text directly.",
  },
  "max-documents-exceeded": {
    title: "Vaulytica accepts up to four files in a single drop.",
    detail: "Remove one of the queued cards to add another.",
  },
  "duplicate-document": {
    title: "That file is already in the bundle.",
    detail: "If you meant to re-run it, remove the existing card first.",
  },
  "unsupported-file-type": {
    title: "Vaulytica accepts .pdf and .docx files only.",
    detail:
      "Open the file in Word or Google Docs and save it as .docx (or print to PDF), then come back.",
  },
};

/** Lookup helper that falls back to a generic message for unknown codes. */
export function v3ErrorMessage(code: string): V3ErrorMessage {
  return (
    V3_ERROR_COPY[code as V3ErrorCode] ?? {
      title: "Something went wrong.",
      detail: code,
    }
  );
}

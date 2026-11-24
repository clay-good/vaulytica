/**
 * The mandated-text drift check.
 *
 * The pure half runs per-commit: every row's recorded digest must match its own
 * committed text, so a passage cannot be edited without its digest moving. The
 * comparison half is tested against supplied bodies rather than the network, so
 * the verdicts are pinned without a socket.
 */
import { describe, expect, it } from "vitest";
import { MANDATED_TEXTS } from "../../src/engine/rules/text/mandated-texts.js";
import { committedDigests, compareAgainstSource, normalizeForDigest, textDigest } from "./drift.js";

const rows = committedDigests();
const holderA = rows.find((r) => r.key === "ftc-holder-notice#§ 433.2(a)")!;

describe("committed digests", () => {
  it("covers every variant of every row", () => {
    const variants = MANDATED_TEXTS.reduce((n, r) => n + r.variants.length, 0);
    expect(rows.length).toBe(variants);
    expect(rows.length, "no rows — every assertion below would be vacuous").toBeGreaterThan(2);
    expect(holderA, "the Holder Rule notice is missing").toBeDefined();
  });

  it("records a digest that matches the row's own text", () => {
    // The per-commit guard: edit the passage without re-deriving the digest
    // and this fails. Derived rather than committed as a literal, so the two
    // cannot drift apart within the repository — what this protects against is
    // the SOURCE moving, which no local check can see.
    for (const r of rows) {
      expect(textDigest(r.text), r.key).toBe(r.digest);
    }
  });

  it("digests the whitespace-normalized form, so reflowing the literal is not drift", () => {
    expect(textDigest("NOTICE  ANY\n HOLDER")).toBe(textDigest("NOTICE ANY HOLDER"));
    expect(normalizeForDigest("  a \n b  ")).toBe("a b");
  });
});

describe("comparing a row against what the source serves", () => {
  it("passes a body that still carries the passage verbatim", () => {
    const body = `<DIV8><HEAD>§ 433.2 Preservation of consumers' claims and defenses.</HEAD><P>${holderA.text}</P><CITA>40 FR 53506</CITA></DIV8>`;
    expect(compareAgainstSource(holderA, body)).toEqual({ key: holderA.key, status: "unchanged" });
  });

  it("passes a body that differs only in case or spacing", () => {
    // § 433.2 prints the notice in capitals; the rules compare case-blind, so
    // a source serving it in mixed case is not an amendment.
    const body = `<P>${holderA.text.toLowerCase().replace(/ /g, "\n  ")}</P>`;
    expect(compareAgainstSource(holderA, body).status).toBe("unchanged");
  });

  it("reports drift and says where the wording diverges", () => {
    const amended = holderA.text.replace(
      "SUBJECT TO ALL CLAIMS AND DEFENSES",
      "SUBJECT TO EVERY CLAIM AND DEFENSE",
    );
    expect(amended).not.toBe(holderA.text);
    const v = compareAgainstSource(holderA, `<P>${amended}</P>`);
    expect(v.status).toBe("drifted");
    // The detail has to point at the amendment, not merely assert a mismatch.
    expect(v.status === "drifted" && v.detail).toContain("diverges");
    expect(v.status === "drifted" && v.detail).toMatch(/first \d+ of \d+ words/);
  });

  it("tells a broken fetch apart from an amended statute", () => {
    // Different causes need different responses: re-read the statute, versus
    // fix the fetch. Collapsing them into one verdict sends a reader to the
    // wrong place.
    expect(compareAgainstSource(holderA, "")).toEqual({
      key: holderA.key,
      status: "not-found",
      detail: "the source served an empty body",
    });
    const unrelated = compareAgainstSource(holderA, "<html><body>Page not found</body></html>");
    expect(unrelated.status).toBe("not-found");
    expect(unrelated.status === "not-found" && unrelated.detail).toContain("check the fetch");
  });

  it("holds every row to the same comparison, not just the Holder notice", () => {
    for (const r of rows) {
      expect(compareAgainstSource(r, `<P>${r.text}</P>`).status, r.key).toBe("unchanged");
      expect(compareAgainstSource(r, "<P>unrelated prose entirely</P>").status, r.key).not.toBe(
        "unchanged",
      );
    }
  });
});

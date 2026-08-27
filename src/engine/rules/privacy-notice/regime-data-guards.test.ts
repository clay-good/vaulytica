/**
 * Five CCPA content items that a compliant notice could not satisfy.
 *
 * The pack is family-wide `negation_guarded`, so a match preceded by a
 * negator is discarded — right for "nothing here limits your right to …",
 * wrong when the negation IS the disclosure. The regulation asks for the
 * categories of sensitive personal information collected; a business that
 * collects none says "we do not collect or process sensitive personal
 * information", and that is the complete answer. The Do-Not-Sell link is
 * required of a business that sells or shares; one that does neither says so.
 * Both were thrown away and reported as unaddressed.
 *
 * The other three were narrow rather than negated. A notice discloses its
 * sources by naming them ("we collect these directly from you", "from our
 * payment processor"), its purposes under a heading reading "How We Use
 * Personal Information", and its recipients by category ("service providers
 * that perform functions on our behalf") — none of which uses the words
 * "sources", "purpose", or "third party".
 *
 * Both directions are pinned: the broadened patterns must not make an item
 * unfireable, which is the failure mode a widened recognizer creates.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { PNOT_RULES } from "./rules.js";

const rule = (id: string) => {
  const r = PNOT_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no PNOT rule ${id}`);
  return r;
};

/** A notice that addresses none of the five items. */
const BARE: [string, ...string[]] = [
  "Privacy Notice",
  "This Privacy Notice explains our approach to personal information.",
  "We collect identifiers, commercial information, and internet activity.",
  "We maintain safeguards designed to protect personal information.",
  "You may have the right to know, to access, to correct, and to delete.",
  // Deliberately names no corporate suffix: OR-007 is satisfied by one,
  // and a "bare" fixture that carries the answer proves nothing.
  "Written questions may be sent to 1 Main Street.",
];

const PURPOSES =
  "How We Use Personal Information. We use personal information to provide and maintain the services and to process payments.";
const RECIPIENTS =
  "We disclose personal information to service providers that perform hosting, payment processing, email delivery, and analytics on our behalf.";

const CASES: Array<[string, string]> = [
  [
    "PNOT-CCPA-002",
    "We collect these directly from you when you create an account, and from our payment processor.",
  ],
  [
    "PNOT-CCPA-003",
    "How We Use Personal Information. We use personal information to provide the services and to process payments.",
  ],
  [
    "PNOT-CCPA-004",
    "We disclose personal information to service providers that perform hosting, payment processing, and analytics on our behalf.",
  ],
  [
    "PNOT-CCPA-009",
    "We do not sell personal information, and we do not share personal information for cross-context behavioral advertising.",
  ],
  [
    "PNOT-CCPA-010",
    "We do not collect or process sensitive personal information as that term is defined under applicable state privacy law.",
  ],
];

/**
 * The same two item types repeat in every state act, with their own pattern
 * arrays copied four times over — so the same compliant notice scored nine
 * more warnings under CO, VA, TX, and OR. Oregon's third-party item asks for
 * more detail than the others, and the notice gives more detail, by naming the
 * functions each recipient performs.
 *
 * OR-007 was a different defect: `\b(inc\.|llc|ltd\.?|corporation)\b` carried a
 * trailing `\b` after a literal period, which demands a word character
 * immediately next — and a company name ends "Inc." at a comma, a newline, or
 * a sentence end every time. That alternative could not match any real notice.
 */
const STATE_CASES: Array<[string, string]> = [
  ["PNOT-CO-002", PURPOSES],
  ["PNOT-VA-002", PURPOSES],
  ["PNOT-TX-002", PURPOSES],
  ["PNOT-OR-002", PURPOSES],
  ["PNOT-CO-005", RECIPIENTS],
  ["PNOT-VA-005", RECIPIENTS],
  ["PNOT-TX-005", RECIPIENTS],
  ["PNOT-OR-005", RECIPIENTS],
  ["PNOT-OR-007", "Vanterra Analytics, Inc., Attn: Privacy, 4400 Harbor Point Drive."],
];

describe("state-act content items a compliant notice must be able to satisfy", () => {
  it.each(STATE_CASES)(
    "%s is satisfied by the disclosure a real notice makes",
    (id, disclosure) => {
      const finding = rule(id).check(buildContext([...BARE, disclosure]));
      expect(
        finding,
        `flagged a notice that makes the disclosure: ${finding?.title ?? ""}`,
      ).toBeNull();
    },
  );

  it.each(STATE_CASES)("%s still fires on a notice that makes none of them", (id) => {
    const finding = rule(id).check(buildContext(BARE));
    expect(finding, "the widened patterns made the item unfireable").not.toBeNull();
  });
});

describe("CCPA content items a compliant notice must be able to satisfy", () => {
  it.each(CASES)("%s is satisfied by the disclosure a real notice makes", (id, disclosure) => {
    const finding = rule(id).check(buildContext([...BARE, disclosure]));
    expect(
      finding,
      `flagged a notice that makes the disclosure: ${finding?.title ?? ""}`,
    ).toBeNull();
  });

  it.each(CASES)("%s still fires on a notice that makes none of them", (id) => {
    const finding = rule(id).check(buildContext(BARE));
    expect(finding, "the widened patterns made the item unfireable").not.toBeNull();
  });
});

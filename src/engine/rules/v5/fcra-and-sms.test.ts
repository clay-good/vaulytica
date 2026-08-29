import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";

const rule = (id: string) => {
  const r = V5_RULES.find((x) => x.id === id);
  if (!r) throw new Error(`no v5 rule ${id}`);
  return r;
};

/**
 * Two FCRA columns could not be satisfied by a COMPLIANT document. A lawful
 * stand-alone disclosure does not describe itself as stand-alone and does not
 * announce that it carries no liability waiver — it simply carries neither.
 * Both reported at `critical` on the very form they exist to bless.
 */
describe("the FCRA stand-alone disclosure, as one is actually written", () => {
  const DISCLOSURE =
    'Halverson Grid Services, Inc. may obtain information about you from a consumer reporting agency for employment purposes. Thus, you may be the subject of a "consumer report" which may include information about your character, general reputation, personal characteristics, and mode of living.';

  it("EMP-148 reads the disclosure statement itself", () => {
    expect(
      rule("EMP-148").check(
        buildContext(["Disclosure Regarding Background Investigation", DISCLOSURE]),
      ),
    ).toBeNull();
  });

  it("EMP-148 still fires on a form that discloses nothing", () => {
    expect(
      rule("EMP-148").check(
        buildContext([
          "Application for Employment",
          "Please complete every field and return this form to the hiring manager.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("EMP-149 is never asked of a disclosure that carries no release", () => {
    expect(
      rule("EMP-149").check(
        buildContext(["Disclosure Regarding Background Investigation", DISCLOSURE]),
      ),
    ).toBeNull();
  });

  it("EMP-149 fires on a disclosure with a release embedded in it", () => {
    expect(
      rule("EMP-149").check(
        buildContext([
          "Disclosure and Authorization",
          DISCLOSURE,
          "I release the Company, the consumer reporting agency, and their agents from any and all liability and claims arising out of the procurement or use of these reports.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * Consumer messaging terms address the reader in the SECOND person, and after
 * Facebook v. Duguid almost nobody writes "autodialer" about texting.
 */
describe("an SMS program disclosure in the CTIA-standard wording", () => {
  const PROGRAM = [
    "SMS Program Terms",
    'By entering your mobile number and selecting "Sign up for texts," you consent to receive recurring automated marketing text messages from Ridgeback Outfitters, Inc. at the number you provide. Consent is not a condition of any purchase.',
    "Message frequency varies. Message and data rates may apply. Reply STOP to cancel, HELP for help.",
  ] as [string, ...string[]];

  it("PRV-113 reads the second-person consent sentence", () => {
    expect(rule("PRV-113").check(buildContext(PROGRAM))).toBeNull();
  });

  it("PRV-115 reads 'automated' as the technology disclosure", () => {
    expect(rule("PRV-115").check(buildContext(PROGRAM))).toBeNull();
  });

  it("PRV-113 still fires on a page that never says what you consent to", () => {
    expect(
      rule("PRV-113").check(
        buildContext([
          "SMS Program Terms",
          "Message frequency varies. Message and data rates may apply.",
        ]),
      ),
    ).not.toBeNull();
  });
});

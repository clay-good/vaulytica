import { describe, expect, it } from "vitest";
import { isPersonalName, withoutFilledDate } from "./_signature-name.js";

describe("isPersonalName — one owner for STRUCT-003 and STRUCT-013", () => {
  it.each([
    "Daniel K. Osei",
    "Gregory Halstead",
    "José García",
    "Zoë Müller",
    "Siobhan O'Brien",
    "Ian McDonald",
    "Anneke Achebe-Lindström",
    "Dr. Helena Vasquez",
    "Jonathan Pierce, Manager",
  ])("accepts %s", (name) => {
    expect(isPersonalName(name)).toBe(true);
  });

  it.each(["Company Name", "TBD Party", "Insert Signatory", "XXX YYY", "Print Name", "Date"])(
    "rejects %s",
    (text) => {
      expect(isPersonalName(text)).toBe(false);
    },
  );

  it("strips a filled-in date caption", () => {
    expect(withoutFilledDate("Daniel K. Osei Date: July 15, 2026")).toBe("Daniel K. Osei");
    expect(withoutFilledDate("Daniel K. Osei")).toBe("Daniel K. Osei");
  });
});

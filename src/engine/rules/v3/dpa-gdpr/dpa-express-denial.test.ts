import { describe, expect, it } from "vitest";

import { DPA_GDPR_RULES } from "./rules.js";
import { buildContext } from "../../../_test-fixtures.js";

const CLEAN_DPA =
  "Data Processing Agreement. Subject-matter: hosting. Duration: the term of the Agreement. Nature and purpose of processing: provision of the Services. Type of personal data: contact details. Categories of data subjects: customer employees. Obligations and rights of the controller are set out below. " +
  "Processor shall process personal data only on documented instructions from the Controller. " +
  "Processor shall ensure that persons authorised to process personal data are bound by confidentiality and a duty of confidence. " +
  "Processor shall implement the technical and organisational measures required by Article 32 security, including pseudonymisation and encryption, and shall ensure confidentiality, integrity, availability and resilience. " +
  "Processor shall assist the Controller in responding to data-subject requests and data-subject rights. " +
  "Processor shall assist the Controller with breach notification and any data protection impact assessment (DPIA) under Articles 32 to 36. " +
  "At the end of the services Processor shall, at the Controller's choice, delete or return all personal data. " +
  "Processor shall make available all information necessary to demonstrate compliance and shall allow for and contribute to audits and inspections by the Controller. " +
  "Processor shall not engage a subprocessor without the Controller's prior written authorisation, and shall notify the Controller of any intended change with a right to object. " +
  "Processor shall impose the same data protection obligations on each subprocessor by way of flow-down. " +
  "This DPA is in writing including electronic form.";

const DENIALS: [string, string][] = [
  ["DPA-008", "Authorised persons are not bound by confidentiality."],
  ["DPA-009", "Processor does not implement technical and organisational measures."],
  ["DPA-011", "Processor does not assist the Controller with data-subject requests."],
  ["DPA-012", "Processor provides no assistance with breach notification."],
  ["DPA-013", "Processor shall not delete or return personal data at the end of the services."],
  ["DPA-014", "The Controller may not audit the Processor."],
  [
    "DPA-015",
    "Processor is not required to obtain prior written authorisation before engaging a subprocessor.",
  ],
  ["DPA-017", "Subprocessors are not bound by the same data protection obligations."],
  ["DPA-024", "Processor is not required to notify Controller of any personal data breach."],
];

const DECOYS: string[] = [
  "",
  "Processor shall not disclose personal data except to persons bound by confidentiality.",
  "Nothing in this DPA limits the Controller's right to audits and inspections.",
  "This Section does not apply to audits requested more than twice per year.",
  "Processor may not engage a subprocessor without prior written authorisation.",
  "Personal data shall not be retained after the deletion or return obligation is discharged.",
  "The security measures do not affect any stricter measures agreed in an Order Form.",
];

const denied = (text: string): string[] =>
  DPA_GDPR_RULES.filter((r) => {
    const f = r.check(buildContext(["Data Processing Agreement", text]));
    // "excused" joins the vocabulary with DPA-024. The missing-clause titles in
    // this pack use none of these words, so the filter still proves it was
    // `denied_if` that matched, not the ordinary absence branch.
    return f !== null && /disclaim|denied|excused/i.test(f.title);
  }).map((r) => r.id);

/**
 * A DPA clause-presence rule fires when NONE of its `present_patterns` match,
 * so a DPA that AFFIRMATIVELY DISCLAIMS an Art. 28(3) obligation matches every
 * topic word and the rule stays silent — while one that merely omits the topic
 * is flagged. The disclaimer is the worse document. `denied_if` inverts that.
 *
 * The assertion reads the finding TITLE: a fixture also trips the ordinary
 * missing-clause branch on unrelated rules, so only the denial title proves
 * `denied_if` is what matched.
 */
describe("v3 DPA-GDPR presence rules — express denial", () => {
  it.each(DENIALS)("%s fires on an express disclaimer: %s", (id, tail) => {
    expect(denied(`${CLEAN_DPA} ${tail}`)).toContain(id);
  });

  // DPA-007's compliant drafting is itself a negation ("shall process personal
  // data ONLY on documented instructions"), so it carries no denial guard.
  it("leaves the rule whose required clause is itself a restriction unguarded", () => {
    const dpa007 = DPA_GDPR_RULES.find((r) => r.id === "DPA-007");
    expect(dpa007).toBeDefined();
    expect(dpa007!.check(buildContext(["Data Processing Agreement", CLEAN_DPA]))).toBeNull();
  });

  it.each(DECOYS)("does not read compliant drafting as a denial: %s", (tail) => {
    expect(denied(`${CLEAN_DPA} ${tail}`)).toEqual([]);
  });
});

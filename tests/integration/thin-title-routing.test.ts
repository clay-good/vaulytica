/**
 * A short document routes on its title and a little generic text.
 *
 * A sweep of everyday titles over the same thin body (parties, a services
 * line, a payment line) found two catalog defects that realistic specimens
 * hide, because they carry enough family vocabulary to route anyway:
 *
 *   - "Personal Loan Agreement" fell to generic-fallback: `loan-agreement`
 *     credits a title keyword in the OPENING position twice, and "Loan
 *     Agreement Between Friends" opens with one while this does not.
 *   - "Letter of Intent" went to the lease-LOI family: it listed "this letter
 *     of intent" as a DISTINGUISHING phrase, which every LOI contains, so it
 *     out-scored `loi-term-sheet` on any letter that names itself.
 */
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const thin = (title: string, extra = ""): string =>
  `${title.toUpperCase()}\n\nThis ${title} (this "Agreement") is entered into as of March 1, 2027 between Alpha LLC and Jordan Lee.\n\n1. Terms. ${extra}\n\n2. Payment. Alpha LLC shall pay the amounts stated in this Agreement within thirty (30) days after invoice.`;

describe("thin documents route on their titles", () => {
  it("a personal loan agreement reaches loan-agreement", async () => {
    const r = await analyzeText(thin("Personal Loan Agreement"), "doc.txt");
    expect(r.run.playbook_id).toBe("loan-agreement");
  });

  it("a business letter of intent that names itself does not go to the lease LOI family", async () => {
    const r = await analyzeText(
      thin(
        "Letter of Intent",
        "This letter of intent is non-binding until a definitive agreement is signed.",
      ),
      "doc.txt",
    );
    expect(r.run.playbook_id).toBe("loi-term-sheet");
  });
}, 120_000);

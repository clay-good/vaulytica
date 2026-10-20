/** A final draft and its executed copy (add-executed-copy-conformity). */
export const FINAL = `CONSULTING AGREEMENT

This Consulting Agreement is made as of ____________, 2026 between Acme Components, Inc. ("Client") and Jordan Lee ("Consultant").

1. Services. Consultant shall provide the strategy services described in Exhibit A.

2. Fees. Client shall pay Consultant $12,500 per month, payable within thirty days of invoice.

3. Term. This Agreement continues for twelve months unless terminated on thirty days' notice.

IN WITNESS WHEREOF, the parties have signed this Agreement as of the date first written above.

ACME COMPONENTS, INC.

By: ______________________
Name:
Title:

CONSULTANT

______________________
Jordan Lee
`;

export const EXECUTED = FINAL.replace("____________, 2026", "June 3, 2026")
  .replace(
    "By: ______________________\nName:\nTitle:",
    "By: /s/ Maria Ortiz\nName: Maria Ortiz\nTitle: Chief Executive Officer",
  )
  .replace("CONSULTANT\n\n______________________", "CONSULTANT\n\n/s/ Jordan Lee")
  .replace("CONSULTING AGREEMENT", "EXECUTION VERSION\n\nCONSULTING AGREEMENT");

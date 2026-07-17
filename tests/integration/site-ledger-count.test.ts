/**
 * Guard: the public site's attorney-signed count is wired to the ledger.
 *
 * `site/index.html` states how many rules a licensed attorney has independently
 * signed off on (add-attorney-review-ledger, task 5). That number is the
 * honest zero today, but it must never drift from the actual ledger — a stale
 * "0" the day an attorney signs the first rule would be exactly the kind of
 * marketing claim this product exists to break. This guard reads the number
 * out of the site (the `data-ledger-signed` span) and pins it to the live
 * ledger length, so the site can never silently overclaim OR underclaim. When
 * the first entry is signed, this fails until the site is updated in the same
 * change — by design (the same discipline as the scoreboard-current guard).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { loadLegalBasisLedger } from "../../tools/accuracy/legal-basis.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = join(__dirname, "..", "..", "site", "index.html");

describe("site attorney-signed count is wired to the ledger", () => {
  it("the site's stated signed count equals the ledger length (update both together)", async () => {
    const html = readFileSync(INDEX_HTML, "utf8");
    const match = /<span data-ledger-signed>(\d+)<\/span>/.exec(html);
    expect(match, "site/index.html must carry a <span data-ledger-signed> count").not.toBeNull();
    const siteCount = Number(match![1]);

    const ledger = await loadLegalBasisLedger();
    expect(siteCount).toBe(ledger.length);
  });
});

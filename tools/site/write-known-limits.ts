/** `npm run site:known-limits` — regenerate `tools/site/known-limits.json`. */
import { writeFileSync } from "node:fs";
import { buildKnownLimits, serializeKnownLimits } from "./known-limits.js";

const data = await buildKnownLimits();
writeFileSync("tools/site/known-limits.json", serializeKnownLimits(data));
console.log(
  `Wrote tools/site/known-limits.json (${data.open.length} open debts, ${data.held_at_zero.length} held at zero)`,
);

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ingestPaste } from "./src/ingest/paste.js";
import { extractAll } from "./src/extract/index.js";
import { extractAllV3 } from "./src/extract/v3/index.js";
const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const files = readdirSync(DIR).filter((f) => f.endsWith(".txt")).sort();
let withTransfers=0, withSub=0, withIns=0, n=0;
const t0 = Date.now();
for (const f of files) {
  const ing = await ingestPaste(readFileSync(join(DIR,f),"utf8"));
  const ex = extractAll(ing.tree);
  const v3 = extractAllV3(ing.tree, { parties: ex.parties });
  n++;
  if ((v3.transfer_mechanisms ?? []).length) withTransfers++;
  if (v3.subprocessor) withSub++;
  const ins: any = v3.insurance;
  if (ins && (ins.lines?.length || ins.endorsements?.length)) withIns++;
}
console.log(`${n} specimens in ${((Date.now()-t0)/1000).toFixed(1)}s`);
console.log(`  transfer mechanisms: ${withTransfers}`);
console.log(`  subprocessor inventory: ${withSub}`);
console.log(`  insurance schedule: ${withIns}`);

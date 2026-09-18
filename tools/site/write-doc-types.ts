/** `npm run site:doc-types` — regenerate `tools/site/doc-types.json`. */
import { writeFileSync } from "node:fs";
import { buildDocTypes, serializeDocTypes } from "./doc-types.js";

const data = buildDocTypes();
writeFileSync("tools/site/doc-types.json", serializeDocTypes(data));
console.log(`Wrote tools/site/doc-types.json (${data.types.length} document types)`);

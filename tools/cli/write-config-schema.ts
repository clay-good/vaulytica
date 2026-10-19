/**
 * Rewrites `docs/config.schema.json` from the Zod schema in `config.ts`
 * (add-project-config-file). `config.test.ts` fails when the two differ.
 *
 *   npx tsx tools/cli/write-config-schema.ts
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildConfigJsonSchema } from "./config.js";

writeFileSync(join(process.cwd(), "docs", "config.schema.json"), buildConfigJsonSchema());

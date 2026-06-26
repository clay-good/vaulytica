/**
 * Guard the committed worked-example playbooks (spec-v6 Step 94).
 *
 * The authoring guide (`docs/v6/authoring-a-playbook.md`) points readers at
 * two example `.json` playbooks. If the schema ever tightens, these examples
 * must keep validating — otherwise the docs ship a broken template. This test
 * loads each example, validates it against the public schema, and confirms a
 * catalog-aware preview can be computed against the real rule catalog.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseCustomPlaybookJson, previewCustomPlaybook, RULE_CATALOG_VERSION } from "./index.js";
import { LAUNCH_RULES, V3_RULES } from "../engine/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXAMPLES = join(__dirname, "..", "..", "docs", "v6", "examples");

const FILES = ["saas-buyer.playbook.json", "vendor-redlines.playbook.json"];

const catalogIds = [...LAUNCH_RULES, ...V3_RULES].map((r) => r.id);

describe("worked-example playbooks", () => {
  for (const file of FILES) {
    it(`${file} validates against the public schema`, () => {
      const text = readFileSync(join(EXAMPLES, file), "utf8");
      const result = parseCustomPlaybookJson(text);
      if (!result.ok) {
        throw new Error(`${file} failed validation:\n${result.errors.join("\n")}`);
      }
      expect(result.playbook.id).toBeTruthy();
      // Targets the current catalog version, so the loader shows no mismatch warning.
      expect(result.playbook.catalog_version).toBe(RULE_CATALOG_VERSION);

      const preview = previewCustomPlaybook(result.playbook, {
        rule_ids: catalogIds,
        version: RULE_CATALOG_VERSION,
      });
      // Every rule id referenced in selection/overrides exists in the catalog.
      expect(preview.unknown_selection_rule_ids).toEqual([]);
      expect(preview.unknown_override_rule_ids).toEqual([]);
      // The examples are augment-mode, so they keep the built-in catalog.
      expect(preview.mode).toBe("augment");
      expect(preview.selected_builtin_rule_ids.length).toBeGreaterThan(0);
      expect(preview.custom_rule_count).toBeGreaterThan(0);
    });
  }
});

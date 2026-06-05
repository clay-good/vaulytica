// ESLint 9 flat config (migrated from .eslintrc.cjs, 2026-06-04).
//
// ESLint 8 reached end-of-life in October 2024 and its legacy `.eslintrc`
// system pulled the deprecated `@humanwhocodes/config-array` / `inflight` /
// `rimraf` transitive packages. This flat config is behavior-preserving: same
// ignores, same browser+node globals (was `env`), same two rule overrides as
// the old `.eslintrc.cjs`. The toolchain is now `eslint@9`, the unified
// `typescript-eslint@8` meta-package (replacing the separate
// `@typescript-eslint/{parser,eslint-plugin}`), and `eslint-config-prettier@10`.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier/flat";

export default tseslint.config(
  // Global ignores. node_modules/ and .git/ are ignored by default in flat
  // config; these are the project's build outputs + the old-style CJS files.
  { ignores: ["dist/", "dkb/dist/", "dkb/build/cache/", "**/*.cjs"] },

  // Base recommended rule sets: core JS, then TypeScript (non-type-checked, to
  // match the prior `plugin:@typescript-eslint/recommended` — no typed linting).
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Browser + Node globals across the whole tree (the old `env` block).
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: { ...globals.browser, ...globals.node },
    },
  },

  // Project rule overrides — scoped to TS files so the `@typescript-eslint`
  // plugin is registered in context. Identical to the old `.eslintrc.cjs`.
  {
    files: ["**/*.ts", "**/*.tsx", "**/*.mts"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },

  // Turn off stylistic rules that conflict with Prettier. Must be last.
  prettier,
);

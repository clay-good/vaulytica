/**
 * Import this FIRST. The `docx` package bundles a browser `util-deprecate`
 * shim that reads `globalThis.localStorage` at import, and from Node 25 that
 * getter prints an `ExperimentalWarning` on every run. Defining the property
 * as a plain `undefined` means the getter is never called. Skipped when a DOM
 * is present (the test environment supplies its own storage).
 */
if (typeof window === "undefined") {
  Object.defineProperty(globalThis, "localStorage", {
    value: undefined,
    configurable: true,
    writable: true,
  });
}

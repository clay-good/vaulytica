/**
 * UI layer barrel. The marketing page imports `main.ts` as the entry
 * module; this barrel re-exports the modules for tests.
 */
export { bootUi } from "./main.js";
export { bindDropzone, validateFile, type DropResult } from "./dropzone.js";
export { createProgressBar, type ProgressBar } from "./progress.js";
export { createRuleTicker, type RuleTicker } from "./ticker.js";
export { renderState, select, type DropzoneState } from "./states.js";
export { registerServiceWorker } from "./sw-register.js";
export {
  applyTheme,
  bindThemeToggle,
  currentTheme,
  persistTheme,
  readPersistedTheme,
  type Theme,
} from "./theme.js";

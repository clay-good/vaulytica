/**
 * Vite entry shim.
 *
 * The real UI entry is `src/ui/main.ts`, which lives outside the Vite
 * root (`site/`). A production build resolves an out-of-root
 * `<script src="../src/ui/main.ts">` fine, but the dev server does
 * not rewrite it: the browser requests `/src/ui/main.ts`, the SPA
 * fallback answers with `index.html` as `text/html`, and the module
 * is refused on MIME type — `npm run dev` renders a dead page.
 *
 * Pointing the tag at this in-root module fixes dev (the path
 * resolves under the root) while leaving the build identical: the
 * shim is a single re-export, so the emitted entry chunk is still
 * `main-*.js` with `src/ui/main.ts` inlined.
 */

import "../src/ui/main.js";

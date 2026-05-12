/**
 * Playwright smoke-test config (spec §26 step 14).
 *
 * The smoke test hits a baseURL (deployed Cloudflare Pages site or a
 * local preview), drops a fixture contract, waits for the download
 * button, and verifies the downloaded DOCX is a valid OOXML zip of
 * nonzero size. See `tests/e2e/smoke.spec.ts`.
 */

import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.VAULYTICA_E2E_PORT ?? 4173);
const BASE_URL = process.env.VAULYTICA_E2E_BASE_URL ?? `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  /**
   * If `VAULYTICA_E2E_BASE_URL` is set (CI hitting a Pages deploy),
   * skip the local web server. Otherwise spin up the Vite preview
   * server against the build output.
   */
  webServer: process.env.VAULYTICA_E2E_BASE_URL
    ? undefined
    : {
        command: `npm run preview -- --port ${PORT} --strictPort`,
        url: BASE_URL,
        timeout: 60_000,
        reuseExistingServer: !process.env.CI,
      },
});

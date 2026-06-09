import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: ".",
  use: { ...devices["Desktop Chrome"], deviceScaleFactor: 2 },
  projects: [{ name: "chromium" }],
});

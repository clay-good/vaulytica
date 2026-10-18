/**
 * A document's own text is data, never markup, everywhere the app renders it.
 *
 * The UI builds its result panels with about thirty `innerHTML` templates, and
 * a static read cannot follow every pre-built fragment into them. So this drives
 * the real app: a contract carrying HTML and script payloads in its title,
 * party names, a defined term, clause text, the governing-law line and the
 * signature block is dropped alone and as a two-document bundle, and the live
 * DOM is inspected afterwards.
 *
 * Three things must hold: no dialog fires; no element anywhere carries an event
 * handler, a `javascript:` URL, or is an element the payload names; and the
 * payload TEXT is visible on the page, so a pass means "escaped", not "never
 * rendered".
 */
import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// The FILENAME is the field the result panel shows, so the payload rides in
// the name as well as the text. In-memory, because Windows cannot check out a
// file whose name holds "<" or ">".
const file = (fixture: string, name: string) => ({
  name,
  mimeType: "text/plain",
  buffer: readFileSync(join(__dirname, "sample-docs", fixture)),
});
const ONE = file("injection-nda.txt", "<img src=x onerror=alert('f1')>.txt");
const TWO = file("injection-nda-2.txt", "\"><svg onload=alert('f2')>.txt");

async function injected(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const bad: string[] = [];
    for (const el of Array.from(document.querySelectorAll("*"))) {
      for (const a of Array.from(el.attributes)) {
        const v = a.value.trim().toLowerCase();
        if (a.name.toLowerCase().startsWith("on")) bad.push(`${el.tagName} ${a.name}`);
        if ((a.name === "href" || a.name === "src") && v.startsWith("javascript:"))
          bad.push(`${el.tagName} ${a.name}=${v.slice(0, 30)}`);
      }
      const tag = el.tagName.toLowerCase();
      if (tag === "iframe" || tag === "svg" || tag === "img") {
        // The app ships no iframe and no payload-shaped image; an svg icon is
        // fine only if it carries no handler (caught above) and no foreign text.
        if (tag !== "svg" || /alert\(/.test(el.outerHTML))
          bad.push(`<${tag}> ${el.outerHTML.slice(0, 60)}`);
      }
      if (tag === "script" && /alert\(/.test(el.textContent ?? ""))
        bad.push("<script> with payload");
    }
    return bad;
  });
}

async function drop(
  page: Page,
  files: ReturnType<typeof file>[],
  state: string,
): Promise<string[]> {
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await page.goto("/");
  await page.locator('#dropzone input[type="file"]:not([webkitdirectory])').setInputFiles(files);
  await page.locator(`#dropzone[data-state="${state}"]`).waitFor({ timeout: 120_000 });
  return dialogs;
}

test("a single document's payloads render as text", async ({ page }) => {
  const dialogs = await drop(page, [ONE], "complete");
  expect(dialogs).toEqual([]);
  expect(await injected(page)).toEqual([]);
  // Anti-vacuity: the hostile filename reached the page, as text.
  await expect(page.locator("#dropzone")).toContainText("<img src=x onerror=alert('f1')>.txt");
});

test("a bundle's payloads render as text", async ({ page }) => {
  const dialogs = await drop(page, [ONE, TWO], "bundle-complete");
  expect(dialogs).toEqual([]);
  expect(await injected(page)).toEqual([]);
  await expect(page.locator("#dropzone")).toContainText("<svg onload=alert('f2')>.txt");
});

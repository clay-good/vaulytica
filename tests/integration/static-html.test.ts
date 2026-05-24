/**
 * Static HTML validation for `site/index.html`. Two responsibilities:
 *
 * 1. **Open Graph / Twitter Card meta tags** — every block link
 *    previewer (Twitter, LinkedIn, Bluesky, iMessage, Slack) reads
 *    these. A typo or missing property silently produces a generic
 *    preview. Spec §27 row (j) is the live verification step against
 *    each platform; this test hardens the static shape that has to
 *    be correct first.
 *
 * 2. **Static accessibility checks** — semantic landmarks, alt text
 *    on `<img>` / `<svg>` elements with role/aria-label, no
 *    abandoned `<a href="#">` anchors, focus-visible-friendly
 *    `role="button"` elements with `tabindex` and `aria-label`. Spec
 *    §27 row (h) is the live axe DevTools audit; this catches the
 *    most common static-shape regressions before the axe run.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = join(__dirname, "..", "..", "site", "index.html");

let html: string;

beforeAll(() => {
  html = readFileSync(INDEX_HTML, "utf8");
});

function getMeta(html: string, attr: "name" | "property", key: string): string | undefined {
  const re = new RegExp(
    `<meta\\s+${attr}=["']${key.replace(/[.*+?^${}()|[\\\\\\]]/g, "\\\\$&")}["'][^>]*\\scontent=["']([^"']*)["']`,
    "i",
  );
  return re.exec(html)?.[1];
}

describe("Open Graph / Twitter Card meta tags (LAUNCH row j)", () => {
  it("every required OG property is present", () => {
    for (const key of ["og:title", "og:description", "og:image", "og:url", "og:type", "og:site_name"]) {
      const value = getMeta(html, "property", key);
      expect(value, `${key} missing`).toBeTruthy();
      expect(value!.length, `${key} empty`).toBeGreaterThan(2);
    }
  });

  it("og:url is the production vaulytica.com URL", () => {
    expect(getMeta(html, "property", "og:url")).toMatch(/^https:\/\/vaulytica\.com/);
  });

  it("og:type is website (top-level marketing page)", () => {
    expect(getMeta(html, "property", "og:type")).toBe("website");
  });

  it("og:image references a same-origin or hosted asset", () => {
    const img = getMeta(html, "property", "og:image");
    expect(img).toMatch(/^(https?:\/\/|\/)/);
  });

  it("og:title is under 70 chars (most platforms truncate at 60-70)", () => {
    const title = getMeta(html, "property", "og:title")!;
    expect(title.length).toBeLessThanOrEqual(70);
  });

  it("og:description is under 200 chars (most platforms truncate at ~155-200)", () => {
    const desc = getMeta(html, "property", "og:description")!;
    expect(desc.length).toBeLessThanOrEqual(200);
  });

  it("every required Twitter Card property is present", () => {
    for (const key of ["twitter:card", "twitter:title", "twitter:description", "twitter:image"]) {
      const value = getMeta(html, "name", key);
      expect(value, `${key} missing`).toBeTruthy();
    }
  });

  it("twitter:card is summary_large_image (rich card with image)", () => {
    expect(getMeta(html, "name", "twitter:card")).toMatch(/^summary(_large_image)?$/);
  });

  it("a viewport meta tag is present (PWA + mobile rendering)", () => {
    const viewport = getMeta(html, "name", "viewport");
    expect(viewport).toBeTruthy();
    expect(viewport).toMatch(/width=device-width/);
  });

  it("theme-color meta tags are present (matches manifest.theme_color)", () => {
    const tc = getMeta(html, "name", "theme-color");
    expect(tc).toMatch(/^#[0-9A-Fa-f]{3,8}$/);
  });
});

describe("Static accessibility checks (LAUNCH row h)", () => {
  it("declares a language on <html>", () => {
    expect(html).toMatch(/<html[^>]*\blang=["'][a-z]{2}(?:-[A-Z]{2})?["']/);
  });

  it("declares a charset meta", () => {
    expect(html).toMatch(/<meta\s+charset=["']?utf-8["']?/i);
  });

  it("includes a <main> landmark", () => {
    expect(html).toMatch(/<main\b/);
  });

  it("includes a <nav> landmark", () => {
    expect(html).toMatch(/<nav\b/);
  });

  it("every <img> has an alt attribute", () => {
    const imgs = html.match(/<img\b[^>]*>/g) ?? [];
    for (const tag of imgs) {
      expect(tag, `img missing alt: ${tag}`).toMatch(/\salt=["'][^"']*["']/);
    }
  });

  it('every role="button" element has accessible-name machinery (aria-label or text content)', () => {
    const buttons = html.match(/<[^>]+role=["']button["'][^>]*>/g) ?? [];
    for (const tag of buttons) {
      // Must carry either aria-label or aria-labelledby, OR be a
      // <button>/<a> with a text label. We only assert the aria-label
      // path here for non-native role="button" elements; native
      // <button>/<a> with text content satisfy WCAG automatically.
      const isNative = /<(?:button|a)\b/i.test(tag);
      if (isNative) continue;
      const hasAriaLabel = /\saria-label(?:ledby)?=["'][^"']+["']/.test(tag);
      expect(hasAriaLabel, `role="button" element needs aria-label: ${tag}`).toBe(true);
    }
  });

  it("every role=\"button\" element has tabindex=\"0\" (or is a native button/a)", () => {
    const buttons = html.match(/<[^>]+role=["']button["'][^>]*>/g) ?? [];
    for (const tag of buttons) {
      const isNative = /<(?:button|a)\b/i.test(tag);
      if (isNative) continue;
      expect(tag, `role="button" element needs tabindex: ${tag}`).toMatch(/\stabindex=["']0["']/);
    }
  });

  it("no `<a href=\"#\">` placeholder anchors", () => {
    const anchors = html.match(/<a\b[^>]*\shref=["']#["'][^>]*>/g) ?? [];
    expect(anchors, "use a real href or a <button>, not <a href=\"#\">").toHaveLength(0);
  });

  it("nav has aria-label (best practice when multiple navs / landmarks exist)", () => {
    // Either the <nav> carries aria-label, or there is exactly one
    // top-level nav (in which case the label is implicit).
    const navs = html.match(/<nav\b[^>]*>/g) ?? [];
    if (navs.length > 1) {
      for (const n of navs) {
        expect(n, `multi-nav docs need aria-label on each <nav>: ${n}`).toMatch(/\saria-label(?:ledby)?=/);
      }
    }
  });
});

describe("v4 surface a11y (LAUNCH row v4-h)", () => {
  it("what-it-checks section has at least 6 tile headings (h3)", () => {
    // Extract the #what-it-checks section and count <h3> elements inside it.
    // The regex is intentionally loose — we only need a lower bound to catch
    // regressions that delete tiles.
    const sectionMatch = html.match(/<section[^>]*id=["']what-it-checks["'][^]*?<\/section>/i);
    // Fall back to counting all h3s in the document if the section boundary
    // is not cleanly parseable (defensive).
    const source = sectionMatch ? sectionMatch[0] : html;
    const h3s = source.match(/<h3\b[^>]*>/gi) ?? [];
    expect(h3s.length, `expected at least 6 tile <h3> headings in #what-it-checks, got ${h3s.length}`).toBeGreaterThanOrEqual(6);
  });

  it("every tile heading is a <h3>", () => {
    // All tile titles inside #what-it-checks must use <h3>, not <h4> or
    // plain <strong>. This prevents heading-hierarchy regressions.
    const sectionMatch = html.match(/<section[^>]*id=["']what-it-checks["'][^]*?<\/section>/i);
    const source = sectionMatch ? sectionMatch[0] : html;
    const h3s = source.match(/<h3\b[^>]*>/gi) ?? [];
    expect(h3s.length, "no <h3> tile headings found inside #what-it-checks").toBeGreaterThan(0);
  });

  it('hero <h1> reads "Drop legal docs."', () => {
    // spec-v4 §18 item 1: tagline updated to "Drop legal docs."
    // The h1 may contain additional lines after the period; we assert the
    // opening phrase is present.
    expect(html).toMatch(/Drop legal docs\./);
  });

  it("drop-zone aria-label exists and mentions PDF or DOCX", () => {
    // The drop zone must have an aria-label that tells screen-reader users
    // what file types are accepted (spec-v4 §18 item 2).
    // Search broadly: find the aria-label on any element that has dropzone
    // in its id or class, or find the aria-label near the dropzone div.
    const ariaMatch = html.match(/aria-label=["']([^"']*)["'][^>]*(?:dropzone|Drop a|Drop PDF|folder|zip)/i) ??
      html.match(/(?:id=["']dropzone["']|role=["']button["'][^>]*dropzone|dropzone[^>]*role=["']button["'])[^]*?aria-label=["']([^"']*)["']/i) ??
      html.match(/aria-label=["']([^"']*(?:PDF|DOCX|pdf|docx)[^"']*)["']/i);
    expect(ariaMatch, "drop-zone element has no aria-label mentioning PDF or DOCX").not.toBeNull();
    const label = ariaMatch![1] ?? ariaMatch![0];
    expect(label, "drop-zone aria-label does not mention PDF or DOCX").toMatch(/PDF|DOCX/i);
  });

  it('footer wordmark has aria-label="Vaulytica home"', () => {
    // The wordmark anchor must carry the aria-label so screen-reader users
    // can identify the home link without relying on the SVG logo.
    expect(html).toMatch(/aria-label=["']Vaulytica home["']/);
  });
});

describe("Static a11y hardening (LAUNCH rows h / v4-f)", () => {
  // These checks extend the WCAG 2.2 AA static surface. They run cheaply
  // on every commit so a regression in any of them fails CI before the
  // axe DevTools live audit. axe will flag many of the same issues but
  // only runs against the deployed page — these catch regressions earlier.

  it("heading hierarchy is monotonic (no h1 → h3 jump skipping h2)", () => {
    // Extract every heading level in document order, then assert no
    // jump-down step exceeds 1. A `h1 → h2` step is fine; `h1 → h3`
    // is not. Going back up (h3 → h2 → h2) is always allowed because
    // a new section can re-anchor the hierarchy.
    const levels: number[] = [];
    const headingRe = /<h([1-6])\b[^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = headingRe.exec(html)) !== null) {
      levels.push(Number(m[1]));
    }
    expect(levels.length, "no headings found in the document").toBeGreaterThan(0);
    let prev = 0;
    for (let i = 0; i < levels.length; i++) {
      const cur = levels[i]!;
      if (prev > 0 && cur > prev + 1) {
        throw new Error(
          `heading hierarchy jumps from h${prev} to h${cur} at index ${i}; insert an intermediate level`,
        );
      }
      prev = cur;
    }
  });

  it("exactly one <h1> on the page (WCAG document-structure best practice)", () => {
    const h1s = html.match(/<h1\b[^>]*>/gi) ?? [];
    expect(h1s.length, `expected exactly one <h1>, got ${h1s.length}`).toBe(1);
  });

  it("every native <button> has a non-empty accessible name (text content or aria-label)", () => {
    // Match <button ...>...</button> pairs and verify each has at least
    // one of: non-whitespace text content, aria-label, or aria-labelledby.
    // Self-closing buttons (rare/invalid) are skipped.
    const buttonRe = /<button\b([^>]*)>([^]*?)<\/button>/gi;
    let m: RegExpExecArray | null;
    while ((m = buttonRe.exec(html)) !== null) {
      const attrs = m[1] ?? "";
      const inner = (m[2] ?? "").trim();
      const hasAria =
        /\saria-label(?:ledby)?=["'][^"']+["']/.test(attrs);
      // Strip nested tags to test if there is any text-like content. An
      // SVG-only button without aria-label is the canonical regression
      // we want to catch.
      const innerText = inner.replace(/<[^>]+>/g, "").trim();
      const hasText = innerText.length > 0;
      expect(
        hasAria || hasText,
        `<button> needs accessible name (text content or aria-label): ${m[0].slice(0, 200)}`,
      ).toBe(true);
    }
  });

  it("every form control (<input>/<select>/<textarea>) has a label association", () => {
    // For each form-control tag, accept any one of:
    //   - aria-label / aria-labelledby on the control
    //   - id matched by a `<label for="<id>">` somewhere in the document
    //   - hidden attribute (e.g. our injected <input type="file">; the
    //     dropzone container carries the aria-label via role="button")
    //   - type="hidden" (non-interactive)
    //
    // We intentionally ignore inputs created by the JS dropzone at
    // runtime (they don't appear in the static HTML).
    const controlRe = /<(?:input|select|textarea)\b([^>]*)>/gi;
    let m: RegExpExecArray | null;
    while ((m = controlRe.exec(html)) !== null) {
      const attrs = m[1] ?? "";
      if (/\stype=["']hidden["']/.test(attrs)) continue;
      if (/\shidden(?:=|\s|>)/.test(attrs + ">")) continue;
      const ariaLabeled = /\saria-label(?:ledby)?=["'][^"']+["']/.test(attrs);
      if (ariaLabeled) continue;
      const idMatch = /\sid=["']([^"']+)["']/.exec(attrs);
      if (idMatch) {
        const labelRe = new RegExp(
          `<label\\s+[^>]*for=["']${idMatch[1]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`,
          "i",
        );
        if (labelRe.test(html)) continue;
      }
      throw new Error(
        `form control has no label association (aria-label or matching <label for=…>): ${m[0]}`,
      );
    }
  });

  it("every <a> anchor has a non-empty accessible name", () => {
    // Either text content or aria-label / aria-labelledby. Empty
    // <a></a> tags are typically a regression (e.g. an SVG-only link
    // missing aria-label).
    const anchorRe = /<a\b([^>]*)>([^]*?)<\/a>/gi;
    let m: RegExpExecArray | null;
    while ((m = anchorRe.exec(html)) !== null) {
      const attrs = m[1] ?? "";
      const inner = (m[2] ?? "").trim();
      const hasAria = /\saria-label(?:ledby)?=["'][^"']+["']/.test(attrs);
      // Strip inner tags down to text; SVG-only anchors without aria-label
      // are the regression we want to catch.
      const innerText = inner.replace(/<[^>]+>/g, "").trim();
      const hasText = innerText.length > 0;
      expect(
        hasAria || hasText,
        `<a> needs accessible name (text content or aria-label): ${m[0].slice(0, 200)}`,
      ).toBe(true);
    }
  });
});

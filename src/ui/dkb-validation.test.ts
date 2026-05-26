/**
 * Unit coverage for the DKB-validation footer hookup
 * (spec-v3 §14 / Step 20). The production fetch hits
 * `/dkb/v3/validation-status.json`; the build pipeline (Vite's
 * deployAssets plugin) writes a default file when no real one
 * exists so the fetch never 404s in production. These tests pin
 * the render contract (which `[data-role="…"]` nodes get
 * populated) and the failure modes that must NOT throw or render
 * partial state — a network or schema failure leaves the footer
 * at its default text.
 */

import { describe, expect, it } from "vitest";

import {
  hydrateDkbValidation,
  renderDkbValidation,
  type DkbValidationStatus,
} from "./dkb-validation.js";

function makeFooter(): HTMLElement {
  const root = document.createElement("div");
  root.innerHTML = `
    <p data-role="dkb-validation">
      Last validated: <span data-role="dkb-validated-at">—</span> ·
      <span data-role="dkb-stale-count">0</span> stale citations
    </p>
  `;
  return root;
}

function mkFetch(opts: {
  ok?: boolean;
  status?: number;
  json?: unknown;
  throws?: Error;
}): typeof fetch {
  return ((async () => {
    if (opts.throws) throw opts.throws;
    return {
      ok: opts.ok ?? true,
      status: opts.status ?? 200,
      async json() {
        return opts.json;
      },
    } as unknown as Response;
  }) as unknown) as typeof fetch;
}

describe("renderDkbValidation", () => {
  it("formats an ISO timestamp to YYYY-MM-DD and writes the count", () => {
    const root = makeFooter();
    const status: DkbValidationStatus = {
      dkb_last_validated_at: "2026-03-05T14:00:00.000Z",
      stale_citations_pending_review: 3,
    };
    renderDkbValidation(root, status);
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]')!.textContent,
    ).toBe("2026-03-05");
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-stale-count"]')!.textContent,
    ).toBe("3");
    const wrapper = root.querySelector<HTMLElement>('[data-role="dkb-validation"]')!;
    expect(wrapper.dataset.validatedAt).toBe("2026-03-05T14:00:00.000Z");
    expect(wrapper.dataset.staleCount).toBe("3");
  });

  it("keeps the original string when the timestamp is unparseable", () => {
    const root = makeFooter();
    renderDkbValidation(root, {
      dkb_last_validated_at: "not-a-date",
      stale_citations_pending_review: 0,
    });
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]')!.textContent,
    ).toBe("not-a-date");
  });

  it("renders zero stale-citation count as the literal '0'", () => {
    const root = makeFooter();
    renderDkbValidation(root, {
      dkb_last_validated_at: "2026-01-01T00:00:00.000Z",
      stale_citations_pending_review: 0,
    });
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-stale-count"]')!.textContent,
    ).toBe("0");
  });

  it("is a no-op when the footer DOM is absent (no targets to fill)", () => {
    const root = document.createElement("div");
    // Should not throw even though there are no [data-role] hooks.
    expect(() =>
      renderDkbValidation(root, {
        dkb_last_validated_at: "2026-01-01T00:00:00.000Z",
        stale_citations_pending_review: 0,
      }),
    ).not.toThrow();
  });
});

describe("hydrateDkbValidation", () => {
  it("fetches, parses, and renders a well-formed payload", async () => {
    const root = makeFooter();
    const status = await hydrateDkbValidation({
      base: "/dkb",
      fetchImpl: mkFetch({
        ok: true,
        json: {
          dkb_last_validated_at: "2026-04-15T00:00:00.000Z",
          stale_citations_pending_review: 7,
        },
      }),
      root,
    });
    expect(status).toEqual({
      dkb_last_validated_at: "2026-04-15T00:00:00.000Z",
      stale_citations_pending_review: 7,
    });
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]')!.textContent,
    ).toBe("2026-04-15");
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-stale-count"]')!.textContent,
    ).toBe("7");
  });

  it("hits the configured base URL exactly", async () => {
    let calledWith = "";
    const fetchImpl: typeof fetch = (async (input: RequestInfo | URL) => {
      calledWith = typeof input === "string" ? input : (input as URL).toString();
      return {
        ok: true,
        async json() {
          return {
            dkb_last_validated_at: "2026-01-01T00:00:00.000Z",
            stale_citations_pending_review: 0,
          };
        },
      } as Response;
    }) as unknown as typeof fetch;
    await hydrateDkbValidation({ base: "/custom-dkb", fetchImpl, root: makeFooter() });
    expect(calledWith).toBe("/custom-dkb/v3/validation-status.json");
  });

  it("returns null and leaves the DOM untouched on a 404", async () => {
    const root = makeFooter();
    const baseline = root.querySelector<HTMLElement>(
      '[data-role="dkb-validated-at"]',
    )!.textContent;
    const status = await hydrateDkbValidation({
      fetchImpl: mkFetch({ ok: false, status: 404 }),
      root,
    });
    expect(status).toBeNull();
    expect(
      root.querySelector<HTMLElement>('[data-role="dkb-validated-at"]')!.textContent,
    ).toBe(baseline);
  });

  it("returns null on malformed JSON shape (missing field)", async () => {
    const root = makeFooter();
    const status = await hydrateDkbValidation({
      fetchImpl: mkFetch({ ok: true, json: { only: "wrong" } }),
      root,
    });
    expect(status).toBeNull();
  });

  it("returns null on wrong field types (count as string)", async () => {
    const root = makeFooter();
    const status = await hydrateDkbValidation({
      fetchImpl: mkFetch({
        ok: true,
        json: {
          dkb_last_validated_at: "2026-01-01T00:00:00.000Z",
          stale_citations_pending_review: "many",
        },
      }),
      root,
    });
    expect(status).toBeNull();
  });

  it("returns null when JSON is null or non-object", async () => {
    const root = makeFooter();
    expect(
      await hydrateDkbValidation({
        fetchImpl: mkFetch({ ok: true, json: null }),
        root,
      }),
    ).toBeNull();
    expect(
      await hydrateDkbValidation({
        fetchImpl: mkFetch({ ok: true, json: "string-body" }),
        root,
      }),
    ).toBeNull();
  });

  it("swallows fetch rejections and returns null (privacy promise — never throws)", async () => {
    const root = makeFooter();
    const status = await hydrateDkbValidation({
      fetchImpl: mkFetch({ throws: new Error("offline") }),
      root,
    });
    expect(status).toBeNull();
  });

  it("returns null when no fetch implementation is available globally", async () => {
    const originalFetch = globalThis.fetch;
    // Force the fallback `?? globalThis.fetch` to land on undefined so
    // the function's early-return path is exercised.
    (globalThis as { fetch?: typeof fetch }).fetch = undefined;
    try {
      const status = await hydrateDkbValidation({ root: makeFooter() });
      expect(status).toBeNull();
    } finally {
      (globalThis as { fetch?: typeof fetch }).fetch = originalFetch;
    }
  });
});

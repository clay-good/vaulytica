/**
 * @vitest-environment happy-dom
 */
import { beforeEach, describe, expect, it } from "vitest";

import { hydrateDkbValidation, renderDkbValidation } from "../../../src/ui/dkb-validation.js";

const footerHtml = `
  <p data-role="dkb-validation">
    DKB last validated: <span data-role="dkb-validated-at">—</span>.
    Stale citations under review: <span data-role="dkb-stale-count">0</span>.
  </p>
`;

beforeEach(() => {
  document.body.innerHTML = footerHtml;
});

describe("renderDkbValidation", () => {
  it("updates the date and count spans and sets data-* attributes", () => {
    renderDkbValidation(document, {
      dkb_last_validated_at: "2026-05-12T00:00:00Z",
      stale_citations_pending_review: 3,
    });
    const wrapper = document.querySelector('[data-role="dkb-validation"]')!;
    expect(wrapper.querySelector('[data-role="dkb-validated-at"]')!.textContent).toBe("2026-05-12");
    expect(wrapper.querySelector('[data-role="dkb-stale-count"]')!.textContent).toBe("3");
    expect((wrapper as HTMLElement).dataset.staleCount).toBe("3");
  });
});

describe("hydrateDkbValidation", () => {
  it("fetches the status JSON and renders the footer", async () => {
    const fakeFetch = (async () => ({
      ok: true,
      json: async () => ({
        dkb_last_validated_at: "2026-05-01T00:00:00Z",
        stale_citations_pending_review: 0,
      }),
    })) as unknown as typeof fetch;
    const result = await hydrateDkbValidation({ fetchImpl: fakeFetch });
    expect(result?.stale_citations_pending_review).toBe(0);
    expect(document.querySelector('[data-role="dkb-validated-at"]')!.textContent).toBe(
      "2026-05-01",
    );
  });

  it("returns null and leaves DOM unchanged on a bad payload", async () => {
    const fakeFetch = (async () => ({
      ok: true,
      json: async () => ({ not: "valid" }),
    })) as unknown as typeof fetch;
    const result = await hydrateDkbValidation({ fetchImpl: fakeFetch });
    expect(result).toBeNull();
    expect(document.querySelector('[data-role="dkb-validated-at"]')!.textContent).toBe("—");
  });

  it("returns null when fetch fails", async () => {
    const fakeFetch = (async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    const result = await hydrateDkbValidation({ fetchImpl: fakeFetch });
    expect(result).toBeNull();
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { registerServiceWorker } from "./sw-register.js";

const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis.navigator, "serviceWorker");

afterEach(() => {
  // Restore the real navigator after each test.
  if (originalDescriptor) {
    Object.defineProperty(globalThis.navigator, "serviceWorker", originalDescriptor);
  } else {
    // happy-dom's navigator may not have serviceWorker — define and clear.
    try {
      delete (globalThis.navigator as unknown as Record<string, unknown>).serviceWorker;
    } catch {
      /* ignore */
    }
  }
});

function installFakeSw(opts: { controller?: object | null } = {}): {
  register: ReturnType<typeof vi.fn>;
  addEventListener: ReturnType<typeof vi.fn>;
} {
  const register = vi.fn();
  register.mockImplementation(() => Promise.resolve({}));
  const addEventListener = vi.fn();
  Object.defineProperty(globalThis.navigator, "serviceWorker", {
    configurable: true,
    value: {
      register,
      controller: opts.controller ?? null,
      addEventListener,
    },
  });
  return { register, addEventListener };
}

describe("registerServiceWorker", () => {
  it("registers the SW at the given URL when serviceWorker is supported", async () => {
    const { register } = installFakeSw();
    await registerServiceWorker({ url: "/sw.js" });
    expect(register).toHaveBeenCalledWith("/sw.js", { scope: "/" });
  });

  it("is a no-op when serviceWorker is unavailable", async () => {
    Object.defineProperty(globalThis.navigator, "serviceWorker", {
      configurable: true,
      value: undefined,
    });
    await expect(registerServiceWorker()).resolves.toBeUndefined();
  });

  it("shows the badge when controller is present and subscribes to controllerchange", async () => {
    const badge = document.createElement("span");
    badge.hidden = true;
    const { addEventListener } = installFakeSw({ controller: {} });
    await registerServiceWorker({ badge });
    expect(badge.hidden).toBe(false);
    expect(badge.getAttribute("aria-hidden")).toBe("false");
    expect(addEventListener).toHaveBeenCalledWith("controllerchange", expect.any(Function));
  });

  it("keeps the badge hidden when no controller is active yet", async () => {
    const badge = document.createElement("span");
    badge.hidden = true;
    installFakeSw({ controller: null });
    await registerServiceWorker({ badge });
    expect(badge.hidden).toBe(true);
  });

  it("swallows registration errors so the app remains usable online", async () => {
    Object.defineProperty(globalThis.navigator, "serviceWorker", {
      configurable: true,
      value: {
        register: vi.fn(async () => {
          throw new Error("blocked");
        }),
        controller: null,
        addEventListener: vi.fn(),
      },
    });
    await expect(registerServiceWorker()).resolves.toBeUndefined();
  });
});

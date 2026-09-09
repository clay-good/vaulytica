import { beforeAll, describe, expect, it } from "vitest";
import { bootUi } from "./main.js";

/**
 * `bootUi` is the wire between the page and everything else — the dropzone, the
 * empty state, and the three optional assertion panels — and it had **no test
 * at all**. `src/ui/main.ts` measured 0% of 185 statements: if this function
 * stopped binding the dropzone, every feature in the browser would be dead and
 * the suite would stay green.
 *
 * What is covered here is the wiring, not the pipeline: a REJECTED file and the
 * drag state never reach the analyzer, so these tests stay fast and headless.
 * Each panel is documented as optional — "when absent, the affordance is simply
 * not rendered" — which is a claim about behavior and is checked in both
 * directions.
 */
describe("bootUi", () => {
  // 🚨 `dragenter` fires `preloadPipeline()`, whose `void import("./pipeline.js")`
  // is deliberately unawaited — it races the user's file-pick gesture in the
  // browser. In a test it races TEARDOWN instead: the chunk finished loading
  // after the environment closed and vitest failed the whole run with an
  // `EnvironmentTeardownError`, while every test still reported green. (It
  // passed locally and broke CI, which is the timing all the way through.)
  // Loading the module up front puts it in the registry, so the preload
  // resolves from cache inside the test's own lifetime.
  beforeAll(async () => {
    await import("./pipeline.js");
  }, 60_000);

  const dropzone = (): HTMLElement => {
    const dz = document.createElement("div");
    document.body.appendChild(dz);
    return dz;
  };

  it("renders the empty state into the drop zone", async () => {
    const dz = dropzone();
    expect(dz.innerHTML).toBe("");
    await bootUi({ dropzone: dz });
    expect(dz.innerHTML.length, "the drop zone booted empty").toBeGreaterThan(0);
    expect(dz.textContent ?? "").toMatch(/drop|drag|choose/i);
  });

  it("binds the drop zone: a rejected file becomes the error state", async () => {
    const dz = dropzone();
    await bootUi({ dropzone: dz });
    const transfer = { files: [new File(["x"], "legacy.doc")], items: [] };
    const event = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "dataTransfer", { value: transfer });
    dz.dispatchEvent(event);
    expect(dz.textContent ?? "", "a .doc drop did not reach the error state").toMatch(
      /save it as \.docx/i,
    );
  });

  it("tracks the drag state on the drop zone element", async () => {
    const dz = dropzone();
    await bootUi({ dropzone: dz });
    // `dragenter` is what sets it — `dragover` only preventDefaults, which is
    // what keeps the browser from navigating to the dropped file.
    dz.dispatchEvent(new Event("dragenter", { bubbles: true, cancelable: true }));
    // Let the (now cached) preload settle inside the test's own lifetime.
    await new Promise((r) => setTimeout(r, 0));
    expect(dz.classList.contains("is-dragging")).toBe(true);
    dz.dispatchEvent(new Event("dragleave", { bubbles: true, cancelable: true }));
    expect(dz.classList.contains("is-dragging")).toBe(false);
  });

  it("renders each optional panel when given a container", async () => {
    const dz = dropzone();
    const panels = {
      playbookPanelContainer: document.createElement("div"),
      regimePanelContainer: document.createElement("div"),
      estatePanelContainer: document.createElement("div"),
    };
    for (const el of Object.values(panels)) document.body.appendChild(el);
    await bootUi({ dropzone: dz, ...panels });
    for (const [name, el] of Object.entries(panels)) {
      expect(
        el.innerHTML.length,
        `${name} was given a container and rendered nothing`,
      ).toBeGreaterThan(0);
    }
  });

  it("renders no panel affordance when no container is given", async () => {
    const dz = dropzone();
    await expect(bootUi({ dropzone: dz })).resolves.toBeUndefined();
    // The claim in the option docs: absent container, no affordance — and, in
    // particular, nothing appended to the drop zone or the document body.
    expect(document.querySelector("[data-role='playbook-panel']")).toBeNull();
  });
});

/**
 * What makes the results page clickable (add-results-page): rows open and close
 * in place, Copy puts the suggested change on the clipboard, and printing opens
 * every fold. The page itself is rendered in the lazy pipeline chunk
 * (`results-page.ts`); this is the part the eager entry has to carry.
 */

/**
 * Behavior for every row under `root`. The text Copy puts on the clipboard
 * rides on the button itself, escaped, so nothing here needs the model.
 */
export function wireResultsPage(root: HTMLElement): void {
  root.addEventListener("click", (e) => {
    const target = e.target as Element | null;
    const toggle = target?.closest<HTMLButtonElement>('[data-role="result-row"]');
    if (toggle && root.contains(toggle)) {
      e.stopPropagation();
      const detail = root.querySelector<HTMLElement>(
        `#${CSS.escape(toggle.getAttribute("aria-controls") ?? "")}`,
      );
      if (!detail) return;
      const open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
      detail.hidden = open;
      return;
    }
    const copy = target?.closest<HTMLButtonElement>('[data-role="copy-suggested"]');
    if (copy && root.contains(copy)) {
      e.stopPropagation();
      const status = copy
        .closest('[data-role="result-detail"]')
        ?.querySelector<HTMLElement>('[data-role="copy-status"]');
      if (status) void copyText(copy.getAttribute("data-copy") ?? "", status);
    }
  });
}

/** Clipboard first; where it is refused, the text selected in a box to copy by hand. */
async function copyText(text: string, status: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    status.textContent = "Copied.";
  } catch {
    status.textContent = "Select the text below and copy it.";
    let box = status.nextElementSibling;
    if (!(box instanceof HTMLTextAreaElement)) {
      box = document.createElement("textarea");
      status.after(box);
    }
    const area = box as HTMLTextAreaElement;
    area.className = "result-copy-box";
    area.readOnly = true;
    area.value = text;
    area.select();
  }
}

let printInstalled = false;

/**
 * Printing (or Save as PDF) gives the whole page: every fold opens for the
 * print and closes again after, so the copy on paper is never missing what a
 * reader had not clicked. Rows open through the print stylesheet.
 */
export function installPrintExpansion(): void {
  if (printInstalled || typeof window === "undefined") return;
  printInstalled = true;
  let opened: HTMLDetailsElement[] = [];
  window.addEventListener("beforeprint", () => {
    opened = Array.from(
      document.querySelectorAll<HTMLDetailsElement>('[data-state="complete"] details:not([open])'),
    );
    for (const d of opened) d.open = true;
  });
  window.addEventListener("afterprint", () => {
    for (const d of opened) d.open = false;
    opened = [];
  });
}

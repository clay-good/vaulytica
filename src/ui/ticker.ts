/**
 * Rule ticker. As the engine executes each rule, the ticker appends
 * a "checking RULE-ID name" line and scrolls the previous line off
 * the top with a CSS transform. The host element holds at most
 * {@link MAX_VISIBLE} lines; older lines are removed from the DOM so
 * a long run doesn't accumulate thousands of nodes.
 */

const MAX_VISIBLE = 8;

export type RuleTicker = {
  push(ruleId: string, name: string): void;
  clear(): void;
  destroy(): void;
};

export function createRuleTicker(host: HTMLElement): RuleTicker {
  host.setAttribute("role", "log");
  host.setAttribute("aria-live", "polite");
  host.setAttribute("aria-atomic", "false");
  const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  if (reduce) host.dataset.reducedMotion = "true";

  const push = (ruleId: string, name: string): void => {
    const line = document.createElement("div");
    line.className = "rule-ticker__line";
    line.textContent = `checking ${ruleId} — ${name}`;
    host.appendChild(line);
    while (host.children.length > MAX_VISIBLE) {
      host.removeChild(host.children[0]!);
    }
  };

  const clear = (): void => {
    while (host.firstChild) host.removeChild(host.firstChild);
  };

  const destroy = (): void => {
    clear();
    host.removeAttribute("role");
    host.removeAttribute("aria-live");
    host.removeAttribute("aria-atomic");
    delete host.dataset.reducedMotion;
  };

  return { push, clear, destroy };
}

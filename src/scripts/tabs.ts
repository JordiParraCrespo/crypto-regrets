/**
 * Keyboard support for an ARIA tablist (APG "tabs with automatic activation"):
 * only the selected tab is in the Tab order, Arrow keys / Home / End move between tabs
 * and activate them. `select(tab)` updates aria-selected and the panels.
 */
export function wireTabs(tabs: HTMLElement[], select: (tab: HTMLElement) => void) {
  const activate = (t: HTMLElement, focus: boolean) => {
    select(t);
    for (const o of tabs) o.tabIndex = o === t ? 0 : -1;
    if (focus) t.focus();
  };
  tabs.forEach((t, k) => {
    t.tabIndex = t.getAttribute('aria-selected') === 'true' ? 0 : -1;
    t.addEventListener('click', () => activate(t, false));
    t.addEventListener('keydown', (e) => {
      const next = { ArrowRight: k + 1, ArrowLeft: k - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (next === undefined) return;
      e.preventDefault();
      activate(tabs[(next + tabs.length) % tabs.length], true);
    });
  });
}

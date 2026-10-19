/**
 * Upgrades every `select.select` into a searchable, styled listbox popover.
 *
 * The native <select> stays in the DOM (visually hidden) and remains the source of truth:
 * picking an option sets its value and dispatches `input` + `change`, so page scripts that
 * read or listen to the select keep working. Lists longer than SEARCH_MIN options get a
 * search field; an option's `data-count` is shown right-aligned.
 */

const SEARCH_MIN = 6;
let uid = 0;

const norm = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

function enhance(select: HTMLSelectElement) {
  if (select.dataset.combo) return;
  select.dataset.combo = '1';
  const id = `cb${uid++}`;
  const options = Array.from(select.options);
  const searchable = options.length > SEARCH_MIN || select.dataset.search != null;
  const label = select.getAttribute('aria-label') ?? '';

  const root = document.createElement('div');
  root.className = 'combo';
  select.parentNode!.insertBefore(root, select);
  root.append(select);
  select.classList.add('combo-native');
  select.tabIndex = -1;
  select.setAttribute('aria-hidden', 'true');

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'combo-btn';
  button.setAttribute('aria-haspopup', 'listbox');
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-controls', `${id}-pop`);
  const value = document.createElement('span');
  value.className = 'combo-value';
  button.append(value);

  const pop = document.createElement('div');
  pop.className = 'combo-pop';
  pop.id = `${id}-pop`;
  pop.hidden = true;

  const list = document.createElement('ul');
  list.className = 'combo-list';
  list.id = `${id}-list`;
  list.setAttribute('role', 'listbox');
  list.setAttribute('aria-label', label);
  list.tabIndex = -1;

  let search: HTMLInputElement | null = null;
  if (searchable) {
    search = document.createElement('input');
    search.type = 'search';
    search.className = 'combo-search';
    search.placeholder = `Search ${label.toLowerCase()}…`;
    search.setAttribute('role', 'combobox');
    search.setAttribute('aria-label', `Search ${label.toLowerCase()}`);
    search.setAttribute('aria-controls', list.id);
    search.setAttribute('aria-expanded', 'true');
    search.setAttribute('aria-autocomplete', 'list');
    search.autocomplete = 'off';
    pop.append(search);
  }
  const empty = document.createElement('p');
  empty.className = 'combo-empty';
  empty.textContent = 'No matches';
  empty.hidden = true;
  pop.append(list, empty);
  root.append(button, pop);

  const items = options.map((o, i) => {
    const li = document.createElement('li');
    li.id = `${id}-o${i}`;
    li.className = 'combo-opt';
    li.setAttribute('role', 'option');
    li.dataset.value = o.value;
    const name = document.createElement('span');
    name.textContent = o.textContent ?? '';
    li.append(name);
    if (o.dataset.count) {
      const n = document.createElement('span');
      n.className = 'combo-count';
      n.textContent = o.dataset.count;
      li.append(n);
    }
    list.append(li);
    return { li, text: norm(o.textContent ?? ''), value: o.value };
  });

  let active = -1;
  const visible = () => items.filter((x) => !x.li.hidden);

  function sync() {
    const opt = select.selectedOptions[0] ?? options[0];
    value.textContent = opt?.textContent ?? '';
    button.classList.toggle('is-set', select.value !== options[0]?.value);
    button.setAttribute('aria-label', `${label}: ${opt?.textContent ?? ''}`);
    for (const x of items) x.li.setAttribute('aria-selected', String(x.value === select.value));
  }

  function setActive(i: number) {
    const vis = visible();
    if (!vis.length) return;
    active = Math.max(0, Math.min(i, vis.length - 1));
    for (const x of items) x.li.classList.remove('is-active');
    const cur = vis[active].li;
    cur.classList.add('is-active');
    (search ?? list).setAttribute('aria-activedescendant', cur.id);
    cur.scrollIntoView({ block: 'nearest' });
  }

  function filter(q: string) {
    const nq = norm(q.trim());
    for (const x of items) x.li.hidden = !!nq && !x.text.includes(nq);
    empty.hidden = visible().length > 0;
    setActive(0);
  }

  function open() {
    if (!pop.hidden) return;
    document.dispatchEvent(new CustomEvent('combo:open', { detail: root }));
    pop.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    // Open towards the side with room, so popovers near the right edge stay on screen.
    pop.classList.toggle('align-right', button.getBoundingClientRect().left + 320 > window.innerWidth);
    if (search) {
      search.value = '';
      filter('');
      search.focus();
    } else list.focus();
    const sel = visible().findIndex((x) => x.value === select.value);
    setActive(sel < 0 ? 0 : sel);
  }

  function close(focus = true) {
    if (pop.hidden) return;
    pop.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    if (focus) button.focus();
  }

  function choose(v: string) {
    if (select.value !== v) {
      select.value = v;
      select.dispatchEvent(new Event('input', { bubbles: true }));
      select.dispatchEvent(new Event('change', { bubbles: true }));
    }
    sync();
    close();
  }

  button.addEventListener('click', () => (pop.hidden ? open() : close()));
  button.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      open();
    }
  });
  list.addEventListener('click', (e) => {
    const li = (e.target as HTMLElement).closest<HTMLLIElement>('.combo-opt');
    if (li) choose(li.dataset.value!);
  });
  list.addEventListener('mousemove', (e) => {
    const li = (e.target as HTMLElement).closest<HTMLLIElement>('.combo-opt');
    if (li) setActive(visible().findIndex((x) => x.li === li));
  });
  search?.addEventListener('input', () => filter(search!.value));
  pop.addEventListener('keydown', (e) => {
    const vis = visible();
    if (e.key === 'ArrowDown') setActive(active + 1);
    else if (e.key === 'ArrowUp') setActive(active - 1);
    else if (e.key === 'Home' && !search) setActive(0);
    else if (e.key === 'End' && !search) setActive(vis.length - 1);
    else if (e.key === 'PageDown') setActive(active + 8);
    else if (e.key === 'PageUp') setActive(active - 8);
    else if (e.key === 'Enter') vis[active] && choose(vis[active].value);
    else if (e.key === 'Escape') close();
    else if (e.key === 'Tab') return close(false);
    else return;
    e.preventDefault();
  });
  document.addEventListener('pointerdown', (e) => {
    if (!root.contains(e.target as Node)) close(false);
  });
  document.addEventListener('combo:open', (e) => {
    if ((e as CustomEvent).detail !== root) close(false);
  });
  // Page scripts may set the value programmatically (e.g. from the URL or a reset).
  select.addEventListener('input', sync);
  select.addEventListener('combo:sync', sync);
  sync();
}

for (const s of document.querySelectorAll<HTMLSelectElement>('select.select')) enhance(s);

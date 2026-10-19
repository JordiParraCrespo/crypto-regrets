/**
 * Internal links. Every page is built as a directory (`/hacks/` → hacks/index.html) and the
 * site uses `trailingSlash: 'always'`, so page links end in '/' to avoid a redirect on
 * GitHub Pages. Files (`/api/incidents.json`) and query/hash suffixes are left as they are.
 */
export const base = import.meta.env.BASE_URL.replace(/\/$/, '');

export function href(p: string): string {
  const [path, suffix = ''] = (p.startsWith('/') ? p : `/${p}`).split(/(?=[?#])/);
  const slashed = path.endsWith('/') || /\.[a-z0-9]+$/i.test(path) ? path : `${path}/`;
  return `${base}${slashed}${suffix}`;
}

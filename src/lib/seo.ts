import { href } from './paths';

/** schema.org BreadcrumbList from [name, root-relative path] pairs, the last item being the current page. */
export function breadcrumb(site: URL | undefined, items: [string, string][]) {
  return {
    '@type': 'BreadcrumbList',
    itemListElement: items.map(([name, path], i) => ({ '@type': 'ListItem', position: i + 1, name, item: new URL(href(path), site).toString() })),
  };
}

const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];

/** "Seventeen" for prose that starts a sentence with a count; digits above twenty. */
export const countWord = (n: number) => {
  const w = WORDS[n] ?? String(n);
  return w[0].toUpperCase() + w.slice(1);
};

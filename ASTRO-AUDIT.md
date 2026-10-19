# Astro Audit — crypto-regrets
2026-10-19 · Astro 7.4.0 (upgraded from 5.18.2 via 6.4.8) · output static · adapter none ·
integrations @astrojs/sitemap, @astrojs/check · `astro check` 0 errors / 0 warnings / 0 hints ·
`astro build` pass, 3,193 pages, dist 110 MB (85 MB before; see F-perf note)

Method: [astro-skills](https://github.com/JordiParraCrespo/astro-skills) `astro-audit`. One scanner run, five specialist agents in parallel (architect, performance, SEO, accessibility, security), findings merged and scored with the skill's model (critical 15, high 8, medium 3, low 1; each rule capped at 2× its weight). Fixes were then applied with the matching sub-skills and every finding re-verified.

## Score
**Before: 5/100 (at risk)** → **After: 98/100 (excellent)**. The scanner alone scored 90 before (it knows 19 rules); the agents found 40 more distinct problems, and the overall score is computed over all of them, so it is not an average of the category scores.

| Category | Before | After | Open after fixes |
|----------|--------|-------|------------------|
| Architecture | 80 | 98 | 2 low |
| Performance | 80 | 100 | 0 |
| SEO | 79 | 100 | 0 |
| Accessibility | 76 | 100 | 0 |
| Security | 90 | 100 | 0 |

## Upgrade (astro-upgrade)
| Hop | Guide | Applied | Verification |
|-----|-------|---------|--------------|
| 5.18 → 6.4.8 | [upgrade-to/v6](https://docs.astro.build/en/guides/upgrade-to/v6/) | Version bump only: Node 22.22 ≥ 22.12, no legacy collections / `Astro.glob` / `<ViewTransitions />` / numeric params; data schemas keep their own zod | Text of all 3,192 pages identical to v5; routes identical; check 0 errors |
| 6.4.8 → 7.4.0 | [upgrade-to/v7](https://docs.astro.build/en/guides/upgrade-to/v7/) | Rust compiler accepted every template; kept the new `compressHTML: 'jsx'` default | Pixel diff of 120 pages against an HTML-whitespace build: only the incident table lost stray whitespace text nodes (columns shift ~4px), no words joined |

Revert a hop with `git revert <hop commit>`.

## Priority matrix
| Bucket | ID | Finding | Effort | Impact | Status |
|--------|----|---------|--------|--------|--------|
| High | F1 | /hacks shipped all 3,093 rows + search text (677 KB gzip, TBT 1.9 s) | M | high | Fixed |
| High | F2 | Focus ring invisible on set filter buttons | S | high | Fixed |
| Quick win (high) | F3 | No canonical URL | S | high | Fixed |
| Quick win (high) | F4 | No sitemap | S | high | Fixed |
| Medium | F5 | Render-blocking Google Fonts | S | medium | Fixed |
| Medium | F6 | No CSP | M | medium | Fixed |
| Medium | F7 | Scraped URLs accept `javascript:` | S | medium | Fixed |
| Medium | F8 | 550 incident pages share titles | S | medium | Fixed |
| Medium | F9 | No Open Graph / Twitter cards | S | medium | Fixed |
| Medium | F10 | No Dataset JSON-LD on /data | S | medium | Fixed |
| Medium | F11 | "Show more" visible when nothing is left (`hidden` overridden) | S | medium | Fixed |
| Medium | F12 | Pagination not announced to screen readers | S | medium | Fixed |
| Medium | F13 | Listbox active option ~1.15:1 contrast; Space does nothing | S | medium | Fixed |
| Medium | F14 | Skip link invisible on focus | S | medium | Fixed |
| Medium | F15 | Focused rows hidden under the sticky filter bar | S | medium | Fixed |
| Medium | F16 | Internal links redirect (no trailing slash) | S | medium | Fixed |
| Medium | F17 | Hardcoded counts in copy ("56 classes" when there are 57) | S | medium | Fixed |
| Medium | F18 | "Latest" lists rely on file order | S | medium | Fixed |
| Medium | F19 | ecosystems/[id] 361-line monolith | M | medium | Fixed |
| Quick win | F20–F33 | Low findings, see below | S | low | Fixed (2 partial) |

## Findings
### F1 · performance.oversized-client-paginated-list + performance.inline-search-corpus · high · performance
- **Where:** `src/pages/hacks/index.astro`
- **Evidence:** 3.5 MB HTML / 677 KB gzip, 25,135 DOM nodes; `data-t` (full root causes) was 77% of the bytes. 412px, 4× CPU: DCL 3,091 ms, TBT 1,918 ms.
- **Fix:** Render the newest 100 rows (shared `IncidentRow.astro`). The filter index is a static endpoint `hacks/rows.json` (134 KB gzip), fetched on first interaction. The search corpus is `hacks/search.json` (459 KB gzip), fetched only when the search box gets focus. Rows are built from a `<template>` of the same component. Search input is debounced.
- **Verified:** HTML 14 KB gzip, 2,017 nodes, DCL ~350 ms, TBT 63–113 ms. No JSON fetched on load. "reentrancy" still matches 93 incidents, year 2022 matches 401.

### F2 · a11y.focus-indicator-removed · high · accessibility
- **Fix:** an outline ring on `.combo-btn:focus-visible` (a box-shadow ring lost to the `.is-set` rule). Inputs keep their ring under keyboard focus.
- **Verified:** Tab to a set filter: `outlineStyle` is `solid`.

### F3–F4, F8–F10, F16 · SEO (astro-seo)
- `src/components/Seo.astro`, following the skill's pattern, adds: canonical, `og:*` and `twitter:card` with a 1200×630 `og-default.png`, `noindex` (used by the new 404 page), and a JSON-LD `@graph` with `<` escaped.
- Descriptions are clipped to 155 characters at a word boundary.
- `@astrojs/sitemap` lists 3,192 URLs (the 404 page is excluded).
- New endpoints: `robots.txt` and `llms.txt`.
- JSON-LD: a Dataset on /data, WebSite on the home page, and BreadcrumbList on all detail pages.
- Incident titles read "<name> hack, <date>". "Unknown" and "unverified" names become "Unattributed <chain> <class> exploit". The loss is appended only where a name and date repeat.
- `trailingSlash: 'always'`, with `href()` adding the slash (files and `?`/`#` suffixes kept).
- **Verified (BASE_PATH=/crypto-regrets build):**
  - every canonical, og:image, sitemap `<loc>` and Dataset URL is absolute and base-prefixed;
  - 0 duplicate titles, 0 descriptions over 160 characters, 0 heading skips, 0 internal links without a trailing slash.

### F5 · performance.third-party-fonts · medium
- **Fix:** Astro 7 Fonts API (`fonts` + `<Font>`): Inter 400/500 and Geist Mono 400/700, Latin subset, self-hosted with preload and metric-matched fallbacks.
- **Verified:** no requests to fonts.googleapis.com or fonts.gstatic.com; CLS 0 on every measured route.
- **Note:** each page inlines 4.7 KB of `@font-face` rules. That accounts for most of the growth from 85 to 110 MB, but it is about 1.5 KB per page after gzip.
- **Note:** glyphs Inter lacks (→, ≥) now come from the size-adjusted Arial fallback instead of the system UI font.

### F6 · security.no-csp · medium
- **Fix:** Astro's stable `security.csp`, emitted as a per-page `<meta>` because GitHub Pages cannot set headers:
  - scripts: `'self'` plus sha256 hashes only;
  - `<style>` elements: hashed in `style-src-elem`;
  - inline `style=""` attributes: allowed through `style-src-attr 'unsafe-inline'`;
  - everything else: `default-src`, `img-src`, `font-src` and `connect-src` set to `'self'`; `object-src 'none'`; `base-uri` and `form-action` set to `'self'`.

  Supporting changes:
  - The two inline `onsubmit` handlers became script listeners.
  - The `is:inline` header script is now bundled.
  - Shiki is disabled, since the project has no Markdown.
  - A Referrer-Policy is set with `<meta name="referrer">`.
- **Verified:**
  - 0 violations across every page type, with the interactions exercised;
  - an injected inline script and an `onclick` handler are both blocked (`script-src-elem`, `script-src-attr`).
- **Limits:** a meta CSP cannot set `frame-ancestors` or reporting; that needs a CDN in front of Pages.

### F7 · security.unsafe-url-scheme · medium
- **Fix:** an `httpUrl` zod refinement on references, PoC, advisory, source-audit and Cosmos URLs.
- **Verified:** adding `javascript:alert(1)` to a reference makes `astro build` fail with "URL must be http(s)".

### F11–F15 · accessibility (astro-a11y)
- **F11:** a global `[hidden] { display: none !important }` rule.
- **F12:** `#more-count` has `role="status"`, and focus moves to the first new row when "Show more" disappears.
- **F13:** the active option gets a 2px ink inset ring, and Space selects in lists without a search box.
- **F14:** a `.skip-link` that slides in on focus.
- **F15:** `html { scroll-padding-top }`, raised on /hacks to clear the sticky filter bar.
- **Tabs (F20, low):** shared `src/scripts/tabs.ts` adds roving tabindex, Arrow/Home/End keys, and `aria-controls`/`tabpanel` wiring in `Switch` and `CodeTabs`.
- **Verified:**
  - 0 of 40 focused rows are obscured;
  - skip link is 133×36 and inside the viewport;
  - ArrowRight selects "Incidents";
  - Space sets the minimum loss to $1M;
  - axe: 0 WCAG 2 A/AA violations on all page types.

### F17–F19 and low architecture findings (astro-components / astro-routing / astro-styling)
- Counts are derived from data: classes, patterns, layers, years.
- `incidents` is sorted once when loaded.
- `CosmosResearch.astro` was extracted: ecosystem pages drop from 361 to 157 lines, and the other ecosystem pages no longer compute the Cosmos aggregates.
- New shared components:
  - `IncidentRow` (used by the incident tables and /hacks);
  - `FilterSelect` (imports the combobox script, so a filter can't render unenhanced);
  - `Seo`.
- The developers checklist sections are one map instead of two copies.
- Typed `getStaticPaths` (`satisfies GetStaticPaths` + `InferGetStaticPropsType`) on all four dynamic routes.
- One `CLASSES` source, widened in `lib/classes.ts`.
- `data.ts` has all imports at the top; the Cosmos schemas moved to `types.ts`.
- `href()` lives in `lib/paths.ts`.
- Code snippets gained an `html` language.
- `Terminal` accepts `class` and other attributes.
- Shared layout classes (`.page-head`, `.cta`, `.chips`, `.split`, `.stats`, `.ranked`) are global, replacing 14 page copies.
- The heatmap ramp and code colors are tokens.
- Dead imports removed.
- **Verified:** `npm run check` (astro check + tsc) reports 0 errors, 0 warnings and 0 hints. Raw hex colors remain only in `:root` and the `theme-color` meta.

### Open (low)
- **styles.inline-spacing** (low): about 190 inline `style="margin…"` attributes remain. Spacing utilities on the `--s-*` tokens would let the CSP drop `style-src-attr 'unsafe-inline'`.
- **components.props-typing** (low, partial): `Bars` and `Heatmap` do not accept `class` or other attributes yet.

### Also done
- GitHub Actions:
  - least privilege (`contents: read`; only the deploy job has `pages`/`id-token`);
  - actions pinned to commit SHAs;
  - Dependabot for actions and npm.
- `.env*` added to `.gitignore`.
- `npm audit`: 0 vulnerabilities (the esbuild dev-server advisory fixed through `npm audit fix`).
- A second data dedup pass (previous PR) already removed the 5× WazirX double count.

## Rejected scanner findings
| Rule | File | Why it is a false positive |
|------|------|----------------------------|
| images.raw-img | `src/layouts/Base.astro` | 999-byte SVG logo with width and height set, `alt=""` next to visible text; it is also the favicon, so it needs a stable `public/` URL. `astro:assets` does not optimise SVG. |
| security.set-html | `src/components/Seo.astro` | JSON-LD via `JSON.stringify` (the skill's own pattern), with `<` escaped as `<`, so a third-party incident name cannot close the script element. |
| islands.client-load | — | No `client:*` directives and no UI framework. |
| links.hardcoded-internal / ts.not-strict / config.missing-site | — | Already clean: every link goes through `href()`, tsconfig extends `astro/tsconfigs/strict`, and `site` and `base` are set from env. |
| content.json-not-collection | `src/lib/data.ts` | Machine-generated, zod-validated JSON consumed synchronously; a Content Layer migration would add top-level awaits for no gain. Revisit if incidents become authored Markdown. |

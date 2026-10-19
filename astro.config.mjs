import { defineConfig, fontProviders } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// SITE / BASE_PATH let the same build deploy to a custom domain or GitHub Pages (/crypto-regrets).
export default defineConfig({
  site: process.env.SITE ?? 'https://jordiparracrespo.github.io',
  base: process.env.BASE_PATH ?? '/',
  // Pages are directories (hacks/index.html); linking with the slash avoids a redirect on GitHub Pages.
  trailingSlash: 'always',
  build: { format: 'directory' },
  integrations: [sitemap({ filter: (page) => !page.endsWith('/404/') })],
  // No Markdown in this project; Shiki's inline styles would otherwise trip the CSP check.
  markdown: { syntaxHighlight: false },
  prefetch: { prefetchAll: false, defaultStrategy: 'hover' },
  // GitHub Pages cannot send headers, so the policy ships as a <meta> tag with hashes of every script
  // and <style> Astro emits. Inline style="" attributes are allowed; scripts never run inline.
  security: {
    csp: {
      directives: [
        "default-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ],
      styleDirective: {
        resources: [
          { resource: "'self'", kind: 'element' },
          { resource: "'unsafe-inline'", kind: 'attribute' },
        ],
      },
    },
  },
  // Self-hosted with size-adjusted fallbacks instead of a render-blocking Google Fonts stylesheet.
  fonts: [
    { provider: fontProviders.google(), name: 'Inter', cssVariable: '--font-inter', weights: [400, 500], subsets: ['latin'], fallbacks: ['sans-serif'] },
    { provider: fontProviders.google(), name: 'Geist Mono', cssVariable: '--font-geist-mono', weights: [400, 700], subsets: ['latin'], fallbacks: ['monospace'] },
  ],
});

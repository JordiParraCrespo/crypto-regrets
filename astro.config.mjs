import { defineConfig } from 'astro/config';

// SITE / BASE_PATH let the same build deploy to a custom domain or GitHub Pages (/crypto-regrets).
export default defineConfig({
  site: process.env.SITE ?? 'https://jordiparracrespo.github.io',
  base: process.env.BASE_PATH ?? '/',
  trailingSlash: 'ignore',
  build: { format: 'directory' },
});

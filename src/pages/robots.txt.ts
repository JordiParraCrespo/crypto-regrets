import type { APIRoute } from 'astro';
import { href } from '../lib/paths';

// Only takes effect at a host root (custom domain); on github.io/<repo> submit the sitemap in Search Console.
export const GET: APIRoute = ({ site }) =>
  new Response(`User-agent: *\nAllow: /\n\nSitemap: ${new URL(href('/sitemap-index.xml'), site)}\n`, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });

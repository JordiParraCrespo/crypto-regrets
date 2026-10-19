import type { APIRoute } from 'astro';
import { incidents } from '../../lib/data';

/** Full-text search corpus for /hacks (root causes are long), fetched only once someone types a query. Same order as rows.json. */
export const GET: APIRoute = () =>
  new Response(JSON.stringify(incidents.map((i) => `${i.name} ${i.technique ?? ''} ${i.rootCause ?? ''}`.toLowerCase())), {
    headers: { 'Content-Type': 'application/json' },
  });

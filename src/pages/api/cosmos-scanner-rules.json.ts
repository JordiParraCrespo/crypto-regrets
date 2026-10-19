import type { APIRoute } from 'astro';
import { COSMOS_AREAS, COSMOS_CLASSES } from '../../lib/cosmos';

/** Scanner-ready export: every Cosmos class with its rules, code shapes and fixes. */
export const GET: APIRoute = () =>
  new Response(
    JSON.stringify({ areas: COSMOS_AREAS, classes: Object.entries(COSMOS_CLASSES).map(([id, c]) => ({ id, ...c })) }, null, 1),
    { headers: { 'Content-Type': 'application/json' } },
  );

import type { APIRoute } from 'astro';
import { CATEGORIES, LAYERS, ERAS } from '../../lib/taxonomy';

export const GET: APIRoute = () => new Response(JSON.stringify({ layers: LAYERS, categories: CATEGORIES, eras: ERAS }), { headers: { 'Content-Type': 'application/json' } });

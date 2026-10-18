import type { APIRoute } from 'astro';
import { incidents } from '../../lib/data';

export const GET: APIRoute = () => new Response(JSON.stringify(incidents), { headers: { 'Content-Type': 'application/json' } });

import type { APIRoute } from 'astro';
import { advisories } from '../../lib/data';

export const GET: APIRoute = () => new Response(JSON.stringify(advisories), { headers: { 'Content-Type': 'application/json' } });

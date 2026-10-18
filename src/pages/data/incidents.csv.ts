import type { APIRoute } from 'astro';
import csv from '../../../data/incidents.csv?raw';

export const GET: APIRoute = () => new Response(csv, { headers: { 'Content-Type': 'text/csv; charset=utf-8' } });

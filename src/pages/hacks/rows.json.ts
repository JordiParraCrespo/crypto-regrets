import type { APIRoute } from 'astro';
import { incidents, fmtUsd, fmtDate, labelOf } from '../../lib/data';
import type { IndexRow } from '../../lib/types';

/**
 * Compact filter index for /hacks, loaded on the first interaction instead of rendering every
 * incident into the page. Display strings are formatted here so the client never re-implements them.
 */
export const GET: APIRoute = () => {
  const rows: IndexRow[] = incidents.map((i) => ({
    id: i.id,
    n: i.name,
    d: i.date,
    dl: fmtDate(i.date),
    a: i.amountUsd ?? 0,
    al: fmtUsd(i.amountUsd),
    ch: i.chains,
    s: [i.chains.slice(0, 3).join(' · '), i.technique].filter(Boolean).join(' — '),
    k: i.vulnClass,
    c: i.category,
    l: labelOf(i),
    p: i.poc ? 1 : 0,
    by: i.classifiedBy,
    dis: i.ai && i.ai.category !== i.category ? 1 : 0,
    fl: i.ai && i.ai.flashLoan >= 0.5 ? 1 : 0,
    t: `${i.name} ${i.technique ?? ''}`.toLowerCase(),
  }));
  return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
};

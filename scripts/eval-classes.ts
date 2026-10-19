/**
 * Score TypeSafe's level-2 (vulnerability class) answers against analyst technique labels that
 * map to exactly one class (TECHNIQUE_TO_CLASS).
 *
 *   npx tsx scripts/eval-classes.ts            # from the cache (model saw the technique label)
 *   npx tsx scripts/eval-classes.ts --blind    # re-ask with the label hidden: the honest number
 *                                              # for incidents that only have free text
 */
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { incidentSchema } from '../src/lib/types';
import { CLASSES, TECHNIQUE_TO_CLASS } from '../src/lib/classes';
import { CLASS_CACHE_FILE, aiState, classQuestion, classStateHash, type CachedClass } from './classify-spec';
import { systemOne } from './typesafe';

const incidents = z.array(incidentSchema).parse(JSON.parse(readFileSync('data/incidents.json', 'utf8')));
const cache: Record<string, CachedClass> = JSON.parse(readFileSync(CLASS_CACHE_FILE, 'utf8'));
const rows = incidents.flatMap((i) => {
  const ref = i.technique ? TECHNIQUE_TO_CLASS[i.technique] : undefined;
  const c = cache[i.id];
  if (!ref || CLASSES[ref].parent !== i.category || !c || c.hash !== classStateHash(i)) return [];
  return [{ i, ref, got: c.class as string, conf: c.confidence }];
});

if (process.argv.includes('--blind')) {
  const apiKey = process.env.TYPESAFE_API_KEY;
  if (!apiKey) throw new Error('Set TYPESAFE_API_KEY');
  const queue = [...rows];
  await Promise.all(
    Array.from({ length: 8 }, async () => {
      for (let r = queue.shift(); r; r = queue.shift()) {
        if (r.i.category === 'unknown') continue;
        const res = await systemOne({ apiKey, state: { ...aiState(r.i), technique_label: null }, questions: { vuln_class: classQuestion(r.i.category) } });
        r.got = res.answers.vuln_class.choice;
        r.conf = res.answers.vuln_class.confidence;
      }
    }),
  );
}
const pct = (n: number, d: number) => `${((100 * n) / Math.max(d, 1)).toFixed(1)}% (${n}/${d})`;
console.log(`labelled test set: ${rows.length}`);
console.log(`overall  ${pct(rows.filter((r) => r.got === r.ref).length, rows.length)}`);
for (const [lo, hi] of [[0, 0.5], [0.5, 0.7], [0.7, 0.9], [0.9, 1.01]]) {
  const xs = rows.filter((r) => r.conf >= lo && r.conf < hi);
  console.log(`conf ${lo}-${hi}: ${pct(xs.filter((r) => r.got === r.ref).length, xs.length)}`);
}
const byRef = new Map<string, typeof rows>();
for (const r of rows) byRef.set(r.ref, [...(byRef.get(r.ref) ?? []), r]);
console.log('\nper class:');
for (const [k, xs] of [...byRef].sort((a, b) => b[1].length - a[1].length)) console.log(`  ${k.padEnd(30)} ${pct(xs.filter((r) => r.got === r.ref).length, xs.length)}`);

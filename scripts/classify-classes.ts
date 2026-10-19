/**
 * Level-2 classification: the vulnerability class within each incident's category.
 *
 *   TYPESAFE_API_KEY=... npx tsx scripts/classify-classes.ts [--limit N]
 *
 * Answers are cached in data/typesafe/classes.json keyed by incident id + hash(category, input);
 * `npm run ingest` applies them. Run after `npm run ingest` so categories are final.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { z } from 'zod';
import { incidentSchema } from '../src/lib/types';
import type { ClassId } from '../src/lib/classes';
import { systemOne } from './typesafe';
import { CLASS_CACHE_FILE, aiState, classQuestion, classStateHash, type CachedClass } from './classify-spec';

const apiKey = process.env.TYPESAFE_API_KEY;
if (!apiKey) throw new Error('Set TYPESAFE_API_KEY');
const limitArg = process.argv.indexOf('--limit');
const limit = limitArg > 0 ? Number(process.argv[limitArg + 1]) : Infinity;

const incidents = z.array(incidentSchema).parse(JSON.parse(readFileSync('data/incidents.json', 'utf8')));
const cache: Record<string, CachedClass> = existsSync(CLASS_CACHE_FILE) ? JSON.parse(readFileSync(CLASS_CACHE_FILE, 'utf8')) : {};
const stale = incidents.filter((i) => i.category !== 'unknown' && cache[i.id]?.hash !== classStateHash(i));
const todo = stale.slice(0, limit);
console.log(`${incidents.length} incidents, classifying ${todo.length} (${stale.length} stale)`);

const save = () =>
  writeFileSync(CLASS_CACHE_FILE, JSON.stringify(Object.fromEntries(Object.entries(cache).sort(([a], [b]) => a.localeCompare(b))), null, 1));

let done = 0;
let failed = 0;
let tokens = 0;
const queue = [...todo];
await Promise.all(
  Array.from({ length: 8 }, async () => {
    for (let i = queue.shift(); i; i = queue.shift()) {
      if (i.category === 'unknown') continue;
      try {
        const r = await systemOne({ apiKey, state: aiState(i), questions: { vuln_class: classQuestion(i.category) } });
        const a = r.answers.vuln_class;
        cache[i.id] = {
          hash: classStateHash(i),
          model: r.model,
          class: a.choice,
          confidence: a.confidence,
          probabilities: Object.fromEntries(
            (Object.entries(a.probabilities) as [ClassId, number][]).filter(([, p]) => p >= 0.01).sort((x, y) => y[1] - x[1]),
          ),
        };
        tokens += (r.usage?.input_tokens ?? 0) + (r.usage?.output_tokens ?? 0);
      } catch (e) {
        failed++;
        console.error(`${i.id}: ${(e as Error).message}`);
      }
      if (++done % 200 === 0) {
        save();
        console.log(`${done}/${todo.length} (${failed} failed, ${tokens.toLocaleString('en')} tokens)`);
      }
    }
  }),
);
save();
console.log(`done: ${done - failed} classified, ${failed} failed, ${tokens.toLocaleString('en')} tokens`);

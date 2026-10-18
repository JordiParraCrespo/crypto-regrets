/**
 * Classify incidents with TypeSafe (Jev) and cache the answers in data/typesafe/classifications.json.
 *
 *   TYPESAFE_API_KEY=... npm run classify              # all incidents not yet cached
 *   TYPESAFE_API_KEY=... npm run classify -- --limit 50
 *
 * Then `npm run ingest` applies the cache. Builds never need the key.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { z } from 'zod';
import { incidentSchema } from '../src/lib/types';
import type { CategoryId } from '../src/lib/taxonomy';
import { systemOne } from './typesafe';
import { QUESTIONS, aiState, stateHash, CACHE_FILE, type CachedClassification } from './classify-spec';

const apiKey = process.env.TYPESAFE_API_KEY;
if (!apiKey) throw new Error('Set TYPESAFE_API_KEY');
const arg = (name: string) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const limit = Number(arg('--limit') ?? Infinity);
const concurrency = Number(arg('--concurrency') ?? 8);

const incidents = z.array(incidentSchema).parse(JSON.parse(readFileSync('data/incidents.json', 'utf8')));
const cache: Record<string, CachedClassification> = existsSync(CACHE_FILE) ? JSON.parse(readFileSync(CACHE_FILE, 'utf8')) : {};
const stale = incidents.filter((i) => cache[i.id]?.hash !== stateHash(i));
const todo = stale.slice(0, limit);
console.log(`${incidents.length} incidents, ${incidents.length - stale.length} cached, classifying ${todo.length}`);

const save = () => {
  mkdirSync(dirname(CACHE_FILE), { recursive: true });
  const sorted = Object.fromEntries(Object.entries(cache).sort(([a], [b]) => a.localeCompare(b)));
  writeFileSync(CACHE_FILE, JSON.stringify(sorted, null, 1));
};

let done = 0;
let failed = 0;
let tokens = 0;
const queue = [...todo];
await Promise.all(
  Array.from({ length: concurrency }, async () => {
    for (let i = queue.shift(); i; i = queue.shift()) {
      try {
        const r = await systemOne({ apiKey, state: aiState(i), questions: QUESTIONS });
        const c = r.answers.category;
        cache[i.id] = {
          hash: stateHash(i),
          model: r.model,
          category: c.choice,
          confidence: c.confidence,
          probabilities: Object.fromEntries(
            (Object.entries(c.probabilities) as [CategoryId, number][]).filter(([, p]) => p >= 0.01).sort((x, y) => y[1] - x[1]),
          ),
          hasRootCause: r.answers.has_root_cause.noul,
          flashLoan: r.answers.flash_loan.noul,
          stateActor: r.answers.state_actor.noul,
        };
        tokens += (r.usage?.input_tokens ?? 0) + (r.usage?.output_tokens ?? 0);
      } catch (e) {
        failed++;
        console.error(`${i.id}: ${(e as Error).message}`);
      }
      if (++done % 50 === 0) {
        save();
        console.log(`${done}/${todo.length} (${failed} failed, ${tokens.toLocaleString('en')} tokens)`);
      }
    }
  }),
);
save();
console.log(`done: ${done - failed} classified, ${failed} failed, ${tokens.toLocaleString('en')} tokens`);

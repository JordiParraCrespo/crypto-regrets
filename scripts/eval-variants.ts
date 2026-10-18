/**
 * A/B test question designs in ONE request per incident: questions are evaluated independently
 * against the same state, so every variant sees identical input and the comparison is clean.
 *
 *   TYPESAFE_API_KEY=... npx tsx scripts/eval-variants.ts
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { incidentSchema, type Incident } from '../src/lib/types';
import { CATEGORIES, CATEGORY_IDS, type CategoryId } from '../src/lib/taxonomy';
import { systemOne, type ChoiceQuestion } from './typesafe';
import { QUESTIONS, aiState, bestDescription } from './classify-spec';
import { RUBRIC } from '../src/lib/rubric';

const apiKey = process.env.TYPESAFE_API_KEY;
if (!apiKey) throw new Error('Set TYPESAFE_API_KEY');
const incidents = z.array(incidentSchema).parse(JSON.parse(readFileSync('data/incidents.json', 'utf8')));

const labelled = incidents.filter((i) => (i.classifiedBy === 'curated' || i.classifiedBy === 'defillama') && i.category !== 'unknown' && bestDescription(i));
const sample: Incident[] = labelled.filter((i) => i.classifiedBy === 'curated');
const byCat = new Map<CategoryId, Incident[]>();
for (const i of labelled.filter((i) => i.classifiedBy === 'defillama')) byCat.set(i.category, [...(byCat.get(i.category) ?? []), i]);
for (const xs of byCat.values()) sample.push(...xs.sort((a, b) => a.id.localeCompare(b.id)).slice(0, 15));

const OPTS = CATEGORY_IDS.filter((c) => c !== 'unknown');
const v1Criteria = Object.fromEntries(OPTS.map((id) => [id, { name: CATEGORIES[id].name, covers: CATEGORIES[id].description }]));
const V1_INSTR =
  'Which failure pattern is the primary root cause of this crypto security incident? Pick the underlying flaw that made the loss possible, not the tools used (a flash loan alone is not a root cause).';

const rubric = (order: typeof OPTS) => Object.fromEntries(order.map((id) => [id, { name: CATEGORIES[id].name, ...RUBRIC[id as keyof typeof RUBRIC] }]));

// `production` is what classify.ts asks; the others are the alternatives it was chosen over.
const VARIANTS = {
  production: QUESTIONS.category,
  v1_instructions: { type: 'choice', instructions: V1_INSTR, criteria: v1Criteria },
  rubric: { type: 'choice', instructions: QUESTIONS.category.instructions, criteria: rubric(OPTS) },
  rubric_reversed: { type: 'choice', instructions: QUESTIONS.category.instructions, criteria: rubric([...OPTS].reverse()) },
} satisfies Record<string, ChoiceQuestion<string>>;

const state = (i: Incident) => aiState(i);

const rows: { id: string; ref: CategoryId; curated: boolean; ans: Record<string, { c: string; conf: number }> }[] = [];
let tokens = 0;
const queue = [...sample];
await Promise.all(
  Array.from({ length: 8 }, async () => {
    for (let i = queue.shift(); i; i = queue.shift()) {
      const r = await systemOne({ apiKey, state: state(i), questions: VARIANTS });
      tokens += (r.usage?.input_tokens ?? 0) + (r.usage?.output_tokens ?? 0);
      const ans = Object.fromEntries(Object.entries(r.answers).map(([k, a]) => [k, { c: (a as { choice: string }).choice, conf: (a as { confidence: number }).confidence }]));
      rows.push({ id: i.id, ref: i.category, curated: i.classifiedBy === 'curated', ans });
    }
  }),
);

const pct = (n: number, d: number) => `${((n / Math.max(d, 1)) * 100).toFixed(1)}% (${n}/${d})`;
console.log(`test set ${rows.length}, tokens ${tokens.toLocaleString('en')} (${Math.round(tokens / rows.length)}/incident for all variants)\n`);
for (const v of Object.keys(VARIANTS)) {
  const ok = rows.filter((r) => r.ans[v].c === r.ref).length;
  const hi = rows.filter((r) => r.ans[v].conf >= 0.9);
  const hiOk = hi.filter((r) => r.ans[v].c === r.ref).length;
  const lay = rows.filter((r) => CATEGORIES[r.ans[v].c as CategoryId].layer === CATEGORIES[r.ref].layer).length;
  console.log(`${v.padEnd(16)} exact ${pct(ok, rows.length).padEnd(18)} layer ${pct(lay, rows.length).padEnd(18)} conf>=0.9: ${pct(hiOk, hi.length)} covering ${pct(hi.length, rows.length)}`);
}
writeFileSync('data/typesafe/eval-variants.json', JSON.stringify({ when: new Date().toISOString(), rows }, null, 1));

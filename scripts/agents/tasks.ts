/**
 * Named automations both platforms can run. Each prompt is self-contained: the agent starts from a fresh
 * checkout with no memory of earlier runs.
 */
const RULES = `Rules: run \`npm ci\`, then \`npm run ingest\`, \`npm run check\` and \`npm run build\` before you finish; all must pass.
Keep the diff focused on this task. Never commit API keys. Summarize what changed and why in the PR description.`;

export const TASKS = {
  'refresh-data': {
    title: 'Refresh incident data from sources',
    prompt: `Refresh the Crypto Regrets dataset.
1. Run \`npm run ingest -- --fetch\` to re-download the snapshots in data/raw and rebuild src/data/*.json.
2. Review the diff: new incidents, changed amounts, merges that look wrong (two different hacks joined, or one hack split in two). Fix bad matches with the alias table or date windows in scripts/ingest.ts.
3. If a source fails to download, keep its old snapshot and say so in the PR.
${RULES}`,
  },
  'triage-unclassified': {
    title: 'Classify unclassified incidents',
    prompt: `Reduce the number of incidents that have no category or only a keyword guess.
1. Run \`npm run ingest\` and list incidents in src/data/incidents.json whose category is missing or came from KEYWORD_RULES.
2. For patterns you can recognize from their titles and excerpts, add or tighten ordered keyword rules in scripts/ingest.ts (KEYWORD_RULES). Prefer precise rules over broad ones; check that no previously correct label changes.
3. Report before/after counts in the PR.
${RULES}`,
  },
  'add-recent-incidents': {
    title: 'Add notable recent incidents',
    prompt: `Look for crypto hacks, exploits and base-layer failures from the last 60 days that are large (over $5M) or teach a new lesson, and that have a published post-mortem.
For each one missing from src/data/incidents.json, add a curated entry in scripts/curated.ts following the existing entries: root cause from the post-mortem, the matching taxonomy category from src/lib/taxonomy.ts, and reference links. Do not guess amounts; leave them blank if sources disagree.
${RULES}`,
  },
  'review-patterns': {
    title: 'Review pattern guides against recent incidents',
    prompt: `Review the failure-pattern guides (src/lib/taxonomy.ts and src/pages/patterns) against incidents from the last two years.
Where recent incidents show an attack variant or a prevention step a guide does not cover, update its anatomy or checklist and cite the incidents. Keep the OWASP SC Top 10 / SWC mappings accurate.
${RULES}`,
  },
} as const satisfies Record<string, { title: string; prompt: string }>;

export type TaskId = keyof typeof TASKS;
export const isTaskId = (s: string): s is TaskId => s in TASKS;

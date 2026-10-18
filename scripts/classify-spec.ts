/**
 * What we ask TypeSafe about each incident. Shared by classify.ts (asks) and ingest.ts (applies),
 * so a change to the questions or to an incident's text invalidates its cached answer.
 */
import { createHash } from 'node:crypto';
import { CATEGORIES, CATEGORY_IDS, type CategoryId } from '../src/lib/taxonomy';
import type { Incident } from '../src/lib/types';
import type { ChoiceQuestion, NoulQuestion } from './typesafe';

const criteria = Object.fromEntries(
  CATEGORY_IDS.map((id) => [
    id,
    id === 'unknown'
      ? 'Not enough information in the state to tell what the root cause was.'
      : { name: CATEGORIES[id].name, covers: CATEGORIES[id].description },
  ]),
) as Record<CategoryId, string | Record<string, unknown>>;

export const QUESTIONS = {
  category: {
    type: 'choice',
    instructions:
      'Which failure pattern is the primary root cause of this crypto security incident? Pick the underlying flaw that made the loss possible, not the tools used (a flash loan alone is not a root cause).',
    criteria,
  } satisfies ChoiceQuestion<CategoryId>,
  flash_loan: {
    type: 'noul',
    instructions: 'The attacker used a flash loan as part of this attack.',
  } satisfies NoulQuestion,
  state_actor: {
    type: 'noul',
    instructions: "This incident is attributed to a state-sponsored group, such as North Korea's Lazarus Group.",
  } satisfies NoulQuestion,
};

export const SPEC_VERSION = 1;

/** The facts we send. Deliberately excludes our own category so the model judges independently. */
export function aiState(i: Incident) {
  return {
    incident: i.name,
    date: i.date,
    chains: i.chains,
    target_type: i.targetType,
    technique_label: i.technique,
    root_cause_description: i.rootCause,
    loss_usd: i.amountUsd == null ? null : String(Math.round(i.amountUsd)),
    bridge: i.bridge,
  };
}

export function stateHash(i: Incident): string {
  return createHash('sha256').update(JSON.stringify({ v: SPEC_VERSION, s: aiState(i) })).digest('hex').slice(0, 16);
}

export interface CachedClassification {
  hash: string;
  model: string;
  category: CategoryId;
  confidence: number;
  probabilities: Partial<Record<CategoryId, number>>;
  flashLoan: number;
  stateActor: number;
}

export const CACHE_FILE = 'data/typesafe/classifications.json';

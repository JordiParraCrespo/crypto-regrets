/**
 * What we ask TypeSafe about each incident. Shared by classify.ts (asks) and ingest.ts (applies),
 * so a change to the questions or to an incident's text invalidates its cached answer.
 *
 * Design choices, each measured with scripts/eval-variants.ts against human labels (see README):
 *  - ONE best description in the state. Sending every source's account cost 7 points of accuracy
 *    (Jev degrades on large, overlapping state).
 *  - Plain option descriptions + an instruction that weighs the analysts' technique label. Longer
 *    "what / not_for / examples" rubrics and asking twice in reversed option order were no better
 *    (within ±2.4 points) at 3x the tokens, so we don't use them.
 *  - "Not enough information" is its own Noul, not an option inside the category Choice.
 *  - Confidence gates adoption: >= 0.7 beats our keyword rules (76-91% vs 59-72%); below it doesn't.
 */
import { createHash } from 'node:crypto';
import { CATEGORIES, CATEGORY_IDS, LAYERS, type CategoryId, type LayerId } from '../src/lib/taxonomy';
import type { Incident } from '../src/lib/types';
import type { ChoiceQuestion, NoulQuestion } from './typesafe';
import { CLASSES, classesOf, type ClassId } from '../src/lib/classes';

export const SPEC_VERSION = 3;

const OPTIONS = CATEGORY_IDS.filter((c): c is Exclude<CategoryId, 'unknown'> => c !== 'unknown');
const criteria = Object.fromEntries(OPTIONS.map((id) => [id, { name: CATEGORIES[id].name, covers: CATEGORIES[id].description }])) as Record<
  (typeof OPTIONS)[number],
  { name: string; covers: string }
>;

const CATEGORY_INSTRUCTIONS = {
  question: 'Which failure pattern is the primary root cause of the incident in `description`?',
  decision_rule:
    'The primary root cause is the flaw which, had it been fixed, would have prevented the loss. Tools the attacker used (flash loans, mixers, MEV bots) are not root causes.',
  focus:
    'Classify by how the attacker gained the ability to take funds. Descriptions often report only the outcome (e.g. "private key compromised"); `technique_label` comes from analysts and often names how access was gained (e.g. Phishing, Malware, Delegatecall Hijack), so weigh it as evidence.',
};

export const QUESTIONS = {
  category: { type: 'choice', instructions: CATEGORY_INSTRUCTIONS, criteria } satisfies ChoiceQuestion<(typeof OPTIONS)[number]>,
  has_root_cause: {
    type: 'noul',
    instructions: 'The `description` explains how the attacker caused the loss (the flaw or method), not just that a loss happened.',
  } satisfies NoulQuestion,
  flash_loan: {
    type: 'noul',
    instructions: 'The `description` says the attacker used a flash loan (borrowed and repaid within the same transaction) as part of this attack.',
  } satisfies NoulQuestion,
  state_actor: {
    type: 'noul',
    instructions: "The `description` attributes this incident to a state-sponsored group, such as North Korea's Lazarus Group / TraderTraitor.",
  } satisfies NoulQuestion,
};

/** All root-cause texts we know for an incident, labelled by origin. */
export type Description = { source: string; text: string };

/**
 * The one description to send. Jev loses accuracy when the state carries several overlapping
 * accounts (measured: -7 points), so pick the most technical source rather than all of them.
 */
const SOURCE_PRIORITY = ['Curated post-mortem', 'DeFiHackLabs explorer', 'DeFiHackLabs', 'SlowMist', 'RevertIQ', 'REKT', 'BlockSec'];
export function bestDescription(i: { descriptions: Description[] }): Description | undefined {
  const usable = i.descriptions.filter((d) => d.text.length >= 40);
  return usable.sort((a, b) => rank(a) - rank(b))[0];
}
const rank = (d: Description) => {
  const r = SOURCE_PRIORITY.indexOf(d.source);
  return r === -1 ? SOURCE_PRIORITY.length : r;
};

/** The facts we send. Deliberately excludes our own category so the model judges independently. */
export function aiState(i: Pick<Incident, 'name' | 'year' | 'chains' | 'targetType' | 'technique' | 'bridge' | 'descriptions'>) {
  return {
    incident: i.name,
    year: i.year,
    chains: i.chains,
    target_type: i.targetType,
    technique_label: i.technique,
    bridge: i.bridge,
    description: bestDescription(i)?.text ?? null,
  };
}

export function stateHash(i: Parameters<typeof aiState>[0]): string {
  return createHash('sha256').update(JSON.stringify({ v: SPEC_VERSION, s: aiState(i) })).digest('hex').slice(0, 16);
}

export interface CachedClassification {
  hash: string;
  model: string;
  category: CategoryId;
  confidence: number;
  /** Probabilities >= 0.01. */
  probabilities: Partial<Record<CategoryId, number>>;
  /** P(descriptions explain the attack). Below 0.5 the incident is treated as unclassifiable. */
  hasRootCause: number;
  flashLoan: number;
  stateActor: number;
}

/** Sum category probabilities per layer: the parent-level fallback when confidence is low. */
export function layerProbabilities(p: Partial<Record<CategoryId, number>>): Record<LayerId, number> {
  const out = Object.fromEntries(Object.keys(LAYERS).map((l) => [l, 0])) as Record<LayerId, number>;
  for (const id of CATEGORY_IDS) out[CATEGORIES[id].layer] += p[id] ?? 0;
  return out;
}

export const CACHE_FILE = 'data/typesafe/classifications.json';

// ---------------------------------------------------------------- vulnerability class (level 2)
//
// Hierarchical classification, as TypeSafe's docs recommend for taxonomies: once the category is
// known, a second Choice picks among that category's classes only.

export const CLASS_CACHE_FILE = 'data/typesafe/classes.json';
/**
 * Measured with scripts/eval-classes.ts --blind (analyst label hidden, 714 labelled incidents):
 * >= 0.9 → 81% correct, 0.7-0.9 → 67%, overall 69%. Below 0.9 we leave the class unspecified.
 */
export const TYPESAFE_CLASS_MIN_CONFIDENCE = 0.9;

export function classQuestion(category: Exclude<CategoryId, 'unknown'>) {
  const options = classesOf(category);
  return {
    type: 'choice',
    instructions: {
      question: `This incident is a case of "${CATEGORIES[category].name}". Which specific vulnerability class within it best matches the \`description\`?`,
      focus: 'Pick the class describing the flaw that made the loss possible. Weigh `technique_label` as analyst evidence.',
    },
    criteria: Object.fromEntries(options.map((id) => [id, { name: CLASSES[id].name, covers: CLASSES[id].summary }])) as Record<ClassId, { name: string; covers: string }>,
  } satisfies ChoiceQuestion<ClassId>;
}

export function classStateHash(i: Parameters<typeof aiState>[0] & { category: CategoryId }): string {
  return createHash('sha256').update(JSON.stringify({ v: SPEC_VERSION, c: i.category, s: aiState(i) })).digest('hex').slice(0, 16);
}

export interface CachedClass {
  hash: string;
  model: string;
  class: ClassId;
  confidence: number;
  probabilities: Partial<Record<ClassId, number>>;
}

import { z } from 'zod';
import { CATEGORY_IDS, type CategoryId } from './taxonomy';
import { CLASS_IDS, type ClassId } from './classes';

/** Source datasets an incident record can be attributed to. */
export const SOURCE_IDS = ['defillama', 'defihacklabs', 'rekt', 'slowmist', 'blocksec', 'revertiq', 'graveyard', 'seal911', 'w3igg', 'curated'] as const;
export type SourceId = (typeof SOURCE_IDS)[number];

export const CLASSIFIERS = ['defillama', 'keywords', 'typesafe', 'curated', 'none'] as const;
export type Classifier = (typeof CLASSIFIERS)[number];

/**
 * URLs scraped from third-party feeds end up in href attributes. z.string().url() accepts
 * javascript: and data: URLs, so only http(s) passes: a poisoned record fails the build.
 */
export const httpUrl = z
  .string()
  .url()
  .refine((u) => /^https?:$/.test(new URL(u).protocol), { message: 'URL must be http(s)' });

export const referenceSchema = z.object({
  source: z.enum(SOURCE_IDS),
  label: z.string(),
  url: httpUrl,
});

export const incidentSchema = z.object({
  id: z.string(),
  name: z.string(),
  /** ISO date (YYYY-MM-DD), UTC. */
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  year: z.number().int(),
  amountUsd: z.number().nonnegative().nullable(),
  returnedUsd: z.number().nonnegative().nullable(),
  chains: z.array(z.string()),
  targetType: z.string().nullable(),
  category: z.enum(CATEGORY_IDS as [CategoryId, ...CategoryId[]]),
  /** Vulnerability class (the level below `category`), or null when the evidence doesn't say. */
  vulnClass: z.enum(CLASS_IDS as [ClassId, ...ClassId[]]).nullable(),
  /** Who decided `vulnClass`: an unambiguous analyst technique label, a curated post-mortem, or TypeSafe. */
  vulnClassBy: z.enum(['technique', 'curated', 'typesafe']).nullable(),
  /** TypeSafe's class answer within the assigned category, kept even when not adopted. */
  aiClass: z.object({ id: z.enum(CLASS_IDS as [ClassId, ...ClassId[]]), confidence: z.number().min(0).max(1) }).nullable(),
  /** Finer-grained technique label, e.g. "Spot Price Manipulation". */
  technique: z.string().nullable(),
  /** Why we chose a category different from the upstream label, if we did. */
  classificationNote: z.string().nullable(),
  /** Who decided `category`: upstream human label, our keyword rules, TypeSafe's model, or a curated post-mortem. */
  classifiedBy: z.enum(CLASSIFIERS),
  /** TypeSafe (Jev) second opinion, kept even when we don't adopt its category. */
  ai: z
    .object({
      model: z.string(),
      category: z.enum(CATEGORY_IDS as [CategoryId, ...CategoryId[]]),
      confidence: z.number().min(0).max(1),
      /** Top alternatives, highest first. */
      top: z.array(z.object({ category: z.enum(CATEGORY_IDS as [CategoryId, ...CategoryId[]]), p: z.number() })),
      /** P(attack used a flash loan). */
      flashLoan: z.number().min(0).max(1),
      /** P(attributed to a state-sponsored group, e.g. Lazarus). */
      stateActor: z.number().min(0).max(1),
      /** P(the descriptions explain how the loss happened). Low = the model had too little to go on. */
      hasRootCause: z.number().min(0).max(1),
    })
    .nullable(),
  bridge: z.boolean(),
  language: z.string().nullable(),
  /** Best single root-cause narrative (curated > DeFiHackLabs > other sources). */
  rootCause: z.string().nullable(),
  /** Every source's account of the incident, side by side (what the classifier sees). */
  descriptions: z.array(z.object({ source: z.string(), text: z.string() })),
  /** Audit status as reported by REKT ("Unaudited", "Peckshield", ...). */
  audit: z.string().nullable(),
  /** Attack transaction hashes (DeFiHackLabs explorer, BlockSec). */
  txHashes: z.array(z.string()),
  /** DeFiHackLabs Foundry proof-of-concept, when one exists. */
  poc: httpUrl.nullable(),
  sources: z.array(z.enum(SOURCE_IDS)),
  references: z.array(referenceSchema),
});

export type Incident = z.infer<typeof incidentSchema>;

export const ADVISORY_IMPACTS = [
  'consensus-split',
  'inflation',
  'remote-crash',
  'dos',
  'chain-halt',
  'rce',
  'censorship',
  'other',
] as const;
export type AdvisoryImpact = (typeof ADVISORY_IMPACTS)[number];

export const advisorySchema = z.object({
  id: z.string(),
  project: z.string(),
  cve: z.string().nullable(),
  title: z.string(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  severity: z.string().nullable(),
  impact: z.enum(ADVISORY_IMPACTS),
  summary: z.string().nullable(),
  url: httpUrl,
});

export type Advisory = z.infer<typeof advisorySchema>;

export const sourceAuditSchema = z.object({
  id: z.number(),
  name: z.string(),
  url: httpUrl,
  category: z.string(),
  status: z.string(),
  tracks: z.string(),
  machineReadable: z.string(),
  coverage: z.string(),
  chains: z.string(),
  metadata: z.string(),
  updateFrequency: z.string(),
  license: z.string(),
  concerns: z.string(),
  priority: z.number(),
  notes: z.string(),
});

export type SourceAudit = z.infer<typeof sourceAuditSchema>;

/** One row of /hacks/rows.json: the filterable fields plus pre-formatted display strings. */
export type IndexRow = {
  id: string; n: string; d: string; dl: string; a: number; al: string; ch: string[]; s: string;
  k: string | null; c: string; l: string; p: 0 | 1; by: string; dis: 0 | 1; fl: 0 | 1; t: string;
};

// ------------------------------------------------------------------ Cosmos ecosystem research (data/raw)
export const cosmosIncidentSchema = z.object({
  name: z.string(),
  date: z.string(),
  chain: z.string().nullish(),
  lossUsd: z.number().nullish(),
  component: z.string().nullish(),
  rootCause: z.string().nullish(),
  vulnerabilityClass: z.string().nullish(),
  language: z.string().nullish(),
  patchedIn: z.union([z.string(), z.array(z.string())]).nullish(),
  sources: z.array(httpUrl).default([]),
  confidence: z.string().nullish(),
  incidentType: z.string().nullish(),
  notes: z.string().nullish(),
});
export const cosmosAdvisorySchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).default([]),
  project: z.string(),
  title: z.string(),
  summary: z.string().nullish(),
  published: z.string().nullish(),
  severity: z.string().nullish(),
  component: z.string().nullish(),
  impact: z.string().nullish(),
  url: httpUrl.nullish(),
});

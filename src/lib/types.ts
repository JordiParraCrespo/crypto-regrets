import { z } from 'zod';
import { CATEGORY_IDS, type CategoryId } from './taxonomy';

/** Source datasets an incident record can be attributed to. */
export const SOURCE_IDS = ['defillama', 'defihacklabs', 'rekt', 'curated'] as const;
export type SourceId = (typeof SOURCE_IDS)[number];

export const CLASSIFIERS = ['defillama', 'keywords', 'typesafe', 'curated', 'none'] as const;
export type Classifier = (typeof CLASSIFIERS)[number];

export const referenceSchema = z.object({
  source: z.enum(SOURCE_IDS),
  label: z.string(),
  url: z.string().url(),
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
    })
    .nullable(),
  bridge: z.boolean(),
  language: z.string().nullable(),
  /** Technical root-cause narrative (DeFiHackLabs, REKT excerpt, or curated). */
  rootCause: z.string().nullable(),
  /** Audit status as reported by REKT ("Unaudited", "Peckshield", ...). */
  audit: z.string().nullable(),
  /** DeFiHackLabs Foundry proof-of-concept, when one exists. */
  poc: z.string().url().nullable(),
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
  project: z.enum(['Bitcoin Core', 'Geth', 'Cosmos']),
  cve: z.string().nullable(),
  title: z.string(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  severity: z.string().nullable(),
  impact: z.enum(ADVISORY_IMPACTS),
  summary: z.string().nullable(),
  url: z.string().url(),
});

export type Advisory = z.infer<typeof advisorySchema>;

export const sourceAuditSchema = z.object({
  id: z.number(),
  name: z.string(),
  url: z.string(),
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

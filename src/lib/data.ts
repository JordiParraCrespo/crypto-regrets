import { z } from 'zod';
import incidentsJson from '../../data/incidents.json';
import advisoriesJson from '../../data/advisories.json';
import { incidentSchema, advisorySchema, sourceAuditSchema, type Incident, type SourceAudit } from './types';
import { CATEGORIES, CATEGORY_IDS, LAYERS, ERAS, eraForYear, type CategoryId, type LayerId } from './taxonomy';

// Validate at build time: a malformed record fails the build instead of rendering garbage.
export const incidents: Incident[] = z.array(incidentSchema).parse(incidentsJson);
export const advisories = z.array(advisorySchema).parse(advisoriesJson);

const sourceFiles = import.meta.glob<{ default: unknown }>('../../data/sources.json', { eager: true });
const sourcesRaw = Object.values(sourceFiles)[0]?.default ?? [];
export const sourceAudit: SourceAudit[] = z.array(sourceAuditSchema).parse(sourcesRaw);

export const LAYER_ORDER = Object.keys(LAYERS) as LayerId[];
/** Fixed categorical slot per layer (never cycled). */
export const layerSlot = (l: LayerId) => LAYER_ORDER.indexOf(l) + 1;

export const layerOf = (c: CategoryId): LayerId => CATEGORIES[c].layer;

export const YEARS = (() => {
  const ys = incidents.map((i) => i.year);
  const min = Math.min(...ys);
  const max = Math.max(...ys);
  return Array.from({ length: max - min + 1 }, (_, k) => min + k);
})();

export const sum = (xs: Incident[]) => xs.reduce((s, i) => s + (i.amountUsd ?? 0), 0);

export function fmtUsd(n: number | null | undefined): string {
  if (n == null || n === 0) return '—';
  if (n >= 1e9) return `$${(n / 1e9).toFixed(n >= 1e10 ? 0 : 2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(n >= 1e8 ? 0 : 1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(0)}K`;
  return `$${Math.round(n)}`;
}

export function fmtDate(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
}

export const byCategory = (c: CategoryId) => incidents.filter((i) => i.category === c);

export interface CategoryStats {
  id: CategoryId;
  count: number;
  usd: number;
  first: Incident | undefined;
  last: Incident | undefined;
  biggest: Incident[];
}

export function categoryStats(c: CategoryId): CategoryStats {
  const xs = byCategory(c);
  const sorted = [...xs].sort((a, b) => a.date.localeCompare(b.date));
  return {
    id: c,
    count: xs.length,
    usd: sum(xs),
    first: sorted[0],
    last: sorted[sorted.length - 1],
    biggest: [...xs].sort((a, b) => (b.amountUsd ?? 0) - (a.amountUsd ?? 0)).slice(0, 8),
  };
}

export const allCategoryStats = CATEGORY_IDS.map(categoryStats).sort((a, b) => b.usd - a.usd);

/** Year x layer matrix for stacked charts. */
export function yearLayerMatrix(metric: 'count' | 'usd', filter: (i: Incident) => boolean = () => true) {
  return YEARS.map((year) => {
    const row: Record<LayerId, number> = Object.fromEntries(LAYER_ORDER.map((l) => [l, 0])) as Record<LayerId, number>;
    for (const i of incidents) {
      if (i.year !== year || !filter(i)) continue;
      row[layerOf(i.category)] += metric === 'count' ? 1 : (i.amountUsd ?? 0);
    }
    return { year, row };
  });
}

export function yearCategorySeries(c: CategoryId) {
  return YEARS.map((year) => {
    const xs = incidents.filter((i) => i.year === year && i.category === c);
    return { year, count: xs.length, usd: sum(xs) };
  });
}

export function eraStats() {
  return ERAS.map((era) => {
    const xs = incidents.filter((i) => eraForYear(i.year) === era.id);
    const cats = CATEGORY_IDS.filter((c) => c !== 'unknown')
      .map((c) => {
        const ys = xs.filter((i) => i.category === c);
        return { id: c, count: ys.length, usd: sum(ys) };
      })
      .filter((c) => c.count > 0);
    return {
      ...era,
      count: xs.length,
      usd: sum(xs),
      topByUsd: [...cats].sort((a, b) => b.usd - a.usd).slice(0, 4),
      topByCount: [...cats].sort((a, b) => b.count - a.count).slice(0, 4),
      notable: [...xs].sort((a, b) => (b.amountUsd ?? 0) - (a.amountUsd ?? 0)).slice(0, 6),
    };
  });
}

export const base = import.meta.env.BASE_URL.replace(/\/$/, '');
export const href = (p: string) => `${base}${p.startsWith('/') ? p : `/${p}`}`;

// ------------------------------------------------------------------ labels shared across pages

import type { SourceId, Classifier } from './types';
import { CLASSES as CLASS_DEFS, CLASS_IDS, type ClassId, type VulnClass } from './classes';
/** Widened to VulnClass so optional fields (vulnerable, cwe, ...) are accessible on any class. */
export const CLASSES: Record<ClassId, VulnClass> = CLASS_DEFS;

export const SOURCE_NAMES = {
  defillama: 'DefiLlama',
  defihacklabs: 'DeFiHackLabs',
  rekt: 'REKT',
  slowmist: 'SlowMist',
  blocksec: 'BlockSec',
  revertiq: 'RevertIQ',
  graveyard: 'Blockchain Graveyard',
  seal911: 'SEAL 911',
  w3igg: 'Web3 Is Going Great',
  curated: 'Curated post-mortem',
} as const satisfies Record<SourceId, string>;

export const CLASSIFIER_NAMES = {
  defillama: 'DefiLlama analyst label',
  keywords: 'Keyword rules',
  typesafe: 'TypeSafe (Jev)',
  curated: 'Curated post-mortem',
  none: 'Unclassified',
} as const satisfies Record<Classifier, string>;

export const CLASS_BY_NAMES = { technique: 'Analyst technique label', curated: 'Curated post-mortem', typesafe: 'TypeSafe (Jev), ≥ 0.9 confidence' } as const;

export interface ClassStats {
  id: ClassId;
  count: number;
  usd: number;
  withPoc: number;
  first: Incident | undefined;
  peakYear: number | undefined;
  recent: number;
}

export const byClass = (c: ClassId) => incidents.filter((i) => i.vulnClass === c);

export const classStats: ClassStats[] = CLASS_IDS.map((id) => {
  const xs = byClass(id);
  const years = new Map<number, number>();
  for (const i of xs) years.set(i.year, (years.get(i.year) ?? 0) + 1);
  const latestYear = YEARS[YEARS.length - 1];
  return {
    id,
    count: xs.length,
    usd: sum(xs),
    withPoc: xs.filter((i) => i.poc).length,
    first: [...xs].sort((a, b) => a.date.localeCompare(b.date))[0],
    peakYear: [...years].sort((a, b) => b[1] - a[1])[0]?.[0],
    recent: xs.filter((i) => i.year >= latestYear - 1).length,
  };
}).sort((a, b) => b.count - a.count);

export const classified = incidents.filter((i) => i.vulnClass).length;

export function classYearSeries(c: ClassId) {
  return YEARS.map((year) => ({ year, value: incidents.filter((i) => i.year === year && i.vulnClass === c).length }));
}

export function yearSeries(metric: 'count' | 'usd', filter: (i: Incident) => boolean = () => true) {
  return YEARS.map((year) => {
    const xs = incidents.filter((i) => i.year === year && filter(i));
    return { year, value: metric === 'count' ? xs.length : sum(xs) };
  });
}


// ------------------------------------------------------------------ trends

import tvlRaw from '../../data/raw/llama_tvl.json';
import { CHAIN_FAMILIES, chainFamily, type ChainFamilyId } from './chains';

export const familyOf = (i: Incident): ChainFamilyId => chainFamily(i.chains, i.targetType);
export const FAMILY_IDS = Object.keys(CHAIN_FAMILIES) as ChainFamilyId[];

/** Heatmap columns: early years are sparse, so they share one bucket. */
export const TREND_COLS = ['≤2015', ...YEARS.filter((y) => y >= 2016).map(String)];
export const trendCol = (year: number) => (year <= 2015 ? '≤2015' : String(year));

export type Metric = 'usd' | 'count';

/** rows × TREND_COLS matrix of losses or counts. */
export function matrix<R extends string>(rowOf: (i: Incident) => R | null, metric: Metric, xs: Incident[] = incidents) {
  const m = new Map<R, Map<string, number>>();
  for (const i of xs) {
    const r = rowOf(i);
    if (r === null) continue;
    const row = m.get(r) ?? new Map<string, number>();
    const c = trendCol(i.year);
    row.set(c, (row.get(c) ?? 0) + (metric === 'usd' ? (i.amountUsd ?? 0) : 1));
    m.set(r, row);
  }
  return m;
}

/** DefiLlama total DeFi TVL, averaged per calendar year. */
export const tvlByYear: Map<number, number> = (() => {
  const acc = new Map<number, { s: number; n: number }>();
  for (const p of tvlRaw as { date: number; tvl: number }[]) {
    const y = new Date(p.date * 1000).getUTCFullYear();
    const a = acc.get(y) ?? { s: 0, n: 0 };
    a.s += p.tvl;
    a.n += 1;
    acc.set(y, a);
  }
  return new Map([...acc].map(([y, a]) => [y, a.s / a.n]));
})();

/**
 * Losses comparable to DeFi TVL: on smart-contract chains, not exchanges, wallets or chain-level
 * events. (LuBian's $3.5B Bitcoin mining-pool theft would otherwise read as an 85% "DeFi loss rate".)
 */
const NON_DEFI_FAMILIES = new Set<ChainFamilyId>(['bitcoin', 'offchain', 'unknown']);
const NON_DEFI_TARGETS = new Set(['CEX', 'Wallet', 'Chain', 'Layer 1']);
export const isDefiLoss = (i: Incident) =>
  !NON_DEFI_FAMILIES.has(familyOf(i)) &&
  !NON_DEFI_TARGETS.has(i.targetType ?? '') &&
  i.category !== 'client-bug' &&
  i.category !== 'consensus-attack';

// ------------------------------------------------------------------ Cosmos ecosystem research

const cosmosIncidentSchema = z.object({
  name: z.string(),
  date: z.string(),
  chain: z.string().nullish(),
  lossUsd: z.number().nullish(),
  component: z.string().nullish(),
  rootCause: z.string().nullish(),
  vulnerabilityClass: z.string().nullish(),
  language: z.string().nullish(),
  patchedIn: z.union([z.string(), z.array(z.string())]).nullish(),
  sources: z.array(z.string()).default([]),
  confidence: z.string().nullish(),
  incidentType: z.string().nullish(),
  notes: z.string().nullish(),
});
const cosmosAdvisorySchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).default([]),
  project: z.string(),
  title: z.string(),
  summary: z.string().nullish(),
  published: z.string().nullish(),
  severity: z.string().nullish(),
  component: z.string().nullish(),
  impact: z.string().nullish(),
  url: z.string().nullish(),
});
export type CosmosIncident = z.infer<typeof cosmosIncidentSchema>;
export type CosmosAdvisory = z.infer<typeof cosmosAdvisorySchema>;

const cosmosFiles = import.meta.glob<{ default: unknown }>(['../../data/raw/cosmos_incidents_research.json', '../../data/raw/cosmos_advisories.json'], { eager: true });
const pick = (name: string) => Object.entries(cosmosFiles).find(([k]) => k.endsWith(name))?.[1]?.default ?? [];
export const cosmosIncidents: CosmosIncident[] = z.array(cosmosIncidentSchema).parse(pick('cosmos_incidents_research.json'))
  .filter((i) => /^\d{4}-\d{2}/.test(i.date))
  .sort((a, b) => b.date.localeCompare(a.date));
export const cosmosAdvisories: CosmosAdvisory[] = z.array(cosmosAdvisorySchema).parse(pick('cosmos_advisories.json'))
  .sort((a, b) => (b.published ?? '').localeCompare(a.published ?? ''));

// ------------------------------------------------------------------ ecosystems

/** Families that get their own page (unknown / off-chain are not ecosystems). */
export const ECOSYSTEM_IDS = FAMILY_IDS.filter((f) => f !== 'unknown' && f !== 'offchain');

const median = (xs: number[]) => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};

/** Advisory projects relevant to each ecosystem (client, SDK, compiler, library). */
const ECO_ADVISORY_PROJECTS: Partial<Record<ChainFamilyId, string[]>> = {
  ethereum: ['Geth', 'Vyper', 'OpenZeppelin Contracts', 'web3.js', 'Besu'],
  l2: ['Geth', 'Vyper', 'OpenZeppelin Contracts'],
  'evm-other': ['Geth', 'Vyper', 'OpenZeppelin Contracts'],
  bsc: ['Geth', 'OpenZeppelin Contracts'],
  bitcoin: ['Bitcoin Core', 'btcd', 'Lightning (lnd)'],
  cosmos: ['Cosmos', 'Evmos'],
};

export function ecosystem(f: ChainFamilyId) {
  const xs = incidents.filter((i) => familyOf(i) === f);
  const amounts = xs.map((i) => i.amountUsd ?? 0).filter((a) => a > 0);
  const total = sum(xs);
  const years = [...new Set(xs.map((i) => i.year))].sort((a, b) => a - b);
  const fromYear = Math.max(years[0] ?? 2016, 2010);
  const series = (metric: Metric) =>
    YEARS.filter((y) => y >= fromYear).map((year) => {
      const ys = xs.filter((i) => i.year === year);
      return { year, value: metric === 'usd' ? sum(ys) : ys.length };
    });

  // Which patterns are over-represented here vs everywhere else (by incident count).
  const others = incidents.filter((i) => familyOf(i) !== f);
  const lift = CATEGORY_IDS.filter((c) => c !== 'unknown')
    .map((c) => {
      const here = xs.filter((i) => i.category === c).length;
      const there = others.filter((i) => i.category === c).length;
      const shareHere = here / Math.max(xs.length, 1);
      const shareThere = there / Math.max(others.length, 1);
      return { c, here, shareHere, shareThere, ratio: shareThere ? shareHere / shareThere : 0 };
    })
    .filter((x) => x.here >= 3)
    .sort((a, b) => b.ratio - a.ratio);

  const classCount = new Map<ClassId, number>();
  for (const i of xs) if (i.vulnClass) classCount.set(i.vulnClass, (classCount.get(i.vulnClass) ?? 0) + 1);
  const chainStats = new Map<string, { n: number; usd: number }>();
  for (const i of xs) for (const c of i.chains) {
    const s = chainStats.get(c) ?? { n: 0, usd: 0 };
    s.n++;
    s.usd += i.amountUsd ?? 0;
    chainStats.set(c, s);
  }
  const layerShare = LAYER_ORDER.map((l) => ({
    l,
    here: xs.filter((i) => layerOf(i.category) === l).length / Math.max(xs.length, 1),
    all: incidents.filter((i) => layerOf(i.category) === l).length / incidents.length,
  }));
  const projects = ECO_ADVISORY_PROJECTS[f] ?? [];
  return {
    id: f,
    incidents: xs,
    count: xs.length,
    usd: total,
    shareOfAll: total / Math.max(sum(incidents), 1),
    median: median(amounts),
    withPoc: xs.filter((i) => i.poc).length,
    firstYear: years[0],
    series,
    lift,
    classes: [...classCount].sort((a, b) => b[1] - a[1]),
    chains: [...chainStats].sort((a, b) => b[1].usd - a[1].usd || b[1].n - a[1].n),
    layerShare,
    biggest: [...xs].sort((a, b) => (b.amountUsd ?? 0) - (a.amountUsd ?? 0)).slice(0, 10),
    latest: xs.slice(0, 8),
    advisories: advisories.filter((a) => projects.includes(a.project)),
  };
}

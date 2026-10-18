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


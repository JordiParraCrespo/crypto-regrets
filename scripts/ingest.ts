/**
 * Build the incident index from raw source snapshots in data/raw/.
 *
 *   npm run ingest            # parse snapshots in data/raw
 *   npm run ingest -- --fetch # refresh snapshots from the network first
 *
 * Output (all schema-validated), under data/:
 *   incidents.json            every incident, one per line
 *   incidents.csv             flat export for spreadsheets
 *   incidents/<year>/<id>.json one file per incident
 *   advisories.json           client & consensus advisories
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { CATEGORIES, type CategoryId } from '../src/lib/taxonomy';
import {
  incidentSchema,
  advisorySchema,
  type Incident,
  type Advisory,
  type AdvisoryImpact,
  type SourceId,
} from '../src/lib/types';
import { CURATED } from './curated';
import { canonicalChain } from '../src/lib/chains';
import { classifyText } from './keywords';
import { CACHE_FILE, CLASS_CACHE_FILE, TYPESAFE_CLASS_MIN_CONFIDENCE, classStateHash, stateHash, type CachedClass, type CachedClassification } from './classify-spec';
import { CLASSES, CLASS_IDS, TECHNIQUE_TO_CLASS, type ClassId } from '../src/lib/classes';

const RAW = 'data/raw';
const OUT = 'data';

const DHL_YEARS = [2021, 2022, 2023, 2024, 2025];
const DHL_RAW = 'https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main';
const FETCH: Record<string, string> = {
  'llama.json': 'https://api.llama.fi/hacks',
  'dhl.md': `${DHL_RAW}/README.md`,
  ...Object.fromEntries(DHL_YEARS.map((y) => [`dhl_${y}.md`, `${DHL_RAW}/past/${y}/README.md`])),
  'btc.html': 'https://bitcoincore.org/en/security-advisories/',
  'geth.json': 'https://geth.ethereum.org/docs/vulnerabilities/vulnerabilities.json',
  'cosmos.md': 'https://raw.githubusercontent.com/cosmos/security/main/ADVISORIES.md',
  'llama_tvl.json': 'https://api.llama.fi/v2/historicalChainTvl',
};

async function fetchAll() {
  mkdirSync(RAW, { recursive: true });
  for (const [file, url] of Object.entries(FETCH)) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: ${res.status}`);
    writeFileSync(join(RAW, file), await res.text());
    console.log(`fetched ${file}`);
  }
  // REKT has no public API; its leaderboard page embeds the data as Next.js JSON.
  const html = await (await fetch('https://rekt.news/leaderboard/')).text();
  const m = html.match(/__NEXT_DATA__" type="application\/json"[^>]*>(.*?)<\/script>/s);
  if (!m) throw new Error('REKT leaderboard: __NEXT_DATA__ not found');
  writeFileSync(join(RAW, 'rekt.json'), JSON.stringify(JSON.parse(m[1]).props.pageProps.leaderboard));
  console.log('fetched rekt.json');
}

const raw = (f: string) => readFileSync(join(RAW, f), 'utf8');

// ---------------------------------------------------------------- helpers

const STOP = /\b(finance|protocol|network|exchange|bridge|token|swap|dao|labs?|v\d|the|io|fi|rekt|defi|money|capital|staking|nft|lending|market|vault|pool|core|yield)\b/g;

/** Loose name key used to join records across sources. */
function nameKey(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // CamelCase → words ("SetProtocol" → "Set Protocol")
    .replace(/([A-Z])([A-Z][a-z])/g, '$1 $2') // "FHToken" → "FH Token"
    .toLowerCase()
    .replace(/[-_.]/g, ' ')
    .replace(/\s+-\s+rekt.*$/i, '')
    .replace(STOP, '')
    .replace(/[^a-z0-9]/g, '');
}

/** Same incident, different names across sources. Keys are nameKey() outputs. */
const ALIASES: Record<string, string> = {
  bnb: 'binance',
  wormhole: 'portal',
  onethatgotaway: 'lubian',
  ronin: 'roninbridge',
};

function namesMatch(a: string, b: string): boolean {
  if (a.trim().toLowerCase() === b.trim().toLowerCase()) return true;
  const ka = ALIASES[nameKey(a)] ?? nameKey(a);
  const kb = ALIASES[nameKey(b)] ?? nameKey(b);
  if (!ka || !kb) return false;
  if (ka === kb) return true;
  const [s, l] = ka.length < kb.length ? [ka, kb] : [kb, ka];
  if (s.length >= 4 && l.includes(s)) return true;
  // shared prefix of 5+ chars ("sorstaking" ~ "sorra" is too loose, "morphoblue" ~ "morphobluemarket" is fine)
  let p = 0;
  while (p < s.length && s[p] === l[p]) p++;
  return p >= 5 && p >= s.length * 0.6;
}

const DAY = 86_400_000;
const daysApart = (a: string, b: string) => Math.abs(Date.parse(a) - Date.parse(b)) / DAY;

function slugify(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60);
}

const isoFromUnix = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);

function isoFromUS(d: string): string | null {
  const m = d.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  return `${m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
}

// ---------------------------------------------------------------- classification

const LLAMA_CLASS: Record<string, CategoryId> = {
  'Access Control': 'access-control',
  'Protocol Logic': 'logic-error',
  'Token & Share Accounting': 'accounting-math',
  'Oracle Manipulation': 'oracle-manipulation',
  'Key Compromise': 'key-compromise',
  'Frontend & Infrastructure': 'frontend-infra',
  'Input Validation': 'input-validation',
  Reentrancy: 'reentrancy',
  'Social Engineering': 'social-engineering',
  'Bridge & Cross-Chain': 'bridge-crosschain',
  Rugpull: 'rugpull',
  Governance: 'governance',
  'Market Manipulation': 'market-manipulation',
};

/** Technique labels that move an incident to a more specific category. */
const LLAMA_TECHNIQUE: Record<string, CategoryId> = {
  'Arbitrary External Call': 'arbitrary-call',
  'Token Approval Abuse': 'arbitrary-call',
  'Signature Verification Flaw': 'signature-crypto',
  'Signature Replay': 'signature-crypto',
  'Weak Key Generation': 'signature-crypto',
  'Key Brute Forced': 'signature-crypto',
  // DefiLlama files these under "Frontend & Infrastructure", but the asset taken was a key:
  // our taxonomy classifies by what the attacker obtained, so they are key compromises.
  'Key Leaked via Infrastructure': 'key-compromise',
  'API Key Compromised': 'key-compromise',
  'Key Stored Publicly': 'key-compromise',
  'Session Key Compromised': 'key-compromise',
};

interface LlamaHack {
  date: number;
  name: string;
  classification: string | null;
  technique: string | null;
  amount: number | null;
  chain: string[] | null;
  bridgeHack: boolean;
  targetType: string | null;
  source: string;
  returnedFunds: number | null;
  language: string | null;
}

function classifyLlama(h: LlamaHack): { category: CategoryId; note: string | null } {
  const isChain = h.targetType === 'Chain' || h.targetType === 'Layer 1';
  // DefiLlama files 51% attacks on PoW chains under "Bridge & Cross-Chain / Forged Proof"
  // or "Validator Key Compromised". They are consensus attacks, not bridge bugs.
  if (
    isChain &&
    !h.bridgeHack &&
    !/bridge/i.test(h.name) &&
    ['Forged Proof', 'Validator Key Compromised'].includes(h.technique ?? '')
  ) {
    return {
      category: 'consensus-attack',
      note: `Upstream label "${h.classification} / ${h.technique}" on a base-layer chain: reclassified as a 51%/consensus attack.`,
    };
  }
  if (h.name === 'Verge') {
    return { category: 'consensus-attack', note: 'Verge 2018 was a timestamp-manipulation (time-warp) attack on block difficulty.' };
  }
  const byTechnique = h.technique ? LLAMA_TECHNIQUE[h.technique] : undefined;
  if (byTechnique) return { category: byTechnique, note: null };
  return { category: (h.classification && LLAMA_CLASS[h.classification]) || 'unknown', note: null };
}


function keywordCategory(text: string, from: string): Pick<Draft, 'category' | 'classificationNote' | 'classifiedBy'> {
  const category = classifyText(text);
  return {
    category,
    classifiedBy: category === 'unknown' ? 'none' : 'keywords',
    classificationNote: category === 'unknown' ? null : `Classified by keyword rules from the ${from}.`,
  };
}

function addDescription(d: Draft, source: string, text: string | null | undefined) {
  const t = text?.trim();
  if (!t || d.descriptions.some((x) => x.text === t)) return;
  d.descriptions.push({ source, text: t });
}

function setKeywordCategory(d: Draft, category: CategoryId) {
  if (category === 'unknown') return;
  d.category = category;
  d.classifiedBy = 'keywords';
  d.classificationNote = 'Upstream label missing; classified by keyword rules from the root-cause text.';
}

// TypeSafe answers (see scripts/classify.ts). Only replace categories nobody has vouched for:
// keyword guesses and unclassified incidents. Human labels (DefiLlama, curated) are kept and the
// model's disagreement is surfaced on the incident page instead.
// Measured on the eval set: at >= 0.7 the model beats our keyword rules; below, it does not.
const TYPESAFE_MIN_CONFIDENCE = 0.7;
const typesafeCache: Record<string, CachedClassification> = existsSync(CACHE_FILE) ? JSON.parse(readFileSync(CACHE_FILE, 'utf8')) : {};

function applyTypeSafe(i: Incident): Incident {
  const c = typesafeCache[i.id];
  if (!c || c.hash !== stateHash(i)) return i;
  const top = (Object.entries(c.probabilities) as [CategoryId, number][])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([category, p]) => ({ category, p }));
  const ai = { model: c.model, category: c.category, confidence: c.confidence, top, flashLoan: c.flashLoan, stateActor: c.stateActor, hasRootCause: c.hasRootCause };
  const adopt =
    (i.classifiedBy === 'keywords' || i.classifiedBy === 'none') &&
    c.category !== 'unknown' &&
    c.hasRootCause >= 0.5 &&
    c.confidence >= TYPESAFE_MIN_CONFIDENCE;
  if (!adopt) return { ...i, ai };
  const replaced = i.classifiedBy === 'keywords' && i.category !== c.category ? ` Replaced keyword guess "${i.category}".` : '';
  return {
    ...i,
    ai,
    category: c.category,
    classifiedBy: 'typesafe',
    classificationNote: `Classified by TypeSafe ${c.model} (confidence ${c.confidence.toFixed(2)}).${replaced}`,
  };
}

// Vulnerability class: curated post-mortem > unambiguous analyst technique label > TypeSafe.
const typesafeClassCache: Record<string, CachedClass> = existsSync(CLASS_CACHE_FILE) ? JSON.parse(readFileSync(CLASS_CACHE_FILE, 'utf8')) : {};

function applyClasses(i: Incident, curatedClass: ClassId | undefined): Incident {
  const cached = typesafeClassCache[i.id];
  const aiClass = cached && cached.hash === classStateHash(i) ? { id: cached.class, confidence: cached.confidence } : null;
  const fromTechnique = i.technique ? TECHNIQUE_TO_CLASS[i.technique] : undefined;
  if (curatedClass) return { ...i, vulnClass: curatedClass, vulnClassBy: 'curated', aiClass };
  if (fromTechnique && CLASSES[fromTechnique].parent === i.category) return { ...i, vulnClass: fromTechnique, vulnClassBy: 'technique', aiClass };
  if (aiClass && aiClass.confidence >= TYPESAFE_CLASS_MIN_CONFIDENCE && (i.ai?.hasRootCause ?? 1) >= 0.5) {
    return { ...i, vulnClass: aiClass.id, vulnClassBy: 'typesafe', aiClass };
  }
  return { ...i, aiClass };
}

// ---------------------------------------------------------------- sources

/** Class fields are filled at the end (applyClasses); curatedClass is internal and stripped by zod. */
type Draft = Omit<Incident, 'id' | 'year' | 'vulnClass' | 'vulnClassBy' | 'aiClass'> & { curatedClass?: ClassId };

function fromLlama(): Draft[] {
  const data = JSON.parse(raw('llama.json')) as LlamaHack[];
  return data.map((h) => {
    const { category, note } = classifyLlama(h);
    return {
      name: h.name,
      date: isoFromUnix(h.date),
      amountUsd: h.amount ?? null,
      returnedUsd: h.returnedFunds ?? null,
      chains: h.chain ?? [],
      targetType: h.targetType,
      category,
      technique: h.technique && h.technique !== 'Unknown' ? h.technique : null,
      classificationNote: note,
      classifiedBy: category === 'unknown' ? 'none' : 'defillama',
      ai: null,
      bridge: h.bridgeHack,
      language: h.language,
      rootCause: null,
      descriptions: [],
      audit: null,
      poc: null,
      txHashes: [],
      sources: ['defillama'],
      references: [{ source: 'defillama', label: 'DefiLlama hacks', url: 'https://defillama.com/hacks' }],
    } satisfies Draft;
  });
}

interface DhlEntry {
  date: string;
  name: string;
  title: string;
  lost: string | null;
  poc: string | null;
  links: string[];
}

function parseDhl(md: string, base: string): DhlEntry[] {
  const out: DhlEntry[] = [];
  const blocks = md.split(/^### (?=\d{8} )/m).slice(1);
  for (const b of blocks) {
    const header = b.split('\n', 1)[0];
    const m = header.replace(/^(\d{8}) - /, '$1 ').match(/^(\d{4})(\d{2})(\d{2}) (.+?)(?: - (.*))?$/);
    if (!m) continue;
    const lost = b.match(/^#{3,4} Lost:?\s*(.+)$/m)?.[1]?.trim() ?? null;
    const pocPath = b.match(/\]\((?:\.\/)?((?:\.\.\/)*src\/test\/[^)]+\.sol)\)/)?.[1];
    const poc = pocPath ? `https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/${base}${pocPath}`.replace(/past\/\d{4}\/\.\.\/\.\.\//, '') : null;
    const links = [...b.matchAll(/^(https?:\/\/\S+)\s*$/gm)].map((x) => x[1]).slice(0, 6);
    out.push({ date: `${m[1]}-${m[2]}-${m[3]}`, name: m[4].replace(/^-\s*/, '').trim(), title: (m[5] ?? '').trim(), lost, poc, links });
  }
  return out;
}

function fromDhl(): DhlEntry[] {
  const entries = parseDhl(raw('dhl.md'), '');
  for (const y of DHL_YEARS) entries.push(...parseDhl(raw(`dhl_${y}.md`), `past/${y}/`));
  // de-dup identical headers that appear in both the README and past/ files
  const seen = new Set<string>();
  return entries.filter((e) => {
    const k = `${e.date}|${e.name}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const USD_LIKE = /^(\$|usd|usdt|usdc|busd|busdt|dai|usde|fdusd|usd1|tusd)$/i;

/** Parse "$1.2M", "1.5B", "742,286.27 BUSD" into USD; non-dollar assets (ETH, BNB...) return null. */
function parseLostUsd(lost: string | null): number | null {
  if (!lost) return null;
  const s = lost.replace(/~|≈|approx(\.|imately)?/gi, ' ');
  const m =
    s.match(/\$\s?([\d,]+(?:\.\d+)?)\s*(k|m|mm|million|b|bn|billion)?\b/i) ??
    s.match(/\b([\d,]+(?:\.\d+)?)\s*(k|m|million|b|bn|billion)?\s+([a-z$]+\d?)\b/i);
  if (!m) return null;
  const currency = m[0].startsWith('$') ? '$' : (m[3] ?? '$');
  if (!USD_LIKE.test(currency)) return null;
  // "6,5M" is a European decimal comma, "6,500" a thousands separator.
  const n = parseFloat(/,\d{1,2}$/.test(m[1]) ? m[1].replace(',', '.') : m[1].replace(/,/g, ''));
  const unit = (m[2] ?? '').toLowerCase();
  const mult = unit.startsWith('b') ? 1e9 : unit.startsWith('m') ? 1e6 : unit === 'k' ? 1e3 : 1;
  return Number.isFinite(n) ? n * mult : null;
}

interface RektEntry {
  title: string;
  slug: string;
  excerpt: string;
  tags: string[];
  rekt: { amount: number; audit: string; date: string };
}

// ---------------------------------------------------------------- extra sources (scripts/fetch-extra.ts)

const extraRecordSchema = z.object({
  name: z.string(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  amountUsd: z.number().nullable(),
  chains: z.array(z.string()),
  label: z.string().nullable(),
  rootCause: z.string().nullable(),
  txHashes: z.array(z.string()),
  url: z.string().nullable(),
  references: z.array(z.string()),
});

/**
 * Processed in this order, each matched against everything merged before it. DeFiHackLabs is
 * Apache-2.0, so its text is kept whole; other sources are quoted briefly with a link back.
 */
const EXTRA_SOURCES: { id: SourceId; name: string; file: string; maxText: number; headlines?: boolean; enrichOnly?: boolean }[] = [
  { id: 'defihacklabs', name: 'DeFiHackLabs explorer', file: 'dhl_explorer.json', maxText: 2000 },
  { id: 'blocksec', name: 'BlockSec', file: 'blocksec.json', maxText: 700 },
  { id: 'slowmist', name: 'SlowMist', file: 'slowmist.json', maxText: 700 },
  { id: 'revertiq', name: 'RevertIQ', file: 'revertiq.json', maxText: 700 },
  { id: 'graveyard', name: 'Blockchain Graveyard', file: 'graveyard.json', maxText: 700 },
  { id: 'seal911', name: 'SEAL 911', file: 'seal911.json', maxText: 700 },
  // Headlines include individual thefts, lawsuits and news: enrich known incidents only.
  { id: 'w3igg', name: 'Web3 Is Going Great', file: 'web3isgoinggreat.json', maxText: 700, headlines: true, enrichOnly: true },
];

function capText(t: string, max: number): string {
  const s = t.replace(/\s+/g, ' ').trim();
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  return `${cut.slice(0, Math.max(cut.lastIndexOf('. ') + 1, max - 40)).trim()}…`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return 'link';
  }
}

// ---------------------------------------------------------------- merge

function attach(d: Draft, source: SourceId, ref: { label: string; url: string }) {
  if (!d.sources.includes(source)) d.sources.push(source);
  if (!d.references.some((r) => r.url === ref.url)) d.references.push({ source, ...ref });
}

const rawKey = (n: string) => n.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Strict fallback: within 2 days, one raw name is a prefix of the other ("Rho Market" ~ "Rho Markets"). */
function namesMatchStrict(a: string, b: string): boolean {
  const [s, l] = [rawKey(a), rawKey(b)].sort((x, y) => x.length - y.length);
  return s.length >= 4 && l.startsWith(s);
}

/** For sources whose "name" is a news headline: an incident within 3 days whose name appears in it. */
function findInHeadline(pool: Draft[], headline: string, date: string): Draft | undefined {
  const h = rawKey(headline);
  let best: Draft | undefined;
  let bestScore = -Infinity;
  for (const d of pool) {
    const days = daysApart(d.date, date);
    const k = rawKey(d.name);
    const core = nameKey(d.name);
    if (days > 3) continue;
    const hit = (k.length >= 4 && h.includes(k)) || (core.length >= 4 && h.includes(core));
    if (!hit) continue;
    const score = Math.max(k.length, core.length) - days; // longer, closer names win
    if (score > bestScore) {
      best = d;
      bestScore = score;
    }
  }
  return best;
}

function findMatch(pool: Draft[], name: string, date: string, maxDays: number): Draft | undefined {
  let best: Draft | undefined;
  let bestDays = Infinity;
  for (const d of pool) {
    const days = daysApart(d.date, date);
    if (days < bestDays && ((days <= maxDays && namesMatch(d.name, name)) || (days <= 2 && namesMatchStrict(d.name, name)))) {
      best = d;
      bestDays = days;
    }
  }
  return best;
}

function build(): { incidents: Incident[]; stats: Record<string, number> } {
  const drafts = fromLlama();
  const stats: Record<string, number> = { defillama: drafts.length, dhl: 0, dhlMatched: 0, rekt: 0, rektMatched: 0, curated: 0, curatedMatched: 0 };

  for (const e of fromDhl()) {
    stats.dhl++;
    const rootCause = e.title ? `${e.title}${e.lost ? `. Lost: ${e.lost}` : ''}` : e.lost ? `Lost: ${e.lost}` : null;
    const match = findMatch(drafts, e.name, e.date, 7);
    const ref = { label: 'DeFiHackLabs PoC', url: e.poc ?? 'https://github.com/SunWeb3Sec/DeFiHackLabs' };
    if (match) {
      stats.dhlMatched++;
      match.rootCause ??= rootCause;
      addDescription(match, 'DeFiHackLabs', rootCause);
      match.poc ??= e.poc;
      if (match.category === 'unknown' && e.title) setKeywordCategory(match, classifyText(e.title));
      attach(match, 'defihacklabs', ref);
    } else {
      drafts.push({
        name: e.name,
        date: e.date,
        amountUsd: parseLostUsd(e.lost),
        returnedUsd: null,
        chains: [],
        targetType: 'DeFi Protocol',
        ...keywordCategory(`${e.title} ${e.lost ?? ''}`, 'DeFiHackLabs root-cause title'),
        technique: e.title.length > 0 && e.title.length <= 60 ? e.title : null,
        ai: null,
        bridge: /bridge/i.test(e.name),
        language: 'Solidity',
        rootCause,
        descriptions: rootCause ? [{ source: 'DeFiHackLabs', text: rootCause }] : [],
        audit: null,
        poc: e.poc,
        txHashes: [],
        sources: ['defihacklabs'],
        references: [{ source: 'defihacklabs', ...ref }],
      });
    }
    for (const url of e.links.slice(0, 3)) {
      const target = match ?? drafts[drafts.length - 1];
      if (!target.references.some((r) => r.url === url)) target.references.push({ source: 'defihacklabs', label: new URL(url).hostname, url });
    }
  }

  const rekt = JSON.parse(raw('rekt.json')) as RektEntry[];
  for (const r of rekt) {
    const date = isoFromUS(r.rekt.date);
    if (!date) continue;
    stats.rekt++;
    const name = r.title.replace(/\s*-\s*rekt.*$/i, '').trim();
    const audit = r.rekt.audit && !/^n\/?a$/i.test(r.rekt.audit) ? r.rekt.audit.replace(/^Out of Scope$/i, 'Out of scope') : null;
    const ref = { label: `REKT: ${r.title}`, url: `https://rekt.news/${r.slug}` };
    const match = findMatch(drafts, name, date, 10);
    if (match) {
      stats.rektMatched++;
      match.audit ??= audit;
      match.rootCause ??= r.excerpt;
      addDescription(match, 'REKT', r.excerpt);
      if (match.category === 'unknown') setKeywordCategory(match, classifyText(r.excerpt));
      attach(match, 'rekt', ref);
    } else {
      drafts.push({
        name,
        date,
        amountUsd: r.rekt.amount || null,
        returnedUsd: null,
        chains: [],
        targetType: null,
        ...keywordCategory(`${r.excerpt} ${r.tags.join(' ')}`, 'REKT article excerpt'),
        technique: null,
        ai: null,
        bridge: /bridge/i.test(r.title + r.excerpt),
        language: null,
        rootCause: r.excerpt,
        descriptions: [{ source: 'REKT', text: r.excerpt }],
        audit,
        poc: null,
        txHashes: [],
        sources: ['rekt'],
        references: [{ source: 'rekt', ...ref }],
      });
    }
  }

  for (const src of EXTRA_SOURCES) {
    const all = z.array(extraRecordSchema).parse(JSON.parse(raw(src.file)));
    // SlowMist also lists Ponzi schemes and frauds (BitConnect, OneCoin, Wirecard...). They are
    // not security failures and would swamp the loss statistics, so the index leaves them out.
    const recs = all.filter((r) => !(src.id === 'slowmist' && /^(scam|ponzi)$/i.test(r.label ?? '')));
    stats[`${src.file}ExcludedFraud`] = all.length - recs.length;
    let matched = 0;
    for (const r of recs) {
      const text = r.rootCause ? capText(r.rootCause, src.maxText) : null;
      const refs = [...(r.url ? [{ label: src.name, url: r.url }] : []), ...r.references.slice(0, 3).map((url) => ({ label: hostOf(url), url }))];
      const match = src.headlines ? findInHeadline(drafts, r.name, r.date) : findMatch(drafts, r.name, r.date, 7);
      if (match) {
        matched++;
        addDescription(match, src.name, text);
        match.rootCause ??= text;
        match.amountUsd ??= r.amountUsd;
        if (match.chains.length === 0) match.chains = r.chains;
        match.technique ??= r.label && !/^(unknown|others?)$/i.test(r.label) ? r.label : null;
        for (const h of r.txHashes) if (!match.txHashes.includes(h)) match.txHashes.push(h);
        if (match.category === 'unknown') setKeywordCategory(match, classifyText(`${r.label ?? ''} ${text ?? ''}`));
        for (const ref of refs) attach(match, src.id, ref);
      } else if (!src.enrichOnly) {
        drafts.push({
          name: r.name,
          date: r.date,
          amountUsd: r.amountUsd,
          returnedUsd: null,
          chains: r.chains,
          targetType: null,
          ...keywordCategory(`${r.label ?? ''} ${text ?? ''}`, `${src.name} label and description`),
          technique: r.label && !/^(unknown|others?)$/i.test(r.label) ? r.label : null,
          ai: null,
          bridge: /bridge/i.test(`${r.name} ${r.label ?? ''}`),
          language: null,
          rootCause: text,
          descriptions: text ? [{ source: src.name, text }] : [],
          audit: null,
          poc: null,
          txHashes: r.txHashes,
          sources: [src.id],
          references: refs.map((x) => ({ source: src.id, ...x })),
        });
      }
    }
    (stats as Record<string, number>)[src.file] = recs.length;
    (stats as Record<string, number>)[`${src.file}Matched`] = matched;
  }

  for (const c of CURATED) {
    stats.curated++;
    const match = findMatch(drafts, c.matchName ?? c.name.split(' ')[0], c.date, 3);
    if (match) {
      stats.curatedMatched++;
      match.rootCause = c.rootCause;
      match.descriptions.unshift({ source: 'Curated post-mortem', text: c.rootCause });
      match.technique = c.technique;
      if (match.category !== c.category) {
        match.classificationNote = `Curated: reclassified from "${match.category}" based on the published post-mortem.`;
        match.category = c.category;
      }
      match.classifiedBy = 'curated';
      match.curatedClass = c.vulnClass;
      for (const ref of c.references) attach(match, 'curated', ref);
      continue;
    }
    drafts.push({
      name: c.name,
      date: c.date,
      amountUsd: c.amountUsd,
      returnedUsd: null,
      chains: c.chains,
      targetType: 'Chain',
      category: c.category,
      technique: c.technique,
      classificationNote: null,
      classifiedBy: 'curated',
      curatedClass: c.vulnClass,
      ai: null,
      bridge: false,
      language: null,
      rootCause: c.rootCause,
      descriptions: [{ source: 'Curated post-mortem', text: c.rootCause }],
      audit: null,
      poc: null,
      txHashes: [],
      sources: ['curated'],
      references: c.references.map((r) => ({ source: 'curated' as const, ...r })),
    });
  }

  // One spelling per chain across sources ("BNB Chain" / "Binance Smart Chain" → "BSC").
  for (const d of drafts) d.chains = [...new Set(d.chains.map(canonicalChain).filter((c): c is string => c !== null))];

  drafts.sort((a, b) => b.date.localeCompare(a.date) || (b.amountUsd ?? 0) - (a.amountUsd ?? 0));
  const ids = new Set<string>();
  const incidents = drafts.map((d) => {
    let id = `${d.date}-${slugify(d.name)}`;
    for (let i = 2; ids.has(id); i++) id = `${d.date}-${slugify(d.name)}-${i}`;
    ids.add(id);
    return applyClasses(applyTypeSafe({ ...d, id, year: Number(d.date.slice(0, 4)), vulnClass: null, vulnClassBy: null, aiClass: null }), d.curatedClass);
  });
  return { incidents: incidents.map((i) => incidentSchema.parse(i)), stats };
}

// ---------------------------------------------------------------- advisories

function impactFromText(t: string): AdvisoryImpact {
  const s = t.toLowerCase();
  if (/inflation|counterfeit|duplicate input/.test(s)) return 'inflation';
  if (/remote code execution|\brce\b/.test(s)) return 'rce';
  if (/halt|stall network/.test(s)) return 'chain-halt';
  if (/netsplit|chain split|consensus|fork|not ready for/.test(s)) return 'consensus-split';
  if (/censorship/.test(s)) return 'censorship';
  if (/crash|panic|stack overflow/.test(s)) return 'remote-crash';
  if (/dos|denial|memory|cpu|disk|oom|exhaust|infinite loop|propagation|spam|instability|sync/.test(s)) return 'dos';
  return 'other';
}

function buildAdvisories(): Advisory[] {
  const out: Advisory[] = [];

  const btc = raw('btc.html');
  const seen = new Set<string>();
  for (const m of btc.matchAll(/<a href="(\/en\/(\d{4})\/(\d{2})\/(\d{2})\/[^"]+)" title="([^"]+)"/g)) {
    const [, path, y, mo, d, title] = m;
    if (seen.has(path)) continue;
    seen.add(path);
    const cve = title.match(/CVE-\d{4}-\d+/)?.[0] ?? null;
    out.push({
      id: `btc-${slugify(path)}`,
      project: 'Bitcoin Core',
      cve,
      title: title.replace(/^Disclosure of /, ''),
      date: `${y}-${mo}-${d}`,
      severity: null,
      impact: impactFromText(title),
      summary: null,
      url: `https://bitcoincore.org${path}`,
    });
  }

  const geth = z
    .array(z.object({ uid: z.string(), name: z.string(), summary: z.string(), CVE: z.string().nullish(), severity: z.string(), published: z.string(), links: z.array(z.string()) }).passthrough())
    .parse(JSON.parse(raw('geth.json')));
  for (const g of geth) {
    out.push({
      id: `geth-${g.uid.toLowerCase()}`,
      project: 'Geth',
      cve: g.CVE ?? null,
      title: g.name,
      date: g.published,
      severity: g.severity,
      impact: impactFromText(`${g.name} ${g.summary}`),
      summary: g.summary,
      url: g.links.find((l) => l.includes('/security/advisories/')) ?? 'https://geth.ethereum.org/docs/developers/geth-developer/disclosures',
    });
  }

  for (const m of raw('cosmos.md').matchAll(/^\|\[(ASA-\d{4}-\d+)\]\(([^)]+)\)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|(.+?)\|\s*$/gm)) {
    const [, asa, url, team, severity, title] = m;
    out.push({
      id: `cosmos-${asa.toLowerCase()}`,
      project: 'Cosmos',
      cve: asa,
      title: `${team.trim()}: ${title.trim().replace(/`/g, '')}`,
      date: null,
      severity: severity.trim(),
      impact: impactFromText(title),
      summary: null,
      url,
    });
  }

  // OSV (GitHub Security Advisories + Go/PyPI databases) for clients, SDKs and compilers.
  const ghsa = (x: string) => x.match(/GHSA-[\w-]+/i)?.[0]?.toUpperCase();
  const seen2 = new Set(out.flatMap((a) => [ghsa(a.url), a.cve].filter(Boolean) as string[]));
  const osv = z
    .array(z.object({ project: z.string(), id: z.string(), aliases: z.array(z.string()), title: z.string(), summary: z.string().nullable(), published: z.string().nullable(), severity: z.string().nullable(), url: z.string() }))
    .parse(JSON.parse(raw('osv_advisories.json')));
  const PROJECT: Record<string, string> = { vyper: 'Vyper', 'go-ethereum': 'Geth', 'cosmos-sdk': 'Cosmos', cometbft: 'Cosmos', tendermint: 'Cosmos', 'ibc-go': 'Cosmos', evmos: 'Evmos', btcd: 'btcd', lnd: 'Lightning (lnd)', besu: 'Besu', 'web3.js': 'web3.js' };
  for (const o of osv) {
    const ids = [o.id, ...o.aliases].map((x) => x.toUpperCase());
    if (ids.some((x) => seen2.has(x))) continue;
    ids.forEach((x) => seen2.add(x));
    const first = o.project.split(',')[0].trim();
    out.push({
      id: `osv-${slugify(o.id)}`,
      project: first.startsWith('openzeppelin') ? 'OpenZeppelin Contracts' : (PROJECT[first] ?? first),
      cve: ids.find((x) => x.startsWith('CVE-')) ?? o.id,
      title: o.title.replace(/^Vyper:\s*/i, ''),
      date: o.published && /^\d{4}-\d{2}-\d{2}$/.test(o.published) ? o.published : null,
      severity: o.severity,
      impact: impactFromText(`${o.title} ${o.summary ?? ''}`),
      summary: o.summary ? capText(o.summary, 400) : null,
      url: o.url,
    });
  }
  return out.map((a) => advisorySchema.parse(a));
}

/**
 * The dataset a detection / auto-fix tool consumes: every class with its fix knowledge, plus the
 * real incidents labelled with it (PoCs and attack transactions first, as test cases).
 */
function classDataset(xs: Incident[]) {
  return CLASS_IDS.map((id) => {
    const c = CLASSES[id];
    const cases = xs
      .filter((i) => i.vulnClass === id)
      .sort((a, b) => Number(!!b.poc) - Number(!!a.poc) || b.txHashes.length - a.txHashes.length || (b.amountUsd ?? 0) - (a.amountUsd ?? 0));
    return {
      id,
      ...c,
      category: c.parent,
      layer: CATEGORIES[c.parent].layer,
      incidents: cases.length,
      lossUsd: cases.reduce((s, i) => s + (i.amountUsd ?? 0), 0),
      withPoc: cases.filter((i) => i.poc).length,
      cases: cases.map((i) => ({
        id: i.id,
        name: i.name,
        date: i.date,
        chains: i.chains,
        lossUsd: i.amountUsd,
        labelledBy: i.vulnClassBy,
        rootCause: i.rootCause,
        poc: i.poc,
        txHashes: i.txHashes,
      })),
    };
  });
}

function toCsv(xs: Incident[]): string {
  const cols = ['id', 'date', 'name', 'amountUsd', 'chains', 'targetType', 'category', 'vulnClass', 'vulnClassBy', 'technique', 'classifiedBy', 'aiCategory', 'aiConfidence', 'bridge', 'audit', 'poc', 'sources', 'rootCause'] as const;
  const cell = (v: unknown) => {
    const s = v == null ? '' : Array.isArray(v) ? v.join('; ') : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const row = (i: Incident) =>
    cols
      .map((c) => cell(c === 'aiCategory' ? i.ai?.category : c === 'aiConfidence' ? i.ai?.confidence.toFixed(2) : i[c]))
      .join(',');
  return `${cols.join(',')}\n${xs.map(row).join('\n')}\n`;
}

// ---------------------------------------------------------------- main

if (process.argv.includes('--fetch')) await fetchAll();
const { incidents, stats } = build();
const advisories = buildAdvisories();
mkdirSync(OUT, { recursive: true });
// One record per line keeps git diffs readable when a single incident changes.
writeFileSync(join(OUT, 'incidents.json'), `[\n${incidents.map((i) => JSON.stringify(i)).join(',\n')}\n]\n`);
writeFileSync(join(OUT, 'advisories.json'), JSON.stringify(advisories, null, 1));
rmSync(join(OUT, 'incidents'), { recursive: true, force: true });
for (const i of incidents) {
  const dir = join(OUT, 'incidents', String(i.year));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${i.id}.json`), `${JSON.stringify(i, null, 2)}\n`);
}
writeFileSync(join(OUT, 'incidents.csv'), toCsv(incidents));
writeFileSync(join(OUT, 'vulnerability-classes.json'), `${JSON.stringify(classDataset(incidents), null, 1)}\n`);
console.log(stats);
console.log(`incidents: ${incidents.length}, advisories: ${advisories.length}`);
const byCat: Record<string, number> = {};
for (const i of incidents) byCat[i.category] = (byCat[i.category] ?? 0) + 1;
console.log(byCat);
const byWho: Record<string, number> = {};
for (const i of incidents) byWho[i.classifiedBy] = (byWho[i.classifiedBy] ?? 0) + 1;
console.log(byWho, `typesafe answers: ${incidents.filter((i) => i.ai).length}`);

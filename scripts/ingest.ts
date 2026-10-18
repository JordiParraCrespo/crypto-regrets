/**
 * Build the incident index from raw source snapshots in data/raw/.
 *
 *   npm run ingest            # parse snapshots in data/raw
 *   npm run ingest -- --fetch # refresh snapshots from the network first
 *
 * Output: src/data/incidents.json, src/data/advisories.json (both schema-validated).
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { type CategoryId } from '../src/lib/taxonomy';
import {
  incidentSchema,
  advisorySchema,
  type Incident,
  type Advisory,
  type AdvisoryImpact,
  type SourceId,
} from '../src/lib/types';
import { CURATED } from './curated';

const RAW = 'data/raw';
const OUT = 'src/data';

const DHL_YEARS = [2021, 2022, 2023, 2024, 2025];
const DHL_RAW = 'https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main';
const FETCH: Record<string, string> = {
  'llama.json': 'https://api.llama.fi/hacks',
  'dhl.md': `${DHL_RAW}/README.md`,
  ...Object.fromEntries(DHL_YEARS.map((y) => [`dhl_${y}.md`, `${DHL_RAW}/past/${y}/README.md`])),
  'btc.html': 'https://bitcoincore.org/en/security-advisories/',
  'geth.json': 'https://geth.ethereum.org/docs/vulnerabilities/vulnerabilities.json',
  'cosmos.md': 'https://raw.githubusercontent.com/cosmos/security/main/ADVISORIES.md',
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

/** Keyword classifier for free-text root-cause titles (DeFiHackLabs, REKT). Order matters. */
const KEYWORD_RULES: [RegExp, CategoryId][] = [
  [/reentr|re-entr|erc777|callback re-?enter/i, 'reentrancy'],
  [/oracle|price manipulation|spot price|twap|price feed|manipulat\w* (the )?(price|reserve|rate|nav)|reserve manipulation|self-trade|nav inflation|getprice|pricing/i, 'oracle-manipulation'],
  [/signature|ecrecover|replay|permit\b|weak (private )?key|profanity|vanity/i, 'signature-crypto'],
  [/private key|key (leak|compromis)|hot wallet|multisig (compromis|signer)|stolen key|compromised (wallet|key|account)/i, 'key-compromise'],
  [/phishing|social engineering|malware|impersonat|lazarus/i, 'social-engineering'],
  [/\bdns\b|frontend|front-end|supply chain|\bnpm\b|\bcdn\b/i, 'frontend-infra'],
  [/bridge|cross-chain|crosschain|merkle|proof/i, 'bridge-crosschain'],
  [/governance|proposal|voting/i, 'governance'],
  [/\brug|backdoor|exit scam|insider/i, 'rugpull'],
  [/arbitrary (external )?call|arbitrary.*calldata|approv|transferfrom|allowance|unverified (user )?input.*call|multicall/i, 'arbitrary-call'],
  [/access control|unprotected|permissionless|lack of (permission|auth)|missing (auth|modifier|access|caller|owner|permission)|caller check|onlyowner|initiali[sz]|uninitiali|ungated|no (access|auth)|anyone can|authori[sz]ation bypass|unauthori[sz]ed|unguarded|unrestricted|public (mint|burn|function)/i, 'access-control'],
  [/overflow|underflow|rounding|precision|share (price|accounting|calculation)|inflation|donat|divceil|division|arithmetic|decimal|infinite mint|fee-on-transfer|deflationary|skim|\bsync\b|truncat|accounting|erc-?404|balance (check|update)/i, 'accounting-math'],
  [/input validation|unchecked|insufficient validation|fake (token|pool|market|contract)|lack of validation|missing (check|validation)|not (check|validat)|unverified|arbitrary (token|pool|address)|user-supplied/i, 'input-validation'],
  [/logic|flaw|incorrect|calculation|reward|business|liquidat|withdraw|deposit|claim|swap|mint|burn|stak|duplicate|double|presale|arbitrage|funding|fee|bypass|misclassif|update|redemption|redeem|borrow|lock/i, 'logic-error'],
];

function classifyText(text: string): CategoryId {
  for (const [re, cat] of KEYWORD_RULES) if (re.test(text)) return cat;
  return 'unknown';
}

// ---------------------------------------------------------------- sources

type Draft = Omit<Incident, 'id' | 'year'>;

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
      bridge: h.bridgeHack,
      language: h.language,
      rootCause: null,
      audit: null,
      poc: null,
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

// ---------------------------------------------------------------- merge

function attach(d: Draft, source: SourceId, ref: { label: string; url: string }) {
  if (!d.sources.includes(source)) d.sources.push(source);
  if (!d.references.some((r) => r.url === ref.url)) d.references.push({ source, ...ref });
}

function findMatch(pool: Draft[], name: string, date: string, maxDays: number): Draft | undefined {
  let best: Draft | undefined;
  let bestDays = Infinity;
  for (const d of pool) {
    const days = daysApart(d.date, date);
    if (days <= maxDays && days < bestDays && namesMatch(d.name, name)) {
      best = d;
      bestDays = days;
    }
  }
  return best;
}

function build(): { incidents: Incident[]; stats: Record<string, number> } {
  const drafts = fromLlama();
  const stats = { defillama: drafts.length, dhl: 0, dhlMatched: 0, rekt: 0, rektMatched: 0, curated: 0, curatedMatched: 0 };

  for (const e of fromDhl()) {
    stats.dhl++;
    const rootCause = e.title ? `${e.title}${e.lost ? `. Lost: ${e.lost}` : ''}` : e.lost ? `Lost: ${e.lost}` : null;
    const match = findMatch(drafts, e.name, e.date, 7);
    const ref = { label: 'DeFiHackLabs PoC', url: e.poc ?? 'https://github.com/SunWeb3Sec/DeFiHackLabs' };
    if (match) {
      stats.dhlMatched++;
      match.rootCause ??= rootCause;
      match.poc ??= e.poc;
      if (match.category === 'unknown' && e.title) match.category = classifyText(e.title);
      attach(match, 'defihacklabs', ref);
    } else {
      drafts.push({
        name: e.name,
        date: e.date,
        amountUsd: parseLostUsd(e.lost),
        returnedUsd: null,
        chains: [],
        targetType: 'DeFi Protocol',
        category: classifyText(`${e.title} ${e.lost ?? ''}`),
        technique: e.title.length > 0 && e.title.length <= 60 ? e.title : null,
        classificationNote: 'Classified by keyword rules from the DeFiHackLabs root-cause title.',
        bridge: /bridge/i.test(e.name),
        language: 'Solidity',
        rootCause,
        audit: null,
        poc: e.poc,
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
      if (match.category === 'unknown') match.category = classifyText(r.excerpt);
      attach(match, 'rekt', ref);
    } else {
      drafts.push({
        name,
        date,
        amountUsd: r.rekt.amount || null,
        returnedUsd: null,
        chains: [],
        targetType: null,
        category: classifyText(`${r.excerpt} ${r.tags.join(' ')}`),
        technique: null,
        classificationNote: 'Classified by keyword rules from the REKT article excerpt.',
        bridge: /bridge/i.test(r.title + r.excerpt),
        language: null,
        rootCause: r.excerpt,
        audit,
        poc: null,
        sources: ['rekt'],
        references: [{ source: 'rekt', ...ref }],
      });
    }
  }

  for (const c of CURATED) {
    stats.curated++;
    const match = findMatch(drafts, c.matchName ?? c.name.split(' ')[0], c.date, 3);
    if (match) {
      stats.curatedMatched++;
      match.rootCause = c.rootCause;
      match.technique = c.technique;
      if (match.category !== c.category) {
        match.classificationNote = `Curated: reclassified from "${match.category}" based on the published post-mortem.`;
        match.category = c.category;
      }
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
      bridge: false,
      language: null,
      rootCause: c.rootCause,
      audit: null,
      poc: null,
      sources: ['curated'],
      references: c.references.map((r) => ({ source: 'curated' as const, ...r })),
    });
  }

  drafts.sort((a, b) => b.date.localeCompare(a.date) || (b.amountUsd ?? 0) - (a.amountUsd ?? 0));
  const ids = new Set<string>();
  const incidents = drafts.map((d) => {
    let id = `${d.date}-${slugify(d.name)}`;
    for (let i = 2; ids.has(id); i++) id = `${d.date}-${slugify(d.name)}-${i}`;
    ids.add(id);
    return incidentSchema.parse({ ...d, id, year: Number(d.date.slice(0, 4)) });
  });
  return { incidents, stats };
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

  return out.map((a) => advisorySchema.parse(a));
}

// ---------------------------------------------------------------- main

if (process.argv.includes('--fetch')) await fetchAll();
const { incidents, stats } = build();
const advisories = buildAdvisories();
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'incidents.json'), JSON.stringify(incidents));
writeFileSync(join(OUT, 'advisories.json'), JSON.stringify(advisories, null, 1));
console.log(stats);
console.log(`incidents: ${incidents.length}, advisories: ${advisories.length}`);
const byCat: Record<string, number> = {};
for (const i of incidents) byCat[i.category] = (byCat[i.category] ?? 0) + 1;
console.log(byCat);

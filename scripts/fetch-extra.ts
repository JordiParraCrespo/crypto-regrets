/**
 * Download extra hack-incident sources and write normalized snapshots to data/raw/.
 *
 *   npx tsx scripts/fetch-extra.ts            # all sources
 *   npx tsx scripts/fetch-extra.ts slowmist   # only some (dhl_explorer, blocksec, slowmist, revertiq)
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { z } from "zod";

const OUT_DIR = new URL("../data/raw/", import.meta.url);
const ROOT_CAUSE_MAX = 2000;
const UA = "Mozilla/5.0 (compatible; crypto-regrets-fetch/1.0)";

const RecordSchema = z.object({
  source: z.string().min(1),
  sourceId: z.string().min(1),
  name: z.string().min(1),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  amountUsd: z.number().finite().nonnegative().nullable(),
  chains: z.array(z.string()),
  label: z.string().nullable(),
  rootCause: z.string().nullable(),
  txHashes: z.array(z.string()),
  url: z.string().nullable(),
  references: z.array(z.string()).max(5),
});
type Rec = z.infer<typeof RecordSchema>;

// ---------- helpers ----------
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchText(url: string, init: RequestInit = {}, tries = 3): Promise<string> {
  let last: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, {
        ...init,
        headers: { "user-agent": UA, ...(init.headers ?? {}) },
        signal: AbortSignal.timeout(120_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      return await res.text();
    } catch (e) {
      last = e;
      await sleep(1000 * (i + 1));
    }
  }
  throw last instanceof Error ? last : new Error(String(last));
}
const fetchJson = async (url: string, init: RequestInit = {}): Promise<unknown> =>
  JSON.parse(await fetchText(url, init));

const ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'",
  rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", mdash: "—", ndash: "–", hellip: "…",
};
function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}
function stripHtml(s: string): string {
  return decodeEntities(s.replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, " "));
}
/** Markdown -> plain text (good enough for narrative snippets). */
function stripMarkdown(s: string): string {
  return s
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/(\*\*|__|`)/g, "")
    .replace(/^\s*[-*+]\s+/gm, "- ")
    .replace(/^\s*>\s?/gm, "");
}
function cleanText(s: string | null | undefined, md = false): string | null {
  if (!s) return null;
  let t = md ? stripMarkdown(stripHtml(s)) : stripHtml(s);
  t = t
    .replace(/[ \t ]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (!t) return null;
  if (t.length > ROOT_CAUSE_MAX) t = t.slice(0, ROOT_CAUSE_MAX - 1).trimEnd() + "…";
  return t;
}
const TX_RE = /\b0x[0-9a-fA-F]{64}\b/g;
function extractTx(...texts: (string | null | undefined)[]): string[] {
  const out = new Set<string>();
  for (const t of texts) for (const m of t?.match(TX_RE) ?? []) out.add(m.toLowerCase());
  return [...out];
}
function extractUrls(text: string | null | undefined): string[] {
  if (!text) return [];
  const out: string[] = [];
  for (const m of text.match(/https?:\/\/[^\s)\]"'<>]+/g) ?? []) {
    const u = m.replace(/[.,;:]+$/, "");
    if (/\.(png|jpe?g|gif|webp|svg)(\?|$)/i.test(u)) continue;
    out.push(u);
  }
  return out;
}
function uniq5(urls: (string | null | undefined)[]): string[] {
  const out: string[] = [];
  for (const u of urls) {
    const v = u?.trim();
    if (v && /^https?:\/\//.test(v) && !out.includes(v)) out.push(v);
    if (out.length >= 5) break;
  }
  return out;
}
function toIsoDate(v: unknown): string | null {
  if (v == null || v === "") return null;
  let d: Date | null = null;
  if (typeof v === "number") d = new Date(v < 1e12 ? v * 1000 : v);
  else if (typeof v === "string") {
    const s = v.trim();
    let m = s.match(/^(\d{4})(\d{2})(\d{2})$/);
    if (m) return valid(`${m[1]}-${m[2]}-${m[3]}`);
    m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
    if (m) return valid(`${m[1]}-${m[2].padStart(2, "0")}-${m[3].padStart(2, "0")}`);
    d = new Date(s);
  }
  if (!d || Number.isNaN(d.getTime())) return null;
  return valid(d.toISOString().slice(0, 10));
}
function valid(iso: string): string | null {
  const d = new Date(iso + "T00:00:00Z");
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== iso) return null;
  const y = d.getUTCFullYear();
  return y >= 2009 && y <= 2100 ? iso : null;
}
/** "$1.2M", "$ 350K", "$1,530,000", "1.5B" -> number */
function parseAmount(s: string | number | null | undefined): number | null {
  if (s == null) return null;
  if (typeof s === "number") return Number.isFinite(s) && s >= 0 ? s : null;
  const m = s.replace(/,/g, "").match(/(\d+(?:\.\d+)?)\s*(k|m|mn|million|b|bn|billion|thousand)?\b/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  const mult: Record<string, number> = {
    k: 1e3, thousand: 1e3, m: 1e6, mn: 1e6, million: 1e6, b: 1e9, bn: 1e9, billion: 1e9,
  };
  const v = n * (m[2] ? mult[m[2].toLowerCase()] ?? 1 : 1);
  return Number.isFinite(v) ? v : null;
}
const shortHash = (s: string) => createHash("sha1").update(s).digest("hex").slice(0, 12);

// ---------- source: DeFiHackLabs explorer ----------
const DhlIncident = z.object({
  date: z.union([z.string(), z.number()]),
  name: z.string(),
  type: z.string().nullish(),
  Lost: z.union([z.number(), z.string()]).nullish(),
  lossType: z.string().nullish(),
  Contract: z.string().nullish(),
  chain: z.string().nullish(),
});
const DhlRoot = z.object({
  type: z.string().nullish(),
  date: z.string().nullish(),
  rootCause: z.string().nullish(),
  pocLink: z.string().nullish(),
}).passthrough();
const USD_LIKE = new Set(["USD", "USDC", "USDT", "DAI", "BUSD", "USDC.E", "USDE", "FDUSD", "TUSD"]);

async function dhlExplorer(): Promise<{ fetched: number; raw: Partial<Rec>[] }> {
  const inc = z.array(DhlIncident).parse(await fetchJson("https://defihacklabs.io/explorer/incidents.json"));
  const rc = z.record(z.string(), DhlRoot).parse(await fetchJson("https://defihacklabs.io/explorer/rootcause_data.json"));
  const nameCount = new Map<string, number>();
  for (const r of inc) nameCount.set(r.name, (nameCount.get(r.name) ?? 0) + 1);
  const seen = new Map<string, number>();
  const out: Partial<Rec>[] = [];
  for (const r of inc) {
    const date = toIsoDate(String(r.date));
    const ymd = String(r.date);
    // Join key: rootcause_data is keyed by name; duplicate names are disambiguated as "Name (YYYYMMDD)".
    let root = rc[`${r.name} (${ymd})`];
    if (!root) {
      const cand = rc[r.name];
      if (cand && (nameCount.get(r.name) === 1 || !cand.date || toIsoDate(cand.date) === date)) root = cand;
    }
    const lossType = (r.lossType ?? "").toUpperCase();
    const amount = USD_LIKE.has(lossType) ? parseAmount(r.Lost ?? null) : null;
    const rawRc = root?.rootCause ?? null;
    let id = `${ymd}-${r.name}`;
    const n = (seen.get(id) ?? 0) + 1;
    seen.set(id, n);
    if (n > 1) id += `-${n}`;
    out.push({
      source: "dhl_explorer",
      sourceId: id,
      name: r.name.trim(),
      date: date ?? undefined,
      amountUsd: amount,
      chains: r.chain ? [r.chain.trim()] : [],
      label: r.type?.trim() || root?.type?.trim() || null,
      rootCause: cleanText(rawRc, true),
      txHashes: extractTx(rawRc),
      url: null,
      references: uniq5([root?.pocLink, ...extractUrls(rawRc)]),
    });
  }
  return { fetched: inc.length, raw: out };
}

// ---------- source: BlockSec ----------
const CHAIN_IDS: Record<string, string> = {
  "1": "Ethereum", "5": "Goerli", "10": "Optimism", "25": "Cronos", "56": "BSC", "100": "Gnosis",
  "130": "Unichain", "137": "Polygon", "143": "Monad", "146": "Sonic", "250": "Fantom", "252": "Fraxtal",
  "324": "zkSync Era", "369": "PulseChain", "480": "World Chain", "999": "HyperEVM", "1101": "Polygon zkEVM",
  "1284": "Moonbeam", "2222": "Kava", "5000": "Mantle", "8453": "Base", "34443": "Mode", "42161": "Arbitrum",
  "42220": "Celo", "43114": "Avalanche", "59144": "Linea", "80094": "Berachain", "81457": "Blast",
  "534352": "Scroll", "1313161554": "Aurora",
};
const BsEvent = z.object({
  id: z.union([z.number(), z.string()]),
  project: z.string().nullish(),
  loss: z.union([z.string(), z.number()]).nullish(),
  chainIds: z.array(z.union([z.number(), z.string()])).nullish(),
  transactions: z.array(z.object({ txnHash: z.string().nullish(), chainId: z.union([z.number(), z.string()]).nullish() }).passthrough()).nullish(),
  media: z.string().nullish(),
  rootCause: z.string().nullish(),
  date: z.union([z.number(), z.string()]).nullish(),
  poc: z.string().nullish(),
}).passthrough();

async function blocksec(): Promise<{ fetched: number; raw: Partial<Rec>[] }> {
  const body = z.object({ list: z.array(BsEvent) }).passthrough().parse(
    await fetchJson("https://blocksec.com/api/v1/attack/events", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
  );
  const out = body.list.map((e): Partial<Rec> => {
    const tx = [...new Set((e.transactions ?? []).map((t) => t.txnHash?.trim()).filter((h): h is string => !!h))];
    const chains = [...new Set((e.chainIds ?? []).map((c) => CHAIN_IDS[String(c)] ?? String(c)))];
    return {
      source: "blocksec",
      sourceId: String(e.id),
      name: (e.project ?? "").trim(),
      date: toIsoDate(typeof e.date === "string" && /^\d+$/.test(e.date) ? Number(e.date) : e.date) ?? undefined,
      amountUsd: parseAmount(e.loss ?? null),
      chains,
      label: e.rootCause?.trim() || null,
      rootCause: null, // BlockSec only exposes a short category, stored in `label`
      txHashes: tx,
      url: tx[0] ? `https://blocksec.com/security-incident?hash=${tx[0]}` : null,
      references: uniq5([e.media, e.poc]),
    };
  });
  return { fetched: body.list.length, raw: out };
}

// ---------- source: SlowMist ----------
const SM_BASE = "https://hacked.slowmist.io/en/";
const SM_CHAIN_CATS: Record<string, string> = {
  ETH: "Ethereum", BSC: "BSC", Tron: "Tron", EOS: "EOS", Polygon: "Polygon", HECO: "HECO", Fantom: "Fantom",
  Solana: "Solana", Avalanche: "Avalanche", Polkadot: "Polkadot", Arbitrum: "Arbitrum", Optimism: "Optimism",
  zkSync: "zkSync", Base: "Base",
};
type SmItem = { date: string | null; name: string; desc: string | null; amountText: string | null; method: string | null; refs: string[] };

function parseSlowMistPage(html: string): { items: SmItem[]; lastPage: number } {
  const items: SmItem[] = [];
  const listStart = html.indexOf('class="time"');
  const region = listStart >= 0 ? html.slice(html.lastIndexOf("<ul", listStart)) : "";
  for (const m of region.matchAll(/<li>([\s\S]*?)<\/li>/g)) {
    const li = m[1];
    if (!li.includes('class="time"')) continue;
    const field = (label: string) => {
      const r = li.match(new RegExp(`<em>\\s*${label}\\s*:?\\s*</em>([\\s\\S]*?)</(?:h3|p|span)>`, "i"));
      return r ? cleanText(r[1]) : null;
    };
    const date = li.match(/class="time">([^<]*)</)?.[1]?.trim() ?? null;
    const refs = [...li.matchAll(/class="link-reference"[\s\S]*?<\/p>/g)]
      .flatMap((p) => [...p[0].matchAll(/href="([^"]+)"/g)].map((h) => decodeEntities(h[1]).trim()));
    items.push({
      date,
      name: field("Hacked target") ?? "",
      desc: field("Description of the event"),
      amountText: field("Amount of loss"),
      method: field("Attack method"),
      refs,
    });
  }
  const pages = [...html.matchAll(/page=(\d+)/g)].map((x) => Number(x[1]));
  return { items, lastPage: pages.length ? Math.max(...pages) : 1 };
}

async function crawlSlowMist(cat: string): Promise<SmItem[]> {
  const all: SmItem[] = [];
  let last = 1;
  for (let page = 1; page <= last; page++) {
    const html = await fetchText(`${SM_BASE}?c=${encodeURIComponent(cat)}&page=${page}`);
    const { items, lastPage } = parseSlowMistPage(html);
    if (page === 1) last = lastPage;
    all.push(...items);
    if (items.length === 0) break;
    await sleep(300);
  }
  return all;
}
const smKey = (i: SmItem) => `${i.date}|${i.name}|${(i.desc ?? "").slice(0, 120)}`;

async function slowmist(): Promise<{ fetched: number; raw: Partial<Rec>[] }> {
  const items = await crawlSlowMist("");
  process.stdout.write(`  slowmist: ${items.length} events from main list; crawling ecosystem categories for chains…\n`);
  const chainsByKey = new Map<string, Set<string>>();
  for (const [cat, chain] of Object.entries(SM_CHAIN_CATS)) {
    try {
      for (const it of await crawlSlowMist(cat)) {
        const k = smKey(it);
        if (!chainsByKey.has(k)) chainsByKey.set(k, new Set());
        chainsByKey.get(k)!.add(chain);
      }
    } catch (e) {
      process.stdout.write(`  slowmist: category ${cat} failed (${(e as Error).message}); chains may be incomplete\n`);
    }
  }
  const seen = new Map<string, number>();
  const out = items.map((it): Partial<Rec> => {
    const k = smKey(it);
    let id = shortHash(k);
    const n = (seen.get(id) ?? 0) + 1;
    seen.set(id, n);
    if (n > 1) id += `-${n}`;
    // Only treat dollar-denominated amounts as USD (others are e.g. "12,000 ETH").
    const amt = it.amountText && /\$/.test(it.amountText) ? parseAmount(it.amountText.replace(/^[^$]*\$/, "")) : null;
    return {
      source: "slowmist",
      sourceId: id,
      name: it.name,
      date: toIsoDate(it.date) ?? undefined,
      amountUsd: amt,
      chains: [...(chainsByKey.get(k) ?? [])],
      label: it.method || null,
      rootCause: it.desc,
      txHashes: extractTx(it.desc),
      url: null,
      references: uniq5(it.refs),
    };
  });
  return { fetched: items.length, raw: out };
}

// ---------- source: RevertIQ ----------
const RqItem = z.object({
  id: z.union([z.string(), z.number()]),
  slug: z.string().nullish(),
  title: z.string().nullish(),
  project_name: z.string().nullish(),
  summary: z.string().nullish(),
  incident_date: z.string().nullish(),
  amount_lost_usd: z.union([z.number(), z.string()]).nullish(),
  chains: z.array(z.string()).nullish(),
  attack_vectors: z.array(z.string()).nullish(),
  source_links: z.array(z.object({ url: z.string().nullish() }).passthrough()).nullish(),
  canonical_url: z.string().nullish(),
  root_cause: z.string().nullish(),
  description: z.string().nullish(),
}).passthrough();

async function revertiq(): Promise<{ fetched: number; raw: Partial<Rec>[] }> {
  const body = z.object({ items: z.array(RqItem) }).passthrough().parse(
    await fetchJson("https://revertiqapi.azurewebsites.net/hacks?page=1"),
  );
  const out = body.items.map((h): Partial<Rec> => {
    const narrative = [h.summary, h.root_cause].filter((x) => x && x.trim()).join("\n\n");
    return {
      source: "revertiq",
      sourceId: String(h.id),
      name: (h.project_name || h.title || "").trim(),
      date: toIsoDate(h.incident_date) ?? undefined,
      amountUsd: parseAmount(h.amount_lost_usd ?? null),
      chains: (h.chains ?? []).map((c) => c.trim()).filter(Boolean),
      label: (h.attack_vectors ?? []).filter(Boolean).join("; ") || null,
      rootCause: cleanText(narrative || h.description, true),
      txHashes: extractTx(h.description, h.root_cause, h.summary),
      url: h.slug ? `https://revertiq.ai/hacks/${h.slug}` : null,
      references: uniq5([...(h.source_links ?? []).map((s) => s.url), h.canonical_url]),
    };
  });
  return { fetched: body.items.length, raw: out };
}

// ---------- driver ----------
const SOURCES: Record<string, { file: string; run: () => Promise<{ fetched: number; raw: Partial<Rec>[] }> }> = {
  dhl_explorer: { file: "dhl_explorer.json", run: dhlExplorer },
  blocksec: { file: "blocksec.json", run: blocksec },
  slowmist: { file: "slowmist.json", run: slowmist },
  revertiq: { file: "revertiq.json", run: revertiq },
};

function median(xs: number[]): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  const wanted = process.argv.slice(2);
  const names = wanted.length ? wanted : Object.keys(SOURCES);
  const summary: Record<string, unknown>[] = [];
  for (const name of names) {
    const src = SOURCES[name];
    if (!src) {
      console.error(`unknown source ${name}`);
      continue;
    }
    const t0 = Date.now();
    console.log(`[${name}] fetching…`);
    try {
      const { fetched, raw } = await src.run();
      const good: Rec[] = [];
      let dropped = 0;
      for (const r of raw) {
        const p = RecordSchema.safeParse(r);
        if (p.success) good.push(p.data);
        else dropped++;
      }
      good.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.name.localeCompare(b.name)));
      if (!good.length) throw new Error(`no valid records (fetched ${fetched})`);
      writeFileSync(new URL(src.file, OUT_DIR), JSON.stringify(good, null, 1) + "\n");
      const dates = good.map((g) => g.date).sort();
      const rcLens = good.map((g) => g.rootCause?.length ?? 0).filter((n) => n > 0);
      summary.push({
        source: name,
        fetched,
        written: good.length,
        dropped,
        from: dates[0],
        to: dates[dates.length - 1],
        withRootCause: rcLens.length,
        medianRootCauseLen: median(rcLens),
        secs: Math.round((Date.now() - t0) / 1000),
      });
    } catch (e) {
      console.error(`[${name}] FAILED: ${(e as Error).message} — nothing written`);
      summary.push({ source: name, failed: (e as Error).message });
    }
  }
  console.table(summary);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

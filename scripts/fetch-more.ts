/**
 * Download more hack-incident sources (+ blockchain client advisories) and write
 * normalized snapshots to data/raw/. Same conventions as scripts/fetch-extra.ts.
 *
 *   npx tsx scripts/fetch-more.ts            # all sources
 *   npx tsx scripts/fetch-more.ts seal911    # only some (graveyard, seal911, web3isgoinggreat, osv)
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { z } from "zod";

const OUT_DIR = new URL("../data/raw/", import.meta.url);
const ROOT_CAUSE_MAX = 2000;
const OSV_SUMMARY_MAX = 800;
const UA = "Mozilla/5.0 (compatible; crypto-regrets-fetch/1.0)";

const RecordSchema = z.object({
  source: z.string().min(1),
  sourceId: z.string().min(1),
  name: z.string().min(1),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  amountUsd: z.number().finite().nonnegative().nullable(),
  chains: z.array(z.string()),
  label: z.string().nullable(),
  rootCause: z.string().max(ROOT_CAUSE_MAX).nullable(),
  txHashes: z.array(z.string()),
  url: z.string().nullable(),
  references: z.array(z.string()).max(5),
});
type Rec = z.infer<typeof RecordSchema>;

const AdvisorySchema = z.object({
  project: z.string().min(1),
  ecosystem: z.string().min(1),
  id: z.string().min(1),
  aliases: z.array(z.string()),
  title: z.string().min(1),
  summary: z.string().max(OSV_SUMMARY_MAX).nullable(),
  published: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  severity: z.string().nullable(),
  url: z.string().url(),
});
type Advisory = z.infer<typeof AdvisorySchema>;

// ---------- helpers (copied from fetch-extra.ts so this script stays standalone) ----------
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
      if (e instanceof Error && /HTTP 4\d\d/.test(e.message) && !/HTTP 429/.test(e.message)) break;
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
  return decodeEntities(s.replace(/<br\s*\/?>/gi, "\n").replace(/<\/?p>/gi, "\n").replace(/<[^>]+>/g, " "));
}
/** Markdown -> plain text (good enough for narrative snippets). */
function stripMarkdown(s: string): string {
  return s
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]*)\]\[[^\]]*\]/g, "$1")
    .replace(/^\s*\[[^\]]+\]:\s*\S+.*$/gm, "")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/(\*\*|__|`)/g, "")
    .replace(/^\s*[-*+]\s+/gm, "- ")
    .replace(/^\s*>\s?/gm, "");
}
function cleanText(s: string | null | undefined, md = false, max = ROOT_CAUSE_MAX): string | null {
  if (!s) return null;
  let t = md ? stripMarkdown(stripHtml(s)) : stripHtml(s);
  t = t
    .replace(/[ \t ]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (!t) return null;
  if (t.length > max) t = t.slice(0, max - 1).trimEnd() + "…";
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
const shortHash = (s: string) => createHash("sha1").update(s).digest("hex").slice(0, 12);

type SourceResult = { fetched: number; raw: Partial<Rec>[] };

// ---------- source: Blockchain Graveyard (magoo) ----------
// The GitHub contents API / tarballs are not reachable from here, so the post list comes from
// jsDelivr's GitHub file index and each post is read from raw.githubusercontent.com.
const GY_REPO = "magoo/Blockchain-Graveyard";
const GY_BRANCH = "gh-pages";

function parseFrontMatter(md: string): { fm: Record<string, string | string[]>; body: string } {
  const m = md.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
  if (!m) return { fm: {}, body: md };
  const fm: Record<string, string | string[]> = {};
  let listKey: string | null = null;
  for (const line of m[1].split("\n")) {
    const item = line.match(/^\s*-\s+(.*)$/);
    if (item && listKey) {
      (fm[listKey] as string[]).push(unquote(item[1]));
      continue;
    }
    const kv = line.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
    if (!kv) continue;
    const [, k, v] = kv;
    if (v.trim() === "") {
      fm[k] = [];
      listKey = k;
    } else {
      listKey = null;
      const inline = v.trim().match(/^\[(.*)\]$/);
      fm[k] = inline ? inline[1].split(",").map((x) => unquote(x)).filter(Boolean) : unquote(v);
    }
  }
  return { fm, body: m[2] };
}
const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "").trim();
const fmStr = (v: string | string[] | undefined) => (Array.isArray(v) ? v.join(" ") : v) ?? null;
const fmList = (v: string | string[] | undefined) =>
  (Array.isArray(v) ? v : v ? v.split(/[\s,]+/) : []).map((x) => x.trim()).filter(Boolean);

async function graveyard(): Promise<SourceResult> {
  const idx = z.object({ files: z.array(z.object({ name: z.string() }).passthrough()) }).passthrough().parse(
    await fetchJson(`https://data.jsdelivr.com/v1/packages/gh/${GY_REPO}@${GY_BRANCH}?structure=flat`),
  );
  const posts = idx.files.map((f) => f.name).filter((n) => /^\/_posts\/\d{4}-\d{1,2}-\d{1,2}-.+\.(md|markdown)$/.test(n));
  const out: Partial<Rec>[] = [];
  for (const p of posts) {
    let md: string;
    try {
      md = await fetchText(`https://raw.githubusercontent.com/${GY_REPO}/${GY_BRANCH}${p}`);
    } catch (e) {
      process.stdout.write(`  graveyard: ${p} failed (${(e as Error).message})\n`);
      continue;
    }
    await sleep(100);
    const file = p.replace(/^\/_posts\//, "");
    const slug = file.replace(/\.(md|markdown)$/, "");
    const nameFromSlug = slug.replace(/^\d{4}-\d{1,2}-\d{1,2}-/, "");
    const { fm, body } = parseFrontMatter(md);
    const cats = [...fmList(fm.categories), ...fmList(fm.category)];
    const cause = fmStr(fm.cause) ?? fmStr(fm.root_cause) ?? fmStr(fm.attack);
    const labels = [...new Set([cause, ...cats.map((c) => c.replace(/_/g, " "))].filter((x): x is string => !!x))];
    const link = fmStr(fm.link);
    const amt = fmStr(fm.amount) ?? fmStr(fm.amount_usd) ?? fmStr(fm.loss);
    const amtNum = amt ? Number(amt.replace(/[$,\s]/g, "")) : NaN;
    out.push({
      source: "graveyard",
      sourceId: slug,
      name: (fmStr(fm.title) ?? nameFromSlug).trim(),
      date: toIsoDate(file.match(/^\d{4}-\d{1,2}-\d{1,2}/)?.[0]) ?? toIsoDate(fmStr(fm.date)) ?? undefined,
      amountUsd: Number.isFinite(amtNum) && amtNum >= 0 ? amtNum : null,
      chains: [],
      label: labels.join("; ") || null,
      rootCause: cleanText(body, true),
      txHashes: extractTx(body),
      url: link,
      references: uniq5([link, ...extractUrls(body)]),
    });
  }
  return { fetched: posts.length, raw: out };
}

// ---------- source: SEAL 911 activity log ----------
// The log is a reverse-chronological markdown list "- [Name category](link)" with no dates.
// Date = X/Twitter status-id timestamp (snowflake), else a date embedded in the link URL, else the
// linked page's published-date metadata. Entries with no recoverable date are dropped.
const SEAL_LABELS = [
  "incident resolution", "white hat rescue coordination", "white hat rescue", "domain hijacking",
  "dns takeover", "x account takeover", "twitter account takeover", "supply chain attack",
  "incident support", "ransom incident support", "app takedown", "vulnerability patch",
];
function snowflakeDate(url: string): string | null {
  const m = url.match(/(?:twitter\.com|x\.com)\/[^/]+\/status(?:es)?\/(\d{15,20})/i);
  if (!m) return null;
  const ms = Number(BigInt(m[1]) >> 22n) + 1288834974657;
  return toIsoDate(ms);
}
function urlDate(url: string): string | null {
  let m = url.match(/\/(20\d{2})\/(\d{1,2})\/(\d{1,2})(?:\/|$)/);
  if (m) return valid(`${m[1]}-${m[2].padStart(2, "0")}-${m[3].padStart(2, "0")}`);
  m = url.match(/(20\d{2})-(\d{2})-(\d{2})/);
  if (m) return valid(`${m[1]}-${m[2]}-${m[3]}`);
  m = url.match(/(\d{2})-(\d{2})-(20\d{2})/);
  if (m) return valid(`${m[3]}-${m[2]}-${m[1]}`);
  return null;
}
function htmlPublishedDate(html: string): string | null {
  const pats = [
    /property=["']article:published_time["'][^>]*content=["']([^"']+)/i,
    /content=["']([^"']+)["'][^>]*property=["']article:published_time/i,
    /"datePublished"\s*:\s*"([^"]+)"/i,
    /name=["'](?:date|publish-date|pubdate|dc\.date)["'][^>]*content=["']([^"']+)/i,
    /<time[^>]*datetime=["']([^"']+)/i,
  ];
  for (const p of pats) {
    const m = html.match(p);
    const d = m ? toIsoDate(m[1]) : null;
    if (d) return d;
  }
  return null;
}

async function seal911(): Promise<SourceResult> {
  const md = await fetchText("https://raw.githubusercontent.com/security-alliance/seal-911/main/ACTIVITY.md");
  const lines = md.split("\n").map((l) => l.match(/^\s*[-*]\s+(.+?)\s*$/)?.[1]).filter((l): l is string => !!l);
  const out: Partial<Rec>[] = [];
  let pageLookups = 0;
  for (const line of lines) {
    const lm = line.match(/^\[(.+)\]\((\S+?)\)\s*(.*)$/);
    const text = cleanText(stripMarkdown(lm ? lm[1] : line)) ?? "";
    const link = lm ? lm[2] : null;
    const extra = lm ? cleanText(lm[3], true) : null;
    let name = text;
    let label: string | null = null;
    for (const l of [...SEAL_LABELS].sort((a, b) => b.length - a.length)) {
      if (text.toLowerCase().endsWith(" " + l)) {
        name = text.slice(0, text.length - l.length).trim();
        label = l;
        break;
      }
    }
    let date: string | null = null;
    if (link) date = snowflakeDate(link) ?? urlDate(link);
    if (link && !date && !/(?:x|twitter)\.com|drive\.google\.com/.test(link)) {
      pageLookups++;
      try {
        date = htmlPublishedDate(await fetchText(link, {}, 1));
      } catch {
        /* unreachable page: leave undated */
      }
      await sleep(300);
    }
    out.push({
      source: "seal911",
      sourceId: shortHash(line),
      name,
      date: date ?? undefined,
      amountUsd: null,
      chains: [],
      label: label ?? text, // fall back to the full log line (e.g. "Geth out-of-order EIP application denial-of-service")
      rootCause: extra,
      txHashes: extractTx(line),
      url: link,
      references: uniq5([link, ...extractUrls(lm?.[3])]),
    });
  }
  process.stdout.write(`  seal911: ${lines.length} log lines, ${pageLookups} linked pages fetched for dates\n`);
  return { fetched: lines.length, raw: out };
}

// ---------- source: Web3 is Going Just Great ----------
// The site's Next.js frontend reads a public Firestore collection "entries" (project web3-334501,
// public web API key embedded in the site's JS). We list it through the Firestore REST API.
// Filter: filters.theme contains "hack" and NOT a rug-pull theme.
const W3_PROJECT = "web3-334501";
const W3_KEY = "AIzaSyDLAj91oJ3U_24VU2RW9511RKqYuf-sviQ";
const W3_KEEP_THEMES = new Set(["hack"]);
const W3_EXCLUDE_THEMES = new Set(["rugPull", "rug-pull", "artTheft"]);
const W3_CHAINS: Record<string, string> = {
  ethereum: "Ethereum", bitcoin: "Bitcoin", bsc: "BSC", solana: "Solana", polygon: "Polygon",
  avalanche: "Avalanche", fantom: "Fantom", arbitrum: "Arbitrum", optimism: "Optimism", tron: "Tron",
  cardano: "Cardano", near: "NEAR", cosmos: "Cosmos", terra: "Terra", base: "Base", harmony: "Harmony",
  algorand: "Algorand", tezos: "Tezos", ronin: "Ronin", sui: "Sui", aptos: "Aptos", blast: "Blast",
  ripple: "XRP", xrp: "XRP", cronos: "Cronos", moonriver: "Moonriver", moonbeam: "Moonbeam",
  heco: "HECO", gnosis: "Gnosis", zksync: "zkSync", linea: "Linea", hyperliquid: "Hyperliquid",
};

type FsValue = {
  stringValue?: string; integerValue?: string; doubleValue?: number; booleanValue?: boolean;
  nullValue?: null; timestampValue?: string;
  arrayValue?: { values?: FsValue[] }; mapValue?: { fields?: Record<string, FsValue> };
};
const FsValueSchema: z.ZodType<FsValue> = z.lazy(() =>
  z.object({
    stringValue: z.string().optional(),
    integerValue: z.string().optional(),
    doubleValue: z.number().optional(),
    booleanValue: z.boolean().optional(),
    nullValue: z.null().optional(),
    timestampValue: z.string().optional(),
    arrayValue: z.object({ values: z.array(FsValueSchema).optional() }).optional(),
    mapValue: z.object({ fields: z.record(z.string(), FsValueSchema).optional() }).optional(),
  }).passthrough(),
);
const FsPage = z.object({
  documents: z.array(z.object({ name: z.string(), fields: z.record(z.string(), FsValueSchema) })).optional(),
  nextPageToken: z.string().optional(),
});
function fsPlain(v: FsValue | undefined): unknown {
  if (!v) return undefined;
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.integerValue !== undefined) return Number(v.integerValue);
  if (v.doubleValue !== undefined) return v.doubleValue;
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.timestampValue !== undefined) return v.timestampValue;
  if (v.arrayValue) return (v.arrayValue.values ?? []).map(fsPlain);
  if (v.mapValue) return Object.fromEntries(Object.entries(v.mapValue.fields ?? {}).map(([k, x]) => [k, fsPlain(x)]));
  return null;
}
const W3Entry = z.object({
  id: z.string().optional(),
  date: z.string(),
  title: z.string(),
  shortTitle: z.string().nullish(),
  readableId: z.string().nullish(),
  body: z.string().nullish(),
  filters: z.object({
    theme: z.array(z.string()).nullish(),
    tech: z.array(z.string()).nullish(),
    blockchain: z.array(z.string()).nullish(),
  }).passthrough().nullish(),
  scamAmountDetails: z.object({
    total: z.number().nullish(),
    preRecoveryAmount: z.number().nullish(),
    hasScamAmount: z.boolean().nullish(),
  }).passthrough().nullish(),
  links: z.array(z.object({ href: z.string().nullish() }).passthrough()).nullish(),
}).passthrough();

async function web3isgoinggreat(): Promise<SourceResult> {
  const base = `https://firestore.googleapis.com/v1/projects/${W3_PROJECT}/databases/(default)/documents/entries?pageSize=300&key=${W3_KEY}`;
  const docs: { name: string; fields: Record<string, FsValue> }[] = [];
  let token = "";
  do {
    const page = FsPage.parse(await fetchJson(base + (token ? `&pageToken=${encodeURIComponent(token)}` : "")));
    docs.push(...(page.documents ?? []));
    token = page.nextPageToken ?? "";
    await sleep(200);
  } while (token);
  const out: Partial<Rec>[] = [];
  const themeCounts: Record<string, number> = {};
  let kept = 0;
  for (const d of docs) {
    const plain = Object.fromEntries(Object.entries(d.fields).map(([k, v]) => [k, fsPlain(v)]));
    const p = W3Entry.safeParse(plain);
    if (!p.success) {
      out.push({ source: "web3isgoinggreat", sourceId: d.name.split("/").pop() }); // counted as dropped
      continue;
    }
    const e = p.data;
    const themes = e.filters?.theme ?? [];
    for (const t of themes) themeCounts[t] = (themeCounts[t] ?? 0) + 1;
    if (!themes.some((t) => W3_KEEP_THEMES.has(t)) || themes.some((t) => W3_EXCLUDE_THEMES.has(t))) continue;
    kept++;
    const sa = e.scamAmountDetails;
    const amt = sa?.hasScamAmount ? (sa.preRecoveryAmount || sa.total || null) : null;
    const id = e.id ?? d.name.split("/").pop()!;
    out.push({
      source: "web3isgoinggreat",
      sourceId: id,
      name: cleanText(e.title) ?? e.title,
      date: toIsoDate(e.date) ?? undefined,
      amountUsd: amt != null && amt > 0 ? amt : null,
      chains: [...new Set((e.filters?.blockchain ?? []).map((c) => W3_CHAINS[c] ?? c))],
      label: themes.join("; ") || null,
      rootCause: cleanText(e.body),
      txHashes: extractTx(e.body),
      url: `https://www.web3isgoinggreat.com/?id=${e.readableId ?? id}`,
      references: uniq5((e.links ?? []).map((l) => l.href)),
    });
  }
  process.stdout.write(
    `  web3isgoinggreat: ${docs.length} entries total, kept ${kept} with theme "hack" (excluding rugPull/artTheft); themes: ${JSON.stringify(themeCounts)}\n`,
  );
  return { fetched: docs.length, raw: out };
}

// ---------- source: OSV advisories for blockchain clients/frameworks ----------
type Pkg = { project: string; ecosystem: string; names: string[] };
const goMajors = (base: string, max: number) => [base, ...Array.from({ length: max - 1 }, (_, i) => `${base}/v${i + 2}`)];
const OSV_PACKAGES: Pkg[] = [
  { project: "go-ethereum", ecosystem: "Go", names: ["github.com/ethereum/go-ethereum"] },
  { project: "cosmos-sdk", ecosystem: "Go", names: goMajors("github.com/cosmos/cosmos-sdk", 2) },
  { project: "cometbft", ecosystem: "Go", names: goMajors("github.com/cometbft/cometbft", 2) },
  { project: "tendermint", ecosystem: "Go", names: goMajors("github.com/tendermint/tendermint", 2) },
  { project: "ibc-go", ecosystem: "Go", names: goMajors("github.com/cosmos/ibc-go", 10) },
  { project: "prysm", ecosystem: "Go", names: goMajors("github.com/prysmaticlabs/prysm", 7) },
  { project: "erigon", ecosystem: "Go", names: ["github.com/ledgerwatch/erigon", "github.com/erigontech/erigon", "github.com/erigontech/erigon/v3"] },
  { project: "lnd", ecosystem: "Go", names: ["github.com/lightningnetwork/lnd"] },
  { project: "btcd", ecosystem: "Go", names: ["github.com/btcsuite/btcd", "github.com/btcsuite/btcd/btcec/v2", "github.com/btcsuite/btcutil"] },
  { project: "evmos", ecosystem: "Go", names: goMajors("github.com/evmos/evmos", 20) },
  { project: "optimism", ecosystem: "Go", names: ["github.com/ethereum-optimism/optimism", "github.com/ethereum-optimism/op-geth"] },
  { project: "celestia-app", ecosystem: "Go", names: goMajors("github.com/celestiaorg/celestia-app", 6) },
  { project: "solana", ecosystem: "crates.io", names: ["solana-program", "solana-sdk", "solana-core", "solana-runtime", "solana-zk-token-sdk", "agave-validator"] },
  { project: "sui", ecosystem: "crates.io", names: ["sui-types", "sui-sdk", "move-binary-format", "move-bytecode-verifier"] },
  { project: "aptos", ecosystem: "crates.io", names: ["aptos-sdk", "aptos-types", "aptos-crypto"] },
  { project: "reth", ecosystem: "crates.io", names: ["reth", "reth-primitives", "revm", "alloy-primitives"] },
  { project: "lighthouse", ecosystem: "crates.io", names: ["lighthouse_network", "lighthouse"] },
  { project: "near", ecosystem: "crates.io", names: ["near-vm-runner", "near-primitives", "near-sdk"] },
  { project: "substrate", ecosystem: "crates.io", names: ["sp-core", "sp-runtime", "frame-support", "pallet-balances", "sc-network", "sp-io"] },
  { project: "polkadot", ecosystem: "crates.io", names: ["polkadot", "polkadot-sdk", "polkadot-runtime"] },
  { project: "solang", ecosystem: "crates.io", names: ["solang"] },
  { project: "besu", ecosystem: "Maven", names: ["org.hyperledger.besu:besu", "org.hyperledger.besu:besu-datatypes", "org.hyperledger.besu:evm", "org.hyperledger.besu.internal:core"] },
  { project: "web3.js", ecosystem: "npm", names: ["web3", "web3-utils", "web3-eth-accounts"] },
  { project: "ethers", ecosystem: "npm", names: ["ethers"] },
  { project: "openzeppelin-contracts", ecosystem: "npm", names: ["@openzeppelin/contracts"] },
  { project: "openzeppelin-contracts-upgradeable", ecosystem: "npm", names: ["@openzeppelin/contracts-upgradeable"] },
  { project: "solc-js", ecosystem: "npm", names: ["solc"] },
  { project: "vyper", ecosystem: "PyPI", names: ["vyper"] },
];

const OsvVuln = z.object({
  id: z.string(),
  aliases: z.array(z.string()).nullish(),
  summary: z.string().nullish(),
  details: z.string().nullish(),
  published: z.string().nullish(),
  withdrawn: z.string().nullish(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).nullish(),
  database_specific: z.object({ severity: z.string().nullish() }).passthrough().nullish(),
  affected: z.array(z.object({
    ecosystem_specific: z.object({ severity: z.string().nullish() }).passthrough().nullish(),
    database_specific: z.object({ severity: z.string().nullish() }).passthrough().nullish(),
  }).passthrough()).nullish(),
}).passthrough();
type OsvVulnT = z.infer<typeof OsvVuln>;
const OsvQueryResp = z.object({ vulns: z.array(OsvVuln).optional(), next_page_token: z.string().optional() });

async function osvQuery(name: string, ecosystem: string): Promise<OsvVulnT[]> {
  const all: OsvVulnT[] = [];
  let token: string | undefined;
  do {
    const body: Record<string, unknown> = { package: { name, ecosystem } };
    if (token) body.page_token = token;
    const r = OsvQueryResp.parse(await fetchJson("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }));
    all.push(...(r.vulns ?? []));
    token = r.next_page_token;
    await sleep(150);
  } while (token);
  return all;
}
const QUAL = /^(LOW|MODERATE|MEDIUM|HIGH|CRITICAL)$/i;
function osvSeverity(v: OsvVulnT): string | null {
  const q = [v.database_specific?.severity, ...(v.affected ?? []).flatMap((a) => [a.database_specific?.severity, a.ecosystem_specific?.severity])]
    .find((s) => s && QUAL.test(s.trim()));
  if (q) return q.trim().toUpperCase() === "MEDIUM" ? "MODERATE" : q.trim().toUpperCase();
  const s = v.severity?.find((x) => /CVSS/.test(x.type)) ?? v.severity?.[0];
  return s ? s.score : null;
}

async function osv(): Promise<{ fetched: number; raw: Partial<Advisory>[] }> {
  const byId = new Map<string, { v: OsvVulnT; projects: Set<string>; ecosystems: Set<string> }>();
  let fetched = 0;
  const counts: string[] = [];
  for (const pkg of OSV_PACKAGES) {
    for (const name of pkg.names) {
      let vulns: OsvVulnT[];
      try {
        vulns = await osvQuery(name, pkg.ecosystem);
      } catch (e) {
        counts.push(`${pkg.ecosystem}:${name}=ERR(${(e as Error).message.slice(0, 60)})`);
        continue;
      }
      if (!vulns.length) continue;
      counts.push(`${pkg.ecosystem}:${name}=${vulns.length}`);
      fetched += vulns.length;
      for (const v of vulns) {
        const cur = byId.get(v.id);
        if (cur) {
          cur.projects.add(pkg.project);
          cur.ecosystems.add(pkg.ecosystem);
        } else byId.set(v.id, { v, projects: new Set([pkg.project]), ecosystems: new Set([pkg.ecosystem]) });
      }
    }
  }
  process.stdout.write(`  osv: packages with results: ${counts.join(", ")}\n`);
  // Backfill full records for any entry the query returned without text.
  for (const [id, e] of byId) {
    if (e.v.summary || e.v.details) continue;
    try {
      e.v = OsvVuln.parse(await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`));
    } catch {
      /* keep partial */
    }
    await sleep(150);
  }
  const out: Partial<Advisory>[] = [];
  let withdrawn = 0;
  for (const [id, { v, projects, ecosystems }] of byId) {
    if (v.withdrawn) {
      withdrawn++;
      continue;
    }
    const details = cleanText(v.details, true, OSV_SUMMARY_MAX);
    const title = cleanText(v.summary, true, 300) ?? details?.split("\n")[0].slice(0, 200) ?? id;
    out.push({
      project: [...projects].sort().join(", "),
      ecosystem: [...ecosystems].sort().join(", "),
      id,
      aliases: v.aliases ?? [],
      title,
      summary: details,
      published: toIsoDate(v.published) ?? null,
      severity: osvSeverity(v),
      url: id.startsWith("GHSA-") ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${id}`,
    });
  }
  if (withdrawn) process.stdout.write(`  osv: skipped ${withdrawn} withdrawn advisories\n`);
  return { fetched, raw: out };
}

// ---------- driver ----------
type Src =
  | { kind: "incident"; file: string; run: () => Promise<SourceResult> }
  | { kind: "advisory"; file: string; run: () => Promise<{ fetched: number; raw: Partial<Advisory>[] }> };
const SOURCES: Record<string, Src> = {
  graveyard: { kind: "incident", file: "graveyard.json", run: graveyard },
  seal911: { kind: "incident", file: "seal911.json", run: seal911 },
  web3isgoinggreat: { kind: "incident", file: "web3isgoinggreat.json", run: web3isgoinggreat },
  osv: { kind: "advisory", file: "osv_advisories.json", run: osv },
};

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
      let written: number, dropped: number, dates: string[], withText: number, fetched: number;
      if (src.kind === "incident") {
        const res = await src.run();
        fetched = res.fetched;
        const good: Rec[] = [];
        dropped = 0;
        for (const r of res.raw) {
          const p = RecordSchema.safeParse(r);
          if (p.success) good.push(p.data);
          else dropped++;
        }
        good.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.name.localeCompare(b.name)));
        if (!good.length) throw new Error(`no valid records (fetched ${fetched})`);
        writeFileSync(new URL(src.file, OUT_DIR), JSON.stringify(good, null, 1) + "\n");
        written = good.length;
        dates = good.map((g) => g.date).sort();
        withText = good.filter((g) => g.rootCause).length;
      } else {
        const res = await src.run();
        fetched = res.fetched;
        const good: Advisory[] = [];
        dropped = 0;
        for (const r of res.raw) {
          const p = AdvisorySchema.safeParse(r);
          if (p.success) good.push(p.data);
          else dropped++;
        }
        good.sort((a, b) => ((a.published ?? "") < (b.published ?? "") ? 1 : (a.published ?? "") > (b.published ?? "") ? -1 : a.id.localeCompare(b.id)));
        if (!good.length) throw new Error(`no valid records (fetched ${fetched})`);
        writeFileSync(new URL(src.file, OUT_DIR), JSON.stringify(good, null, 1) + "\n");
        written = good.length;
        dates = good.map((g) => g.published).filter((d): d is string => !!d).sort();
        withText = good.filter((g) => g.summary).length;
      }
      summary.push({
        source: name,
        fetched,
        written,
        dropped,
        from: dates[0],
        to: dates[dates.length - 1],
        withText,
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

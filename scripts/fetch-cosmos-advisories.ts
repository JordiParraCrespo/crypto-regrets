/**
 * Collect published security advisories for the Cosmos ecosystem stack and the
 * security-relevant patch releases of its core repos.
 *
 *   npx tsx scripts/fetch-cosmos-advisories.ts
 *
 * Writes:
 *   data/raw/cosmos_advisories.json         one object per advisory (deduped by GHSA/CVE/ASA/CWA/GO ids)
 *   data/raw/cosmos_security_releases.json  releases (2023-01+) whose notes mention security keywords
 *
 * Sources, in order of preference when merging fields:
 *   1. OSV (api.osv.dev) — Go + crates.io packages of the stack, all module major versions.
 *   2. GitHub repository security advisories API (often 403 from sandboxes) — falls back to
 *      SEED_GITHUB_ONLY below, advisories that are on github.com but missing from OSV
 *      (transcribed from the github.com advisory pages on 2026-10-19).
 *   3. cosmos/security ADVISORIES.md (ASA list) and CosmWasm/advisories CWAs/*.md.
 *   4. Releases: GitHub releases API when reachable, else tags (git, treeless clone) +
 *      CHANGELOG.md sections from release branches (raw.githubusercontent.com).
 *
 * git is used through child_process (clones go to $TMPDIR/cosmos-advisories-cache).
 */
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

const OUT_DIR = new URL("../data/raw/", import.meta.url);
const CACHE = join(tmpdir(), "cosmos-advisories-cache");
const UA = "Mozilla/5.0 (compatible; crypto-regrets-fetch/1.0)";
const SUMMARY_MAX = 600;
const RELEASES_SINCE = "2023-01-01";
const failures: string[] = [];

// ---------------------------------------------------------------- schemas
const PROJECTS = [
  "cosmos-sdk", "cometbft", "ibc-go", "cosmos-evm", "evmos", "wasmd", "wasmvm", "cosmwasm",
  "osmosis", "gaia", "interchain-security", "neutron", "sei", "injective", "dydx", "celestia",
  "iavl", "ics23", "other",
] as const;
const IMPACTS = ["chain-halt", "consensus-failure", "fund-loss", "inflation", "dos", "privilege-escalation", "other"] as const;
const SEVERITIES = ["LOW", "MODERATE", "HIGH", "CRITICAL"] as const;

const AdvisorySchema = z.object({
  id: z.string().min(1),
  aliases: z.array(z.string()),
  project: z.enum(PROJECTS),
  title: z.string().min(1),
  summary: z.string().max(SUMMARY_MAX),
  published: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  severity: z.enum(SEVERITIES).nullable(),
  cvss: z.number().min(0).max(10).nullable(),
  affected: z.string(),
  component: z.string().min(1),
  impact: z.enum(IMPACTS),
  url: z.string().url(),
  sources: z.array(z.string()),
});
type Advisory = z.infer<typeof AdvisorySchema>;

const ReleaseSchema = z.object({
  repo: z.string(),
  tag: z.string(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  title: z.string(),
  mentions: z.array(z.string()).min(1),
  source: z.enum(["github-api", "changelog", "tag-message"]),
});
type Release = z.infer<typeof ReleaseSchema>;

// ---------------------------------------------------------------- helpers
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchRaw(url: string, init: RequestInit = {}, tries = 3): Promise<Response> {
  let last: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, {
        ...init,
        headers: { "user-agent": UA, ...(init.headers ?? {}) },
        signal: AbortSignal.timeout(60_000),
      });
      if (res.status >= 500) throw new Error(`HTTP ${res.status} for ${url}`);
      return res;
    } catch (e) {
      last = e;
      await sleep(800 * (i + 1));
    }
  }
  throw last instanceof Error ? last : new Error(String(last));
}
async function fetchText(url: string, init: RequestInit = {}): Promise<string | null> {
  const res = await fetchRaw(url, init);
  return res.ok ? await res.text() : null;
}
async function fetchJson<T = any>(url: string, init: RequestInit = {}): Promise<T | null> {
  const t = await fetchText(url, init);
  return t == null ? null : (JSON.parse(t) as T);
}
async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const k = i++;
        out[k] = await fn(items[k]);
      }
    }),
  );
  return out;
}
const day = (s: string | null | undefined): string | null => (s && /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : null);
const clip = (s: string, n = SUMMARY_MAX) => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length <= n ? t : t.slice(0, n - 1).trimEnd() + "…";
};
const stripMd = (s: string) =>
  s
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[*_`>#|]+/g, " ")
    .replace(/\\([\[\]#_*])/g, "$1");
function git(args: string[], cwd?: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"], timeout: 600_000 });
}
const SEV_MAP: Record<string, (typeof SEVERITIES)[number]> = {
  low: "LOW", moderate: "MODERATE", medium: "MODERATE", high: "HIGH", critical: "CRITICAL",
};
const normSev = (s: unknown) => (typeof s === "string" ? SEV_MAP[s.trim().toLowerCase()] ?? null : null);

// Advisory-id extraction / normalization (ASA-2024-0012 -> ASA-2024-012).
const ADV_ID_RE = /\b(ASA|ISA|CSA|CWA|ICS|LSM)-(\d{4})-(\d{3,4})\b/g;
function normAdvId(p: string, y: string, n: string) {
  return `${p}-${y}-${String(parseInt(n, 10)).padStart(3, "0")}`;
}
function extractAdvIds(s: string): string[] {
  return [...s.matchAll(ADV_ID_RE)].map((m) => normAdvId(m[1], m[2], m[3]));
}

// CVSS v3.x base score from vector.
function cvss3(vector: string): number | null {
  const m = Object.fromEntries(vector.split("/").slice(1).map((kv) => kv.split(":")));
  const W: Record<string, Record<string, number>> = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 }, I: { H: 0.56, L: 0.22, N: 0 }, A: { H: 0.56, L: 0.22, N: 0 },
  };
  const changed = m.S === "C";
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR as "N" | "L" | "H"];
  const vals = [W.AV[m.AV], W.AC[m.AC], PR, W.UI[m.UI], W.C[m.C], W.I[m.I], W.A[m.A]];
  if (vals.some((v) => v === undefined)) return null;
  const [av, ac, pr, ui, c, i, a] = vals as number[];
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const roundup = (x: number) => Math.ceil(Math.round(x * 100000) / 10000) / 10;
  return roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// ---------------------------------------------------------------- package list
const range = (a: number, b: number) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const majors = (base: string, from: number, to: number, includeBase = true) => [
  ...(includeBase ? [base] : []),
  ...range(from, to).map((v) => `${base}/v${v}`),
];
const SDK_X = ["auth", "authz", "bank", "circuit", "distribution", "epochs", "evidence", "feegrant", "gov", "group", "mint", "nft", "protocolpool", "slashing", "staking", "upgrade", "accounts", "consensus", "params", "tx"];
const GO_PACKAGES: string[] = [
  "github.com/cosmos/cosmos-sdk", "github.com/cosmos/cosmos-sdk/cosmovisor",
  "cosmossdk.io/math", "cosmossdk.io/store", "cosmossdk.io/core", "cosmossdk.io/api", "cosmossdk.io/log",
  "cosmossdk.io/client/v2", "cosmossdk.io/tools/cosmovisor", "cosmossdk.io/collections", "cosmossdk.io/depinject",
  ...SDK_X.map((x) => `cosmossdk.io/x/${x}`),
  ...majors("github.com/cometbft/cometbft", 2, 2), "github.com/tendermint/tendermint",
  ...majors("github.com/cosmos/ibc-go", 1, 11),
  "github.com/cosmos/ibc-go/modules/capability", "github.com/cosmos/ibc-go/modules/apps/callbacks",
  ...majors("github.com/cosmos/ibc-go/modules/light-clients/08-wasm", 10, 10),
  ...majors("github.com/cosmos/ibc-apps/middleware/packet-forward-middleware", 4, 10, false),
  ...majors("github.com/cosmos/ibc-apps/modules/ibc-hooks", 4, 10, false),
  ...majors("github.com/cosmos/ibc-apps/modules/async-icq", 4, 10, false),
  ...majors("github.com/cosmos/ibc-apps/modules/rate-limiting", 4, 10, false),
  ...majors("github.com/strangelove-ventures/packet-forward-middleware", 1, 8),
  ...majors("github.com/cosmos/interchain-security", 2, 7),
  ...majors("github.com/cosmos/gaia", 2, 27),
  "github.com/cosmos/evm", "github.com/evmos/ethermint", ...majors("github.com/evmos/evmos", 1, 20),
  "github.com/CosmWasm/wasmd", ...majors("github.com/CosmWasm/wasmvm", 2, 3),
  ...majors("github.com/osmosis-labs/osmosis", 2, 31),
  "github.com/osmosis-labs/osmosis/osmomath", "github.com/osmosis-labs/osmosis/osmoutils",
  ...majors("github.com/neutron-org/neutron", 2, 9),
  "github.com/sei-protocol/sei-chain", "github.com/sei-protocol/sei-cosmos", "github.com/sei-protocol/sei-tendermint",
  "github.com/InjectiveLabs/injective-core", "github.com/InjectiveLabs/sdk-go",
  "github.com/dydxprotocol/v4-chain/protocol", "github.com/dydxprotocol/v4-chain",
  ...majors("github.com/celestiaorg/celestia-app", 2, 7), "github.com/celestiaorg/celestia-core", "github.com/celestiaorg/celestia-node",
  "github.com/cosmos/iavl", "github.com/cosmos/ics23/go", "github.com/confio/ics23/go",
  "github.com/cosmos/gogoproto", "github.com/cosmos/cosmos-proto", "github.com/cosmos/ledger-cosmos-go", "github.com/cosmos/relayer/v2",
];
const CRATES = [
  "cosmwasm-std", "cosmwasm-vm", "cosmwasm-crypto", "cosmwasm-schema", "cosmwasm-storage", "cw-multi-test",
  "cw20-base", "cw20-ics20", "cw1-whitelist", "cw1-subkeys", "cw3-fixed-multisig", "cw3-flex-multisig",
  "cw4-group", "cw4-stake", "cw-utils", "cw2", "cw20", "cw-storage-plus", "serde-json-wasm",
];

function projectOf(name: string): Advisory["project"] {
  const n = name.toLowerCase();
  if (/cosmos\/evm\b|cosmos-evm/.test(n)) return "cosmos-evm";
  if (/evmos|ethermint/.test(n)) return "evmos";
  if (/cosmwasm\/wasmd|\bwasmd\b|x\/wasm/.test(n)) return "wasmd";
  if (/wasmvm/.test(n)) return "wasmvm";
  if (/cosmwasm|^cw|serde-json-wasm/.test(n)) return "cosmwasm";
  if (/ibc-go|ibc-apps|packet-forward|ibc-hooks|ibc go/.test(n)) return "ibc-go";
  if (/cometbft|tendermint/.test(n)) return n.includes("celestia") ? "celestia" : n.includes("sei") ? "sei" : "cometbft";
  if (/interchain-security|\bics-20\d\d/.test(n)) return "interchain-security";
  if (/cosmos\/gaia|\bgaia\b|\blsm-/.test(n)) return "gaia";
  if (/osmosis/.test(n)) return "osmosis";
  if (/neutron/.test(n)) return "neutron";
  if (/sei-/.test(n)) return "sei";
  if (/injective/.test(n)) return "injective";
  if (/dydx/.test(n)) return "dydx";
  if (/celestia/.test(n)) return "celestia";
  if (/iavl/.test(n)) return "iavl";
  if (/ics23/.test(n)) return "ics23";
  if (/cosmos-sdk|cosmossdk\.io|cosmos sdk|cosmovisor/.test(n)) return "cosmos-sdk";
  return "other";
}

// ---------------------------------------------------------------- classification
function componentOf(project: string, text: string, pkgs: string[]): string {
  const t = text.toLowerCase();
  const p = pkgs.join(" ").toLowerCase();
  const rules: [RegExp, string][] = [
    [/statedb|state ?db/, project === "cosmos-evm" || project === "evmos" ? "x/vm" : ""],
    [/precompile/, "precompile"],
    [/x\/erc20|erc-?20 (module|conversion|token pair)|token pair/, "x/erc20"],
    [/ibc-hooks|ibc hooks|wasm hooks/, "ibc-hooks"],
    [/packet[- ]forward|\bpfm\b/, "pfm"],
    [/statedb|x\/(vm|evm)\b|evm state|ethereum transaction|eth_|json-rpc|\bevm\b/, project === "cosmos-evm" || project === "evmos" ? "x/vm" : ""],
    [/vote ?extension|prepareproposal|processproposal|voteextensionsenableheight/, "abci/vote-extensions"],
    [/block parts?\b|bitarray|peerstate/, "p2p"],
    [/cosmossdk\.io\/math|sdk\.int\b|sdk\.dec\b|legacydec|bit-length/, "math"],
    [/mempool/, "mempool"],
    [/blocksync|block ?sync|fast ?sync/, "blocksync"],
    [/state ?sync|statesync|snapshot/, "statesync"],
    [/light ?client|07-tendermint|08-wasm|misbehaviou?r|client update|ibc-core-client/, "ibc-core-client"],
    [/ics-?20|\btransfer (module|app)|ibc transfer|denom trace|fungible token transfer/, "ics20-transfer"],
    [/\bics-?27|interchain account|\bica\b/, "ibc-ica"],
    [/\bibc\b[\s\S]*(acknowledg|channel|packet|callback)|(acknowledg|channel|packet|callback)[\s\S]*\bibc\b|04-channel|03-connection/, "ibc-core"],
    [/cosmossdk\.io\/math|sdk\.int|sdk\.dec|legacydec|\bmath\b|bit-length/, "math"],
    [/wasmer|singlepass|cranelift|wasm (vm|runtime)|cosmwasm-vm/, "wasm-vm"],
    [/\biavl\b|ics23|merkle proof|kvstore|cachekv|multistore|cosmossdk\.io\/store/, "store"],
    [/cosmovisor/, "cosmovisor"],
    [/x\/group|group module|groups module/, "x/group"],
    [/x\/gov|governance|gov module/, "x/gov"],
    [/x\/authz|authz/, "x/authz"],
    [/vesting/, "x/vesting"],
    [/x\/distribution|distribution module|rewards pool|validator rewards|withdraw.*reward/, "x/distribution"],
    [/slashing|slash|evidence|equivocation|double.?sign/, "x/slashing-evidence"],
    [/x\/staking|staking|delegat|validator set/, "x/staking"],
    [/x\/bank|bank module|blockedaddr|send coins|sendcoins/, "x/bank"],
    [/feegrant/, "x/feegrant"],
    [/x\/upgrade|upgrade module/, "x/upgrade"],
    [/ante ?handler|\bante\b|fee deduct|signature verification|sigverify/, "ante"],
    [/baseapp|tx decod|transaction decod|unpackany|unknown fields|protobuf/, "baseapp"],
    [/p2p|\bpeer|gossip|block parts?|bitarray|\bpex\b|mconnection|secret connection/, "p2p"],
    [/rpc|websocket|grpc|rest api|\bapi\b/, "rpc"],
    [/consensus|commit signature|precommit|prevote|proposer|blockparams|block time/, "consensus"],
    [/wasmer|singlepass|cranelift|metering|gas mispricing|locals|wasm (vm|runtime)|cosmwasm-vm|cosmwasm-crypto/, "wasm-vm"],
    [/cosmwasm-std|cw20|cw-multi-test|cw-|contract api|serde-json-wasm/, "wasm-contract-api"],
    [/x\/wasm|wasmd|smart contract|contract/, project === "wasmd" ? "x/wasm" : ""],
  ];
  for (const [re, c] of rules) if (c && re.test(t)) return c;
  // package-based fallback
  if (/cosmossdk\.io\/math/.test(p)) return "math";
  if (/cosmossdk\.io\/store|iavl|ics23/.test(p)) return "store";
  const x = p.match(/cosmossdk\.io\/(x\/[a-z]+)/);
  if (x) return x[1];
  if (/packet-forward/.test(p)) return "pfm";
  if (/ibc-hooks/.test(p)) return "ibc-hooks";
  if (/08-wasm/.test(p)) return "ibc-core-client";
  if (project === "wasmvm") return "wasm-vm";
  if (project === "wasmd") return "x/wasm";
  if (project === "cosmwasm") return /vm|crypto/.test(p) ? "wasm-vm" : "wasm-contract-api";
  if (project === "cosmos-evm" || project === "evmos") return "x/vm";
  return "other";
}
function impactOf(text: string): Advisory["impact"] {
  const t = text.toLowerCase();
  if (/sandbox escape|remote code execution|\brce\b|arbitrary code execution/.test(t)) return "privilege-escalation";
  if (/steal|theft|stolen|loss of funds|fund loss|funds? (at risk|loss)|drain|double[- ]spend|credit without|extract (legitimate )?tokens|lose funds|loss of (user )?funds|financial loss|without (a corresponding|burning|escrow)/.test(t)) return "fund-loss";
  if (/inflation|infinite mint|mint (arbitrary|unlimited)|unbacked|supply (overflow|inflation)|arbitrary amount of tokens|counterfeit/.test(t)) return "inflation";
  if (/halt|stall the (chain|network)|network halt|chain to stop|liveness/.test(t)) return "chain-halt";
  if (/non-?determinis|consensus failure|chain split|app ?hash|state divergence|fork/.test(t)) return "consensus-failure";
  if (/bypass|unauthori[sz]ed|privilege|impersonat|signer|escalat|sandbox escape|remote code|\brce\b|arbitrary code/.test(t)) return "privilege-escalation";
  if (/denial of service|\bdos\b|resource exhaustion|slow down|memory|stack overflow|\boom\b|crash|panic|block production|gas limit|metering|unbounded/.test(t)) return "dos";
  return "other";
}

// ---------------------------------------------------------------- raw records
interface RawAdv {
  ids: string[]; // all identifiers (primary first)
  src: string;
  rank: number; // lower = more authoritative
  project?: Advisory["project"];
  title?: string;
  details?: string;
  published?: string | null;
  severity?: Advisory["severity"];
  cvss?: number | null;
  affected?: string;
  pkgs?: string[];
  url?: string;
  withdrawn?: boolean;
}
const raws: RawAdv[] = [];

// ---- 1. OSV
function osvAffected(v: any): { affected: string; pkgs: string[] } {
  const parts: string[] = [];
  const pkgs: string[] = [];
  for (const a of v.affected ?? []) {
    const name: string = a.package?.name ?? "?";
    pkgs.push(name);
    const segs: string[] = [];
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      let intro: string | null = null;
      for (const e of r.events ?? []) {
        if (e.introduced !== undefined) intro = e.introduced;
        if (e.fixed !== undefined || e.last_affected !== undefined) {
          const hi = e.fixed !== undefined ? `<${e.fixed}` : `<=${e.last_affected}`;
          segs.push(intro && intro !== "0" ? `>=${intro} ${hi}` : hi);
          intro = null;
        }
      }
      if (intro !== null) segs.push(intro === "0" ? "all" : `>=${intro}`);
    }
    if (!segs.length && a.versions?.length) segs.push(`${a.versions.length} listed versions`);
    parts.push(`${name.replace(/^github\.com\//, "")}: ${segs.join(", ") || "?"}`);
  }
  return { affected: [...new Set(parts)].join("; ").slice(0, 400), pkgs: [...new Set(pkgs)] };
}
function osvToRaw(v: any): RawAdv {
  const { affected, pkgs } = osvAffected(v);
  const isGhsa = v.id.startsWith("GHSA-");
  const sevVec = (v.severity ?? []).find((s: any) => s.type === "CVSS_V3")?.score as string | undefined;
  const head = `${v.summary ?? ""}\n${(v.details ?? "").slice(0, 400)}`;
  const ghsaRepo = (v.references ?? []).map((r: any) => r.url as string).find((u: string) => /github\.com\/[^/]+\/[^/]+\/security\/advisories\/GHSA-/.test(u));
  const proj = projectOf(`${pkgs[0] ?? ""} ${ghsaRepo ?? ""}`);
  return {
    ids: [v.id, ...(v.aliases ?? []), ...extractAdvIds(head)],
    src: `osv:${v.id.split("-")[0]}`,
    rank: isGhsa ? 0 : 2,
    project: proj,
    title: v.summary || v.id,
    details: v.details ?? "",
    published: day(v.published),
    severity: normSev(v.database_specific?.severity),
    cvss: sevVec ? cvss3(sevVec) : null,
    affected,
    pkgs,
    url: ghsaRepo ?? (isGhsa ? `https://github.com/advisories/${v.id}` : `https://osv.dev/vulnerability/${v.id}`),
    withdrawn: !!v.withdrawn,
  };
}
const osvCache = new Map<string, any | null>();
async function osvVuln(id: string): Promise<any | null> {
  if (osvCache.has(id)) return osvCache.get(id);
  const v = await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`).catch(() => null);
  osvCache.set(id, v);
  return v;
}
async function fetchOsv() {
  const queries = [
    ...GO_PACKAGES.map((name) => ({ package: { name, ecosystem: "Go" } })),
    ...CRATES.map((name) => ({ package: { name, ecosystem: "crates.io" } })),
  ];
  const ids = new Set<string>();
  const hits = new Map<string, number>();
  // querybatch with per-query page tokens
  let pending = queries.map((q) => ({ q, token: undefined as string | undefined }));
  while (pending.length) {
    const next: typeof pending = [];
    for (let i = 0; i < pending.length; i += 500) {
      const chunk = pending.slice(i, i + 500);
      const body = { queries: chunk.map(({ q, token }) => (token ? { ...q, page_token: token } : q)) };
      const res = await fetchJson<any>("https://api.osv.dev/v1/querybatch", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
      if (!res) { failures.push("osv querybatch failed"); continue; }
      res.results.forEach((r: any, k: number) => {
        const name = chunk[k].q.package.name;
        for (const v of r.vulns ?? []) { ids.add(v.id); hits.set(name, (hits.get(name) ?? 0) + 1); }
        if (r.next_page_token) next.push({ q: chunk[k].q, token: r.next_page_token });
      });
    }
    pending = next;
  }
  console.log(`OSV: ${ids.size} ids from ${hits.size}/${queries.length} packages with hits`);
  const vulns = await pool([...ids], 16, osvVuln);
  for (const v of vulns) if (v) raws.push(osvToRaw(v));
  return ids;
}

// ---- 2. GitHub repository advisories (API, else seed)
const GH_REPOS = [
  "cosmos/cosmos-sdk", "cometbft/cometbft", "cosmos/ibc-go", "cosmos/ibc-apps", "cosmos/evm", "evmos/evmos",
  "CosmWasm/wasmd", "CosmWasm/wasmvm", "CosmWasm/cosmwasm", "CosmWasm/cw-plus", "cosmos/gaia",
  "cosmos/interchain-security", "osmosis-labs/osmosis", "neutron-org/neutron", "sei-protocol/sei-chain",
  "InjectiveLabs/injective-core", "dydxprotocol/v4-chain", "celestiaorg/celestia-app", "cosmos/iavl", "cosmos/ics23",
  "strangelove-ventures/packet-forward-middleware",
];
/** On github.com but absent from OSV as of 2026-10-19 (transcribed from the advisory pages). */
const SEED_GITHUB_ONLY: RawAdv[] = [
  {
    ids: ["GHSA-7g4w-cg88-2cq2"], src: "github-seed", rank: 1, project: "cosmos-evm",
    title: "Balance underflow in EVM StateDB",
    details: "The EVM StateDB tracks only an account's spendable balance. When a vesting account delegates more than its spendable balance through the staking precompile, the balance write-back subtracts the full amount without a check, an unchecked underflow that wraps the account balance to ~2^256. Chained with a second overflow on a victim account in a supply-neutral transaction, attackers extracted legitimate tokens (theft of funds) from six Cosmos EVM chains in Aug 2026 (~USD 5.7M). The fix adds an underflow guard; state-breaking, requires a coordinated upgrade.",
    published: "2026-08-28", severity: "CRITICAL", cvss: null,
    affected: "cosmos/evm: <0.6.2, >=0.7.0 <0.7.2", pkgs: ["github.com/cosmos/evm"],
    url: "https://github.com/cosmos/evm/security/advisories/GHSA-7g4w-cg88-2cq2",
  },
  {
    ids: ["GHSA-367m-g444-9mg3"], src: "github-seed", rank: 1, project: "cosmos-evm",
    title: "Non-atomic StateDB commit",
    details: "StateDB.Commit persists dirty accounts one at a time in lexicographic address order without rolling back earlier writes if a later one fails; the x/erc20 IBC refund callback swallows the resulting error so partial writes persist. An attacker can create a credit without a matching debit, producing spendable native balance. Fix stages writes in a scratch cache context and publishes them only after all writes succeed.",
    published: "2026-09-03", severity: "CRITICAL", cvss: null,
    affected: "cosmos/evm: >=0.6.0 <0.6.3, >=0.7.0 <0.7.3", pkgs: ["github.com/cosmos/evm"],
    url: "https://github.com/cosmos/evm/security/advisories/GHSA-367m-g444-9mg3",
  },
  {
    ids: ["GHSA-r47q-464x-wx5x", "LSM-2024-001"], src: "github-seed", rank: 1, project: "gaia",
    title: "LSM-2024-001: LSM tokenization allows for potential slashing evasion when tokenizing redelegating shares",
    details: "Liquid staking module tokenization of shares that are being redelegated allows potential slashing evasion.",
    published: "2024-06-05", severity: "MODERATE", cvss: null,
    affected: "cosmos/gaia (LSM fork of x/staking)", pkgs: ["github.com/cosmos/gaia"],
    url: "https://github.com/cosmos/gaia/security/advisories/GHSA-r47q-464x-wx5x",
  },
];
async function fetchGithubAdvisories() {
  let ok = 0;
  for (const repo of GH_REPOS) {
    const res = await fetchRaw(`https://api.github.com/repos/${repo}/security-advisories?per_page=100&state=published`, {
      headers: { accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) },
    }).catch(() => null);
    if (!res?.ok) continue;
    ok++;
    for (const a of (await res.json()) as any[]) {
      const pkgs = (a.vulnerabilities ?? []).map((x: any) => x.package?.name).filter(Boolean);
      raws.push({
        ids: [a.ghsa_id, ...(a.cve_id ? [a.cve_id] : []), ...extractAdvIds(`${a.summary} ${(a.description ?? "").slice(0, 400)}`)],
        src: "github-api", rank: 1, project: projectOf(repo), title: a.summary, details: a.description ?? "",
        published: day(a.published_at), severity: normSev(a.severity), cvss: a.cvss?.score ?? a.cvss_severities?.cvss_v3?.score ?? null,
        affected: (a.vulnerabilities ?? []).map((x: any) => `${x.package?.name}: ${x.vulnerable_version_range}`).join("; "),
        pkgs, url: a.html_url,
      });
    }
  }
  if (ok === 0) {
    failures.push(`GitHub security-advisories API unreachable for all ${GH_REPOS.length} repos (403); used ${SEED_GITHUB_ONLY.length} seeded github.com-only advisories`);
    for (const s of SEED_GITHUB_ONLY) {
      const v = await osvVuln(s.ids[0]);
      if (v && !v.code) raws.push(osvToRaw(v));
      else raws.push(s);
    }
  }
}

// ---- 3a. ASA list
async function fetchAsaList() {
  const md = await fetchText("https://raw.githubusercontent.com/cosmos/security/main/ADVISORIES.md").catch(() => null);
  if (!md) { failures.push("cosmos/security ADVISORIES.md"); return; }
  let n = 0;
  for (const line of md.split("\n")) {
    const m = line.match(/^\|\s*\[(ASA-\d{4}-\d{3,4})\]\((https:\/\/github\.com\/([^/]+\/[^/]+)\/security\/advisories\/(GHSA-[\w-]+))\)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*\|\s*$/);
    if (!m) continue;
    const [, asa, url, repo, ghsa, team, sev, title] = m;
    n++;
    raws.push({
      ids: [ghsa, ...extractAdvIds(asa)], src: "asa-list", rank: 3, project: projectOf(`${repo} ${team}`),
      title: `${asa}: ${title.replace(/`/g, "")}`, details: "", published: null, severity: normSev(sev), cvss: null,
      affected: "", pkgs: [], url,
    });
  }
  console.log(`ASA list: ${n} rows`);
  // other files in cosmos/security that might carry newer advisories (communications/)
  try {
    const dir = cloneRepo("cosmos/security", true);
    for (const f of readdirSync(join(dir, "communications"))) {
      if (!f.endsWith(".md")) continue;
      const txt = readFileSync(join(dir, "communications", f), "utf8");
      const ghsa = txt.match(/GHSA-[\w]{4}-[\w]{4}-[\w]{4}/)?.[0];
      if (ghsa && !raws.some((r) => r.ids.includes(ghsa))) {
        raws.push({ ids: [ghsa], src: "cosmos-security-communications", rank: 4, project: projectOf(txt.slice(0, 300)), title: txt.split("\n")[0].replace(/^#\s*/, ""), details: stripMd(txt.slice(0, 1500)), published: day(txt.match(/\d{4}-\d{2}-\d{2}/)?.[0]), url: `https://github.com/advisories/${ghsa}` });
      }
    }
  } catch (e) {
    failures.push(`cosmos/security clone: ${(e as Error).message.split("\n")[0]}`);
  }
}

// ---- 3b. CosmWasm advisories (CWA)
function cloneRepo(repo: string, blobs: boolean): string {
  mkdirSync(CACHE, { recursive: true });
  const dir = join(CACHE, repo.replace("/", "__") + (blobs ? "" : ".treeless"));
  if (!existsSync(dir)) {
    const args = blobs ? ["clone", "-q", "--filter=blob:none", `https://github.com/${repo}`, dir]
      : ["clone", "-q", "--bare", "--filter=tree:0", `https://github.com/${repo}`, dir];
    git(args);
  } else {
    git(blobs ? ["pull", "-q", "--ff-only"] : ["fetch", "-q", "--tags", "--force", "origin"], dir);
  }
  return dir;
}
async function fetchCwa() {
  let dir: string;
  try { dir = cloneRepo("CosmWasm/advisories", true); } catch (e) { failures.push(`CosmWasm/advisories clone: ${(e as Error).message.split("\n")[0]}`); return; }
  const files = readdirSync(join(dir, "CWAs")).filter((f) => /^CWA-\d{4}-\d{3}\.md$/.test(f));
  const index = readFileSync(join(dir, "CWAs", "README.md"), "utf8");
  for (const f of files) {
    const cwa = f.replace(".md", "");
    const txt = readFileSync(join(dir, "CWAs", f), "utf8");
    const title = txt.split("\n")[0].replace(/^#\s*/, "").trim();
    const sev = txt.match(/\*\*Severity\*\*\s*\n+\s*([A-Za-z]+)/)?.[1];
    const affected = (txt.match(/\*\*Affected versions:?\*\*\s*\n([\s\S]*?)\n\s*\*\*/)?.[1] ?? "")
      .split("\n").map((l) => l.replace(/^[-*]\s*/, "").trim()).filter((l) => l && !/^only supported/i.test(l)).join("; ");
    const desc = txt.match(/## Description[^\n]*\n([\s\S]*?)(\n## |$)/)?.[1] ?? txt.slice(title.length + 2, 1500);
    const row = index.split("\n").find((l) => l.includes(`[${cwa}`)) ?? "";
    const scope = row.split("|")[2]?.trim() ?? "";
    const aliases = [...row.matchAll(/\[(GHSA-[\w-]+|RUSTSEC-\d{4}-\d{4})\]/g)].map((m) => m[1]);
    let published: string | null = null;
    try { published = day(git(["log", "--format=%as", "--", `CWAs/${f}`], dir).trim().split("\n").pop()); } catch { /* ignore */ }
    const project: Advisory["project"] = /^VM/i.test(scope) ? "wasmvm" : /x\/wasm/i.test(scope) ? "wasmd" : /contract/i.test(scope) ? "cosmwasm" : projectOf(title);
    raws.push({
      ids: [...aliases, cwa], src: "cwa", rank: 3, project, title, details: stripMd(desc), published,
      severity: normSev(sev), cvss: null, affected, pkgs: [project === "wasmvm" ? "wasmvm cosmwasm-vm" : project],
      url: `https://github.com/CosmWasm/advisories/blob/main/CWAs/${f}`,
    });
  }
  console.log(`CWA: ${files.length} advisories`);
}

// ---------------------------------------------------------------- merge
function mergeAll(): Advisory[] {
  const parent = new Map<string, string>();
  const find = (x: string): string => { const p = parent.get(x) ?? x; if (p === x) return x; const r = find(p); parent.set(x, r); return r; };
  const union = (a: string, b: string) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(rb, ra); };
  const live = raws.filter((r) => !r.withdrawn);
  // ASA/ISA/CSA numbers are reused across teams (e.g. ASA-2025-003 is both an SDK and a CometBFT
  // advisory), so they only join records of the same project; CWA ids are CosmWasm-wide.
  const CW = new Set(["wasmd", "wasmvm", "cosmwasm"]);
  const key = (id: string, r: RawAdv) =>
    /^(ASA|ISA|CSA|ICS|LSM)-/.test(id) ? `${r.project ?? "other"}|${id}` : /^CWA-/.test(id) && !CW.has(r.project ?? "") ? `${r.project}|${id}` : id;
  for (const r of live) {
    r.ids = [...new Set(r.ids)];
    for (const id of r.ids) { const k = key(id, r); if (!parent.has(k)) parent.set(k, k); union(key(r.ids[0], r), k); }
  }
  const groups = new Map<string, RawAdv[]>();
  for (const r of live) { const k = find(key(r.ids[0], r)); groups.set(k, [...(groups.get(k) ?? []), r]); }
  const out: Advisory[] = [];
  for (const rs of groups.values()) {
    rs.sort((a, b) => a.rank - b.rank);
    const ids = [...new Set(rs.flatMap((r) => r.ids))];
    const pick = <K extends keyof RawAdv>(k: K) => rs.map((r) => r[k]).find((v) => v !== undefined && v !== null && v !== "") as RawAdv[K] | undefined;
    const prio = (id: string) => (id.startsWith("GHSA-") ? 0 : id.startsWith("CVE-") ? 1 : /^(ASA|ISA|CSA|CWA|ICS|LSM)-/.test(id) ? 2 : 3);
    const id = [...ids].sort((a, b) => prio(a) - prio(b) || a.localeCompare(b))[0];
    const pubs = rs.map((r) => r.published).filter(Boolean) as string[];
    // Prefer the GHSA's own date; GO-/RUSTSEC entries are often re-published later.
    const published = rs.find((r) => r.rank <= 1 && r.published)?.published ?? (pubs.sort()[0] ?? null);
    let title = pick("title") ?? id;
    const advId = ids.find((x) => /^(ASA|ISA|CSA|CWA|ICS|LSM)-/.test(x));
    if (advId && !title.includes(advId.slice(0, 8))) title = `${advId}: ${title}`;
    const details = rs.map((r) => r.details ?? "").sort((a, b) => b.length - a.length)[0];
    const pkgs = [...new Set(rs.flatMap((r) => r.pkgs ?? []))];
    const projects = rs.map((r) => r.project).filter((p) => p && p !== "other");
    const project = (projects[0] ?? "other") as Advisory["project"];
    const head = `${title}\n${stripMd(details).slice(0, 500)}`;
    const text = `${title}\n${details}`;
    const comp1 = componentOf(project, title, pkgs);
    const component = comp1 !== "other" && comp1 !== "x/wasm" && comp1 !== "x/vm" ? comp1 : componentOf(project, head, pkgs);
    const imp1 = impactOf(title);
    const impact = imp1 !== "other" ? imp1 : impactOf(head) !== "other" ? impactOf(head) : impactOf(text);
    const summaryBody = stripMd(details).replace(/^\s*(Name|Component|Criticality|Affected Versions|Affected Users|Advisory ID|Status|Published|Contact)\s*:[^\n]*$/gim, " ");
    out.push({
      id, aliases: ids.filter((x) => x !== id).sort(), project, title: clip(title, 300),
      summary: clip(summaryBody || title), published, severity: pick("severity") ?? null, cvss: pick("cvss") ?? null,
      affected: pick("affected") ?? "", component, impact,
      url: pick("url") ?? `https://osv.dev/vulnerability/${id}`, sources: [...new Set(rs.map((r) => r.src))].sort(),
    });
  }
  return out.sort((a, b) => (b.published ?? "").localeCompare(a.published ?? "") || a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------- 4. releases
const REL_REPOS: { repo: string; branches: RegExp }[] = [
  { repo: "cosmos/cosmos-sdk", branches: /^(main|release\/v0\.(47|50|53|54|55)\.x)$/ },
  { repo: "cometbft/cometbft", branches: /^(main|v0\.(34|37|38|39|40)\.x|v[12]\.x)$/ },
  { repo: "cosmos/ibc-go", branches: /^(main|release\/v([4-9]|1[01])\.\d+\.x)$/ },
  { repo: "cosmos/evm", branches: /^(main|release\/v?0\.\d+\.x)$/ },
  { repo: "CosmWasm/wasmd", branches: /^(main|release\/v0\.(4\d|5\d|6\d)\.x)$/ },
  { repo: "CosmWasm/wasmvm", branches: /^(main|release\/v(1\.[2-5]|2\.\d|3\.\d)\.x)$/ },
];
const KW: [string, RegExp][] = [
  ["security", /\bsecurity\b/i], ["ASA-", /\bASA-\d{4}/], ["GHSA", /\bGHSA-/], ["ISA-", /\bISA-\d{4}/],
  ["CSA-", /\bCSA-\d{4}/], ["CWA-", /\bCWA-\d{4}/], ["critical", /\bcritical\b/i], ["vulnerability", /vulnerab/i],
  ["exploit", /\bexploit/i], ["patch", /\bpatch(es|ed)?\b/i],
];
const mentionsOf = (s: string) => KW.filter(([, re]) => re.test(s)).map(([k]) => k);
const MONTHS: Record<string, string> = { january: "01", february: "02", march: "03", april: "04", may: "05", june: "06", july: "07", august: "08", september: "09", october: "10", november: "11", december: "12" };
function parseDate(s: string): string | null {
  const iso = s.match(/\b(20\d\d-\d\d-\d\d)\b/);
  if (iso) return iso[1];
  const m = s.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(20\d\d)/i);
  return m ? `${m[3]}-${MONTHS[m[1].toLowerCase()]}-${m[2].padStart(2, "0")}` : null;
}
function parseChangelog(md: string): Map<string, { date: string | null; text: string; heading: string }> {
  const out = new Map<string, { date: string | null; text: string; heading: string }>();
  const lines = md.split("\n");
  let cur: { v: string; heading: string; buf: string[] } | null = null;
  const flush = () => {
    if (!cur) return;
    const text = cur.buf.join("\n");
    const date = parseDate(cur.heading) ?? parseDate(cur.buf.slice(0, 4).join(" "));
    const prev = out.get(cur.v);
    if (!prev || text.length > prev.text.length) out.set(cur.v, { date: date ?? prev?.date ?? null, text, heading: cur.heading });
  };
  for (const l of lines) {
    const h = l.match(/^##\s+\[?v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\]?/);
    if (h) { flush(); cur = { v: h[1], heading: l, buf: [] }; continue; }
    if (/^##\s/.test(l)) { flush(); cur = null; continue; }
    cur?.buf.push(l);
  }
  flush();
  return out;
}
async function fetchReleasesFor(repo: string, branches: RegExp): Promise<Release[]> {
  // (a) GitHub releases API
  const rel: Release[] = [];
  const first = await fetchRaw(`https://api.github.com/repos/${repo}/releases?per_page=100`).catch(() => null);
  if (first?.ok) {
    for (let page = 1; page <= 10; page++) {
      const arr = page === 1 ? await first.json() : await fetchJson<any[]>(`https://api.github.com/repos/${repo}/releases?per_page=100&page=${page}`);
      if (!arr?.length) break;
      for (const r of arr) {
        const date = day(r.published_at);
        const m = mentionsOf(`${r.name}\n${r.body ?? ""}`);
        if (date && date >= RELEASES_SINCE && m.length) rel.push({ repo, tag: r.tag_name, date, title: r.name || r.tag_name, mentions: m, source: "github-api" });
      }
    }
    return rel;
  }
  // (b) tags via git + CHANGELOG sections from release branches
  const tagDates = new Map<string, { date: string; msg: string }>();
  try {
    const dir = cloneRepo(repo, false);
    const outp = git(["for-each-ref", "refs/tags", "--format=%(refname:short)%1f%(creatordate:short)%1f%(objecttype)%1f%(contents)%1e"], dir);
    for (const rec of outp.split("\x1e")) {
      const [tag, date, type, msg] = rec.replace(/^\n/, "").split("\x1f");
      if (!tag || !/^v?\d+\.\d+\.\d+(\+[\w.]+)?$/.test(tag)) continue; // root, non-prerelease tags
      tagDates.set(tag.replace(/^v/, ""), { date, msg: type === "tag" ? msg ?? "" : "" });
    }
  } catch (e) {
    failures.push(`${repo}: git tag listing failed (${(e as Error).message.split("\n")[0]})`);
  }
  let heads: string[] = [];
  try {
    heads = git(["ls-remote", "--heads", `https://github.com/${repo}`]).split("\n").map((l) => l.split("\t")[1]?.replace("refs/heads/", "")).filter((b): b is string => !!b && branches.test(b));
  } catch { heads = ["main"]; }
  const sections = new Map<string, { date: string | null; text: string; heading: string }>();
  const mds = await pool(heads, 6, (b) => fetchText(`https://raw.githubusercontent.com/${repo}/${b}/CHANGELOG.md`).catch(() => null));
  for (const md of mds) {
    if (!md) continue;
    for (const [v, s] of parseChangelog(md)) {
      const prev = sections.get(v);
      if (!prev || s.text.length > prev.text.length) sections.set(v, { ...s, date: s.date ?? prev?.date ?? null });
    }
  }
  const versions = new Set([...tagDates.keys(), ...[...sections.keys()].filter((v) => !v.includes("-"))]);
  for (const v of versions) {
    const t = tagDates.get(v);
    const s = sections.get(v);
    const date = t?.date ?? s?.date ?? null;
    if (!date || date < RELEASES_SINCE) continue;
    const m = mentionsOf(`${s?.text ?? ""}\n${t?.msg ?? ""}`);
    if (!m.length) continue;
    const firstLine = (s?.text ?? t?.msg ?? "").split("\n").map((l) => stripMd(l).trim()).find((l) => l.length > 15 && !/^\*?[A-Z][a-z]+ \d{1,2}, 20\d\d\*?$/.test(l)) ?? "";
    rel.push({
      repo, tag: `v${v}`, date, title: clip(firstLine || `v${v}`, 200), mentions: m,
      source: s && mentionsOf(s.text).length ? "changelog" : "tag-message",
    });
  }
  console.log(`${repo}: ${tagDates.size} tags, ${heads.length} changelog branches, ${sections.size} sections -> ${rel.length} flagged releases`);
  return rel;
}

// ---------------------------------------------------------------- stats
function quarter(d: string) { return `${d.slice(0, 4)}Q${Math.floor((+d.slice(5, 7) - 1) / 3) + 1}`; }
function table(rows: Record<string, Record<string, number>>, cols: string[], label: string) {
  const w = Math.max(label.length, ...Object.keys(rows).map((k) => k.length));
  console.log(label.padEnd(w) + " " + cols.map((c) => c.padStart(7)).join("") + "  total");
  for (const [k, r] of Object.entries(rows).sort((a, b) => sum(b[1]) - sum(a[1])))
    console.log(k.padEnd(w) + " " + cols.map((c) => String(r[c] ?? "").padStart(7)).join("") + String(sum(r)).padStart(7));
  const tot: Record<string, number> = {};
  for (const r of Object.values(rows)) for (const [c, n] of Object.entries(r)) tot[c] = (tot[c] ?? 0) + n;
  console.log("TOTAL".padEnd(w) + " " + cols.map((c) => String(tot[c] ?? 0).padStart(7)).join("") + String(sum(tot)).padStart(7));
}
const sum = (r: Record<string, number>) => Object.values(r).reduce((a, b) => a + b, 0);
function bump(m: Record<string, Record<string, number>>, k: string, c: string) { (m[k] ??= {})[c] = (m[k][c] ?? 0) + 1; }

function printStats(advs: Advisory[], rels: Release[]) {
  const dated = advs.filter((a) => a.published);
  const years = [...new Set(dated.map((a) => a.published!.slice(0, 4)))].sort().filter((y) => y >= "2018");
  const byYear: Record<string, Record<string, number>> = {};
  for (const a of dated) bump(byYear, a.project, a.published!.slice(0, 4));
  console.log(`\n=== advisories per project per year (n=${advs.length}, undated=${advs.length - dated.length}) ===`);
  table(byYear, years, "project");
  const qs = ["2024", "2025", "2026"].flatMap((y) => [1, 2, 3, 4].map((q) => `${y}Q${q}`)).filter((q) => q <= "2026Q4");
  const byQ: Record<string, Record<string, number>> = {};
  for (const a of dated) if (a.published! >= "2024-01-01") bump(byQ, a.project, quarter(a.published!));
  console.log("\n=== advisories per project per quarter, 2024–2026 ===");
  table(byQ, qs, "project");
  const sevQ: Record<string, Record<string, number>> = {};
  for (const a of dated) if (a.published! >= "2024-01-01") bump(sevQ, a.severity ?? "null", quarter(a.published!));
  console.log("\n=== severity per quarter, 2024–2026 ===");
  table(sevQ, qs, "severity");
  const sevAll: Record<string, number> = {};
  for (const a of advs) sevAll[a.severity ?? "null"] = (sevAll[a.severity ?? "null"] ?? 0) + 1;
  console.log("\nseverity mix (all):", sevAll);
  const sev24: Record<string, number> = {};
  for (const a of dated) if (a.published! >= "2024-01-01") sev24[a.severity ?? "null"] = (sev24[a.severity ?? "null"] ?? 0) + 1;
  console.log("severity mix (2024+):", sev24);
  const comp: Record<string, Record<string, number>> = {};
  for (const a of dated) if (a.published! >= "2024-01-01") bump(comp, a.component, a.published!.slice(0, 4));
  console.log("\n=== components (2024+) per year ===");
  table(Object.fromEntries(Object.entries(comp).sort((a, b) => sum(b[1]) - sum(a[1])).slice(0, 20)), ["2024", "2025", "2026"], "component");
  const imp: Record<string, Record<string, number>> = {};
  for (const a of dated) if (a.published! >= "2024-01-01") bump(imp, a.impact, a.published!.slice(0, 4));
  console.log("\n=== impact (2024+) per year ===");
  table(imp, ["2024", "2025", "2026"], "impact");
  const relQ: Record<string, Record<string, number>> = {};
  const relQStrong: Record<string, Record<string, number>> = {};
  for (const r of rels) {
    if (r.date < "2024-01-01") continue;
    bump(relQ, r.repo, quarter(r.date));
    if (r.mentions.some((m) => m !== "patch")) bump(relQStrong, r.repo, quarter(r.date));
  }
  console.log(`\n=== flagged releases per quarter (any keyword, n=${rels.length} since ${RELEASES_SINCE}) ===`);
  table(relQ, qs, "repo");
  console.log("\n=== releases mentioning security/ASA/GHSA/ISA/CSA/CWA/critical/vuln/exploit (excl. 'patch'-only) ===");
  table(relQStrong, qs, "repo");
}

// ---------------------------------------------------------------- main
async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  await fetchOsv().catch((e) => failures.push(`OSV: ${e}`));
  await fetchGithubAdvisories().catch((e) => failures.push(`GitHub advisories: ${e}`));
  await fetchAsaList().catch((e) => failures.push(`ASA: ${e}`));
  await fetchCwa().catch((e) => failures.push(`CWA: ${e}`));
  // Resolve ids referenced only by the ASA/CWA lists that OSV queries did not return.
  const have = new Set(raws.filter((r) => r.src.startsWith("osv")).flatMap((r) => r.ids));
  const missing = [...new Set(raws.filter((r) => !r.src.startsWith("osv")).flatMap((r) => r.ids).filter((i) => /^(GHSA|RUSTSEC)-/.test(i) && !have.has(i)))];
  for (const v of await pool(missing, 8, osvVuln)) if (v && !v.code) raws.push(osvToRaw(v));

  const advisories = mergeAll().map((a) => AdvisorySchema.parse(a));
  writeFileSync(new URL("cosmos_advisories.json", OUT_DIR), JSON.stringify(advisories, null, 2) + "\n");

  const releases: Release[] = [];
  for (const { repo, branches } of REL_REPOS) {
    try { releases.push(...(await fetchReleasesFor(repo, branches))); }
    catch (e) { failures.push(`releases ${repo}: ${(e as Error).message.split("\n")[0]}`); }
  }
  if (!releases.some((r) => r.source === "github-api")) failures.push("GitHub releases API unreachable (403); releases derived from git tags + CHANGELOG.md (silent patches with security-only release notes are missed)");
  const relOut = z.array(ReleaseSchema).parse(releases.sort((a, b) => b.date.localeCompare(a.date) || a.repo.localeCompare(b.repo)));
  writeFileSync(new URL("cosmos_security_releases.json", OUT_DIR), JSON.stringify(relOut, null, 2) + "\n");

  console.log(`\nwrote ${advisories.length} advisories, ${relOut.length} releases`);
  printStats(advisories, relOut);
  if (failures.length) console.log("\nFAILURES / FALLBACKS:\n- " + failures.join("\n- "));
}
main().catch((e) => { console.error(e); process.exit(1); });

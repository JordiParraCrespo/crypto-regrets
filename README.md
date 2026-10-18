# Crypto Regrets

A classified index of crypto hacks, exploits and base-layer failures from 2010 to today. It's built for learning security research: what keeps going wrong, how the patterns changed over time, and what developers should do about it.

- **~1,800 incidents** merged from DefiLlama, DeFiHackLabs and REKT, deduplicated and cross-linked
- **17 failure patterns** in 6 layers (smart contract, economic, cross-chain, operational, infrastructure, trust abuse), each with attack anatomy, prevention checklist and OWASP SC Top 10 / SWC mapping
- **860+ incidents linked to a runnable Foundry PoC** (DeFiHackLabs)
- **56 client/consensus advisories** (Bitcoin Core, Geth, Cosmos) plus curated base-layer incidents
- **Audit of 30 public security sources** (`data/sources.json`, shown at `/sources`)

## Pages

| Route | What |
|---|---|
| `/` | Overview, trends by layer, patterns ranked by losses |
| `/history` | Eras from Genesis (2009) to the operational-security era (2023+) |
| `/hacks` | Filterable/searchable index (state kept in URL, e.g. `/hacks?cat=reentrancy&poc=1`) |
| `/hacks/[id]` | One page per incident: root cause, PoC, references, similar incidents |
| `/patterns`, `/patterns/[id]` | Taxonomy and per-pattern guides |
| `/infrastructure` | Consensus/client failures and advisories |
| `/developers` | Secure-development checklist ranked by money lost |
| `/sources` | Method and source audit |
| `/api/incidents.json`, `/api/taxonomy.json`, `/api/advisories.json` | Raw data |

## Run it

```sh
npm install
npm run ingest            # rebuild src/data/*.json from snapshots in data/raw
npm run ingest -- --fetch # refresh snapshots from the network first
npm run dev               # http://localhost:4321
npm run build && npm run check
```

## How it works

```
data/raw/*            source snapshots (committed so builds are reproducible offline)
scripts/ingest.ts     parse → match/merge across sources → classify → zod-validate → src/data/*.json
scripts/curated.ts    hand-written landmark + base-layer incidents (post-mortem root causes)
src/lib/taxonomy.ts   layers, categories, eras ─ the classification is typed (CategoryId is a literal union)
src/lib/types.ts      zod schemas: Incident, Advisory, SourceAudit (single source of truth for types)
src/lib/data.ts       loads + validates data at build time, aggregations
src/pages/            Astro static pages
```

**Classification.** DefiLlama's `classification`/`technique` labels are mapped onto our categories (`LLAMA_CLASS`, `LLAMA_TECHNIQUE` in `scripts/ingest.ts`), with documented overrides. For example, 51% attacks that DefiLlama files as "Bridge & Cross-Chain / Forged Proof" become `consensus-attack`. Free-text-only records (DeFiHackLabs titles, REKT excerpts) go through ordered keyword rules (`KEYWORD_RULES`). Curated post-mortems override both. Any reclassification is recorded in `classificationNote` and shown on the incident page.

**Matching.** Records are joined by fuzzy name key + date window (DeFiHackLabs ±7 days, REKT ±10 days), with an alias table for renamed incidents (Wormhole ⇄ Portal, BNB ⇄ Binance Bridge…).

## Plugging in another classifier / API

Every incident must satisfy `incidentSchema` in `src/lib/types.ts`, and `category` must be a `CategoryId`. To use an external classification API, call it in `scripts/ingest.ts` after `build()` and overwrite `category` / `technique` / `classificationNote`. The zod parse at the end rejects any label outside the taxonomy, so the build fails loudly instead of silently mis-filing incidents.

## Data licensing & caveats

- DeFiHackLabs: Apache-2.0. DefiLlama: public API, attribution. REKT: we store only titles, slugs, dates, amounts, audit status and short excerpts, and link to the articles.
- Amounts are nominal USD at incident time as reported by sources; non-USD DeFiHackLabs losses (e.g. "12 ETH") are left blank rather than guessed.
- Fuzzy matching can miss or wrongly merge a small number of records. Corrections welcome.
- Educational use only.

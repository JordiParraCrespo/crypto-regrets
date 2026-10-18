# Crypto Regrets

A classified index of crypto hacks, exploits and base-layer failures from 2010 to today. It's built for learning security research: what keeps going wrong, how the patterns changed over time, and what developers should do about it.

- **~3,100 incidents** merged from DefiLlama, DeFiHackLabs (README + explorer), REKT, SlowMist, BlockSec and RevertIQ, deduplicated and cross-linked
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
npm run ingest            # rebuild data/incidents* from snapshots in data/raw
npm run ingest -- --fetch # refresh DefiLlama/DeFiHackLabs/REKT/advisory snapshots first
npx tsx scripts/fetch-extra.ts  # refresh DeFiHackLabs explorer, BlockSec, SlowMist, RevertIQ snapshots
npm run dev               # http://localhost:4321
npm run build && npm run check
```

## How it works

```
data/incidents.json   THE dataset: every incident, one per line (also incidents.csv)
data/incidents/<year>/<id>.json   one file per incident
data/raw/*            source snapshots (committed so builds are reproducible offline)
scripts/fetch-extra.ts  scrapes DeFiHackLabs explorer, BlockSec, SlowMist, RevertIQ → data/raw
scripts/ingest.ts     parse → match/merge across sources → classify → zod-validate → data/incidents*
scripts/curated.ts    hand-written landmark + base-layer incidents (post-mortem root causes)
src/lib/taxonomy.ts   layers, categories, eras ─ the classification is typed (CategoryId is a literal union)
src/lib/types.ts      zod schemas: Incident, Advisory, SourceAudit (single source of truth for types)
src/lib/data.ts       loads + validates data at build time, aggregations
scripts/classify.ts   TypeSafe classification → data/typesafe/classifications.json
src/pages/            Astro static pages
```

**Classification.** DefiLlama's `classification`/`technique` labels are mapped onto our categories (`LLAMA_CLASS`, `LLAMA_TECHNIQUE` in `scripts/ingest.ts`), with documented overrides. For example, 51% attacks that DefiLlama files as "Bridge & Cross-Chain / Forged Proof" become `consensus-attack`. Free-text-only records (DeFiHackLabs titles, REKT excerpts) go through ordered keyword rules (`KEYWORD_RULES`). Curated post-mortems override both. Any reclassification is recorded in `classificationNote` and shown on the incident page.

**Matching.** Records are joined by fuzzy name key + date window (DeFiHackLabs ±7 days, REKT ±10 days), with an alias table for renamed incidents (Wormhole ⇄ Portal, BNB ⇄ Binance Bridge…).

## Model classification with TypeSafe

Every incident also gets a second opinion from [TypeSafe](https://docs.typesafe.ai)'s System One model (Jev). One request per incident (`scripts/classify-spec.ts`):

- `category`: a **Choice** over the taxonomy (each option = name + definition)
- `has_root_cause`, `flash_loan`, `state_actor`: **Noul** (probability a statement is true)

The state is the incident's facts plus its **single** most technical description (curated > DeFiHackLabs > SlowMist > RevertIQ > REKT).

```sh
export TYPESAFE_API_KEY=...        # never commit it; in CI use a repository secret
npm run classify                   # only incidents whose input changed since the last run
npm run ingest                     # applies the cached answers
npx tsx scripts/eval-variants.ts   # re-run the design comparison below
```

### How the design was chosen (measured, not guessed)

`scripts/eval-variants.ts` asks several question designs **in the same request** (so they see identical input) for a fixed ~250-incident test set stratified by pattern, scored against human labels (DefiLlama + curated):

| Finding | Evidence |
|---|---|
| One description beats all of them | Sending every source's account: **−7 points** (Jev degrades on large, overlapping state) |
| Prompt wording barely matters | Plain definitions vs. "covers / not for / examples" rubrics vs. reversed option order: **78–80% exact, ~87% layer-level**, all within ±2.4 points. Kept the cheapest (rubrics cost 3× tokens) |
| Confidence is the lever | ≥ 0.9 → **~91% correct**; 0.7–0.9 → 76%; below 0.7 our keyword rules do better |
| Fix the taxonomy before the prompt | Several "errors" were our mapping contradicting our own definitions (keys stolen from servers filed as infrastructure). Fixing it: **+3 points** |

**Adoption policy** (`applyTypeSafe` in `scripts/ingest.ts`): the model's category is used only where no human label exists (keyword guesses, unclassified), with confidence ≥ 0.7 and `has_root_cause` ≥ 0.5. DefiLlama and curated labels are never overwritten; disagreements are shown per incident, listed on `/sources`, and filterable at `/hacks?by=dis`. The rubrics weren't better for the model but are good for people, so they appear on each pattern page ("How to tell it apart", `src/lib/rubric.ts`).

## Data licensing & caveats

- DeFiHackLabs: Apache-2.0. DefiLlama: public API, attribution. REKT: we store only titles, slugs, dates, amounts, audit status and short excerpts, and link to the articles.
- Amounts are nominal USD at incident time as reported by sources; non-USD DeFiHackLabs losses (e.g. "12 ETH") are left blank rather than guessed.
- Fuzzy matching can miss or wrongly merge a small number of records (e.g. the same hack dated weeks apart by different sources). Corrections welcome: edit the incident's file under `data/incidents/` or the matching rules in `scripts/ingest.ts`.
- SlowMist includes scams and exit scams as well as hacks; RevertIQ summaries appear to be machine-written. Both are quoted briefly and linked.
- Educational use only.

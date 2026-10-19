# Crypto Regrets

A classified index of crypto hacks, exploits and base-layer failures from 2010 to today, built to learn the common failure patterns, and as groundwork for tooling that detects and fixes them.

- **3,093 incidents** ($27.1B) merged from DefiLlama, DeFiHackLabs (README + explorer), REKT, SlowMist, BlockSec, RevertIQ, Blockchain Graveyard and SEAL 911 (Web3 Is Going Great used for enrichment), deduplicated (a second pass folds same-event records with different names; see `data/consolidated.log`) and cross-linked
- **Two-level taxonomy**: 17 failure patterns in 6 layers → **57 vulnerability classes** (integer overflow, unprotected initializer, spot-price oracle, signer blind-signing, dependency supply chain…), each with CWE/SWC, vulnerable vs fixed code (or missing vs fixed control), detection signals and remediation
- **1,589 incidents traced to a class**, 860+ with a runnable Foundry PoC, 1,100+ with attack transactions
- **176 client/SDK/compiler advisories** (Bitcoin Core, Geth, Cosmos, Vyper, OpenZeppelin…) plus curated base-layer incidents
- **Every model decision measured** against human labels before being allowed to set a label (see below)
- **Audit of 30 public security sources** (`data/sources.json`, shown at `/sources`)

## For tool builders

`data/vulnerability-classes.json` (also served at `/api/vulnerability-classes.json`) is the dataset a detection / auto-fix tool needs: for every class, the fix knowledge from `src/lib/classes.ts` plus every labelled incident (PoCs and attack transactions first) as test cases.

```sh
jq '.[] | select(.id=="integer-overflow") | .cases[] | select(.poc) | {name, poc, txHashes}' data/vulnerability-classes.json
```

## Pages

| Route | What |
|---|---|
| `/` | Overview: top vulnerability classes, how failures moved from code to people, latest incidents |
| `/trends` | Losses and incidents per year, DeFi TVL and loss rate, chain-family and vulnerability heatmaps over time |
| `/classes`, `/classes/[id]` | Vulnerability classes: vulnerable vs fixed code, detection, fixes, PoCs, incidents |
| `/hacks`, `/hacks/[id]` | Filterable index (state in URL, e.g. `/hacks?cls=read-only-reentrancy&poc=1`) and one page per incident |
| `/patterns`, `/history`, `/infrastructure` | Failure patterns, eras, base-layer incidents and advisories |
| `/developers` | Secure-coding checklist ranked by frequency |
| `/data`, `/sources` | Downloads; method, evaluation and source audit |

## Run it

```sh
npm install
npm run ingest            # rebuild data/incidents* from snapshots in data/raw
npm run fetch             # refresh every source snapshot in data/raw (network)
npm run dev               # http://localhost:4321
npm run build && npm run check
```

## How it works

```
data/incidents.json   THE dataset: every incident, one per line (also incidents.csv)
data/incidents/<year>/<id>.json   one file per incident
data/raw/*            source snapshots (committed so builds are reproducible offline)
scripts/fetch-extra.ts  scrapes DeFiHackLabs explorer, BlockSec, SlowMist, RevertIQ → data/raw
scripts/fetch-more.ts   scrapes Blockchain Graveyard, SEAL 911, Web3 Is Going Great, OSV advisories → data/raw
src/lib/classes.ts    the 57 vulnerability classes (fix knowledge) + analyst-label → class map
src/lib/chains.ts     canonical chain names + chain families
scripts/ingest.ts     parse → match/merge across sources → classify → zod-validate → data/incidents*
scripts/curated.ts    hand-written landmark + base-layer incidents (post-mortem root causes)
src/lib/taxonomy.ts   layers, categories, eras ─ the classification is typed (CategoryId is a literal union)
src/lib/types.ts      zod schemas: Incident, Advisory, SourceAudit (single source of truth for types)
src/lib/data.ts       loads + validates data at build time, aggregations
scripts/classify.ts           TypeSafe pattern classification → data/typesafe/classifications.json
scripts/classify-classes.ts   TypeSafe class classification (within the pattern) → data/typesafe/classes.json
src/pages/            Astro static pages
```

**Classification.** DefiLlama's `classification`/`technique` labels are mapped onto our categories (`LLAMA_CLASS`, `LLAMA_TECHNIQUE` in `scripts/ingest.ts`), with documented overrides. For example, 51% attacks that DefiLlama files as "Bridge & Cross-Chain / Forged Proof" become `consensus-attack`. Free-text-only records (DeFiHackLabs titles, REKT excerpts) go through ordered keyword rules (`KEYWORD_RULES`). Curated post-mortems override both. Any reclassification is recorded in `classificationNote` and shown on the incident page.

**Matching.** Records are joined by fuzzy name key + date window (DeFiHackLabs ±7 days, REKT ±10 days), with an alias table for renamed incidents (Wormhole ⇄ Portal, BNB ⇄ Binance Bridge…).

## Classification

Two levels, evidence first. Every level has a fixed priority, and the model only fills gaps:

| Level | 1st | 2nd | 3rd | otherwise |
|---|---|---|---|---|
| Pattern (17) | curated post-mortem | DefiLlama analyst label (mapped, documented overrides) | TypeSafe Jev, confidence ≥ 0.7 and the text explains the attack | keyword rules |
| Class (57) | curated post-mortem | analyst technique label naming exactly one class (`TECHNIQUE_TO_CLASS`) | TypeSafe Jev choosing among the pattern's classes, confidence ≥ 0.9 | *unspecified* (no guessing) |

```sh
export TYPESAFE_API_KEY=...       # never commit it; in CI use a repository secret
npm run classify                  # pattern level, only incidents whose input changed
npm run ingest
npm run classify:classes          # class level
npm run ingest
npm run eval && npm run eval:classes   # re-run the measurements below
```

Answers are cached in `data/typesafe/` keyed by incident id + a hash of exactly what was sent, so builds never need the key.

### Measured, not assumed (`data/typesafe/evaluation.json`)

| Finding | Evidence |
|---|---|
| One description beats all of them | Sending every source's account: **−7 points** (Jev degrades on large, overlapping state) |
| Prompt wording barely matters | Plain definitions vs. rubrics vs. reversed option order: 78–80% exact, ~87% layer-level, within ±2.4 points. Kept the cheapest |
| Confidence is the lever (pattern) | ≥ 0.9 → ~91% correct; 0.7–0.9 → 76%; below 0.7 keyword rules do better |
| Class level, analyst label hidden | 69% overall, **81% at ≥ 0.9** (52% of cases), 67% at 0.7–0.9 → threshold 0.9 |
| Claude Haiku as an alternative | 71% vs TypeSafe 80% on the same 251 incidents; on disagreements TypeSafe right 34×, Haiku 12×. Not used |
| Fix the taxonomy before the prompt | Our mapping contradicted our own definitions (keys stolen from servers filed as infrastructure); fixing it: +3 points |

## Data licensing & caveats

- DeFiHackLabs: Apache-2.0. DefiLlama: public API, attribution. REKT: we store only titles, slugs, dates, amounts, audit status and short excerpts, and link to the articles.
- Amounts are nominal USD at incident time as reported by sources; non-USD DeFiHackLabs losses (e.g. "12 ETH") are left blank rather than guessed.
- Fuzzy matching can miss or wrongly merge a small number of records (e.g. the same hack dated weeks apart by different sources). Corrections welcome: edit the incident's file under `data/incidents/` or the matching rules in `scripts/ingest.ts`.
- SlowMist entries labelled Scam/Ponzi are excluded (frauds, not security failures). RevertIQ summaries appear machine-written. Web3 Is Going Great headlines include individual thefts and news, so it only enriches incidents already indexed. Third-party text is quoted briefly and linked.
- The design system is light-only by design (warm-cream editorial system).
- Educational use only.

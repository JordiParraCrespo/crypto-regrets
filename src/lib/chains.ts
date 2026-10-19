/**
 * Chain names differ across sources ("BSC" / "BNB Chain" / "Binance Smart Chain").
 * `canonicalChain` maps them to one spelling at ingest; `chainFamily` groups chains for charts.
 */

const ALIASES: Record<string, string> = {
  'ethereum mainnet': 'Ethereum',
  eth: 'Ethereum',
  'bnb chain': 'BSC',
  'binance smart chain': 'BSC',
  bnb: 'BSC',
  binance: 'BSC',
  bsc: 'BSC',
  'arbitrum one': 'Arbitrum',
  zksync: 'zkSync Era',
  ripple: 'XRP',
  tron: 'Tron',
  near: 'Near',
  'avalanche c-chain': 'Avalanche',
  avax: 'Avalanche',
  matic: 'Polygon',
  'polygon pos': 'Polygon',
};

/** Placeholder values that mean "several" or "don't know" rather than a chain. */
const NOT_A_CHAIN = new Set(['multiple', 'multi-chain', 'multichain', 'unknown', 'n/a', '']);

export function canonicalChain(name: string): string | null {
  const k = name.trim().toLowerCase();
  if (NOT_A_CHAIN.has(k)) return null;
  return ALIASES[k] ?? name.trim();
}

export const CHAIN_FAMILIES = {
  ethereum: { name: 'Ethereum', blurb: 'Ethereum mainnet' },
  l2: { name: 'Ethereum L2s', blurb: 'Arbitrum, Optimism, Base, zkSync, Linea, Blast…' },
  bsc: { name: 'BNB Chain', blurb: 'BNB Smart Chain' },
  'evm-other': { name: 'Other EVM chains', blurb: 'Polygon, Avalanche, Fantom, Cronos, Gnosis…' },
  solana: { name: 'Solana', blurb: 'Solana' },
  bitcoin: { name: 'Bitcoin & PoW coins', blurb: 'Bitcoin, Litecoin, Zcash, Monero, small PoW chains' },
  tron: { name: 'Tron', blurb: 'Tron' },
  eos: { name: 'EOS', blurb: 'EOS (2018–2019 dapp exploits)' },
  cosmos: { name: 'Cosmos ecosystem', blurb: 'Terra, Osmosis, Neutron, Secret…' },
  move: { name: 'Move chains', blurb: 'Sui, Aptos' },
  other: { name: 'Other chains', blurb: 'Polkadot, Cardano, XRP, TON, Near, Algorand…' },
  multi: { name: 'Multi-chain', blurb: 'Incidents spanning several chain families (often bridges)' },
  offchain: { name: 'Exchanges & off-chain', blurb: 'Centralized exchanges and custodians with no single chain recorded' },
  unknown: { name: 'Chain not recorded', blurb: 'Sources did not record a chain' },
} as const;

export type ChainFamilyId = keyof typeof CHAIN_FAMILIES;

const FAMILY_OF: Record<string, ChainFamilyId> = {
  Ethereum: 'ethereum',
  Arbitrum: 'l2',
  Optimism: 'l2',
  Base: 'l2',
  'zkSync Era': 'l2',
  Linea: 'l2',
  Blast: 'l2',
  Scroll: 'l2',
  Starknet: 'l2',
  Taiko: 'l2',
  Mantle: 'l2',
  Unichain: 'l2',
  'Polygon zkEVM': 'l2',
  Mode: 'l2',
  Manta: 'l2',
  Metis: 'l2',
  Boba: 'l2',
  Ink: 'l2',
  Zora: 'l2',
  Abstract: 'l2',
  'Robinhood Chain': 'l2',
  BSC: 'bsc',
  opBNB: 'bsc',
  Polygon: 'evm-other',
  Avalanche: 'evm-other',
  Fantom: 'evm-other',
  Sonic: 'evm-other',
  Cronos: 'evm-other',
  'Gnosis Chain': 'evm-other',
  Gnosis: 'evm-other',
  Celo: 'evm-other',
  Harmony: 'evm-other',
  Moonriver: 'evm-other',
  Moonbeam: 'evm-other',
  Berachain: 'evm-other',
  HECO: 'evm-other',
  Fuse: 'evm-other',
  Kava: 'evm-other',
  Klaytn: 'evm-other',
  Kaia: 'evm-other',
  Aurora: 'evm-other',
  Evmos: 'evm-other',
  Canto: 'evm-other',
  Core: 'evm-other',
  Sei: 'evm-other',
  'Hyperliquid L1': 'evm-other',
  Solana: 'solana',
  Bitcoin: 'bitcoin',
  Litecoin: 'bitcoin',
  BitcoinCash: 'bitcoin',
  'Bitcoin Cash': 'bitcoin',
  'Bitcoin Gold': 'bitcoin',
  'Bitcoin SV': 'bitcoin',
  Zcash: 'bitcoin',
  Monero: 'bitcoin',
  Dogecoin: 'bitcoin',
  Vertcoin: 'bitcoin',
  'Pirate Chain': 'bitcoin',
  'Ethereum Classic': 'bitcoin',
  Verge: 'bitcoin',
  Grin: 'bitcoin',
  Stacks: 'bitcoin',
  Tron: 'tron',
  EOS: 'eos',
  Terra: 'cosmos',
  'Terra Classic': 'cosmos',
  Osmosis: 'cosmos',
  Neutron: 'cosmos',
  Secret: 'cosmos',
  Cosmos: 'cosmos',
  Injective: 'cosmos',
  Juno: 'cosmos',
  Nomic: 'cosmos',
  Crescent: 'cosmos',
  Umee: 'cosmos',
  Sui: 'move',
  Aptos: 'move',
};

export function chainFamily(chains: string[], targetType: string | null): ChainFamilyId {
  if (chains.length === 0) return targetType === 'CEX' ? 'offchain' : 'unknown';
  const fams = new Set(chains.map((c) => FAMILY_OF[c] ?? 'other'));
  return fams.size > 1 ? 'multi' : [...fams][0];
}

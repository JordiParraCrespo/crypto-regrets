import type { CategoryId } from '../src/lib/taxonomy';
import type { ClassId } from '../src/lib/classes';

/**
 * Hand-curated landmark incidents that the exploit databases miss, mostly
 * base-layer / client failures. Kept deliberately small and well-documented.
 */
export interface CuratedIncident {
  name: string;
  /** Name to join on when it differs from the display name's first word. */
  matchName?: string;
  date: string;
  category: CategoryId;
  vulnClass: ClassId;
  technique: string;
  chains: string[];
  amountUsd: number | null;
  rootCause: string;
  references: { label: string; url: string }[];
}

export const CURATED: CuratedIncident[] = [

  // ---- Landmark incidents: these merge into existing records and replace the root-cause text.
  {
    name: 'Mt. Gox collapse',
    matchName: 'Mt. Gox',
    date: '2014-02-07',
    category: 'key-compromise',
    vulnClass: 'hot-wallet-compromise',
    technique: 'Hot wallet drained over years; insolvency hidden',
    chains: ['Bitcoin'],
    amountUsd: 470000000,
    rootCause:
      'Mt. Gox, then handling ~70% of BTC volume, lost ~850,000 BTC. The hot wallet private key (wallet.dat) was stolen around 2011 and funds were siphoned for years without the books being reconciled. "Transaction malleability" was blamed publicly but explained very little of the loss. Lesson: proof of reserves and reconciliation.',
    references: [{ label: 'WizSec: Breakdown of the Mt. Gox theft', url: 'https://blog.wizsec.jp/2015/04/the-missing-mtgox-bitcoins.html' }],
  },
  {
    name: 'The DAO',
    matchName: 'The DAO',
    date: '2016-06-17',
    category: 'reentrancy',
    vulnClass: 'single-function-reentrancy',
    technique: 'Recursive call in splitDAO before balance update',
    chains: ['Ethereum'],
    amountUsd: 60000000,
    rootCause:
      'splitDAO() sent ETH to the caller before zeroing their balance. The attacker\'s fallback re-entered splitDAO recursively, draining 3.6M ETH into a child DAO. Ethereum hard-forked to return the funds, splitting off Ethereum Classic. It made checks-effects-interactions a standard rule.',
    references: [{ label: 'Phil Daian: Analysis of the DAO exploit', url: 'https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/' }],
  },
  {
    name: 'Parity Multisig freeze',
    date: '2017-11-09',
    category: 'access-control',
    vulnClass: 'uninitialized-implementation',
    technique: 'Unprotected initWallet on shared library; selfdestruct',
    chains: ['Ethereum'],
    amountUsd: 150000000,
    rootCause:
      'Multisig wallets delegatecalled into a shared library contract that was never initialized. A user called initWallet() on the library itself, became its owner, and called kill(), self-destructing the library and permanently freezing 513k ETH in every dependent wallet.',
    references: [{ label: 'Parity post-mortem', url: 'https://www.parity.io/blog/a-postmortem-on-the-parity-multi-sig-library-self-destruct/' }],
  },
  {
    name: 'Ronin Bridge',
    date: '2022-03-23',
    category: 'social-engineering',
    vulnClass: 'malware-fake-job',
    technique: '5 of 9 validator keys compromised',
    chains: ['Ronin', 'Ethereum'],
    amountUsd: 624000000,
    rootCause:
      'Lazarus Group compromised a Sky Mavis engineer via a fake job offer, obtaining 4 Sky Mavis validator keys. A stale allow-list that let Sky Mavis sign on behalf of the Axie DAO validator supplied the 5th signature. The theft went unnoticed for 6 days. Lessons: validator independence, monitoring, revoking temporary permissions.',
    references: [{ label: 'Ronin post-mortem', url: 'https://roninchain.com/blog/posts/back-to-building-ronin-security-breach-6513cc78a5edc1001b03c364' }],
  },
  {
    name: 'Wormhole',
    date: '2022-02-02',
    category: 'bridge-crosschain',
    vulnClass: 'message-verification-bypass',
    technique: 'Spoofed sysvar account bypassed signature verification',
    chains: ['Solana', 'Ethereum'],
    amountUsd: 326000000,
    rootCause:
      'Wormhole\'s Solana program used the deprecated load_instruction_at, which did not verify that the passed "instructions sysvar" account was the real one. The attacker passed a fake sysvar, so guardian signature verification was skipped, and minted 120k wETH on Solana with no backing.',
    references: [{ label: 'Kudelski: Wormhole exploit analysis', url: 'https://kudelskisecurity.com/modern-ciso-blog/the-wormhole-hack-how-a-missing-account-check-led-to-a-325m-exploit/' }],
  },
  {
    name: 'Nomad',
    date: '2022-08-01',
    category: 'bridge-crosschain',
    vulnClass: 'trusted-root-misinit',
    technique: 'Zero hash initialized as trusted root',
    chains: ['Ethereum', 'Moonbeam'],
    amountUsd: 190000000,
    rootCause:
      'An upgrade initialized the trusted Merkle root to 0x00. Unproven messages map to root 0x00 by default, so every message counted as proven. Once the first attacker showed how, hundreds of copycats replayed the transaction with their own address: a "crowd-looted" bridge.',
    references: [{ label: 'Nomad post-mortem', url: 'https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd' }],
  },
  {
    name: 'Poly Network',
    date: '2021-08-10',
    category: 'bridge-crosschain',
    vulnClass: 'message-verification-bypass',
    technique: 'Cross-chain message called privileged keeper function',
    chains: ['Ethereum', 'BSC', 'Polygon'],
    amountUsd: 611000000,
    rootCause:
      'EthCrossChainManager would execute any cross-chain message against any contract, including EthCrossChainData, which stored the keeper public keys. The attacker brute-forced a function name whose selector collided with putCurEpochConPubKeyBytes and replaced the keepers with their own key. Most funds were returned.',
    references: [{ label: 'Kudelski: Poly Network hack', url: 'https://research.kudelskisecurity.com/2021/08/12/the-poly-network-hack-explained/' }],
  },
  {
    name: 'Euler Finance',
    matchName: 'Euler',
    date: '2023-03-13',
    category: 'logic-error',
    vulnClass: 'solvency-check-flaw',
    technique: 'donateToReserves without health check',
    chains: ['Ethereum'],
    amountUsd: 197000000,
    rootCause:
      'donateToReserves() let a user burn their own eTokens without checking account health. The attacker built a leveraged position with a flash loan, donated collateral to make it deeply insolvent, then self-liquidated at a discount to extract the surplus. The function was added after earlier audits. The funds were later returned.',
    references: [{ label: 'Cyfrin: Euler hack explained', url: 'https://www.cyfrin.io/blog/how-did-the-euler-finance-hack-happen-hack-analysis' }],
  },
  {
    name: 'Bybit',
    date: '2025-02-21',
    category: 'social-engineering',
    vulnClass: 'blind-signing',
    technique: 'Compromised Safe{Wallet} UI; signers blind-signed delegatecall',
    chains: ['Ethereum'],
    amountUsd: 1400000000,
    rootCause:
      'Lazarus compromised a Safe{Wallet} developer machine and injected JavaScript into the Safe web UI served from AWS S3, targeting only Bybit\'s cold wallet. Signers saw a normal transfer but signed a delegatecall that swapped the Safe implementation for a malicious one, which then drained ~401k ETH. The largest crypto theft ever. Lesson: verify the raw calldata on independent hardware.',
    references: [{ label: 'Sygnia / Verichains investigation summary (Safe)', url: 'https://x.com/safe/status/1894768522720350673' }],
  },
  {
    name: 'Bitcoin value overflow incident',
    date: '2010-08-15',
    category: 'client-bug',
    vulnClass: 'inflation-validation-bug',
    technique: 'Integer overflow in output value check',
    chains: ['Bitcoin'],
    amountUsd: null,
    rootCause:
      'Block 74638 contained a transaction creating 184,467,440,737 BTC. The output-sum check overflowed a 64-bit integer, so the client accepted it as valid. A patched client (0.3.10) and a soft fork orphaned the chain within ~5 hours. (CVE-2010-5139)',
    references: [
      { label: 'Bitcoin Wiki: Value overflow incident', url: 'https://en.bitcoin.it/wiki/Value_overflow_incident' },
      { label: 'NVD CVE-2010-5139', url: 'https://nvd.nist.gov/vuln/detail/CVE-2010-5139' },
    ],
  },
  {
    name: 'Bitcoin 0.8 chain fork',
    date: '2013-03-11',
    category: 'client-bug',
    vulnClass: 'consensus-split',
    technique: 'Consensus split between client versions',
    chains: ['Bitcoin'],
    amountUsd: 10000,
    rootCause:
      'Bitcoin 0.8 switched from BerkeleyDB to LevelDB. A large block exceeded BerkeleyDB lock limits in 0.7 nodes, so 0.7 rejected it and 0.8 accepted it, splitting the chain. Miners coordinated a downgrade; one merchant lost ~$10k to a double-spend. (BIP 50, CVE-2013-3220)',
    references: [{ label: 'BIP 50 post-mortem', url: 'https://github.com/bitcoin/bips/blob/master/bip-0050.mediawiki' }],
  },
  {
    name: 'Ethereum Shanghai DoS attacks',
    date: '2016-09-22',
    category: 'client-bug',
    vulnClass: 'node-dos-halt',
    technique: 'Underpriced opcodes (EXTCODESIZE, SUICIDE)',
    chains: ['Ethereum'],
    amountUsd: null,
    rootCause:
      'Attackers spammed transactions calling underpriced opcodes that forced heavy disk I/O, slowing block processing dramatically during Devcon 2. Fixed by gas repricing in the Tangerine Whistle (EIP-150) and Spurious Dragon (EIP-158/161) hard forks.',
    references: [
      { label: 'EIP-150', url: 'https://eips.ethereum.org/EIPS/eip-150' },
      { label: 'Ethereum blog: transaction spam attack', url: 'https://blog.ethereum.org/2016/09/22/transaction-spam-attack-next-steps' },
    ],
  },
  {
    name: 'Bitcoin CVE-2018-17144 inflation bug',
    date: '2018-09-18',
    category: 'client-bug',
    vulnClass: 'inflation-validation-bug',
    technique: 'Duplicate input not checked (inflation / DoS)',
    chains: ['Bitcoin'],
    amountUsd: null,
    rootCause:
      'An optimization in 0.14 removed a duplicate-input check in block validation. Versions 0.15–0.16.2 would have accepted a block spending the same output twice, inflating supply; 0.14 nodes would crash. Patched and disclosed before exploitation.',
    references: [{ label: 'Bitcoin Core disclosure', url: 'https://bitcoincore.org/en/2018/09/20/notice/' }],
  },
  {
    name: 'Zcash counterfeiting vulnerability',
    date: '2018-03-01',
    category: 'client-bug',
    vulnClass: 'inflation-validation-bug',
    technique: 'Flaw in BCTV14 zk-SNARK parameter setup',
    chains: ['Zcash'],
    amountUsd: null,
    rootCause:
      'Extra elements in the original Sprout trusted-setup parameters would have allowed undetectable creation of counterfeit shielded ZEC. Discovered internally in March 2018, silently fixed by the Sapling upgrade, disclosed in Feb 2019 (CVE-2019-7167).',
    references: [{ label: 'Zcash disclosure', url: 'https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/' }],
  },
  {
    name: 'Ethereum mainnet chain split (old Geth)',
    date: '2020-11-11',
    category: 'client-bug',
    vulnClass: 'consensus-split',
    technique: 'Silently patched consensus bug; un-upgraded nodes forked',
    chains: ['Ethereum'],
    amountUsd: null,
    rootCause:
      'A consensus bug fixed silently in Geth v1.9.17 was triggered on mainnet. Infura and others running older Geth followed a minority fork, breaking MetaMask, Binance withdrawals and many dapps for hours. Lesson: silent fixes require everyone to upgrade.',
    references: [{ label: 'Infura post-mortem', url: 'https://blog.infura.io/post/infura-mainnet-outage-post-mortem-2020-11-11' }],
  },
  {
    name: 'Geth RETURNDATA consensus split',
    date: '2021-08-27',
    category: 'client-bug',
    vulnClass: 'consensus-split',
    technique: 'Memory corruption in precompile datacopy',
    chains: ['Ethereum'],
    amountUsd: null,
    rootCause:
      'A crafted transaction exploited CVE-2021-39137, where Geth could corrupt RETURNDATA after a datacopy precompile call. Unpatched Geth nodes forked away from patched nodes and other clients; client diversity limited the damage.',
    references: [{ label: 'Geth vulnerability disclosure', url: 'https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq' }],
  },
  {
    name: 'Solana 17-hour outage',
    date: '2021-09-14',
    category: 'client-bug',
    vulnClass: 'node-dos-halt',
    technique: 'Transaction flood exhausts validator memory',
    chains: ['Solana'],
    amountUsd: null,
    rootCause:
      'Bots spammed ~400k TPS of transactions at the Grape Protocol IDO. Validators exhausted memory, forked and failed to reach consensus; the network halted ~17 hours and required a coordinated restart. Led to QUIC, stake-weighted QoS and fee markets.',
    references: [{ label: 'Solana outage report', url: 'https://solana.com/news/9-14-network-outage-initial-overview' }],
  },
  {
    name: 'Polygon Genesis contract bug',
    date: '2021-12-03',
    category: 'access-control',
    vulnClass: 'missing-access-modifier',
    technique: 'Missing balance check in MRC20 transfer-with-signature',
    chains: ['Polygon'],
    amountUsd: 2040000,
    rootCause:
      'The native MATIC (MRC20) system contract failed to validate the signer and balance in transferWithSig, putting ~9.2B MATIC at risk. Whitehats reported it; an attacker stole ~801,601 MATIC before a hard fork patched it.',
    references: [{ label: 'Immunefi bugfix review', url: 'https://medium.com/immunefi/polygon-lack-of-balance-check-bugfix-postmortem-2-2m-bounty-64ec66c24c7d' }],
  },
  {
    name: 'Optimism infinite ETH bug (Geth fork)',
    date: '2022-02-02',
    category: 'client-bug',
    vulnClass: 'inflation-validation-bug',
    technique: 'SELFDESTRUCT not clearing OVM balance',
    chains: ['Optimism'],
    amountUsd: null,
    rootCause:
      "Optimism's l2geth stored ETH balances as an ERC20 and failed to zero them on SELFDESTRUCT, letting a contract duplicate its balance repeatedly. Reported by saurik (Jay Freeman) for a $2M bounty and patched before exploitation.",
    references: [{ label: 'saurik write-up', url: 'https://www.saurik.com/optimism.html' }],
  },
  {
    name: 'Cosmos IBC Dragonberry (ICS23 proof forgery)',
    date: '2022-10-14',
    category: 'bridge-crosschain',
    vulnClass: 'message-verification-bypass',
    technique: 'ICS23 Merkle proof verification flaw',
    chains: ['Cosmos'],
    amountUsd: null,
    rootCause:
      'The same class of IAVL/ICS23 proof-verification flaw exploited in the BNB Bridge hack affected IBC across Cosmos chains. Coordinated, quiet patching of dozens of chains ("Dragonberry") prevented exploitation.',
    references: [{ label: 'Cosmos security advisory Dragonberry', url: 'https://forum.cosmos.network/t/ibc-security-advisory-dragonberry/7702' }],
  },
  {
    name: 'Ethereum beacon chain finality loss',
    date: '2023-05-11',
    category: 'client-bug',
    vulnClass: 'node-dos-halt',
    technique: 'Expensive attestation processing in Prysm/Teku',
    chains: ['Ethereum'],
    amountUsd: null,
    rootCause:
      'Prysm and Teku clients became overloaded processing old-but-valid attestations, so the beacon chain lost finality twice (~25 min and ~1 hour). Blocks kept being produced thanks to client diversity; patches limited the reprocessing.',
    references: [{ label: 'Prysm post-mortem', url: 'https://offchain.medium.com/post-mortem-report-ethereum-mainnet-finality-05-11-2023-95e271dfd8b2' }],
  },
  {
    name: 'Solana mainnet halt (JIT cache bug)',
    date: '2024-02-06',
    category: 'client-bug',
    vulnClass: 'node-dos-halt',
    technique: 'Infinite recompile loop in program cache',
    chains: ['Solana'],
    amountUsd: null,
    rootCause:
      'A bug in the Agave JIT program cache caused an infinite recompile loop when a legacy loader program was invoked, stalling block production for ~5 hours until validators upgraded and restarted.',
    references: [{ label: 'Solana post-mortem', url: 'https://solana.com/news/02-06-24-solana-mainnet-beta-outage-report' }],
  },
];

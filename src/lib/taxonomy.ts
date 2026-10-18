/**
 * Crypto Regrets failure taxonomy.
 *
 * Every incident in the index is assigned exactly one primary `CategoryId`.
 * Categories are grouped into `Layer`s so we can ask "where in the stack did it break?"
 * The `as const` + `satisfies` pattern keeps ids literal types, so a typo in any
 * mapping table is a compile error rather than a silently unclassified hack.
 */

export const LAYERS = {
  'smart-contract': {
    name: 'Smart contract code',
    blurb: 'Bugs in on-chain code: the contract did exactly what it was written to do, and that was wrong.',
  },
  economic: {
    name: 'Economic & oracle design',
    blurb: 'The code is "correct" but the economic assumptions (prices, liquidity, incentives) can be bent.',
  },
  'cross-chain': {
    name: 'Bridges & cross-chain',
    blurb: 'Systems that hold assets on one chain and mint claims on another. Huge honeypots, complex trust.',
  },
  operational: {
    name: 'Keys & operational security',
    blurb: 'The chain and the code were fine; the humans, servers or keys around them were not.',
  },
  infrastructure: {
    name: 'Chain & client infrastructure',
    blurb: 'Consensus failures, node crashes, chain halts, 51% attacks and implementation bugs in the base layer.',
  },
  'trust-abuse': {
    name: 'Insider & trust abuse',
    blurb: 'Rugpulls, backdoors, governance capture: someone with power used it against users.',
  },
} as const satisfies Record<string, { name: string; blurb: string }>;

export type LayerId = keyof typeof LAYERS;

export interface Category {
  name: string;
  layer: LayerId;
  /** One-line summary shown in lists. */
  short: string;
  /** What the failure pattern is. */
  description: string;
  /** How an attack typically unfolds, step by step. */
  anatomy: string[];
  /** Concrete defensive practices for developers. */
  prevention: string[];
  /** Related OWASP Smart Contract Top 10 (2025) entries, when applicable. */
  owasp?: string[];
  /** Related SWC registry ids, when applicable. */
  swc?: string[];
}

export const CATEGORIES = {
  'access-control': {
    name: 'Access control',
    layer: 'smart-contract',
    short: 'A privileged function anyone could call.',
    description:
      'A function that moves funds, mints tokens, upgrades code or changes configuration is missing (or has a broken) authorization check. Includes unprotected initializers, uninitialized proxies, and functions that trust msg.sender/tx.origin incorrectly.',
    anatomy: [
      'Attacker scans verified contracts for external functions without onlyOwner / role checks.',
      'Calls the unprotected function directly (e.g. initialize(), setOwner(), withdrawTo()).',
      'Takes ownership or transfers balances in a single transaction.',
    ],
    prevention: [
      'Default-deny: every state-changing external function needs an explicit, tested authorization rule.',
      'Use battle-tested role libraries (OpenZeppelin AccessControl / Ownable2Step).',
      'Call _disableInitializers() in implementation constructors; initialize proxies atomically at deploy.',
      'Never use tx.origin for authorization.',
      'Write invariant tests asserting that non-privileged actors cannot change privileged state.',
    ],
    owasp: ['SC01: Access Control Vulnerabilities'],
    swc: ['SWC-105', 'SWC-106', 'SWC-115', 'SWC-118'],
  },
  'arbitrary-call': {
    name: 'Arbitrary external call & approval abuse',
    layer: 'smart-contract',
    short: 'Contract makes a call whose target or calldata the attacker controls.',
    description:
      'A router, zap, aggregator or helper contract lets the caller choose the target address and calldata of an external call. Because users granted that contract token approvals, the attacker makes it call transferFrom(victim, attacker, amount).',
    anatomy: [
      'Users approve a helper contract (often with unlimited allowance).',
      'Helper exposes a function that performs target.call(data) with user-supplied target/data.',
      'Attacker passes token.transferFrom(victim, attacker, balance) and drains every approver.',
    ],
    prevention: [
      'Never forward arbitrary calldata; whitelist targets and function selectors.',
      'Pull tokens from msg.sender only, never from an address parameter.',
      'Prefer exact approvals or Permit2 with short expiries over unlimited approvals.',
      'Check return values of low-level calls.',
    ],
    owasp: ['SC06: Unchecked External Calls', 'SC04: Lack of Input Validation'],
    swc: ['SWC-104', 'SWC-112'],
  },
  reentrancy: {
    name: 'Reentrancy',
    layer: 'smart-contract',
    short: 'External call lets the attacker re-enter before state is updated.',
    description:
      'The contract hands control to an untrusted address (ETH transfer, ERC777/ERC721/ERC1155 hooks, callbacks, flash-loan receivers) before finishing its own state updates, so the attacker re-enters and acts on stale state. Variants: single-function, cross-function, cross-contract and read-only reentrancy.',
    anatomy: [
      'Attacker deploys a contract with a fallback / hook function.',
      'Calls withdraw(); the victim sends funds before zeroing the balance.',
      'The hook calls withdraw() again (or a view the victim relies on) and repeats until drained.',
    ],
    prevention: [
      'Checks-Effects-Interactions: update all state before any external call.',
      'Use ReentrancyGuard (nonReentrant), including across sibling functions sharing state.',
      'Treat token hooks (ERC777 tokensReceived, onERC721Received) as external calls.',
      'Guard view functions used by other protocols against read-only reentrancy.',
    ],
    owasp: ['SC05: Reentrancy Attacks'],
    swc: ['SWC-107'],
  },
  'input-validation': {
    name: 'Input validation',
    layer: 'smart-contract',
    short: 'Parameters were trusted without being checked.',
    description:
      'Missing checks on user-supplied values: zero amounts, fake token or pool addresses, empty arrays, duplicated ids, unchecked array lengths, or crafted structs that the contract treats as genuine.',
    anatomy: [
      'Attacker deploys a fake token/pool contract that returns whatever the victim expects.',
      'Passes it as a parameter; the victim never checks it against a registry.',
      'Victim credits the attacker with real assets.',
    ],
    prevention: [
      'Validate every address parameter against an allow-list or factory registry.',
      'Bounds-check amounts, lengths and indices; reject duplicates.',
      'Fuzz entry points with adversarial inputs (Foundry/Echidna/Medusa).',
    ],
    owasp: ['SC04: Lack of Input Validation'],
    swc: ['SWC-123'],
  },
  'logic-error': {
    name: 'Business logic flaw',
    layer: 'smart-contract',
    short: 'The protocol rules themselves were wrong.',
    description:
      'The code implements a flawed specification: reward math that can be farmed, withdraw paths that skip checks, liquidation logic that pays out twice, swap logic that mis-handles fees, state machines with unintended transitions.',
    anatomy: [
      'Attacker reads the protocol and finds a sequence of legitimate calls with an unintended outcome.',
      'Often amplified with a flash loan to make the edge case profitable.',
      'Repeats the sequence in one transaction until liquidity runs out.',
    ],
    prevention: [
      'Write the specification first, then encode invariants ("total shares * price <= assets").',
      'Invariant/property-based testing and formal verification of core accounting.',
      'Multiple independent audits plus a bug bounty sized to TVL.',
      'Gradual TVL caps and circuit breakers for new code.',
    ],
    owasp: ['SC03: Logic Errors'],
  },
  'accounting-math': {
    name: 'Token & share accounting / arithmetic',
    layer: 'smart-contract',
    short: 'Rounding, overflow, donation and share-price bugs.',
    description:
      'Numeric bugs in balances, share prices and conversions: integer overflow/underflow (pre-0.8 Solidity), precision loss, rounding in the wrong direction, ERC4626 first-depositor / donation inflation, fee-on-transfer and rebasing token mismatches, infinite mint.',
    anatomy: [
      'Attacker manipulates a ratio (e.g. donates tokens to a vault with tiny supply).',
      'Exploits rounding so that a deposit mints 0 shares or a withdrawal returns too much.',
      'Repeats with flash-loaned capital, extracting the rounding error each loop.',
    ],
    prevention: [
      'Use Solidity >= 0.8 checked math; audit every unchecked{} block.',
      'Always round in favor of the protocol (down on mint/withdraw-out, up on burn/withdraw-in).',
      'Use virtual shares/assets offsets or dead shares for ERC4626 vaults.',
      'Account balances internally instead of trusting balanceOf().',
      'Explicitly support or reject fee-on-transfer and rebasing tokens.',
    ],
    owasp: ['SC07: Arithmetic Errors', 'SC08: Integer Overflow and Underflow'],
    swc: ['SWC-101'],
  },
  'oracle-manipulation': {
    name: 'Oracle & price manipulation',
    layer: 'economic',
    short: 'Protocol read a price the attacker could move.',
    description:
      'A lending market, vault or AMM uses a manipulable price (spot reserves of a thin pool, its own LP token price, a stale or misconfigured feed). With a flash loan the attacker moves the price within one transaction, borrows or redeems against it, and restores it.',
    anatomy: [
      'Flash-borrow a large amount of asset A.',
      'Swap into a thin pool to inflate the spot price of asset B.',
      'Use B as overvalued collateral (or redeem at the skewed price) in the victim protocol.',
      'Unwind the swap, repay the loan, keep the difference.',
    ],
    prevention: [
      'Never use spot AMM reserves as an oracle; use TWAPs or decentralized feeds (Chainlink, Pyth, RedStone).',
      'Check feed staleness, sequencer uptime (L2) and min/max price bounds.',
      'Use multiple oracle sources with deviation checks.',
      'Model flash-loan-sized capital in economic reviews.',
    ],
    owasp: ['SC02: Price Oracle Manipulation', 'SC10: Flash Loan Attacks'],
  },
  'market-manipulation': {
    name: 'Market & economic manipulation',
    layer: 'economic',
    short: 'Thin markets and incentives exploited without a code bug.',
    description:
      'Attacks on economic design rather than code: pumping illiquid collateral on CEXs to borrow against it (e.g. Mango Markets), depegs and bank runs, MEV/sandwich extraction, liquidation cascades.',
    anatomy: [
      'Accumulate a large position in an illiquid asset.',
      'Pump its price across the venues the oracle reads.',
      'Borrow everything else against the inflated collateral and walk away.',
    ],
    prevention: [
      'Per-asset borrow caps and collateral factors tied to real on-chain liquidity.',
      'Isolated markets for long-tail assets.',
      'Stress-test parameters against coordinated manipulation.',
    ],
    owasp: ['SC10: Flash Loan Attacks'],
  },
  'bridge-crosschain': {
    name: 'Bridge & cross-chain verification',
    layer: 'cross-chain',
    short: 'Forged messages or proofs accepted by a bridge.',
    description:
      'A bridge accepts a deposit or message that never happened on the source chain: forged Merkle proofs, an initialized-to-zero trusted root, spoofed signer sets, mis-verified light clients, or unbacked mints on the destination chain.',
    anatomy: [
      'Attacker crafts a withdrawal message / proof for funds never deposited.',
      'Bridge verification has a gap (zero root, wrong sysvar, missing signer check).',
      'Destination contract releases or mints assets against the forged message.',
    ],
    prevention: [
      'Treat bridge message verification as the single most critical code path; formally verify it.',
      'Rate limits and withdrawal delays on large outflows.',
      'Independent monitoring of mint vs. lock parity across chains.',
      'Defense in depth: multiple verification paths (ZK + committee) for high-value routes.',
    ],
  },
  'signature-crypto': {
    name: 'Signatures & cryptography',
    layer: 'smart-contract',
    short: 'Signature replay, malleability or weak key generation.',
    description:
      'Broken use of cryptography: signatures that can be replayed across chains/contracts, missing nonce or deadline, ecrecover returning address(0), weak randomness in key generation (Profanity vanity addresses), or flawed verification logic.',
    anatomy: [
      'Attacker obtains a valid signature (on-chain, mempool or another chain).',
      'Replays it where domain separation / nonces are missing, or brute-forces a weak key.',
      'Executes privileged actions as the signer.',
    ],
    prevention: [
      'Use EIP-712 with chainId and verifyingContract, plus per-signer nonces and deadlines.',
      'Use OpenZeppelin ECDSA (rejects malleable signatures and address(0)).',
      'Never generate keys with non-cryptographic RNGs or vanity tools with small seed space.',
    ],
    owasp: ['SC09: Insecure Randomness'],
    swc: ['SWC-117', 'SWC-120', 'SWC-121', 'SWC-122'],
  },
  'key-compromise': {
    name: 'Private key compromise',
    layer: 'operational',
    short: 'Hot wallet, deployer, multisig or validator keys stolen.',
    description:
      'Attackers obtain keys that control funds or contracts: exchange hot wallets, deployer/admin EOAs, a majority of multisig or validator keys. The dominant cause of losses at centralized exchanges and the largest losses overall.',
    anatomy: [
      'Initial access via phishing, malware, a compromised employee machine or a leaked secret.',
      'Lateral movement to the systems that hold or can sign with keys.',
      'Signs withdrawal transactions that look legitimate to the chain.',
    ],
    prevention: [
      'Keep the bulk of funds in cold storage; hot-wallet limits sized to daily need.',
      'Multisig / MPC with independent signers, devices and organizations.',
      'Hardware security modules; never store keys in env vars, repos or CI.',
      'Timelocks and withdrawal velocity limits so a single compromise is not total.',
    ],
  },
  'social-engineering': {
    name: 'Social engineering & phishing',
    layer: 'operational',
    short: 'Humans tricked into signing or running something malicious.',
    description:
      'Fake job offers carrying malware, impersonation of partners, signer phishing (blind-signing a malicious transaction), address poisoning, and drainer kits. Increasingly attributed to state-sponsored groups.',
    anatomy: [
      'Attacker builds trust (fake recruiter, investor, auditor or support agent).',
      'Victim opens a malicious file or signs a transaction they cannot read.',
      'Attacker uses the access or signature to move funds.',
    ],
    prevention: [
      'Never blind-sign: decode and simulate every transaction on an independent device.',
      'Dedicated, locked-down signing machines.',
      'Security awareness training aimed at targeted attacks, not generic phishing.',
      'Out-of-band verification for any request involving keys or transfers.',
    ],
  },
  'frontend-infra': {
    name: 'Infrastructure, frontend & supply chain',
    layer: 'operational',
    short: 'Servers, DNS, CDN, npm packages or cloud accounts were breached.',
    description:
      'The contracts are fine, but the systems around them are compromised: breached exchange servers and hosting providers (common in 2011–2014), DNS hijacks, scripts injected via a CDN or third-party analytics, malicious npm package releases, compromised cloud or API keys, or a signing UI swapped for a malicious one.',
    anatomy: [
      'Attacker takes over the DNS registrar, CDN, cloud account or a package dependency.',
      'Serves a modified frontend that requests approvals to an attacker address.',
      'Users sign; funds flow to the attacker until the site is restored.',
    ],
    prevention: [
      'Registrar lock, DNSSEC, and hardware 2FA on registrar and cloud accounts.',
      'Subresource Integrity and strict CSP; pin and audit dependencies; lockfiles in CI.',
      'Show human-readable transaction intent; wallets should simulate and warn.',
    ],
  },
  governance: {
    name: 'Governance attack',
    layer: 'trust-abuse',
    short: 'Voting power borrowed or bought to pass a malicious proposal.',
    description:
      'An attacker gains enough voting power (often via flash loan or cheap tokens) to pass a proposal that transfers the treasury or upgrades contracts to malicious code; or hides malicious code in an innocuous-looking proposal.',
    anatomy: [
      'Acquire voting power (flash loan, market buy, or delegation farming).',
      'Submit a proposal containing a hidden malicious action.',
      'Vote and execute before defenders react.',
    ],
    prevention: [
      'Snapshot voting power at proposal creation, not at vote time.',
      'Timelocks between passing and execution, with a guardian veto.',
      'Quorum and proposal thresholds that cannot be met with flash-loanable liquidity.',
    ],
  },
  rugpull: {
    name: 'Rugpull & insider theft',
    layer: 'trust-abuse',
    short: 'Team or insider drained the protocol.',
    description:
      'The people with privileged access are the attackers: liquidity pulled, backdoored contracts, hidden mint functions, admin drains, or exit scams by exchange operators.',
    anatomy: [
      'Deploy with hidden privileges (unrestricted mint, upgradeable owner, fee switch).',
      'Attract deposits and liquidity.',
      'Use the privilege to drain and disappear.',
    ],
    prevention: [
      'As a user/integrator: inspect owner privileges, upgradeability, and timelocks before depositing.',
      'As a builder: renounce or timelock privileges and publish the trust model.',
    ],
  },
  'consensus-attack': {
    name: '51% & consensus attacks',
    layer: 'infrastructure',
    short: 'Majority hash/stake rented to rewrite history.',
    description:
      'An attacker controls enough hashrate or stake to reorganize the chain and double-spend deposits at exchanges. Typical against small proof-of-work chains whose hashrate can be rented (NiceHash). Also includes timestamp manipulation (time-warp) attacks.',
    anatomy: [
      'Rent hashrate exceeding the honest network.',
      'Deposit coins at an exchange while privately mining a competing chain.',
      'Withdraw other assets, then publish the longer chain that erases the deposit.',
    ],
    prevention: [
      'Exchanges: confirmation requirements proportional to the cost of renting hashrate.',
      'Chains: merged mining, checkpointing, or migration away from rentable PoW algorithms.',
    ],
  },
  'client-bug': {
    name: 'Client & consensus implementation bug',
    layer: 'infrastructure',
    short: 'Node software bug: crashes, chain splits, inflation, halts.',
    description:
      'Bugs in blockchain node implementations: value overflow and inflation bugs, consensus splits between client versions, remote crashes and DoS, chain halts from non-determinism, and resource exhaustion through the P2P layer.',
    anatomy: [
      'Attacker (or ordinary traffic) triggers an edge case in node software.',
      'Nodes crash, disagree on validity, or accept invalid state.',
      'Network halts or splits; in the worst case invalid coins are created.',
    ],
    prevention: [
      'Client diversity, so one bug cannot finalize an invalid chain.',
      'Differential fuzzing across client implementations.',
      'Bounded resource use on every P2P message type.',
      'Coordinated disclosure processes and staged upgrades.',
    ],
  },
  unknown: {
    name: 'Unclassified',
    layer: 'smart-contract',
    short: 'Root cause not publicly determined.',
    description: 'Public sources did not disclose enough detail to classify this incident.',
    anatomy: [],
    prevention: [],
  },
} as const satisfies Record<string, Category>;

export type CategoryId = keyof typeof CATEGORIES;
export const CATEGORY_IDS = Object.keys(CATEGORIES) as CategoryId[];

export function categoriesInLayer(layer: LayerId): CategoryId[] {
  return CATEGORY_IDS.filter((id) => CATEGORIES[id].layer === layer);
}

/**
 * Historical eras used to tell the story of how failure patterns evolved.
 * Year ranges are inclusive.
 */
export const ERAS = [
  {
    id: 'genesis',
    name: 'Genesis & first exchanges',
    from: 2009,
    to: 2013,
    summary:
      'Bitcoin is a hobbyist experiment. The first critical bug (the 2010 value-overflow incident) mints 184 billion BTC. Early exchanges and web wallets run on improvised infrastructure, with keys on internet-facing servers.',
  },
  {
    id: 'custodial',
    name: 'Custodial collapse',
    from: 2014,
    to: 2016,
    summary:
      'Mt. Gox collapses and Bitfinex loses 120k BTC: the lesson is that whoever holds the keys holds the risk. Ethereum launches, and The DAO reentrancy forces a contentious hard fork.',
  },
  {
    id: 'ico',
    name: 'ICO boom & smart-contract awakening',
    from: 2017,
    to: 2019,
    summary:
      'Thousands of tokens launched by inexperienced teams. Parity multisig bugs freeze and steal hundreds of millions; batchOverflow-style integer bugs; 51% attacks on small PoW chains; Asian exchange hot wallets drained.',
  },
  {
    id: 'defi-summer',
    name: 'DeFi summer & flash loans',
    from: 2020,
    to: 2021,
    summary:
      'Composability plus flash loans means anyone can deploy millions of dollars of capital for one transaction. Oracle manipulation and economic exploits explode; ERC777 hooks revive reentrancy.',
  },
  {
    id: 'bridges',
    name: 'The bridge catastrophe',
    from: 2022,
    to: 2022,
    summary:
      'Ronin ($624M), Wormhole ($326M), Nomad ($190M) and BNB Bridge ($570M). Cross-chain bridges become the largest honeypots, and state-sponsored groups (Lazarus) become the most prolific attackers.',
  },
  {
    id: 'opsec',
    name: 'Operational security era',
    from: 2023,
    to: 2026,
    summary:
      'Audits make shallow contract bugs rarer in major protocols. The biggest losses now come from compromised keys, signer phishing and supply-chain attacks on signing UIs (Bybit, $1.4B), while long-tail forks keep repeating old smart-contract bugs.',
  },
] as const;

export type EraId = (typeof ERAS)[number]['id'];

export function eraForYear(year: number): EraId {
  const era = ERAS.find((e) => year >= e.from && year <= e.to);
  return era ? era.id : year < 2009 ? 'genesis' : 'opsec';
}

import type { CategoryId } from './taxonomy';

/** How to tell each pattern apart from its neighbours. Shown on pattern pages. */
export type Rubric = { what: string; not_for: string; examples: string[] };

export const RUBRIC: Record<Exclude<CategoryId, 'unknown'>, Rubric> = {
  'access-control': {
    what: 'A privileged contract function (withdraw, mint, upgrade, set owner, initialize, configure) was callable by anyone because an authorization check was missing or wrong.',
    not_for: 'Stolen or leaked private keys (key-compromise); a router that forwards attacker-chosen calldata (arbitrary-call); a check that exists but trusts a fake token or pool (input-validation).',
    examples: ['Unprotected initialize() let attacker become owner', 'Anyone could call setPrice()', 'Uninitialized proxy implementation taken over'],
  },
  'arbitrary-call': {
    what: 'A contract executes an external call whose target or calldata the attacker controls, typically abused to call transferFrom on tokens users had approved to that contract.',
    not_for: 'A missing onlyOwner on an ordinary admin function (access-control); a fake token passed as a parameter (input-validation).',
    examples: ['Aggregator swap() accepted arbitrary calldata and drained user approvals', 'Zap contract call(target, data) with user-supplied target'],
  },
  reentrancy: {
    what: 'The contract made an external call (ETH transfer, token hook such as ERC777/ERC721 callbacks, flash-loan callback) before updating its own state, and the attacker re-entered to act on stale state, including read-only reentrancy.',
    not_for: 'Callbacks used only to manipulate a price (oracle-manipulation); share-price rounding without re-entry (accounting-math).',
    examples: ['withdraw() sent ETH before zeroing balance', 'ERC777 tokensReceived hook re-entered a lending market', 'Read-only reentrancy on a Curve pool get_virtual_price'],
  },
  'input-validation': {
    what: 'The contract trusted a user-supplied parameter without checking it: fake token or pool addresses, unchecked array lengths or indices, zero or duplicate values, crafted structs or messages.',
    not_for: 'Missing caller authorization (access-control); cryptographic signature checks (signature-crypto).',
    examples: ['Passing a fake pool contract that reports inflated reserves', 'Duplicate ids in an array counted twice', 'Unchecked user-supplied market address'],
  },
  'logic-error': {
    what: 'The protocol rules themselves are wrong: reward, liquidation, withdrawal, staking, swap-fee or state-machine logic that lets a sequence of legitimate calls produce an unintended payout.',
    not_for: 'Numeric rounding, overflow or share-price inflation (accounting-math); price feeds that can be moved (oracle-manipulation); missing authorization (access-control).',
    examples: ['Rewards claimable multiple times for the same deposit', 'Self-liquidation pays more than the debt', 'Fee charged on the wrong side of a swap'],
  },
  'accounting-math': {
    what: 'Arithmetic and balance-accounting bugs: integer overflow/underflow, precision loss, rounding in the wrong direction, vault share inflation or donation attacks, fee-on-transfer or rebasing token mismatches, infinite mint from a bad balance update.',
    not_for: 'Reward or liquidation rules that are wrong by design (logic-error); prices read from a manipulable pool (oracle-manipulation).',
    examples: ['batchTransfer integer overflow minted huge balances', 'First depositor donated tokens to inflate ERC4626 share price', 'divCeil rounding let redeem return more than deposited'],
  },
  'oracle-manipulation': {
    what: 'The protocol read a price the attacker could move within the attack: spot AMM reserves, its own LP token price, a thin pool, or a stale or misconfigured price feed. Usually funded with a flash loan.',
    not_for: 'Pumping an illiquid asset across real markets over hours or days (market-manipulation); a flash loan used only as working capital for another bug (classify by that bug).',
    examples: ['Lending market priced collateral from a Uniswap pair the attacker skewed', 'Stale Chainlink price accepted', 'Vault used balanceOf-based price per share'],
  },
  'market-manipulation': {
    what: 'An economic attack without a code bug: pumping a thin asset on external markets to borrow against it, depeg or bank-run dynamics, liquidation cascades, MEV extraction.',
    not_for: 'Single-transaction price moves of an on-chain pool the protocol reads (oracle-manipulation).',
    examples: ['Mango Markets: pumped MNGO perp price and borrowed treasury', 'Coordinated pump of an illiquid collateral token'],
  },
  'bridge-crosschain': {
    what: 'A cross-chain bridge or messaging layer accepted a deposit, proof or message that never happened on the source chain: forged Merkle proofs, zero or wrong trusted root, spoofed verification accounts, light-client or relayer verification flaws, unbacked mints on the destination chain.',
    not_for: 'Bridge validator or multisig keys that were stolen (key-compromise); 51% attacks on a base chain (consensus-attack).',
    examples: ['Wormhole: spoofed sysvar skipped guardian signature check', 'Nomad: zero root made every message valid', 'Forged IAVL proof minted BNB on the bridge'],
  },
  'signature-crypto': {
    what: 'Broken use of cryptography: signatures replayable across chains or contracts, missing nonce or deadline, malleable signatures, ecrecover returning address(0), incomplete fields covered by the signature, or private keys generated with weak randomness (e.g. Profanity vanity addresses).',
    not_for: 'Keys stolen through phishing, malware or server breaches (key-compromise or social-engineering).',
    examples: ['Permit signature replayed on another chain', 'Profanity vanity address private key brute-forced', 'Signed order did not cover the recipient field'],
  },
  'key-compromise': {
    what: 'An attacker obtained private keys or signing power that control funds: exchange hot wallets, deployer or admin EOAs, a threshold of multisig or bridge validator keys. The chain and contracts worked as designed.',
    not_for: 'Keys obtained by tricking a person into running malware or signing (social-engineering); keys guessable due to weak generation (signature-crypto); breached web servers serving a malicious frontend (frontend-infra).',
    examples: ['Exchange hot wallet drained after key theft', 'Five of nine bridge validator keys compromised', 'Leaked deployer key used to upgrade contracts'],
  },
  'social-engineering': {
    what: 'A human was deceived: phishing, fake job offers carrying malware, impersonation, signers tricked into blind-signing a malicious transaction, address poisoning, wallet drainers.',
    not_for: 'Keys stolen without any deception of a person, e.g. from a hacked server (key-compromise); a hijacked website or DNS (frontend-infra).',
    examples: ['Engineer ran malware from a fake recruiter', 'Multisig signers approved a disguised delegatecall', 'Discord admin phished, drainer link posted'],
  },
  'frontend-infra': {
    what: "Infrastructure around the protocol was breached: web servers or hosting, DNS hijack, CDN or third-party script injection, malicious npm package release, compromised cloud or API accounts, exchange backend systems.",
    not_for: 'The private keys themselves being the entry point (key-compromise); a person deceived into signing (social-engineering).',
    examples: ['DNS hijack served a malicious approval page', 'Compromised Ledger Connect Kit npm release', 'Exchange servers breached and withdrawal system abused'],
  },
  governance: {
    what: 'Voting power was borrowed, bought or farmed to pass a malicious governance proposal, or a malicious payload was hidden inside a proposal.',
    not_for: 'Insiders using admin keys directly (rugpull); a missing authorization check on a governance contract function (access-control).',
    examples: ['Flash-loaned governance tokens passed a proposal draining the treasury', 'Proposal contained hidden code granting the attacker control'],
  },
  rugpull: {
    what: 'The project team or an insider stole the funds: liquidity pulled, backdoored contracts, hidden mint functions, admin drains, exit scams.',
    not_for: 'An outside attacker exploiting a bug or stealing keys.',
    examples: ['Developer removed all liquidity and disappeared', 'Hidden mint function used by the deployer'],
  },
  'consensus-attack': {
    what: 'An attacker controlled a majority of hashrate or stake to reorganize a base-layer chain and double-spend, or manipulated block timestamps (time-warp).',
    not_for: 'Bugs in node software (client-bug); bridges accepting forged messages (bridge-crosschain).',
    examples: ['51% attack on Ethereum Classic double-spent exchange deposits', 'Verge time-warp attack'],
  },
  'client-bug': {
    what: 'A bug in blockchain node or client software: value overflow or inflation bugs, consensus splits between versions, remote crashes, chain halts, resource exhaustion through the P2P layer.',
    not_for: 'Smart-contract bugs deployed on the chain; 51% attacks (consensus-attack).',
    examples: ['Bitcoin value overflow created 184 billion BTC', 'Geth bug split the chain between client versions', 'Network halted for hours after transaction flood'],
  },
};

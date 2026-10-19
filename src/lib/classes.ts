/**
 * Vulnerability classes: the fine-grained level below each failure pattern (category).
 *
 * This is the level a detection / auto-fix tool works at. Every class carries the shape of the
 * vulnerable code (or missing control), the fixed shape, signals a detector can look for, and the
 * remediation. Ids are literal types, so incident labels can never reference a class that
 * doesn't exist, and `parent` must be a real category.
 */
import type { CategoryId } from './taxonomy';

export interface Snippet {
  lang: 'solidity' | 'typescript' | 'yaml' | 'text' | 'json' | 'go' | 'rust';
  code: string;
}

export interface VulnClass {
  name: string;
  parent: Exclude<CategoryId, 'unknown'>;
  summary: string;
  cwe?: string[];
  swc?: string[];
  vulnerable?: Snippet;
  fixed?: Snippet;
  /** What a static analyzer, fuzzer or reviewer should look for. */
  detect: string[];
  /** How to remediate. */
  fix: string[];
}

export const CLASSES = {
  // ------------------------------------------------------------------ access control
  'missing-access-modifier': {
    name: 'Missing access modifier',
    parent: 'access-control',
    summary: 'A function that moves funds, mints, upgrades or reconfigures has no authorization check.',
    cwe: ['CWE-284', 'CWE-862'],
    swc: ['SWC-105', 'SWC-106'],
    vulnerable: {
      lang: 'solidity',
      code: `function setOracle(address o) external {
    oracle = IOracle(o);          // anyone can point the protocol at their own oracle
}
function sweep(IERC20 t, address to) external {
    t.transfer(to, t.balanceOf(address(this)));
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function setOracle(address o) external onlyRole(ADMIN_ROLE) {
    oracle = IOracle(o);
}
function sweep(IERC20 t, address to) external onlyOwner {
    t.safeTransfer(to, t.balanceOf(address(this)));
}`,
    },
    detect: [
      'external/public functions that write privileged state (owner, oracle, fee, implementation, mint, transfer of contract balance) without a modifier or msg.sender check',
      'functions named set*/update*/withdraw*/sweep*/mint*/burn*/upgrade* callable by an arbitrary address in a fork test',
      'invariant: an unprivileged actor can never change privileged storage slots',
    ],
    fix: ['Default-deny: add an explicit role check to every state-changing external function', 'Use OpenZeppelin AccessControl / Ownable2Step', 'Add a test per privileged function asserting it reverts for a random caller'],
  },
  'unprotected-initializer': {
    name: 'Unprotected or re-callable initializer',
    parent: 'access-control',
    summary: 'initialize() can be called by anyone, or called again, letting the caller become owner.',
    cwe: ['CWE-665'],
    swc: ['SWC-118'],
    vulnerable: {
      lang: 'solidity',
      code: `function initialize(address _owner) external {
    owner = _owner;               // no initializer guard: callable again by anyone
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function initialize(address _owner) external initializer {
    __Ownable_init(_owner);
}
constructor() { _disableInitializers(); }   // lock the implementation`,
    },
    detect: ['initialize/init/setup functions without the initializer modifier or a one-time flag', 'proxies deployed and initialized in separate transactions (front-runnable)', 'implementation contracts whose constructor does not call _disableInitializers()'],
    fix: ['Use OpenZeppelin Initializable with initializer / reinitializer(n)', 'Deploy and initialize atomically (constructor args of the proxy)', 'Disable initializers on implementation contracts'],
  },
  'uninitialized-implementation': {
    name: 'Uninitialized proxy implementation',
    parent: 'access-control',
    summary: 'The logic contract behind a proxy (or a shared library) was never initialized; an attacker takes it over and self-destructs or reconfigures it.',
    cwe: ['CWE-665'],
    swc: ['SWC-106'],
    vulnerable: {
      lang: 'solidity',
      code: `// Parity-style shared library: wallets delegatecall into it
contract WalletLibrary {
    function initWallet(address[] memory owners) public { /* sets owners */ }
    function kill(address to) external onlyOwner { selfdestruct(payable(to)); }
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `contract WalletLibrary is Initializable {
    constructor() { _disableInitializers(); }   // nobody can own the library itself
    function initWallet(address[] memory owners) public initializer { /* ... */ }
    // no selfdestruct in logic contracts
}`,
    },
    detect: ['implementation addresses whose own storage has owner == 0 / initialized == false', 'selfdestruct or delegatecall reachable in logic contracts', 'UUPS upgradeTo callable on the implementation directly'],
    fix: ['Initialize or disable initializers on every implementation at deploy time', 'Never put selfdestruct in logic contracts', 'Monitor implementation contracts, not only proxies'],
  },
  'tx-origin-auth': {
    name: 'tx.origin authentication',
    parent: 'access-control',
    summary: 'Authorization uses tx.origin, so any contract the owner interacts with can act as the owner.',
    cwe: ['CWE-477'],
    swc: ['SWC-115'],
    vulnerable: { lang: 'solidity', code: `require(tx.origin == owner, "not owner");` },
    fixed: { lang: 'solidity', code: `require(msg.sender == owner, "not owner");` },
    detect: ['any use of tx.origin in a require/if guarding state changes'],
    fix: ['Use msg.sender for authorization', 'Use tx.origin only for EOA-only checks, and prefer not to'],
  },
  'access-misconfiguration': {
    name: 'Role / permission misconfiguration',
    parent: 'access-control',
    summary: 'The checks exist, but deployment or governance granted a powerful role to the wrong address, left a stale allow-list entry, or set an unsafe parameter.',
    cwe: ['CWE-732'],
    detect: ['diff deployed role holders against the documented trust model', 'temporary allow-list entries without expiry', 'admin roles held by EOAs instead of multisig/timelock'],
    fix: ['Treat deployment scripts and role grants as audited code', 'Add expiry to temporary permissions', 'Continuously monitor role changes on-chain'],
  },

  // ------------------------------------------------------------------ arbitrary call
  'arbitrary-external-call': {
    name: 'Arbitrary external call',
    parent: 'arbitrary-call',
    summary: 'The contract calls a target and calldata supplied by the user, so it can be made to call token.transferFrom on its approvers.',
    cwe: ['CWE-20', 'CWE-829'],
    swc: ['SWC-112'],
    vulnerable: {
      lang: 'solidity',
      code: `function swap(address target, bytes calldata data) external {
    (bool ok,) = target.call(data);      // attacker passes token.transferFrom(victim, attacker, amt)
    require(ok);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `mapping(address => bool) public allowedRouter;
function swap(address target, bytes calldata data) external {
    require(allowedRouter[target], "router");
    require(bytes4(data) != IERC20.transferFrom.selector, "selector");
    (bool ok,) = target.call(data);
    require(ok);
}`,
    },
    detect: ['low-level call/delegatecall whose target or calldata derives from function parameters', 'contracts that hold user approvals AND expose generic call forwarding (routers, zaps, aggregators, multicall)'],
    fix: ['Allow-list targets and function selectors', 'Never forward arbitrary calldata from a contract that holds approvals', 'Split approval-holding and call-forwarding into separate contracts'],
  },
  'approval-drain': {
    name: 'Transfer from arbitrary address',
    parent: 'arbitrary-call',
    summary: 'A function pulls tokens from a `from` parameter instead of msg.sender, draining anyone who approved the contract.',
    cwe: ['CWE-639'],
    vulnerable: {
      lang: 'solidity',
      code: `function deposit(address from, uint256 amt) external {
    token.transferFrom(from, address(this), amt);   // pulls from any approver
    balances[msg.sender] += amt;
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function deposit(uint256 amt) external {
    token.safeTransferFrom(msg.sender, address(this), amt);
    balances[msg.sender] += amt;
}`,
    },
    detect: ['transferFrom whose first argument is not msg.sender (Slither: arbitrary-send-erc20)', 'permit + transferFrom flows where the signer is not bound to msg.sender'],
    fix: ['Pull only from msg.sender', 'Use exact approvals or Permit2 with short expiries in frontends'],
  },
  'delegatecall-injection': {
    name: 'Delegatecall to untrusted code',
    parent: 'arbitrary-call',
    summary: 'delegatecall into an address the attacker can influence runs their code with the caller\'s storage and balance.',
    cwe: ['CWE-829'],
    swc: ['SWC-112'],
    vulnerable: {
      lang: 'solidity',
      code: `function execute(address handler, bytes calldata data) external {
    handler.delegatecall(data);          // handler is user-supplied
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function execute(bytes32 handlerId, bytes calldata data) external {
    address handler = registry.handler(handlerId);   // governance-controlled registry
    require(handler != address(0));
    handler.delegatecall(data);
}`,
    },
    detect: ['delegatecall where the target is a parameter or a storage slot writable by users', 'proxy implementation slots writable outside upgrade functions (storage collision)'],
    fix: ['Delegatecall only to immutable or governance-registered addresses', 'Use EIP-1967 slots and storage-layout checks to prevent collisions'],
  },

  // ------------------------------------------------------------------ reentrancy
  'single-function-reentrancy': {
    name: 'Classic reentrancy',
    parent: 'reentrancy',
    summary: 'Value is sent before the balance is updated; the receiver re-enters the same function.',
    cwe: ['CWE-841'],
    swc: ['SWC-107'],
    vulnerable: {
      lang: 'solidity',
      code: `function withdraw() external {
    uint256 amt = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: amt}("");   // re-enters here
    require(ok);
    balances[msg.sender] = 0;
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function withdraw() external nonReentrant {
    uint256 amt = balances[msg.sender];
    balances[msg.sender] = 0;                         // effects before interactions
    (bool ok,) = msg.sender.call{value: amt}("");
    require(ok);
}`,
    },
    detect: ['external call followed by a write to state read before the call (Slither: reentrancy-eth)', 'missing nonReentrant on functions that transfer value'],
    fix: ['Checks-Effects-Interactions', 'ReentrancyGuard on every value-moving entry point'],
  },
  'cross-function-reentrancy': {
    name: 'Cross-function / cross-contract reentrancy',
    parent: 'reentrancy',
    summary: 'The attacker re-enters a different function (or sibling contract) that shares state the first function has not yet updated.',
    cwe: ['CWE-841'],
    swc: ['SWC-107'],
    vulnerable: {
      lang: 'solidity',
      code: `function borrow(uint256 amt) external nonReentrant {
    token.transfer(msg.sender, amt);        // callback → calls exitMarket() (no guard)
    debt[msg.sender] += amt;
}
function exitMarket() external { require(debt[msg.sender] == 0); /* release collateral */ }`,
    },
    fixed: {
      lang: 'solidity',
      code: `function borrow(uint256 amt) external nonReentrant {
    debt[msg.sender] += amt;                // update before transfer
    token.safeTransfer(msg.sender, amt);
}
function exitMarket() external nonReentrant { /* same lock across all entry points */ }`,
    },
    detect: ['functions that share storage where only some are nonReentrant', 'cross-contract calls into protocol siblings during an unfinished state transition'],
    fix: ['One reentrancy lock shared by every function touching the same state (or protocol-wide)', 'Update all state before any external call'],
  },
  'token-hook-reentrancy': {
    name: 'Token callback reentrancy (ERC777/721/1155)',
    parent: 'reentrancy',
    summary: 'Token standards with receiver hooks (tokensReceived, onERC721Received, onERC1155Received) hand control to the attacker mid-transfer.',
    cwe: ['CWE-841'],
    swc: ['SWC-107'],
    vulnerable: {
      lang: 'solidity',
      code: `function supply(IERC777 t, uint256 amt) external {
    uint256 before = t.balanceOf(address(this));
    t.transferFrom(msg.sender, address(this), amt);   // sender hook re-enters supply()
    credit[msg.sender] += t.balanceOf(address(this)) - before;
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function supply(IERC20 t, uint256 amt) external nonReentrant {
    require(isListed[address(t)], "token");           // vet tokens; reject hook tokens
    t.safeTransferFrom(msg.sender, address(this), amt);
    credit[msg.sender] += amt;
}`,
    },
    detect: ['_safeMint / safeTransferFrom / ERC777 transfers before state updates', 'markets that list arbitrary tokens without hook review'],
    fix: ['Treat every token transfer as an external call', 'nonReentrant + CEI around safeMint/safeTransfer', 'Allow-list tokens and exclude hook-bearing standards where unnecessary'],
  },
  'read-only-reentrancy': {
    name: 'Read-only reentrancy',
    parent: 'reentrancy',
    summary: 'During a callback, a view function (e.g. a pool\'s virtual price) returns a stale, manipulated value that another protocol uses for pricing.',
    cwe: ['CWE-841'],
    vulnerable: {
      lang: 'solidity',
      code: `// lender prices collateral from a pool view, mid-callback
uint256 price = curvePool.get_virtual_price();   // inconsistent during remove_liquidity callback`,
    },
    fixed: {
      lang: 'solidity',
      code: `// trigger the pool's reentrancy lock before reading
curvePool.remove_liquidity(0, [uint256(0), 0]);   // reverts if pool is mid-call
uint256 price = curvePool.get_virtual_price();`,
    },
    detect: ['view functions read from third-party pools during price calculations', 'pools that make external calls (ETH transfers) before updating supply/reserves'],
    fix: ['Check the source protocol\'s reentrancy lock before reading', 'Expose a nonReentrant-guarded view (lock check) in your own pools'],
  },

  // ------------------------------------------------------------------ input validation
  'unvalidated-address-input': {
    name: 'Unvalidated contract address input',
    parent: 'input-validation',
    summary: 'The function trusts a user-supplied token, pool, market or vault address, so the attacker passes a fake contract that reports whatever they want.',
    cwe: ['CWE-20'],
    vulnerable: {
      lang: 'solidity',
      code: `function redeem(IPool pool, uint256 shares) external {
    uint256 value = pool.valueOf(shares);    // fake pool returns a huge value
    usdc.transfer(msg.sender, value);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function redeem(IPool pool, uint256 shares) external {
    require(factory.isPool(address(pool)), "unknown pool");
    uint256 value = pool.valueOf(shares);
    usdc.safeTransfer(msg.sender, value);
}`,
    },
    detect: ['interface-typed parameters used for value calculations without a registry check', 'callbacks accepted from any msg.sender (e.g. uniswapV3SwapCallback without pool verification)'],
    fix: ['Validate addresses against a factory/registry', 'Verify callback callers (compute the expected pool address)'],
  },
  'missing-bounds-check': {
    name: 'Missing bounds, length or duplicate checks',
    parent: 'input-validation',
    summary: 'Arrays, amounts or ids are not checked: mismatched lengths, duplicated ids counted twice, zero amounts, out-of-range indices.',
    cwe: ['CWE-20', 'CWE-129'],
    vulnerable: {
      lang: 'solidity',
      code: `function claim(uint256[] calldata ids) external {
    for (uint i; i < ids.length; i++) total += reward[ids[i]];   // same id repeated
    token.transfer(msg.sender, total);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function claim(uint256[] calldata ids) external {
    for (uint i; i < ids.length; i++) {
        require(!claimed[ids[i]] && ownerOf(ids[i]) == msg.sender);
        claimed[ids[i]] = true;
        total += reward[ids[i]];
    }
    token.safeTransfer(msg.sender, total);
}`,
    },
    detect: ['loops over user arrays without uniqueness/ownership checks', 'parallel arrays without length equality checks', 'amount == 0 and from == to edge cases untested'],
    fix: ['Validate lengths, uniqueness, ownership and ranges at entry', 'Fuzz entry points with adversarial arrays'],
  },
  'missing-slippage-protection': {
    name: 'Missing slippage protection',
    parent: 'input-validation',
    summary: 'Swaps or deposits accept any output amount (amountOutMin = 0, no deadline), so MEV bots sandwich them.',
    cwe: ['CWE-20'],
    vulnerable: { lang: 'solidity', code: `router.swapExactTokensForTokens(amtIn, 0, path, address(this), block.timestamp);` },
    fixed: { lang: 'solidity', code: `uint256 minOut = quote(amtIn) * (10_000 - maxSlippageBps) / 10_000;   // from an oracle, not spot
router.swapExactTokensForTokens(amtIn, minOut, path, address(this), deadline);` },
    detect: ['amountOutMin/minAmount of 0 or computed from the same pool\'s spot price', 'deadline = block.timestamp', 'permissionless harvest/compound functions that swap'],
    fix: ['Derive minOut from an independent oracle', 'Let callers pass minOut and deadline', 'Restrict who can trigger protocol swaps or route through private mempools'],
  },

  // ------------------------------------------------------------------ business logic
  'reward-logic-flaw': {
    name: 'Reward / emission logic flaw',
    parent: 'logic-error',
    summary: 'Rewards can be claimed repeatedly, accrue to just-deposited funds, or be inflated by flash deposits.',
    cwe: ['CWE-840'],
    vulnerable: {
      lang: 'solidity',
      code: `function claim() external {
    uint256 r = balance[msg.sender] * rewardPerToken;   // ignores what was already paid
    token.transfer(msg.sender, r);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function claim() external updateReward(msg.sender) {
    uint256 r = rewards[msg.sender];
    rewards[msg.sender] = 0;                            // per-user checkpoint (Synthetix pattern)
    token.safeTransfer(msg.sender, r);
}`,
    },
    detect: ['reward formulas without per-user checkpoints (userRewardPerTokenPaid)', 'rewards based on current balance rather than time-weighted balance', 'same-block deposit → claim → withdraw profitable in a test'],
    fix: ['Use checkpointed accrual (rewardPerTokenStored / userRewardPerTokenPaid)', 'Time-weight balances; disallow same-block deposit/claim'],
  },
  'solvency-check-flaw': {
    name: 'Missing solvency / health check',
    parent: 'logic-error',
    summary: 'A path that changes collateral or debt skips the health-factor check (e.g. Euler donateToReserves), letting the attacker create bad debt and self-liquidate.',
    cwe: ['CWE-840'],
    vulnerable: {
      lang: 'solidity',
      code: `function donateToReserves(uint256 amt) external {
    eToken.burn(msg.sender, amt);            // reduces collateral, no health check
    reserves += amt;
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function donateToReserves(uint256 amt) external {
    eToken.burn(msg.sender, amt);
    reserves += amt;
    require(isHealthy(msg.sender), "insolvent");
}`,
    },
    detect: ['functions that change a user\'s collateral or debt without ending in a health/solvency assertion', 'invariant: no sequence of user actions creates an account with debt > collateral'],
    fix: ['Enforce health checks at the end of every collateral/debt-changing function (modifier)', 'Invariant fuzzing on solvency'],
  },
  'state-update-flaw': {
    name: 'Missing or misordered state update',
    parent: 'logic-error',
    summary: 'A state variable is not updated (or is updated in the wrong order or branch), so the same value can be withdrawn, counted or released twice.',
    cwe: ['CWE-841', 'CWE-372'],
    vulnerable: {
      lang: 'solidity',
      code: `function release(uint256 id) external {
    uint256 amt = vested(id) - released[id];
    token.transfer(owner[id], amt);         // released[id] never updated
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function release(uint256 id) external {
    uint256 amt = vested(id) - released[id];
    released[id] += amt;
    token.safeTransfer(owner[id], amt);
}`,
    },
    detect: ['values read for a payout that are not written in the same function', 'branches (e.g. amount == 0, liquidity == 0) that skip bookkeeping', 'cancel/withdraw paths that double-count already released amounts'],
    fix: ['Write state for every branch before paying out', 'Property tests: calling twice must not pay twice'],
  },
  'business-logic-flaw': {
    name: 'Other protocol logic flaw',
    parent: 'logic-error',
    summary: 'Flawed protocol rules not covered by a more specific class: fee paths, swap math, liquidation incentives, state-machine transitions.',
    cwe: ['CWE-840'],
    detect: ['write the specification and its invariants, then fuzz for violations', 'compare implementation against the whitepaper formulas'],
    fix: ['Specification-first development with invariant tests and formal verification of core accounting'],
  },

  // ------------------------------------------------------------------ arithmetic / accounting
  'integer-overflow': {
    name: 'Integer overflow / underflow',
    parent: 'accounting-math',
    summary: 'Arithmetic wraps around: pre-0.8 Solidity without SafeMath, unchecked blocks, or unsafe downcasts.',
    cwe: ['CWE-190', 'CWE-191', 'CWE-681'],
    swc: ['SWC-101'],
    vulnerable: {
      lang: 'solidity',
      code: `// BeautyChain batchTransfer (2018), Solidity 0.4
uint256 amount = uint256(cnt) * _value;     // overflows to 0 with a huge _value
require(_value > 0 && balances[msg.sender] >= amount);`,
    },
    fixed: {
      lang: 'solidity',
      code: `// Solidity >= 0.8 reverts on overflow; also check downcasts
uint256 amount = cnt * _value;
uint128 small = SafeCast.toUint128(amount);`,
    },
    detect: ['pragma < 0.8 without SafeMath', 'unchecked { } blocks containing user-controlled arithmetic', 'explicit downcasts uint256 → uintN/intN'],
    fix: ['Use Solidity >= 0.8 checked arithmetic', 'Audit every unchecked block', 'Use SafeCast for downcasts'],
  },
  'rounding-precision': {
    name: 'Rounding direction / precision loss',
    parent: 'accounting-math',
    summary: 'Division rounds in the user\'s favour, or precision is lost (divide before multiply, decimals mismatch), and the error is extracted repeatedly.',
    cwe: ['CWE-682', 'CWE-1339'],
    vulnerable: {
      lang: 'solidity',
      code: `function withdraw(uint256 assets) external {
    uint256 shares = assets * totalShares / totalAssets;   // rounds DOWN: burns too few shares
    _burn(msg.sender, shares);
    asset.transfer(msg.sender, assets);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function withdraw(uint256 assets) external {
    uint256 shares = Math.mulDiv(assets, totalShares, totalAssets, Math.Rounding.Ceil);
    _burn(msg.sender, shares);
    asset.safeTransfer(msg.sender, assets);
}`,
    },
    detect: ['division results that favour the caller (mint/withdraw out rounds up, burn/deposit in rounds down)', 'divide-before-multiply (Slither: divide-before-multiply)', 'mixing 6/8/18-decimal tokens without normalization'],
    fix: ['Always round in favour of the protocol', 'Use mulDiv with explicit rounding', 'Normalize decimals explicitly'],
  },
  'share-inflation': {
    name: 'Share inflation / donation attack',
    parent: 'accounting-math',
    summary: 'With a near-empty vault, the attacker donates assets to inflate the share price so later depositors\' shares round to zero (ERC4626 first-depositor attack and variants).',
    cwe: ['CWE-682'],
    vulnerable: {
      lang: 'solidity',
      code: `function totalAssets() public view returns (uint256) {
    return asset.balanceOf(address(this));   // donations move the share price
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `// OpenZeppelin ERC4626 with a virtual offset, or seed dead shares at deploy
function _decimalsOffset() internal pure override returns (uint8) { return 6; }`,
    },
    detect: ['share price derived from raw balanceOf', 'no minimum initial deposit / dead shares', 'empty-market lending pools (Compound forks) listed without seeding'],
    fix: ['Track assets internally instead of balanceOf', 'Virtual shares/assets offset or burn initial shares', 'Seed every new market atomically at listing'],
  },
  'balance-accounting-mismatch': {
    name: 'Balance accounting mismatch',
    parent: 'accounting-math',
    summary: 'Recorded balances diverge from real ones: fee-on-transfer, rebasing and reflection tokens, skim/sync, or balanceOf-delta accounting that can be gamed.',
    cwe: ['CWE-682'],
    vulnerable: {
      lang: 'solidity',
      code: `function deposit(uint256 amt) external {
    token.transferFrom(msg.sender, address(this), amt);   // fee-on-transfer: receives less
    balances[msg.sender] += amt;
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function deposit(uint256 amt) external nonReentrant {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amt);
    balances[msg.sender] += token.balanceOf(address(this)) - before;
}`,
    },
    detect: ['credits based on the requested amount, not the received amount', 'pairs/pools listing deflationary or reflection tokens', 'public skim/sync reachable mid-attack'],
    fix: ['Credit the measured received amount (with a reentrancy guard)', 'Explicitly reject unsupported token types'],
  },
  'unbacked-mint': {
    name: 'Unbacked / infinite mint',
    parent: 'accounting-math',
    summary: 'A minting path creates tokens without the backing being deposited, often from a missing collateral check or an inconsistent balance update.',
    cwe: ['CWE-840'],
    vulnerable: {
      lang: 'solidity',
      code: `function mintFor(address to, uint256 amt, bytes calldata proof) external {
    if (proof.length == 0) return _mint(to, amt);   // fallback path skips collateral check
    ...
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function mintFor(address to, uint256 amt, bytes calldata proof) external {
    require(verifyCollateral(to, amt, proof), "unbacked");
    _mint(to, amt);
}`,
    },
    detect: ['every _mint call path, and whether each enforces backing', 'invariant: totalSupply <= collateral value / ratio'],
    fix: ['Single audited mint path with a supply-vs-collateral invariant', 'Mint caps and rate limits'],
  },

  // ------------------------------------------------------------------ oracle
  'spot-price-oracle': {
    name: 'Spot-price oracle',
    parent: 'oracle-manipulation',
    summary: 'The protocol reads a price from AMM reserves (getReserves, slot0, balanceOf ratios) that a flash loan can move within one transaction.',
    cwe: ['CWE-1339'],
    vulnerable: {
      lang: 'solidity',
      code: `(uint112 r0, uint112 r1,) = pair.getReserves();
uint256 price = r1 * 1e18 / r0;              // moved by one large swap`,
    },
    fixed: {
      lang: 'solidity',
      code: `(, int256 answer,, uint256 updatedAt,) = chainlinkFeed.latestRoundData();
require(answer > 0 && block.timestamp - updatedAt < MAX_DELAY, "stale");
uint256 price = uint256(answer);             // or a sufficiently long TWAP`,
    },
    detect: ['getReserves / slot0 / balanceOf-ratio used in valuation, collateral or minting logic', 'price reads with no TWAP window or deviation bound'],
    fix: ['Use decentralized feeds or long-window TWAPs', 'Bound deviation between sources', 'Simulate flash-loan-sized trades in tests'],
  },
  'share-price-oracle': {
    name: 'Manipulable LP / vault share price',
    parent: 'oracle-manipulation',
    summary: 'Collateral is valued by an LP token or vault share price computed from balances that can be donated to or skewed (e.g. pricePerShare = balance / supply).',
    cwe: ['CWE-1339'],
    vulnerable: { lang: 'solidity', code: `uint256 lpPrice = (reserve0 * p0 + reserve1 * p1) / lp.totalSupply();   // reserves skewable` },
    fixed: { lang: 'solidity', code: `// fair LP pricing (Alpha Homora): 2 * sqrt(r0 * r1) * sqrt(p0 * p1) / totalSupply
uint256 lpPrice = 2 * Math.sqrt(r0 * r1) * Math.sqrt(p0 * p1) / lp.totalSupply();` },
    detect: ['valuation of LP or vault tokens from current reserves/balances', 'pricePerShare consumed by another protocol as collateral price'],
    fix: ['Fair-reserve LP pricing', 'Rate-limit share-price changes; use internal accounting'],
  },
  'stale-misconfigured-feed': {
    name: 'Stale or misconfigured price feed',
    parent: 'oracle-manipulation',
    summary: 'A feed is stale, reports a wrong pair or decimals, is hard-coded, or lacks bounds, so assets are mispriced without anyone moving a market.',
    cwe: ['CWE-754'],
    vulnerable: { lang: 'solidity', code: `(, int256 p,,,) = feed.latestRoundData();   // no staleness, sign or sequencer check
return uint256(p);` },
    fixed: { lang: 'solidity', code: `(, int256 p,, uint256 t,) = feed.latestRoundData();
require(p > 0 && block.timestamp - t <= heartbeat, "stale");
require(sequencerUp(), "L2 down");
return uint256(p) * 10 ** (18 - feed.decimals());` },
    detect: ['latestRoundData without updatedAt / answer checks', 'feeds for a different asset (e.g. using an ETH feed for an LST) or wrong decimals', 'L2 deployments without a sequencer-uptime check'],
    fix: ['Validate freshness, sign, decimals and sequencer status', 'Circuit breakers on sudden price moves'],
  },

  // ------------------------------------------------------------------ market manipulation
  'illiquid-collateral-pump': {
    name: 'Illiquid collateral pump',
    parent: 'market-manipulation',
    summary: 'The attacker pumps a thin asset across the venues the oracle reads, then borrows real assets against it (Mango Markets).',
    cwe: ['CWE-1339'],
    detect: ['collateral factors not tied to on-chain liquidity depth', 'no per-asset borrow or supply caps'],
    fix: ['Liquidity-aware collateral factors and caps', 'Isolated markets for long-tail assets'],
  },
  'mev-frontrunning': {
    name: 'MEV / front-running',
    parent: 'market-manipulation',
    summary: 'Transaction ordering is exploited: sandwiches, front-run initializations or liquidations, and back-running of oracle updates.',
    cwe: ['CWE-362'],
    swc: ['SWC-114'],
    detect: ['value-bearing actions whose outcome depends on mempool ordering', 'two-step processes (commit without reveal)'],
    fix: ['Commit-reveal, private orderflow, batch auctions', 'Slippage bounds and deadlines'],
  },

  // ------------------------------------------------------------------ bridges
  'message-verification-bypass': {
    name: 'Cross-chain message verification bypass',
    parent: 'bridge-crosschain',
    summary: 'A bridge accepts a forged proof, signature set or message because a verification step can be skipped or spoofed (Wormhole sysvar, BNB IAVL proof, Poly keeper overwrite).',
    cwe: ['CWE-345', 'CWE-347'],
    vulnerable: {
      lang: 'solidity',
      code: `function executeMessage(Message calldata m, bytes calldata proof) external {
    if (verifiers[m.srcChain] == address(0)) { _execute(m); return; }   // unverified path
    require(IVerifier(verifiers[m.srcChain]).verify(m, proof));
    _execute(m);
}`,
    },
    fixed: {
      lang: 'solidity',
      code: `function executeMessage(Message calldata m, bytes calldata proof) external {
    address v = verifiers[m.srcChain];
    require(v != address(0), "no verifier");
    require(IVerifier(v).verify(m, proof), "bad proof");
    require(!executed[m.id]); executed[m.id] = true;
    _execute(m);
}`,
    },
    detect: ['any execution path that reaches release/mint without proof verification', 'messages able to target privileged contracts (keepers, verifiers)', 'accounts/sysvars passed in without ownership checks (Solana)'],
    fix: ['Single mandatory verification path; formally verify it', 'Deny messages targeting bridge-internal contracts', 'Rate limits and withdrawal delays on large flows'],
  },
  'trusted-root-misinit': {
    name: 'Trusted root / config mis-initialization',
    parent: 'bridge-crosschain',
    summary: 'An upgrade or deployment sets a trusted Merkle root, verifier or threshold to a default (0x00, 0 signers) that makes every message valid (Nomad).',
    cwe: ['CWE-1188'],
    vulnerable: { lang: 'solidity', code: `confirmAt[committedRoot] = 1;            // committedRoot == 0x00 after upgrade
// later: acceptableRoot(messages[h]) where unknown messages map to 0x00 → accepted` },
    fixed: { lang: 'solidity', code: `require(_committedRoot != bytes32(0), "zero root");
confirmAt[_committedRoot] = 1;` },
    detect: ['initialization that may write zero/default values into trust-critical mappings', 'upgrades without post-deploy invariant checks on bridge config'],
    fix: ['Reject zero/default values in trust-critical setters', 'Post-upgrade simulation of forged messages'],
  },
  'unbacked-crosschain-mint': {
    name: 'Unbacked cross-chain mint',
    parent: 'bridge-crosschain',
    summary: 'Wrapped assets are minted on the destination chain without a corresponding lock on the source chain, from accounting or relayer logic flaws.',
    cwe: ['CWE-840'],
    detect: ['mint-vs-lock parity not monitored across chains', 'relayer logic trusting unconfirmed or reorgable source events'],
    fix: ['Continuous cross-chain supply parity monitoring with auto-pause', 'Wait for source finality'],
  },

  // ------------------------------------------------------------------ signatures & crypto
  'signature-replay': {
    name: 'Signature replay',
    parent: 'signature-crypto',
    summary: 'A valid signature can be reused: no nonce, no chainId/verifyingContract domain, or no deadline.',
    cwe: ['CWE-294'],
    swc: ['SWC-121'],
    vulnerable: {
      lang: 'solidity',
      code: `bytes32 h = keccak256(abi.encode(to, amount));          // no nonce, chainId or contract
require(ECDSA.recover(h, sig) == signer);
token.transfer(to, amount);`,
    },
    fixed: {
      lang: 'solidity',
      code: `bytes32 h = _hashTypedDataV4(keccak256(abi.encode(
    CLAIM_TYPEHASH, to, amount, nonces[to]++, deadline)));   // EIP-712 domain has chainId
require(block.timestamp <= deadline && ECDSA.recover(h, sig) == signer);`,
    },
    detect: ['signed hashes missing nonce, deadline, chainId or address(this)', 'signatures stored or checked without marking them used'],
    fix: ['EIP-712 typed data with domain separator, per-signer nonces and deadlines'],
  },
  'signature-verification-flaw': {
    name: 'Signature verification flaw',
    parent: 'signature-crypto',
    summary: 'The check itself is broken: ecrecover returning address(0) accepted, malleable signatures, not all fields covered, or a verifier that can be skipped.',
    cwe: ['CWE-347'],
    swc: ['SWC-117', 'SWC-122'],
    vulnerable: { lang: 'solidity', code: `address s = ecrecover(h, v, r, s_);
require(s == signers[id]);                 // signers[id] unset → address(0) matches a bad sig` },
    fixed: { lang: 'solidity', code: `address s = ECDSA.recover(h, sig);        // reverts on invalid / malleable sigs
require(s != address(0) && s == signers[id]);` },
    detect: ['raw ecrecover without zero-address check', 'signed structs that omit fields used later (recipient, token, chain)', 'isValidSignature (EIP-1271) results not checked for the magic value'],
    fix: ['Use OpenZeppelin ECDSA / SignatureChecker', 'Sign every field the action depends on'],
  },
  'weak-key-generation': {
    name: 'Weak key generation',
    parent: 'signature-crypto',
    summary: 'Private keys come from a small or predictable seed space (Profanity vanity addresses, weak RNG in wallets) and are brute-forced.',
    cwe: ['CWE-331', 'CWE-338'],
    detect: ['privileged addresses created with vanity-address tools', 'custom key-generation code not using a CSPRNG'],
    fix: ['Rotate any key from a vanity generator', 'Generate keys only with audited wallets/HSMs'],
  },
  'insecure-randomness': {
    name: 'Insecure on-chain randomness',
    parent: 'signature-crypto',
    summary: 'Randomness from block variables (timestamp, blockhash, prevrandao) or predictable state is gamed by miners or contracts (common in gambling dapps and NFT mints).',
    cwe: ['CWE-330'],
    swc: ['SWC-120'],
    vulnerable: { lang: 'solidity', code: `uint256 roll = uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % 100;` },
    fixed: { lang: 'solidity', code: `// request verifiable randomness and settle in the callback
requestId = vrfCoordinator.requestRandomWords(req);` },
    detect: ['block.timestamp / blockhash / prevrandao used to pick winners or values', 'outcome computed and paid in the same transaction'],
    fix: ['Use a VRF or commit-reveal scheme', 'Never settle a random outcome in the transaction that requests it'],
  },

  // ------------------------------------------------------------------ keys
  'hot-wallet-compromise': {
    name: 'Exchange hot wallet compromise',
    parent: 'key-compromise',
    summary: 'Keys or signing systems of an exchange or custodian hot wallet are taken over and drained.',
    cwe: ['CWE-522'],
    vulnerable: { lang: 'text', code: `hot wallet holds most customer funds
single server signs withdrawals automatically
no per-asset / per-hour withdrawal limits` },
    fixed: { lang: 'text', code: `hot wallet sized to ~1 day of withdrawals; rest in cold storage
MPC / HSM signing across independent hosts and teams
velocity limits + anomaly detection that auto-pauses withdrawals` },
    detect: ['share of customer assets held hot', 'withdrawal limits and alerting coverage', 'signing infrastructure reachable from corporate networks'],
    fix: ['Cold-storage majority, MPC/HSM signing, velocity limits, segregated signing networks'],
  },
  'admin-key-compromise': {
    name: 'Admin / deployer key compromise',
    parent: 'key-compromise',
    summary: 'A single EOA with owner, upgrade or mint rights is compromised, and the attacker upgrades contracts or mints directly.',
    cwe: ['CWE-522', 'CWE-250'],
    vulnerable: { lang: 'text', code: `owner()      = 0xDeployerEOA      # single hot key
upgradeTo()  : immediate, no timelock` },
    fixed: { lang: 'text', code: `owner()      = Safe 3-of-5 (hardware keys, distinct people/orgs)
upgradeTo()  : via 48h TimelockController, guardian can cancel` },
    detect: ['privileged roles held by EOAs', 'upgrades and mints executable without delay', 'deployer keys still holding roles after launch'],
    fix: ['Move every privileged role to a multisig behind a timelock', 'Revoke deployer roles after setup', 'Monitor and alert on admin actions'],
  },
  'multisig-threshold-compromise': {
    name: 'Multisig / validator threshold compromise',
    parent: 'key-compromise',
    summary: 'Enough signer or validator keys to reach the threshold are controlled by one party or compromised together (Ronin 5-of-9, Harmony 2-of-5).',
    cwe: ['CWE-654'],
    detect: ['threshold vs. number of independently operated keys', 'keys held by the same organization, cloud or device type'],
    fix: ['Raise thresholds and diversify operators', 'Independent infrastructure per signer', 'Withdrawal limits that a threshold alone cannot bypass'],
  },
  'key-leak-infrastructure': {
    name: 'Key leaked via infrastructure',
    parent: 'key-compromise',
    summary: 'Keys or API credentials leak from servers, CI, repos, env vars, logs or third-party services (including compromised API/session keys at custodians).',
    cwe: ['CWE-798', 'CWE-312', 'CWE-532'],
    vulnerable: { lang: 'yaml', code: `# .github/workflows/deploy.yml
env:
  PRIVATE_KEY: 0x4c0883a6...       # plaintext key in repo / CI logs` },
    fixed: { lang: 'yaml', code: `# keys never leave the HSM / signer service
- run: deploy --signer remote-kms://prod-deployer
  env:
    KMS_ROLE: \${{ secrets.DEPLOY_ROLE_ARN }}   # short-lived, scoped credential` },
    detect: ['secret scanning on repos and CI logs', 'keys in env vars or config on internet-facing servers', 'long-lived API keys with withdrawal permissions'],
    fix: ['HSM/KMS signing, secret scanning, short-lived scoped credentials, IP allow-lists on API keys'],
  },

  // ------------------------------------------------------------------ social engineering
  'phishing-credential-theft': {
    name: 'Phishing & account takeover',
    parent: 'social-engineering',
    summary: 'Credentials, seed phrases or social/admin accounts are phished (fake sites, fake support, SIM swaps, Discord/Twitter takeovers).',
    cwe: ['CWE-1021'],
    detect: ['accounts without phishing-resistant MFA (FIDO2)', 'official channels able to post links without review'],
    fix: ['FIDO2 hardware keys everywhere', 'Out-of-band verification for any request involving keys or funds', 'Lock social accounts against takeover (no SMS recovery)'],
  },
  'malware-fake-job': {
    name: 'Malware via fake jobs / targeted lures',
    parent: 'social-engineering',
    summary: 'Engineers are lured into running malware (fake recruiter coding tests, trading apps, PDFs), giving attackers access to machines that hold keys or deploy rights.',
    cwe: ['CWE-506'],
    detect: ['engineers running untrusted code on machines with production access', 'no EDR / application allow-listing on signer and developer machines'],
    fix: ['Dedicated, locked-down signing devices', 'Run untrusted code only in disposable VMs', 'Training on state-actor lures (TraderTraitor, fake recruiters)'],
  },
  'blind-signing': {
    name: 'Blind signing / signer deception',
    parent: 'social-engineering',
    summary: 'Signers approve a transaction whose real effect they cannot see (spoofed wallet UI, hidden delegatecall, opaque hardware-wallet prompts): Bybit, WazirX, Radiant.',
    cwe: ['CWE-451'],
    vulnerable: { lang: 'text', code: `Safe UI shows: "transfer 0 ETH to cold wallet"
actual calldata: delegatecall → attacker contract (swaps masterCopy)
hardware wallet shows: raw hash only` },
    fixed: { lang: 'text', code: `decode + simulate calldata on an independent machine (not the web UI)
compare safeTxHash across two tools before signing
policy: reject any operation == DELEGATECALL unless allow-listed` },
    detect: ['multisig operations including delegatecall', 'signers relying on a single web UI for transaction details'],
    fix: ['Independent transaction decoding and simulation', 'Guards that block delegatecall and owner changes', 'Clear-signing hardware wallets'],
  },
  'address-poisoning-drainer': {
    name: 'Address poisoning & wallet drainers',
    parent: 'social-engineering',
    summary: 'Users are tricked into sending to look-alike addresses or signing permit/approval drainers.',
    cwe: ['CWE-451'],
    detect: ['zero-value transfers from look-alike addresses', 'off-chain permit signatures to unknown spenders'],
    fix: ['Address books and full-address verification', 'Wallet-level simulation and permit warnings'],
  },

  // ------------------------------------------------------------------ infrastructure / supply chain
  'dns-domain-hijack': {
    name: 'DNS / domain hijack',
    parent: 'frontend-infra',
    summary: 'The registrar or DNS account is taken over and the domain points to a malicious clone that drains approvals.',
    cwe: ['CWE-350'],
    vulnerable: { lang: 'text', code: `registrar login: password + SMS 2FA
no registry lock, no DNSSEC, no monitoring of NS/A records` },
    fixed: { lang: 'text', code: `registrar: hardware-key 2FA, registry lock
DNSSEC + CAA records
alert on any NS/A/CNAME change` },
    detect: ['registrar accounts without hardware 2FA or registry lock', 'no monitoring of DNS record changes'],
    fix: ['Registry lock, DNSSEC, hardware-key 2FA, DNS change alerting'],
  },
  'frontend-injection': {
    name: 'Frontend / CDN script injection',
    parent: 'frontend-infra',
    summary: 'Malicious JavaScript is served through a compromised CDN, hosting bucket or third-party script, changing what users sign.',
    cwe: ['CWE-494', 'CWE-829'],
    vulnerable: { lang: 'typescript', code: `<script src="https://cdn.example.com/widget.js"></script>   <!-- no integrity, mutable -->` },
    fixed: { lang: 'typescript', code: `<script src="https://cdn.example.com/widget@1.4.2.js"
        integrity="sha384-…" crossorigin="anonymous"></script>
// + Content-Security-Policy: script-src 'self' cdn.example.com` },
    detect: ['third-party scripts without Subresource Integrity', 'writable hosting buckets / CI deploy keys', 'missing Content-Security-Policy'],
    fix: ['SRI and strict CSP', 'Immutable, signed deployments; least-privilege deploy credentials', 'Wallets that simulate and show human-readable intent'],
  },
  'dependency-supply-chain': {
    name: 'Dependency supply-chain compromise',
    parent: 'frontend-infra',
    summary: 'A package the protocol or its users depend on (npm, PyPI, crates, Docker image) ships a malicious version, e.g. Ledger Connect Kit, Bittensor PyPI.',
    cwe: ['CWE-1357', 'CWE-506'],
    vulnerable: { lang: 'json', code: `"dependencies": {
  "@ledgerhq/connect-kit-loader": "^1.1.0"   // loads latest kit from CDN at runtime
}` },
    fixed: { lang: 'json', code: `"dependencies": {
  "@ledgerhq/connect-kit-loader": "1.1.8"     // exact pin, lockfile + integrity, reviewed bumps
}` },
    detect: ['floating version ranges for wallet/crypto packages', 'runtime loading of code from CDNs', 'maintainer accounts without 2FA / provenance'],
    fix: ['Exact pins + lockfiles + integrity hashes', 'npm provenance / Sigstore verification', 'Delay adopting new releases of critical packages'],
  },
  'backend-breach': {
    name: 'Backend / database breach',
    parent: 'frontend-infra',
    summary: 'Servers, databases or internal systems are breached and abused (e.g. altering withdrawal records or balances) without the keys themselves being the entry point.',
    cwe: ['CWE-284'],
    detect: ['internal services that can authorize withdrawals without independent checks', 'flat networks between web and signing tiers'],
    fix: ['Network segmentation, independent reconciliation of balances vs. withdrawals, least privilege'],
  },

  // ------------------------------------------------------------------ governance
  'flash-loan-governance': {
    name: 'Borrowed voting power',
    parent: 'governance',
    summary: 'Voting power is measured at vote time, so it can be flash-loaned or briefly bought to pass a proposal (Beanstalk).',
    cwe: ['CWE-841'],
    vulnerable: { lang: 'solidity', code: `uint256 votes = token.balanceOf(msg.sender);     // current balance` },
    fixed: { lang: 'solidity', code: `uint256 votes = token.getPastVotes(msg.sender, proposal.snapshotBlock);   // ERC20Votes` },
    detect: ['voting weight from balanceOf at vote time', 'proposals executable in the same block or without delay'],
    fix: ['Snapshot voting power at proposal creation (ERC20Votes)', 'Timelock between passing and execution'],
  },
  'malicious-proposal': {
    name: 'Malicious proposal payload',
    parent: 'governance',
    summary: 'A proposal hides a harmful action (self-destructing or upgradeable payload, permission grant) that voters do not detect.',
    cwe: ['CWE-506'],
    detect: ['proposal targets that are upgradeable or can selfdestruct', 'payload code not verified/reviewed before voting'],
    fix: ['Simulate every proposal and require verified payloads', 'Guardian veto during the timelock'],
  },

  // ------------------------------------------------------------------ rugpull
  'liquidity-rug': {
    name: 'Liquidity pull / exit scam',
    parent: 'rugpull',
    summary: 'The team removes liquidity or withdraws treasury/user funds and disappears.',
    detect: ['team-controlled LP not locked', 'treasury movable by a single key without timelock'],
    fix: ['(As a user) check LP locks and treasury controls', '(As a builder) timelock and publish the trust model'],
  },
  'backdoor-privilege': {
    name: 'Backdoor / hidden privilege',
    parent: 'rugpull',
    summary: 'Contracts ship with hidden mint, blacklist, fee or upgrade powers that insiders later use.',
    cwe: ['CWE-912'],
    detect: ['owner-only mint/fee/blacklist functions', 'unverified or proxy contracts whose implementation can change silently'],
    fix: ['Verify source, renounce or timelock privileges, document them in the trust model'],
  },

  // ------------------------------------------------------------------ consensus
  'majority-hashrate-attack': {
    name: '51% / majority attack',
    parent: 'consensus-attack',
    summary: 'Majority hashrate (often rented) reorganizes the chain to double-spend exchange deposits.',
    detect: ['rentable hashrate (NiceHash) vs. network hashrate', 'deep reorgs'],
    fix: ['Confirmation counts tied to attack cost', 'Checkpointing / merged mining / consensus change'],
  },
  'timestamp-manipulation': {
    name: 'Timestamp manipulation (time-warp)',
    parent: 'consensus-attack',
    summary: 'Block timestamps are manipulated to lower difficulty or affect time-dependent logic (Verge 2018).',
    detect: ['loose timestamp validation rules', 'difficulty algorithms sensitive to timestamps'],
    fix: ['Tighter timestamp bounds (median time past)', 'Robust difficulty adjustment'],
  },

  // ------------------------------------------------------------------ client bugs
  'consensus-split': {
    name: 'Consensus split between clients',
    parent: 'client-bug',
    summary: 'Clients or versions disagree on validity, splitting the chain (Bitcoin 0.8 fork, Geth RETURNDATA).',
    detect: ['differential fuzzing across client implementations', 'silent consensus fixes without forced upgrades'],
    fix: ['Client diversity, differential fuzzing, coordinated upgrades'],
  },
  'inflation-validation-bug': {
    name: 'Validation / inflation bug',
    parent: 'client-bug',
    summary: 'Block or transaction validation accepts invalid state, e.g. overflowing outputs or duplicate inputs that create coins.',
    cwe: ['CWE-190', 'CWE-20'],
    detect: ['supply invariants checked independently of the client', 'removed or optimized-away validation checks'],
    fix: ['Independent supply audits, conservative changes to validation code'],
  },
  'node-dos-halt': {
    name: 'Node DoS / crash / chain halt',
    parent: 'client-bug',
    summary: 'Crafted messages or load exhaust node resources or trigger panics, crashing nodes or halting the chain.',
    cwe: ['CWE-400', 'CWE-770'],
    detect: ['unbounded resource use per P2P message type', 'panics reachable from network input'],
    fix: ['Bounded resources per peer/message, fuzzing of network handlers, stake-weighted QoS'],
  },
} as const satisfies Record<string, VulnClass>;

export type ClassId = keyof typeof CLASSES;
export const CLASS_IDS = Object.keys(CLASSES) as ClassId[];

export function classesOf(category: CategoryId): ClassId[] {
  return CLASS_IDS.filter((id) => CLASSES[id].parent === category);
}

/**
 * Analyst technique labels (DefiLlama, BlockSec, DeFiHackLabs) that name exactly one class.
 * Generic labels ("Improper Access Control", "Private Key Compromised", "Arithmetic Error") are
 * deliberately absent: those incidents are classified by the model instead.
 */
export const TECHNIQUE_TO_CLASS: Record<string, ClassId> = {
  'Uninitialized Proxy': 'uninitialized-implementation',
  'Arbitrary External Call': 'arbitrary-external-call',
  'Arbitrary Call': 'arbitrary-external-call',
  'Token Approval Abuse': 'approval-drain',
  'Delegatecall Hijack': 'delegatecall-injection',
  'Storage Collision': 'delegatecall-injection',
  'Forged Proof': 'message-verification-bypass',
  'Cross-Chain Message Spoofing': 'message-verification-bypass',
  'Proof Verifier Bug': 'message-verification-bypass',
  'Spoofed Event Log': 'message-verification-bypass',
  'Unbacked Cross-Chain Mint': 'unbacked-crosschain-mint',
  'DNS Hijack': 'dns-domain-hijack',
  'Frontend Compromise': 'frontend-injection',
  'CDN Compromise': 'frontend-injection',
  'Supply Chain Attack': 'dependency-supply-chain',
  'Database Breach': 'backend-breach',
  'Key Leaked via Infrastructure': 'key-leak-infrastructure',
  'API Key Compromised': 'key-leak-infrastructure',
  'Key Stored Publicly': 'key-leak-infrastructure',
  'Session Key Compromised': 'key-leak-infrastructure',
  'Malicious Proposal': 'malicious-proposal',
  'Flashloan Governance Attack': 'flash-loan-governance',
  'Signature Verification Flaw': 'signature-verification-flaw',
  'Incomplete Signature Coverage': 'signature-verification-flaw',
  'Signature Replay': 'signature-replay',
  'Hot Wallet Key Compromised': 'hot-wallet-compromise',
  'Validator Key Compromised': 'multisig-threshold-compromise',
  'Deployer Key Compromised': 'admin-key-compromise',
  'Weak Key Generation': 'weak-key-generation',
  'Key Brute Forced': 'weak-key-generation',
  'Weak RNG': 'insecure-randomness',
  'Spot Price Manipulation': 'spot-price-oracle',
  'Oracle Misconfiguration': 'stale-misconfigured-feed',
  'Stale Oracle Price': 'stale-misconfigured-feed',
  'Reward Logic Flaw': 'reward-logic-flaw',
  'Missing Slippage Check': 'missing-slippage-protection',
  'Lack of Slippage Protection': 'missing-slippage-protection',
  'Read-Only Reentrancy': 'read-only-reentrancy',
  'Liquidity Rug': 'liquidity-rug',
  'Exit Scam': 'liquidity-rug',
  'Admin Drain': 'liquidity-rug',
  'Backdoor Contract': 'backdoor-privilege',
  Phishing: 'phishing-credential-theft',
  'Social Account Takeover': 'phishing-credential-theft',
  'Impersonation Scam': 'phishing-credential-theft',
  Malware: 'malware-fake-job',
  'Signer Phishing': 'blind-signing',
  'Blind Signing': 'blind-signing',
  'Address Poisoning': 'address-poisoning-drainer',
  'Infinite Mint': 'unbacked-mint',
  'Unbacked Mint': 'unbacked-mint',
  'Rounding Error': 'rounding-precision',
  'Precision Loss': 'rounding-precision',
  'Decimal Miscalculation': 'rounding-precision',
  'Donation Attack': 'share-inflation',
  'First Depositor Attack': 'share-inflation',
  'Incorrect Fee Accounting': 'balance-accounting-mismatch',
  Overflow: 'integer-overflow',
  'Integer Overflow': 'integer-overflow',
  'Arithmetic Overflow/Underflow': 'integer-overflow',
};

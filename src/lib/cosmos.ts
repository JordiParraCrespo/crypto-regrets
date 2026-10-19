/**
 * Cosmos-specific vulnerability classes, for scanning Cosmos SDK chains, IBC apps, CosmWasm
 * contracts and Cosmos EVM integrations.
 *
 * Each class has the vulnerable and fixed shape, detection rules a scanner can implement (a regex
 * prefilter where the shape is lexical, plus what an AST/SSA rule must confirm), the fix, and the
 * advisories / incidents where it occurred.
 */
import type { Snippet } from './classes';

export const COSMOS_AREAS = {
  determinism: { name: 'Determinism & liveness', blurb: 'Bugs that split consensus or halt the chain: every validator must compute the same state and never panic.' },
  authz: { name: 'Authorization & message validation', blurb: 'Who may send which message, and what the handler checks before acting.' },
  accounting: { name: 'Accounting & math', blurb: 'Supply, escrow and rounding: the bank module must always add up.' },
  ibc: { name: 'IBC', blurb: 'Packets, acknowledgements, timeouts, light clients and the middleware between them.' },
  cosmwasm: { name: 'CosmWasm contracts', blurb: 'Rust contracts on wasmd: sender checks, submessages, address handling.' },
  evm: { name: 'Cosmos EVM', blurb: 'EVM on Cosmos (formerly Evmos): precompiles and the boundary between EVM state and Cosmos keepers.' },
  governance: { name: 'Governance & operations', blurb: 'Proposals that execute arbitrary messages, bridges secured by keys, oracles.' },
} as const;

export type CosmosAreaId = keyof typeof COSMOS_AREAS;

export interface ScanRule {
  /** Scanner-facing id, stable. */
  id: string;
  target: 'go' | 'rust' | 'solidity' | 'config';
  /** Cheap lexical prefilter (RE2-compatible). Matches are candidates, not findings. */
  regex?: string;
  /** What the precise (AST / SSA / taint) check must confirm. */
  confirm: string;
}

export interface CosmosClass {
  name: string;
  area: CosmosAreaId;
  summary: string;
  vulnerable?: Snippet & { lang: 'go' | 'rust' | 'solidity' | 'text' };
  fixed?: Snippet & { lang: 'go' | 'rust' | 'solidity' | 'text' };
  rules: ScanRule[];
  fix: string[];
  /** Advisory ids and incident names where this class occurred (verified in our data or advisories). */
  seenIn: string[];
}

export const COSMOS_CLASSES = {
  // ------------------------------------------------------------------ determinism & liveness
  'nondeterministic-map-iteration': {
    name: 'Map iteration in state transitions',
    area: 'determinism',
    summary: 'Go randomizes map iteration order. Ranging over a map while writing state, emitting events or building results makes validators diverge (app hash mismatch, chain halt).',
    vulnerable: { lang: 'go', code: `func (k Keeper) Distribute(ctx sdk.Context, shares map[string]math.Int) {
    for addr, amt := range shares {            // order differs per validator
        k.bank.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sdk.MustAccAddressFromBech32(addr), sdk.NewCoins(sdk.NewCoin("uatom", amt)))
    }
}` },
    fixed: { lang: 'go', code: `func (k Keeper) Distribute(ctx sdk.Context, shares map[string]math.Int) {
    addrs := maps.Keys(shares)
    slices.Sort(addrs)                         // deterministic order
    for _, addr := range addrs { /* ... */ }
}` },
    rules: [{ id: 'cosmos-go-map-range-in-keeper', target: 'go', regex: 'for\\s+\\w+(,\\s*\\w+)?\\s*:=\\s*range\\s+\\w+', confirm: 'range expression has map type AND the loop body (transitively) writes to a KVStore, calls a keeper/bank method, emits events, or appends to a returned slice; skip if keys are sorted first.' }],
    fix: ['Collect keys, sort, iterate the sorted slice', 'Prefer store iterators (ordered) or collections.Map over Go maps in state logic'],
    seenIn: ['Recurring audit finding (Oak Security, Informal Systems); app-hash mismatch halts on several chains'],
  },
  'nondeterministic-sources': {
    name: 'Non-deterministic inputs',
    area: 'determinism',
    summary: 'Wall-clock time, randomness, floating point, goroutines/select, or map-based JSON in consensus code produce different results on different validators.',
    vulnerable: { lang: 'go', code: `deadline := time.Now().Add(24 * time.Hour)          // local clock
ratio := float64(a) / float64(b)                    // float rounding differs by platform
go k.updateIndex(ctx)                               // concurrent state access` },
    fixed: { lang: 'go', code: `deadline := ctx.BlockTime().Add(24 * time.Hour)     // consensus time
ratio := math.LegacyNewDec(a).Quo(math.LegacyNewDec(b))
k.updateIndex(ctx)                                  // sequential` },
    rules: [
      { id: 'cosmos-go-time-now', target: 'go', regex: 'time\\.Now\\(|rand\\.(Int|Float|Read|Intn|Seed)', confirm: 'call is reachable from a Msg handler, BeginBlock/EndBlock/PreBlock/FinalizeBlock, ante handler or IBC callback.' },
      { id: 'cosmos-go-float-in-state', target: 'go', regex: '\\bfloat(32|64)\\b', confirm: 'float value flows into a store write, coin amount or consensus-relevant decision.' },
      { id: 'cosmos-go-goroutine-in-state', target: 'go', regex: '\\bgo\\s+\\w+(\\.\\w+)*\\(', confirm: 'goroutine started from consensus code path.' },
    ],
    fix: ['Use ctx.BlockTime(), ctx.BlockHeight(), sdk math types (Int, LegacyDec), and sequential execution in state machine code'],
    seenIn: ['Recurring audit finding across Cosmos SDK chains'],
  },
  'abci-panic-halt': {
    name: 'Panic in block processing (chain halt)',
    area: 'determinism',
    summary: 'A panic in BeginBlock/EndBlock/PreBlock/FinalizeBlock (or code they call) is not recovered like Msg handlers are: every validator halts. Common triggers: nil pointers, Must* helpers, math overflow, index out of range on user-influenced state.',
    vulnerable: { lang: 'go', code: `func (k Keeper) EndBlocker(ctx sdk.Context) {
    for _, p := range k.GetMaturedPositions(ctx) {
        price := k.oracle.MustGetPrice(ctx, p.Denom)   // panics if a user-created denom has no price
        k.settle(ctx, p, price)
    }
}` },
    fixed: { lang: 'go', code: `func (k Keeper) EndBlocker(ctx sdk.Context) error {
    for _, p := range k.GetMaturedPositions(ctx) {
        price, err := k.oracle.GetPrice(ctx, p.Denom)
        if err != nil { k.Logger(ctx).Error("skip position", "id", p.Id, "err", err); continue }
        cacheCtx, write := ctx.CacheContext()
        if err := k.settle(cacheCtx, p, price); err == nil { write() }
    }
    return nil
}` },
    rules: [
      { id: 'cosmos-go-panic-in-blocker', target: 'go', regex: 'func\\s+\\(\\w+\\s+\\*?\\w+\\)\\s+(Begin|End|Pre)Blocker|FinalizeBlock', confirm: 'call graph from the blocker reaches panic(), Must*(), unchecked type assertion, slice index, or math ops that panic (Int overflow, division by zero) on values derived from user-writable state.' },
      { id: 'cosmos-go-must-helpers', target: 'go', regex: '\\bMust[A-Z]\\w*\\(', confirm: 'Must* call reachable from a blocker or IBC callback with user-influenced input.' },
    ],
    fix: ['Return errors instead of panicking; per-item CacheContext with error isolation', 'Bound and validate user-created entries before they reach blockers', 'Fuzz blockers with adversarial state (simulation tests)'],
    seenIn: ['ASA-2024-010 (math bit-length mismatch → panic)', 'ASA-2024-011 (vote extension panic)', 'ASA-2025-003 (x/group proposal can halt chain)'],
  },
  'unbounded-iteration': {
    name: 'Unbounded iteration / unmetered work',
    area: 'determinism',
    summary: 'Blockers or queries iterate over state that users can grow without limit (positions, delegations, denoms). Work outside gas metering lets an attacker slow or halt block production cheaply.',
    vulnerable: { lang: 'go', code: `func (k Keeper) EndBlocker(ctx sdk.Context) {
    k.IterateAllOrders(ctx, func(o types.Order) bool { // anyone can create orders
        k.match(ctx, o)
        return false
    })
}` },
    fixed: { lang: 'go', code: `func (k Keeper) EndBlocker(ctx sdk.Context) {
    n := 0
    k.IterateOrdersFrom(ctx, k.GetCursor(ctx), func(o types.Order) bool {
        k.match(ctx, o)
        n++
        return n >= k.GetParams(ctx).MaxOrdersPerBlock // bounded, resumes next block
    })
}` },
    rules: [{ id: 'cosmos-go-iterate-all-in-blocker', target: 'go', regex: 'Iterate(All)?\\w*\\(ctx|KVStorePrefixIterator|\\.Iterate\\(', confirm: 'iteration reachable from a blocker (or an un-gas-limited query) over a prefix users can append to, with no item cap or cursor.' }],
    fix: ['Cap items per block with a persisted cursor', 'Charge creation fees / minimums for entries processed in blockers', 'Paginate queries with hard limits'],
    seenIn: ['Recurring audit finding; CometBFT/SDK DoS advisories (ASA-2025-001, ASA-2025-002)'],
  },
  'untrusted-decoding-dos': {
    name: 'Resource exhaustion in decoding / P2P',
    area: 'determinism',
    summary: 'Deeply nested Any/proto messages, oversized inputs or malicious peers exhaust stack, memory or CPU before gas applies (transaction decoding, blocksync, block parts).',
    rules: [{ id: 'cosmos-go-any-unpack-depth', target: 'go', regex: 'UnpackAny|UnpackInterfaces|codectypes\\.Any', confirm: 'recursive unpacking of user-supplied Any without depth/size limits on a path executed before gas metering (ante, CheckTx, mempool).' }],
    fix: ['Upgrade to patched SDK/CometBFT versions', 'Enforce max message depth/size before decoding', 'Rate-limit and score peers'],
    seenIn: ['ASA-2024-012/013 (tx decoding stack overflow)', 'ASA-2024-008, ASA-2025-001/002 (blocksync / block-part DoS)'],
  },

  // ------------------------------------------------------------------ authorization
  'missing-signer-check': {
    name: 'Missing signer / authority check in Msg handler',
    area: 'authz',
    summary: 'The handler acts on an address taken from the message (creator, owner, authority) without checking it is the signer, or governance-only messages do not check msg.Authority.',
    vulnerable: { lang: 'go', code: `func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    return &types.MsgUpdateParamsResponse{}, m.SetParams(ctx, msg.Params)  // anyone can change params
}` },
    fixed: { lang: 'go', code: `func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
    if m.authority != msg.Authority {
        return nil, errorsmod.Wrapf(govtypes.ErrInvalidSigner, "expected %s, got %s", m.authority, msg.Authority)
    }
    ctx := sdk.UnwrapSDKContext(goCtx)
    return &types.MsgUpdateParamsResponse{}, m.SetParams(ctx, msg.Params)
}` },
    rules: [
      { id: 'cosmos-go-msg-authority', target: 'go', regex: 'func\\s+\\(\\w+\\s+msgServer\\)\\s+\\w+\\(', confirm: 'handler writes params/admin state but has no comparison of msg.Authority (or the cosmos.msg.v1.signer field) against the keeper authority.' },
      { id: 'cosmos-proto-signer-field', target: 'config', regex: 'option\\s+\\(cosmos\\.msg\\.v1\\.signer\\)', confirm: 'the signer field declared in proto is the same field the handler treats as the acting account.' },
    ],
    fix: ['Compare msg.Authority with the module authority (x/gov address) for privileged msgs', 'Ensure the proto signer field is the account the handler acts for'],
    seenIn: ['Recurring audit finding; MANTRA Chain 2026 (contract-level authorization) under investigation'],
  },
  'nested-msg-bypass': {
    name: 'Nested message bypass (authz / ICA / x/group)',
    area: 'authz',
    summary: 'Checks done in the ante handler or on top-level messages (fee rules, blocked msg types, rate limits) are skipped when the same message arrives wrapped in MsgExec, an ICA packet, a group/gov proposal or a CosmWasm submessage.',
    vulnerable: { lang: 'go', code: `// ante decorator only inspects top-level messages
for _, m := range tx.GetMsgs() {
    if _, ok := m.(*evmtypes.MsgEthereumTx); ok { return ctx, ErrNotAllowed }
}` },
    fixed: { lang: 'go', code: `// recurse into wrapped messages (authz MsgExec, group/gov proposals)
var check func(msgs []sdk.Msg, depth int) error
check = func(msgs []sdk.Msg, depth int) error {
    if depth > maxNesting { return ErrTooDeep }
    for _, m := range msgs {
        if exec, ok := m.(*authz.MsgExec); ok {
            inner, err := exec.GetMessages(); if err != nil { return err }
            if err := check(inner, depth+1); err != nil { return err }
        }
        if _, ok := m.(*evmtypes.MsgEthereumTx); ok { return ErrNotAllowed }
    }
    return nil
}` },
    rules: [{ id: 'cosmos-go-ante-toplevel-only', target: 'go', regex: 'range\\s+tx\\.GetMsgs\\(\\)', confirm: 'decorator enforces a restriction per message type but does not unwrap authz.MsgExec / group / gov / ICA wrappers.' }],
    fix: ['Enforce restrictions in the message server (runs for nested msgs too), not only in ante', 'Recursively unwrap MsgExec with a depth limit', 'Use the circuit breaker / msg allow-lists for ICA host'],
    seenIn: ['Evmos 2023 authz/vesting bypass class; recurring audit finding'],
  },
  'module-account-transfer': {
    name: 'Blocked / module account transfers',
    area: 'authz',
    summary: 'Coins sent to module accounts or blocked addresses (or vesting accounts created for them) corrupt module invariants, lock funds or bypass accounting.',
    rules: [{ id: 'cosmos-go-sendcoins-blocked', target: 'go', regex: 'SendCoins\\(|SendCoinsFromModuleToAccount\\(|NewContinuousVestingAccount|MsgCreateVestingAccount', confirm: 'recipient derived from user input is not checked with bankKeeper.BlockedAddr().' }],
    fix: ['Check BlockedAddr for every user-supplied recipient', 'Use patched x/auth/vesting'],
    seenIn: ['ASA-2024-003 (missing BlockedAddressed validation in vesting)'],
  },

  // ------------------------------------------------------------------ accounting & math
  'sdk-math-overflow-rounding': {
    name: 'SDK math overflow, truncation and rounding',
    area: 'accounting',
    summary: 'math.Int/LegacyDec overflow or panic on big values, TruncateInt/RoundInt in the user\'s favour, or unsafe conversions (Int64(), Uint64(), uint casts) on attacker-sized amounts.',
    vulnerable: { lang: 'go', code: `shares := amount.Mul(totalShares).Quo(totalAssets)     // rounds down: burns too few shares on withdraw
out := uint64(msg.Amount.Int64()) * price               // wraps on large amounts` },
    fixed: { lang: 'go', code: `shares := amount.Mul(totalShares).Add(totalAssets.Sub(math.OneInt())).Quo(totalAssets) // ceil on withdraw
if !msg.Amount.IsUint64() { return ErrAmountTooLarge }
out, overflow := bits.Mul64(msg.Amount.Uint64(), price); if overflow != 0 { return ErrOverflow }` },
    rules: [
      { id: 'cosmos-go-int64-conversion', target: 'go', regex: '\\.Int64\\(\\)|\\.Uint64\\(\\)|uint64\\(|int64\\(', confirm: 'conversion applied to a user-controlled math.Int / amount without IsInt64/IsUint64 bounds check, result used in arithmetic or state.' },
      { id: 'cosmos-go-truncate-direction', target: 'go', regex: 'TruncateInt\\(|RoundInt\\(|QuoTruncate\\(', confirm: 'rounding direction favours the caller on mint/withdraw/redeem paths.' },
    ],
    fix: ['Bounds-check before converting; prefer math.Int end to end', 'Round in the protocol\'s favour (ceil when taking, floor when giving)', 'Property tests: deposit → withdraw never returns more'],
    seenIn: ['ASA-2024-010', 'KiiChain 2026 (integer overflow, $9.7M)', 'CosmWasm 2023 (Jump Crypto report)'],
  },
  'supply-escrow-invariant': {
    name: 'Unbacked mint / escrow invariant break',
    area: 'accounting',
    summary: 'A mint, unescrow or voucher path runs without the matching lock, burn or proof, so supply exceeds backing (liquid staking, bridges, custom tokenfactory modules).',
    vulnerable: { lang: 'go', code: `func (k Keeper) ClaimDeposit(ctx sdk.Context, proof types.DepositProof) error {
    if k.IsClaimed(ctx, proof.TxHash) { return ErrClaimed }
    // proof.Amount trusted: inclusion proof checked, amount/recipient fields not bound to it
    return k.bank.MintCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(denom, proof.Amount)))
}` },
    fixed: { lang: 'go', code: `func (k Keeper) ClaimDeposit(ctx sdk.Context, proof types.DepositProof) error {
    ev, err := k.verifier.VerifyAndDecode(ctx, proof)   // amount/recipient come from the verified event
    if err != nil { return err }
    if k.IsClaimed(ctx, ev.TxHash) { return ErrClaimed }
    k.SetClaimed(ctx, ev.TxHash)
    return k.bank.MintCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(denom, ev.Amount)))
}` },
    rules: [{ id: 'cosmos-go-mintcoins-taint', target: 'go', regex: 'MintCoins\\(', confirm: 'minted amount or recipient is tainted by message fields not cryptographically bound to a verified proof / escrow / burn in the same transaction; and no supply-vs-backing invariant is registered.' }],
    fix: ['Derive amounts only from verified data', 'Register crisis-style invariants (supply ≤ backing) and monitor them off-chain', 'Rate-limit mints per epoch'],
    seenIn: ['Quicksilver 2026 (unchecked proof minting)', 'Namada shielded pools 2026', 'Nomic 2026 (nBTC forwarding)', 'Osmosis 2022 LP bug'],
  },

  // ------------------------------------------------------------------ IBC
  'ibc-proof-forgery': {
    name: 'Light client / proof verification flaw',
    area: 'ibc',
    summary: 'A counterparty proof (ICS23/IAVL membership proof, light-client header, custom verifier) can be crafted to prove a packet or state that never existed, so the chain mints or releases funds.',
    rules: [{ id: 'cosmos-go-custom-light-client', target: 'go', regex: 'VerifyMembership|VerifyNonMembership|VerifyClientMessage|ics23\\.', confirm: 'custom client or verifier: proof spec, path and value are all checked; existence proofs cannot be satisfied with crafted leaf/inner ops; header validation checks trusting period and validator set transitions.' }],
    fix: ['Use maintained light clients (07-tendermint, 08-wasm with audited code)', 'Pin ics23/iavl to patched versions (Dragonberry)', 'Rate-limit inbound IBC flows (ibc-apps rate-limiting)'],
    seenIn: ['Dragonberry 2022 (ICS23/IAVL)', 'BNB Chain bridge 2022 (same IAVL class)', 'Saga 2026 (forged IBC messages, $7M)'],
  },
  'ibc-callback-reentrancy': {
    name: 'IBC callback / middleware reentrancy',
    area: 'ibc',
    summary: 'IBC middleware (ibc-hooks, callbacks, packet-forward) calls into contracts during OnAcknowledgement/OnTimeout; the contract re-enters the transfer before escrow and refund state is final, refunding or crediting twice.',
    vulnerable: { lang: 'go', code: `func (im IBCMiddleware) OnTimeoutPacket(ctx sdk.Context, p channeltypes.Packet, relayer sdk.AccAddress) error {
    im.wasmHooks.OnTimeout(ctx, p)                 // contract callback first: can re-enter transfer
    return im.app.OnTimeoutPacket(ctx, p, relayer) // refund afterwards
}` },
    fixed: { lang: 'go', code: `func (im IBCMiddleware) OnTimeoutPacket(ctx sdk.Context, p channeltypes.Packet, relayer sdk.AccAddress) error {
    if err := im.app.OnTimeoutPacket(ctx, p, relayer); err != nil { return err } // finish refund first
    cacheCtx, write := ctx.CacheContext()
    if err := im.wasmHooks.OnTimeout(cacheCtx, p); err == nil { write() }        // isolated callback
    return nil
}` },
    rules: [{ id: 'cosmos-go-ibc-callback-order', target: 'go', regex: 'OnAcknowledgementPacket|OnTimeoutPacket|OnRecvPacket', confirm: 'middleware invokes external/contract code before the wrapped app finalises escrow/refund state, without a reentrancy guard or cache context.' }],
    fix: ['Finalise refunds and escrow before callbacks; run callbacks in a cache context with gas limits', 'Upgrade ibc-hooks / callbacks middleware to patched versions'],
    seenIn: ['ASA-2024-007 (critical: reentrancy via timeout callbacks in ibc-hooks)'],
  },
  'ics20-denom-escrow': {
    name: 'ICS-20 denom / escrow accounting',
    area: 'ibc',
    summary: 'Transfer logic confuses native and voucher denoms, mis-parses denom traces, or forwards (PFM / custom forwarding) without updating escrow, letting attackers mint vouchers or drain escrow.',
    rules: [{ id: 'cosmos-go-denom-trace-parse', target: 'go', regex: 'ReceiverChainIsSource|SenderChainIsSource|ParseDenomTrace|ExtractDenomFromPath|transfertypes\\.', confirm: 'custom code decides "native vs voucher" or computes escrow amounts outside the ibc-go transfer keeper; forwarding paths update escrow exactly once.' }],
    fix: ['Use ibc-go transfer keeper APIs; never re-implement denom logic', 'Monitor escrow balance == outstanding vouchers per channel'],
    seenIn: ['Nomic 2026 (forwarding minted unbacked nBTC)', 'Axelar–Secret IBC bridge 2026 (unbacked mint)'],
  },

  // ------------------------------------------------------------------ CosmWasm
  'cosmwasm-missing-sender-check': {
    name: 'CosmWasm: missing sender / admin check',
    area: 'cosmwasm',
    summary: 'execute() handlers act without checking info.sender against the owner/admin, or migrate/instantiate admin is left to an EOA or the wrong address.',
    vulnerable: { lang: 'rust', code: `ExecuteMsg::UpdateConfig { new_owner } => {
    CONFIG.update(deps.storage, |mut c| -> StdResult<_> { c.owner = deps.api.addr_validate(&new_owner)?; Ok(c) })?;
    Ok(Response::new())
}` },
    fixed: { lang: 'rust', code: `ExecuteMsg::UpdateConfig { new_owner } => {
    let cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.owner { return Err(ContractError::Unauthorized {}); }
    CONFIG.update(deps.storage, |mut c| -> StdResult<_> { c.owner = deps.api.addr_validate(&new_owner)?; Ok(c) })?;
    Ok(Response::new())
}` },
    rules: [{ id: 'cosmwasm-rs-execute-no-sender', target: 'rust', regex: 'ExecuteMsg::\\w+', confirm: 'branch writes privileged state (config, owner, minter, fees, withdraw) without comparing info.sender to a stored role (or cw_ownable::assert_owner).' }],
    fix: ['Use cw-ownable / explicit role checks on every privileged branch', 'Set contract admin to governance or a multisig'],
    seenIn: ['Recurring audit finding; Terraport 2023 ($4M)'],
  },
  'cosmwasm-submsg-reply': {
    name: 'CosmWasm: submessage / reply state handling',
    area: 'cosmwasm',
    summary: 'State is written before a submessage whose failure is caught (ReplyOn::Error/Always) without rollback, or reply handlers trust data from the callee; callbacks into the contract allow reentrancy-like double accounting.',
    vulnerable: { lang: 'rust', code: `BALANCES.save(deps.storage, &info.sender, &(bal - amount))?;
let msg = SubMsg::reply_on_error(BankMsg::Send { to_address: to, amount: coins(amount.u128(), denom) }, SEND_ID);
// reply(): on error just logs, balance already debited / or credited twice on retry` },
    fixed: { lang: 'rust', code: `let msg = SubMsg::reply_always(WasmMsg::Execute { .. }, SEND_ID);
PENDING.save(deps.storage, SEND_ID, &Pending { who: info.sender.clone(), amount })?;
// reply(): on Ok → finalize; on Err → restore exactly once from PENDING, then remove it` },
    rules: [{ id: 'cosmwasm-rs-reply-on-error', target: 'rust', regex: 'reply_on_error|reply_always|ReplyOn::(Error|Always)', confirm: 'state mutated before the submessage is not restored in the reply error branch, or reply handler can run twice for one logical operation.' }],
    fix: ['Track pending operations explicitly and settle them in reply', 'Prefer plain messages (atomic revert) unless partial failure is required'],
    seenIn: ['Astroport / Terra 2024 (reentrancy-class loss, $6.4M) — under review in research'],
  },
  'cosmwasm-address-validation': {
    name: 'CosmWasm: unvalidated addresses',
    area: 'cosmwasm',
    summary: 'User-supplied addresses stored as raw strings without addr_validate: case variants bypass allow/deny lists and duplicate keys in maps.',
    vulnerable: { lang: 'rust', code: `let recipient = Addr::unchecked(msg.recipient);   // "COSMOS1..." != "cosmos1..."` },
    fixed: { lang: 'rust', code: `let recipient = deps.api.addr_validate(&msg.recipient)?;` },
    rules: [{ id: 'cosmwasm-rs-addr-unchecked', target: 'rust', regex: 'Addr::unchecked\\(', confirm: 'argument originates from a message field (not a constant or test).' }],
    fix: ['Always addr_validate user input; store Addr, not String'],
    seenIn: ['Recurring audit finding'],
  },

  // ------------------------------------------------------------------ Cosmos EVM
  'precompile-authorization': {
    name: 'Precompile authorization bypass',
    area: 'evm',
    summary: 'A stateful precompile (bank, staking, distribution, ERC-20, ICS-20) acts on behalf of an address it takes from calldata or tx.origin instead of the immediate caller, letting any contract move other users\' native funds or stake.',
    vulnerable: { lang: 'go', code: `func (p Precompile) Transfer(ctx sdk.Context, origin common.Address, contract *vm.Contract, args []interface{}) ([]byte, error) {
    from, to, amount := parseArgs(args)                 // "from" taken from calldata
    return nil, p.bankKeeper.SendCoins(ctx, sdk.AccAddress(from.Bytes()), sdk.AccAddress(to.Bytes()), amount)
}` },
    fixed: { lang: 'go', code: `func (p Precompile) Transfer(ctx sdk.Context, origin common.Address, contract *vm.Contract, args []interface{}) ([]byte, error) {
    from, to, amount := parseArgs(args)
    if from != contract.Caller() {                      // immediate caller, not origin or calldata
        if err := p.spendAllowance(ctx, from, contract.Caller(), amount); err != nil { return nil, err }
    }
    return nil, p.bankKeeper.SendCoins(ctx, sdk.AccAddress(from.Bytes()), sdk.AccAddress(to.Bytes()), amount)
}` },
    rules: [{ id: 'cosmos-evm-precompile-actor', target: 'go', regex: 'func\\s+\\(\\w+\\s+\\*?Precompile\\)\\s+\\w+\\(', confirm: 'state-changing precompile method whose acting account comes from calldata or `origin`, not `contract.Caller()`, without an allowance/authorization check.' }],
    fix: ['Authorize against contract.Caller(); use explicit allowances for third-party spends', 'Upgrade to patched cosmos/evm releases; disable unneeded precompiles'],
    seenIn: ['BounceBit 2026 ("authorization flaw in the Evmos stack")', 'Late-Aug 2026 Cosmos EVM cluster — see research findings'],
  },
  'evm-cosmos-state-desync': {
    name: 'EVM ↔ Cosmos state desync',
    area: 'evm',
    summary: 'Precompile calls write Cosmos state that is not journaled with the EVM StateDB: an EVM revert (or try/catch) leaves the Cosmos-side transfer committed, or balances are read stale, enabling double spends and unbacked mints between the native and ERC-20 representations.',
    vulnerable: { lang: 'solidity', code: `// attacker contract on a Cosmos EVM chain
try IBank(BANK).send(attacker, amount) {} catch {}
revert(); // EVM state reverts, Cosmos-side send (not journaled) does not` },
    fixed: { lang: 'text', code: `precompile writes go through the StateDB journal (CacheContext snapshot per call)
EVM revert restores both EVM and Cosmos state
x/erc20 conversions re-read balances after every precompile call` },
    rules: [{ id: 'cosmos-evm-unjournaled-write', target: 'go', regex: 'stateDB\\.|statedb\\.|CacheContext\\(', confirm: 'precompile writes to a Cosmos keeper without registering a journal entry / snapshot that is reverted with the EVM call frame.' }],
    fix: ['Run on a cosmos/evm release where precompile writes are journaled', 'Invariant: native supply == ERC-20 representation supply for every converted denom'],
    seenIn: ['Evmos precompile revert bug class (2024 bug bounty)', 'TAC 2026 ($7.5M "via the Cosmos EVM")'],
  },

  // ------------------------------------------------------------------ governance & ops
  'malicious-governance-proposal': {
    name: 'Malicious governance proposal',
    area: 'governance',
    summary: 'A proposal executes arbitrary messages (contract migrate, admin change, treasury send). Low quorum, short voting periods or unreviewed payloads let attackers pass it.',
    rules: [{ id: 'cosmos-config-gov-params', target: 'config', confirm: 'governance params: quorum, voting period, expedited proposals, deposit size; proposals able to MsgMigrateContract / MsgUpdateAdmin on core contracts; no simulation of proposal payloads in CI/monitoring.' }],
    fix: ['Simulate every proposal and alert on admin/migrate/treasury messages', 'Raise deposits and quorum; use expedited proposals sparingly', 'Timelock contract upgrades behind a guardian'],
    seenIn: ['Astroport (Neutron) 2026 ($4.9M)', 'Drop (Neutron) 2026 ($4.4M)'],
  },
  'bridge-validator-keys': {
    name: 'Bridge validator / multisig compromise',
    area: 'governance',
    summary: 'Peg-zone bridges secured by a validator multisig or orchestrator keys are drained when enough keys are compromised or signing logic is abused.',
    rules: [{ id: 'cosmos-config-bridge-threshold', target: 'config', confirm: 'signer threshold vs number of independent operators; orchestrator keys on shared infrastructure; rate limits on outflows.' }],
    fix: ['Raise thresholds, diversify operators, rate-limit outflows'],
    seenIn: ['Gravity Bridge 2026 ($5.4M)', 'Sentinel 2021 ($40M, key compromise)'],
  },
  'oracle-staleness': {
    name: 'Stale or manipulable oracle',
    area: 'governance',
    summary: 'Chain-native oracles (x/oracle, price feeders) or contract oracles return stale prices after halts, upgrades or feeder outages; protocols keep trading or lending on them.',
    rules: [{ id: 'cosmos-oracle-staleness', target: 'go', regex: 'GetPrice|GetExchangeRate|QueryPrice', confirm: 'consumer checks the price timestamp / block height against a max age and halts markets on staleness.' }],
    fix: ['Max-age checks and circuit breakers', 'Pause markets after chain upgrades until feeds resume'],
    seenIn: ['Anchor 2022 (stale price)', 'Levana Perps 2023 ($1.1M)', 'Harbor Protocol 2023'],
  },
} as const satisfies Record<string, CosmosClass>;

export type CosmosClassId = keyof typeof COSMOS_CLASSES;
export const COSMOS_CLASS_IDS = Object.keys(COSMOS_CLASSES) as CosmosClassId[];

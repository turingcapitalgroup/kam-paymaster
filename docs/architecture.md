# KAM Paymaster Architecture

## Overview

The kPaymaster is an ERC2771-style trusted forwarder that enables gasless interactions with KAM Protocol's kStakingVaults. Users sign meta-transactions off-chain, and trusted executors (relayers) submit them on-chain while deducting fees from the tokens being transferred.

The contract supports autoclaim functionality, where users sign once for both the stake/unstake request and the eventual claim. The fee is paid upfront, allowing executors to claim on behalf of users after settlement without additional signatures.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER WALLET                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  1. Sign EIP-2612 Permit for token approval                         │    │
│  │  2. Sign EIP-712 Request (StakeWithAutoclaim/UnstakeWithAutoclaim) │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUSTED EXECUTOR (Relayer)                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  - Receives signed request + permit from user                       │    │
│  │  - Determines actual fee (must be <= user's maxFee)                 │    │
│  │  - Submits transaction to kPaymaster                                │    │
│  │  - Pays gas costs                                                   │    │
│  │  - Later executes autoclaim after settlement                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              KAM PAYMASTER                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  1. Verify caller is trusted executor                               │    │
│  │  2. Validate EIP-712 request signature                              │    │
│  │  3. Validate fee <= maxFee                                          │    │
│  │  4. Execute permit for token approval                               │    │
│  │  5. Transfer fee to treasury (covers both request + claim)          │    │
│  │  6. Forward call to vault with user address appended                │    │
│  │  7. Register autoclaim for later execution                          │    │
│  │  8. Increment user nonce                                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            kStakingVault                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  - Receives call with user address appended to calldata             │    │
│  │  - Extracts real user via _msgSender() (ERC2771)                    │    │
│  │  - Executes stake/unstake on behalf of user                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Contract Components

### kPaymaster

The main contract that handles gasless meta-transactions with autoclaim.

**Inheritance:**
- `IkPaymaster` - Interface definition
- `EIP712` (Solady) - EIP-712 typed data signing
- `Ownable` (Solady) - Access control

**Storage:**
```solidity
address public treasury;                                        // Fee recipient
mapping(address => uint256) private _nonces;                    // User nonces
mapping(address => bool) private _trustedExecutors;             // Whitelisted relayers
mapping(bytes32 => AutoclaimAuth) private _autoclaimRegistry;   // Autoclaim registrations per requestId
```

### Request Types

All request structs use **packed fields** for gas optimization:

```solidity
// Packed into 4 slots (128 bytes)
struct StakeWithAutoclaimRequest {
    address user;           // 20 bytes ─┐
    uint96 nonce;           // 12 bytes ─┘ Slot 1
    address vault;          // 20 bytes ─┐
    uint96 deadline;        // 12 bytes ─┘ Slot 2
    address recipient;      // 20 bytes ─┐
    uint96 maxFee;          // 12 bytes ─┘ Slot 3
    uint256 kTokenAmount;   // 32 bytes    Slot 4
}

// Packed into 4 slots (128 bytes)
struct UnstakeWithAutoclaimRequest {
    address user;           // 20 bytes ─┐
    uint96 nonce;           // 12 bytes ─┘ Slot 1
    address vault;          // 20 bytes ─┐
    uint96 deadline;        // 12 bytes ─┘ Slot 2
    address recipient;      // 20 bytes ─┐
    uint96 maxFee;          // 12 bytes ─┘ Slot 3
    uint256 stkTokenAmount; // 32 bytes    Slot 4
}
```

### AutoclaimAuth

Stored per `requestId` when a user opts into autoclaim. Single slot.

```solidity
struct AutoclaimAuth {
    address vault;          // 20 bytes ─┐
    bool isStake;           //  1 byte  ─┤ Slot 1
    bool executed;          //  1 byte  ─┘
}
```

### Permit Signature

For EIP-2612 gasless approvals:

```solidity
struct PermitSignature {
    uint256 value;          // Amount to approve
    uint256 deadline;       // Permit expiration
    uint8 v;                // Signature v
    bytes32 r;              // Signature r
    bytes32 s;              // Signature s
}
```

## Flow Diagram

### Stake With Autoclaim Flow

```
User                    Executor                 Paymaster              Vault
 │                         │                         │                    │
 │ Sign Permit             │                         │                    │
 │ Sign StakeWithAutoclaim │                         │                    │
 │────────────────────────>│                         │                    │
 │                         │                         │                    │
 │                         │ executeRequestStake     │                    │
 │                         │ WithAutoclaim(...)      │                    │
 │                         │────────────────────────>│                    │
 │                         │                         │                    │
 │                         │                         │ validate + permit  │
 │                         │                         │ transfer fee       │
 │                         │                         │────────────>Treasury
 │                         │                         │                    │
 │                         │                         │ requestStake       │
 │                         │                         │───────────────────>│
 │                         │                         │<───────────────────│
 │                         │                         │    requestId       │
 │                         │                         │                    │
 │                         │                         │ register autoclaim │
 │                         │                         │ (requestId -> auth)│
 │                         │<────────────────────────│                    │
 │                         │                         │                    │
 ═══════════════════════ settlement happens ═════════════════════════════
 │                         │                         │                    │
 │                         │ executeAutoclaimStaked  │                    │
 │                         │ SharesBatch([ids])      │                    │
 │                         │────────────────────────>│                    │
 │                         │                         │                    │
 │                         │                         │ claimStakedShares  │
 │                         │                         │───────────────────>│
 │                         │                         │<───────────────────│
 │                         │                         │  (mints stkTokens) │
 │                         │                         │                    │
 │                         │                         │ mark executed      │
 │                         │<────────────────────────│                    │
```

If a batch claim fails for one request (not yet settled, etc.), the paymaster emits `AutoclaimFailed` for that request and continues. The entry stays `executed = false` so it can be retried in the next batch.

Non-batch autoclaim calls (`executeAutoclaimStakedShares`, `executeAutoclaimUnstakedAssets`) revert on failure instead, since there's no reason to silently skip a single call.

## Security Model

### Trust Assumptions

1. **Trusted Executors**: Only whitelisted addresses can submit transactions
2. **maxFee Protection**: Users cryptographically commit to maximum acceptable fee
3. **Nonce Protection**: Sequential nonces prevent replay attacks
4. **Deadline Protection**: Requests expire after specified timestamp

### Attack Vectors & Mitigations

| Attack | Mitigation |
|--------|------------|
| Signature replay | Sequential nonces per user |
| Fee manipulation | maxFee in signed message |
| Stale requests | Deadline timestamp check |
| Unauthorized execution | Trusted executor whitelist |
| Permit replay | Token-level nonces |
| Batch autoclaim bricking | `executed` only set on success; failures emit event and stay retryable |

## Gas Optimizations

1. **Packed Structs**: Fields ordered for optimal slot packing (address+uint96 pairs)
2. **Unchecked Arithmetic**: Safe unchecked blocks for nonce increments
3. **Solady Libraries**: Gas-optimized EIP712, SafeTransferLib, `safeApproveWithRetry` for vault approvals
4. **Zero-Fee Optimization**: Skip fee transfer when fee = 0
5. **Calldata over Memory**: Use calldata for all external inputs
6. **AutoclaimAuth Packing**: `vault + isStake + executed` fits in a single storage slot

## Integration with KAM Protocol

### Vault Requirements

The kStakingVault must:
1. Have kPaymaster set as trusted forwarder
2. Implement ERC2771 `_msgSender()` pattern
3. Support EIP-2612 permit for its token (stkToken)

### Token Requirements

kTokens and stkTokens must:
1. Implement EIP-2612 permit
2. Have standard ERC20 transfer functions

### Setup Sequence

```solidity
// 1. Deploy paymaster
kPaymaster paymaster = new kPaymaster(owner, treasury, registry);

// 2. Add trusted executors
paymaster.setTrustedExecutor(relayer, true);

// 3. Set paymaster as trusted forwarder on vault
vault.setTrustedForwarder(address(paymaster));
```

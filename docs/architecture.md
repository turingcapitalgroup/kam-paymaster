# KAM Paymaster Architecture

## Overview

The KamPaymaster is an ERC2771-style trusted forwarder that enables gasless interactions with KAM Protocol's kStakingVaults. Users sign meta-transactions off-chain, and trusted executors (relayers) submit them on-chain while deducting fees from the tokens being transferred.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER WALLET                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  1. Sign EIP-2612 Permit(s) for token approval                      │    │
│  │  2. Sign EIP-712 Request (Stake/Unstake/Claim)                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUSTED EXECUTOR (Relayer)                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  - Receives signed request + permits from user                       │    │
│  │  - Determines actual fee (must be <= user's maxFee)                  │    │
│  │  - Submits transaction to KamPaymaster                               │    │
│  │  - Pays gas costs                                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              KAM PAYMASTER                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  1. Verify caller is trusted executor                                │    │
│  │  2. Validate EIP-712 request signature                               │    │
│  │  3. Validate fee <= maxFee                                           │    │
│  │  4. Execute permit(s) for token approval                             │    │
│  │  5. Transfer fee to treasury                                         │    │
│  │  6. Forward call to vault with user address appended                 │    │
│  │  7. Increment user nonce                                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            kStakingVault                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  - Receives call with user address appended to calldata              │    │
│  │  - Extracts real user via _msgSender() (ERC2771)                     │    │
│  │  - Executes stake/unstake/claim on behalf of user                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Contract Components

### KamPaymaster

The main contract that handles gasless meta-transactions.

**Inheritance:**
- `IKamPaymaster` - Interface definition
- `EIP712` (Solady) - EIP-712 typed data signing
- `Ownable` (Solady) - Access control

**Storage:**
```solidity
address public treasury;                              // Fee recipient
mapping(address => uint256) private _nonces;          // User nonces
mapping(address => bool) private _trustedExecutors;   // Whitelisted relayers
```

### Request Types

All request structs use **packed fields** for gas optimization:

```solidity
// Packed into 4 slots (128 bytes)
struct StakeRequest {
    address user;           // 20 bytes ─┐
    uint96 nonce;           // 12 bytes ─┘ Slot 1
    address vault;          // 20 bytes ─┐
    uint96 deadline;        // 12 bytes ─┘ Slot 2
    address recipient;      // 20 bytes ─┐
    uint96 maxFee;          // 12 bytes ─┘ Slot 3
    uint256 kTokenAmount;   // 32 bytes    Slot 4
}

// Packed into 4 slots (128 bytes)
struct UnstakeRequest {
    address user;           // 20 bytes ─┐
    uint96 nonce;           // 12 bytes ─┘ Slot 1
    address vault;          // 20 bytes ─┐
    uint96 deadline;        // 12 bytes ─┘ Slot 2
    address recipient;      // 20 bytes ─┐
    uint96 maxFee;          // 12 bytes ─┘ Slot 3
    uint256 stkTokenAmount; // 32 bytes    Slot 4
}

// Packed into 4 slots (128 bytes)
struct ClaimRequest {
    address user;           // 20 bytes ─┐
    uint96 nonce;           // 12 bytes ─┘ Slot 1
    address vault;          // 20 bytes ─┐
    uint96 deadline;        // 12 bytes ─┘ Slot 2
    uint96 maxFee;          // 12 bytes    Slot 3 (20 bytes padding)
    bytes32 requestId;      // 32 bytes    Slot 4
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

## Flow Diagrams

### Gasless Stake Flow

```
User                    Executor                 Paymaster              Vault
 │                         │                         │                    │
 │ Sign Permit (fee)       │                         │                    │
 │ Sign Permit (vault)     │                         │                    │
 │ Sign StakeRequest       │                         │                    │
 │────────────────────────>│                         │                    │
 │                         │                         │                    │
 │                         │ executeRequestStake     │                    │
 │                         │ WithPermit(req,permits, │                    │
 │                         │ sig, fee)               │                    │
 │                         │────────────────────────>│                    │
 │                         │                         │                    │
 │                         │                         │ validate signature │
 │                         │                         │ validate fee       │
 │                         │                         │ execute permits    │
 │                         │                         │                    │
 │                         │                         │ transfer fee       │
 │                         │                         │────────────>Treasury
 │                         │                         │                    │
 │                         │                         │ requestStake       │
 │                         │                         │ (appended user)    │
 │                         │                         │───────────────────>│
 │                         │                         │                    │
 │                         │                         │<───────────────────│
 │                         │                         │    requestId       │
 │                         │<────────────────────────│                    │
 │                         │        requestId        │                    │
```

### Gasless Claim Flow

```
User                    Executor                 Paymaster              Vault
 │                         │                         │                    │
 │ Sign Permit (fee)       │                         │                    │
 │ Sign ClaimRequest       │                         │                    │
 │────────────────────────>│                         │                    │
 │                         │                         │                    │
 │                         │ executeClaimStaked      │                    │
 │                         │ SharesWithPermit(...)   │                    │
 │                         │────────────────────────>│                    │
 │                         │                         │                    │
 │                         │                         │ claimStakedShares  │
 │                         │                         │ (appended user)    │
 │                         │                         │───────────────────>│
 │                         │                         │                    │
 │                         │                         │<───────────────────│
 │                         │                         │  (mints stkTokens) │
 │                         │                         │                    │
 │                         │                         │ transfer fee       │
 │                         │                         │────────────>Treasury
 │                         │                         │                    │
 │                         │<────────────────────────│                    │
```

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

## Gas Optimizations

1. **Packed Structs**: Fields ordered for optimal slot packing (address+uint96 pairs)
2. **Unchecked Arithmetic**: Safe unchecked blocks for nonce increments
3. **Solady Libraries**: Gas-optimized EIP712, SafeTransferLib
4. **Zero-Fee Optimization**: Skip fee transfer when fee = 0
5. **Calldata over Memory**: Use calldata for all external inputs

## Integration with KAM Protocol

### Vault Requirements

The kStakingVault must:
1. Have KamPaymaster set as trusted forwarder
2. Implement ERC2771 `_msgSender()` pattern
3. Support EIP-2612 permit for its token (stkToken)

### Token Requirements

kTokens and stkTokens must:
1. Implement EIP-2612 permit
2. Have standard ERC20 transfer functions

### Setup Sequence

```solidity
// 1. Deploy paymaster
KamPaymaster paymaster = new KamPaymaster(owner, treasury);

// 2. Add trusted executors
paymaster.setTrustedExecutor(relayer, true);

// 3. Set paymaster as trusted forwarder on vault
vault.setTrustedForwarder(address(paymaster));
```

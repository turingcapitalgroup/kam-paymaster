# KAM Paymaster

A gasless ERC2771 forwarder contract that enables users to perform gasless interactions with KAM Protocol's kStakingVaults using autoclaim functionality.

## Overview

The kPaymaster contract allows users to execute staking operations without holding ETH for gas. Users sign meta-transactions with a `maxFee` parameter to protect against excessive fees, and trusted executors relay the transactions while deducting fees from the tokens being transferred.

### Key Features

- **EIP-712 Typed Signatures**: Secure meta-transaction signing for gasless operations
- **EIP-2612 Permit Integration**: Gasless token approvals using permit signatures
- **maxFee Protection**: Users specify maximum acceptable fee in their signatures
- **Autoclaim**: Users sign once for both the request and the claim. Fee is paid upfront so the executor can claim without further user interaction after settlement
- **Packed Structs**: Gas-optimized calldata with optimal slot packing (address+uint96 pairs)
- **Trusted Executors**: Permissioned relayer system for transaction execution
- **Batch Operations**: Execute multiple requests in a single transaction

## Architecture

```
User Signs Request + Permit (with maxFee)
         |
   Trusted Executor (specifies actual fee <= maxFee)
         |
   kPaymaster
    |-- Validates signatures
    |-- Validates fee <= maxFee
    |-- Executes permit (gasless approval)
    |-- Deducts fee -> Treasury
    |-- Forwards call to kStakingVault (ERC2771 style)
    +-- Registers autoclaim for later execution
         |
   kStakingVault
    +-- Extracts user from calldata suffix (_msgSender())

...after settlement...

   Trusted Executor
         |
   kPaymaster.executeAutoclaim*(requestId)
    +-- Claims on user's behalf (no signature needed)
```

## Fee Model

### maxFee Protection

Users include a `maxFee` parameter in their signed requests. The executor specifies the actual fee at execution time, which must be less than or equal to `maxFee`. This protects users from:
- Gas price spikes between signing and execution
- Malicious executors charging excessive fees

### Fee Flow

1. User signs request with `maxFee` (maximum they're willing to pay, covers both request + claim)
2. Executor calls paymaster with actual `fee` parameter
3. Paymaster validates `fee <= maxFee`
4. Fee is transferred from user to treasury upfront
5. Remaining amount is forwarded to vault
6. Autoclaim is registered for later execution (no additional fee at claim time)

## Supported Operations

| Operation | Fee Token | Description |
|-----------|-----------|-------------|
| `requestStakeWithAutoclaim` | kToken | Stake + register autoclaim (fee covers both) |
| `requestUnstakeWithAutoclaim` | stkToken | Unstake + register autoclaim (fee covers both) |
| `autoclaimStakedShares` | — | Executor claims on user's behalf (no fee at claim time) |
| `autoclaimUnstakedAssets` | — | Executor claims on user's behalf (no fee at claim time) |

Each operation has:
- **With Permit**: Includes EIP-2612 permit for gasless approval
- **Without Permit**: Requires pre-approval of tokens
- **Batch**: Execute multiple requests in one transaction

Autoclaim batch operations are fault-tolerant — if a single claim in the batch fails (e.g. not yet settled), it emits `AutoclaimFailed` and moves on. The failed autoclaim stays retryable.

## Installation

```bash
# Install dependencies
forge soldeer install

# Build
forge build

# Test
forge test
```

## Testing

The project includes test suites:

```bash
# Unit tests with mocks
forge test --match-contract kPaymasterTest

# Integration tests with mock vault
forge test --match-contract kPaymasterIntegrationTest
```

## Deployment

```bash
# Deploy
forge script script/DeploykPaymaster.s.sol --rpc-url <rpc_url> --broadcast
```

### Post-Deployment Setup

```solidity
// Add trusted executors (relayers)
paymaster.setTrustedExecutor(RELAYER_ADDRESS, true);

// Set paymaster as trusted forwarder on vaults
vault.setTrustedForwarder(address(paymaster));
```

## Contract Interface

### Admin Functions

| Function | Description |
|----------|-------------|
| `setTrustedExecutor(address, bool)` | Add/remove trusted executors |
| `setTreasury(address)` | Update fee recipient |
| `rescueTokens(address, address, uint256)` | Rescue stuck tokens |

### View Functions

| Function | Description |
|----------|-------------|
| `nonces(address)` | Get user's current nonce |
| `DOMAIN_SEPARATOR()` | Get EIP-712 domain separator |
| `isTrustedExecutor(address)` | Check if address is trusted executor |
| `treasury()` | Get treasury address |
| `getAutoclaimAuth(bytes32)` | Get autoclaim registration for a request ID |
| `canAutoclaim(bytes32)` | Check if autoclaim is registered and not yet executed |

## EIP-712 Type Definitions

### StakeWithAutoclaimRequest
```solidity
StakeWithAutoclaimRequest(
    address user,      // 20 bytes ─┐
    uint96 nonce,      // 12 bytes ─┘ Slot 1
    address vault,     // 20 bytes ─┐
    uint96 deadline,   // 12 bytes ─┘ Slot 2
    address recipient, // 20 bytes ─┐
    uint96 maxFee,     // 12 bytes ─┘ Slot 3
    uint256 kTokenAmount // 32 bytes  Slot 4
)
```

### UnstakeWithAutoclaimRequest
```solidity
UnstakeWithAutoclaimRequest(
    address user,      // 20 bytes ─┐
    uint96 nonce,      // 12 bytes ─┘ Slot 1
    address vault,     // 20 bytes ─┐
    uint96 deadline,   // 12 bytes ─┘ Slot 2
    address recipient, // 20 bytes ─┐
    uint96 maxFee,     // 12 bytes ─┘ Slot 3
    uint256 stkTokenAmount // 32 bytes  Slot 4
)
```

### AutoclaimAuth
```solidity
AutoclaimAuth(
    address vault,     // 20 bytes ─┐
    bool isStake,      //  1 byte  ─┤ Slot 1
    bool executed      //  1 byte  ─┘
)
```

Stored per `requestId`. Fits in a single slot.

## Integration Example

```typescript
// 1. Create stake with autoclaim request
const stakeRequest = {
    user: userAddress,
    nonce: await paymaster.nonces(userAddress),
    vault: vaultAddress,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    recipient: userAddress,
    maxFee: parseUnits("100", 6), // Max 100 USDC fee (covers request + claim)
    kTokenAmount: parseUnits("1000", 6)
};

// 2. Sign permit for paymaster (full amount)
const permit = await signPermit(kToken, {
    owner: userAddress,
    spender: paymasterAddress,
    value: stakeRequest.kTokenAmount,
    deadline: stakeRequest.deadline
});

// 3. Sign stake with autoclaim request (EIP-712)
const requestSig = await signTypedData(domain, types, stakeRequest);

// 4. Executor submits transaction
const requestId = await paymaster.executeRequestStakeWithAutoclaimWithPermit(
    stakeRequest,
    permit,
    requestSig,
    actualFee // Must be <= maxFee
);

// 5. After settlement, executor claims on user's behalf
await paymaster.executeAutoclaimStakedShares(requestId);
```

## Security Considerations

1. **maxFee Protection**: Users specify maximum fee they accept
2. **Signature Replay Protection**: Nonces prevent signature replay attacks
3. **Deadline Enforcement**: All requests have expiration timestamps
4. **Trusted Executors Only**: Only whitelisted addresses can execute requests
5. **SafeTransferLib**: Solady's safe transfer patterns; `safeApproveWithRetry` for vault approvals
6. **ERC2771 Forwarding**: User address securely appended to calldata

## Dependencies

- [Solady](https://github.com/Vectorized/solady) - Gas-optimized Solidity utilities
- [KAM Protocol](https://github.com/turingcapitalgroup/kam) - Staking vault infrastructure
- [Forge Std](https://github.com/foundry-rs/forge-std) - Foundry testing utilities

## License

MIT

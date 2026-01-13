# KAM Paymaster

A gasless ERC2771 forwarder contract that enables users to perform gasless interactions with KAM Protocol's kStakingVaults.

## Overview

The KamPaymaster contract allows users to execute staking operations without holding ETH for gas. Users sign meta-transactions with a `maxFee` parameter to protect against excessive fees, and trusted executors relay the transactions while deducting fees from the tokens being transferred.

### Key Features

- **EIP-712 Typed Signatures**: Secure meta-transaction signing for gasless operations
- **EIP-2612 Permit Integration**: Gasless token approvals using permit signatures
- **maxFee Protection**: Users specify maximum acceptable fee in their signatures
- **Packed Structs**: Gas-optimized calldata with optimal slot packing (address+uint96 pairs)
- **Trusted Executors**: Permissioned relayer system for transaction execution
- **Batch Operations**: Execute multiple requests in a single transaction

## Architecture

```
User Signs Request + Permit (with maxFee)
         |
   Trusted Executor (specifies actual fee <= maxFee)
         |
   KamPaymaster
    |-- Validates signatures
    |-- Validates fee <= maxFee
    |-- Executes permit (gasless approval)
    |-- Deducts fee -> Treasury
    +-- Forwards call to kStakingVault (ERC2771 style)
         |
   kStakingVault
    +-- Extracts user from calldata suffix (_msgSender())
```

## Fee Model

### maxFee Protection

Users include a `maxFee` parameter in their signed requests. The executor specifies the actual fee at execution time, which must be less than or equal to `maxFee`. This protects users from:
- Gas price spikes between signing and execution
- Malicious executors charging excessive fees

### Fee Flow

1. User signs request with `maxFee` (maximum they're willing to pay)
2. Executor calls paymaster with actual `fee` parameter
3. Paymaster validates `fee <= maxFee`
4. Fee is transferred from user to treasury
5. Remaining amount is forwarded to vault

## Supported Operations

| Operation | Fee Token | Description |
|-----------|-----------|-------------|
| `requestStake` | kToken | Stake kTokens to receive stkTokens |
| `requestUnstake` | stkToken | Request unstaking of stkTokens |
| `claimStakedShares` | stkToken | Claim stkTokens after stake settles |
| `claimUnstakedAssets` | kToken | Claim kTokens after unstake settles |

Each operation has:
- **With Permit**: Includes EIP-2612 permit for gasless approval
- **Without Permit**: Requires pre-approval of tokens
- **Batch**: Execute multiple requests in one transaction

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

The project includes three test suites:

```bash
# Unit tests with mocks
forge test --match-contract KamPaymasterTest

# Integration tests with mock vault
forge test --match-contract KamPaymasterIntegrationTest

# Integration tests with actual KAM protocol
forge test --match-contract KamPaymasterKAMTest
```

### Environment Setup

For KAM integration tests, create a `.env` file:

```bash
DEPLOYMENT_BASE_PATH=dependencies/kam-1.0/deployments
```

## Deployment

```bash
# Deploy
forge script script/DeployKamPaymaster.s.sol --rpc-url <rpc_url> --broadcast
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

## EIP-712 Type Definitions

### StakeRequest
```solidity
StakeRequest(
    address user,      // 20 bytes ─┐
    uint96 nonce,      // 12 bytes ─┘ Slot 1
    address vault,     // 20 bytes ─┐
    uint96 deadline,   // 12 bytes ─┘ Slot 2
    address recipient, // 20 bytes ─┐
    uint96 maxFee,     // 12 bytes ─┘ Slot 3
    uint256 kTokenAmount // 32 bytes  Slot 4
)
```

### UnstakeRequest
```solidity
UnstakeRequest(
    address user,      // 20 bytes ─┐
    uint96 nonce,      // 12 bytes ─┘ Slot 1
    address vault,     // 20 bytes ─┐
    uint96 deadline,   // 12 bytes ─┘ Slot 2
    address recipient, // 20 bytes ─┐
    uint96 maxFee,     // 12 bytes ─┘ Slot 3
    uint256 stkTokenAmount // 32 bytes  Slot 4
)
```

### ClaimRequest
```solidity
ClaimRequest(
    address user,      // 20 bytes ─┐
    uint96 nonce,      // 12 bytes ─┘ Slot 1
    address vault,     // 20 bytes ─┐
    uint96 deadline,   // 12 bytes ─┘ Slot 2
    uint96 maxFee,     // 12 bytes    Slot 3
    bytes32 requestId  // 32 bytes    Slot 4
)
```

## Integration Example

```typescript
// 1. Create stake request with maxFee protection
const stakeRequest = {
    user: userAddress,
    nonce: await paymaster.nonces(userAddress),
    vault: vaultAddress,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    recipient: userAddress,
    maxFee: parseUnits("100", 6), // Max 100 USDC fee
    kTokenAmount: parseUnits("1000", 6)
};

// 2. Sign permit for paymaster (fee amount)
const permitForForwarder = await signPermit(kToken, {
    owner: userAddress,
    spender: paymasterAddress,
    value: actualFee,
    deadline: stakeRequest.deadline
});

// 3. Sign permit for vault (stake amount minus fee)
const permitForVault = await signPermit(kToken, {
    owner: userAddress,
    spender: vaultAddress,
    value: stakeRequest.kTokenAmount - actualFee,
    deadline: stakeRequest.deadline
});

// 4. Sign stake request (EIP-712)
const requestSig = await signTypedData(domain, types, stakeRequest);

// 5. Executor submits transaction
await paymaster.executeRequestStakeWithPermit(
    stakeRequest,
    permitForForwarder,
    permitForVault,
    requestSig,
    actualFee // Must be <= maxFee
);
```

## Security Considerations

1. **maxFee Protection**: Users specify maximum fee they accept
2. **Signature Replay Protection**: Nonces prevent signature replay attacks
3. **Deadline Enforcement**: All requests have expiration timestamps
4. **Trusted Executors Only**: Only whitelisted addresses can execute requests
5. **SafeTransferLib**: All token transfers use Solady's safe transfer patterns
6. **ERC2771 Forwarding**: User address securely appended to calldata

## Dependencies

- [Solady](https://github.com/Vectorized/solady) - Gas-optimized Solidity utilities
- [KAM Protocol](https://github.com/turingcapitalgroup/kam) - Staking vault infrastructure
- [Forge Std](https://github.com/foundry-rs/forge-std) - Foundry testing utilities

## License

MIT

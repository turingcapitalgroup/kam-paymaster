# KAM Paymaster

A gasless ERC2771 forwarder contract that enables users to perform gasless interactions with KAM Protocol's kStakingVaults using Chainlink oracles for accurate fee calculation.

## Overview

The KamPaymaster contract allows users to execute staking operations without holding ETH for gas. Fees are calculated using Chainlink price oracles and deducted from the tokens being transferred (kTokens for deposits, stkTokens for redemptions and claims).

### Key Features

- **EIP-712 Typed Signatures**: Secure meta-transaction signing for gasless operations
- **EIP-2612 Permit Integration**: Gasless token approvals using permit signatures
- **Chainlink Oracle Integration**: Accurate asset/ETH price feeds for fee calculation
- **Trusted Executors**: Permissioned relayer system for transaction execution
- **Fee on All Operations**: Fees deducted on requestStake, requestUnstake, claimStakedShares, and claimUnstakedAssets

## Architecture

```
User Signs Request + Permit
         ↓
   Trusted Executor
         ↓
   KamPaymaster
    ├── Validates signatures
    ├── Gets asset/ETH price from Chainlink
    ├── Calculates fee in token terms
    ├── Executes permit (gasless approval)
    ├── Deducts fee → Treasury
    └── Forwards call to kStakingVault (ERC2771 style)
         ↓
   kStakingVault
    └── Extracts user from calldata suffix (_msgSender())
```

## Fee Model

### Price Oracle Integration

The contract uses Chainlink price feeds to convert gas costs (in ETH) to token amounts:

- **For kTokens**: Uses the underlying asset's Chainlink price feed (e.g., USDC/ETH for kUSD, WBTC/ETH for kBTC)
- **For stkTokens**: First converts stkTokens to kTokens using vault's `convertToAssets()`, then uses the underlying asset's price feed

### Fee Calculation

```
Fee = GasCostInTokens + BaseFee

Where:
- GasCostInTokens = (gasEstimate × gasPrice × gasMultiplier) ÷ assetPriceInEth
- BaseFee = GasCostInTokens × baseFee(bps) ÷ 10000
```

### Oracle Configuration

```solidity
// Set USDC/ETH price feed for kUSD
paymaster.setAssetPriceFeed(USDC_ADDRESS, CHAINLINK_USDC_ETH_FEED);

// Set WBTC/ETH price feed for kBTC
paymaster.setAssetPriceFeed(WBTC_ADDRESS, CHAINLINK_WBTC_ETH_FEED);
```

## Supported Operations

### 1. Gasless Stake (requestStake)
- User signs permit + stake request
- Fee calculated using kToken's underlying asset price feed
- Fee deducted from kTokens before forwarding to vault

### 2. Gasless Unstake (requestUnstake)
- User signs permit + unstake request
- Fee calculated by converting stkTokens to kTokens (via `convertToAssets`)
- Fee deducted from stkTokens before forwarding to vault

### 3. Gasless Claim Staked Shares (claimStakedShares)
- User signs permit + claim request
- Vault mints stkTokens to user
- Fee calculated based on received stkTokens → kTokens value
- Fee deducted from received stkTokens via permit

### 4. Gasless Claim Unstaked Assets (claimUnstakedAssets)
- User signs permit + claim request
- Vault transfers kTokens to user
- Fee calculated using kToken's price feed
- Fee deducted from received kTokens via permit

## Installation

```bash
# Install dependencies
forge install

# Build
forge build

# Test
forge test
```

## Deployment

```bash
# Set environment variables
export KAM_REGISTRY=<registry_address>
export PAYMASTER_OWNER=<owner_address>
export PAYMASTER_TREASURY=<treasury_address>
export PAYMASTER_BASE_FEE=100  # 1% base fee
export PAYMASTER_GAS_MULTIPLIER=1200000000000000000  # 1.2x

# Deploy
forge script script/DeployKamPaymaster.s.sol --rpc-url <rpc_url> --broadcast
```

### Post-Deployment Setup

```solidity
// Set Chainlink price feeds for supported assets
paymaster.setAssetPriceFeed(USDC, CHAINLINK_USDC_ETH);
paymaster.setAssetPriceFeed(WBTC, CHAINLINK_WBTC_ETH);

// Add trusted executors (relayers)
paymaster.setTrustedExecutor(RELAYER_ADDRESS, true);
```

## Contract Configuration

### Admin Functions

| Function | Description |
|----------|-------------|
| `setTrustedExecutor(address, bool)` | Add/remove trusted executors |
| `setFeeConfig(uint256, uint256)` | Update base fee and gas multiplier |
| `setTreasury(address)` | Update fee recipient |
| `setAssetPriceFeed(address, address)` | Set Chainlink price feed for an asset |
| `rescueTokens(address, address, uint256)` | Rescue stuck tokens |

### View Functions

| Function | Description |
|----------|-------------|
| `nonces(address)` | Get user's current nonce |
| `DOMAIN_SEPARATOR()` | Get EIP-712 domain separator |
| `calculateFeeForKToken(uint256, address)` | Calculate fee for kToken |
| `calculateFeeForStkToken(uint256, address)` | Calculate fee for stkToken |
| `isTrustedExecutor(address)` | Check if address is trusted executor |
| `assetPriceFeeds(address)` | Get Chainlink feed for an asset |

## Chainlink Price Feeds

### Mainnet Examples

| Asset | Price Feed | Description |
|-------|------------|-------------|
| USDC | `0x986b5E1e1755e3C2440e960477f25201B0a8bbD4` | USDC/ETH |
| WBTC | `0xdeb288F737066589598e9214E782fa5A8eD689e8` | WBTC/ETH |
| DAI | `0x773616E4d11A78F511299002da57A0a94577F1f4` | DAI/ETH |

### Price Feed Requirements

- Must return asset/ETH price (not USD)
- Maximum staleness: 1 hour
- Price must be positive

## EIP-712 Type Definitions

### StakeRequest
```solidity
StakeRequest(
    address user,
    address vault,
    uint256 kTokenAmount,
    address recipient,
    uint256 deadline,
    uint256 nonce
)
```

### UnstakeRequest
```solidity
UnstakeRequest(
    address user,
    address vault,
    uint256 stkTokenAmount,
    address recipient,
    uint256 deadline,
    uint256 nonce
)
```

### ClaimRequest
```solidity
ClaimRequest(
    address user,
    address vault,
    bytes32 requestId,
    uint256 deadline,
    uint256 nonce
)
```

## Integration Example

```typescript
// 1. Create stake request
const stakeRequest = {
    user: userAddress,
    vault: vaultAddress,
    kTokenAmount: parseUnits("1000", 6),
    recipient: userAddress,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    nonce: await paymaster.nonces(userAddress)
};

// 2. Sign permit for kToken
const permitSig = await signPermit(kToken, {
    owner: userAddress,
    spender: paymasterAddress,
    value: stakeRequest.kTokenAmount,
    deadline: stakeRequest.deadline
});

// 3. Sign stake request
const requestSig = await signTypedData(domain, types, stakeRequest);

// 4. Execute via trusted executor
await paymaster.executeStakeWithPermit(stakeRequest, permitSig, requestSig);
```

## Security Considerations

1. **Signature Replay Protection**: Nonces prevent signature replay attacks
2. **Deadline Enforcement**: All requests have expiration timestamps
3. **Trusted Executors Only**: Only whitelisted addresses can execute requests
4. **Fee Limits**: Maximum fee capped at 50% to prevent griefing
5. **SafeTransferLib**: All token transfers use safe transfer patterns
6. **Oracle Validation**: Chainlink prices are validated for staleness and positivity
7. **Price Staleness**: Rejects prices older than 1 hour

## License

MIT

# Contract Interfaces

## IKamPaymaster

The main interface for the KamPaymaster contract.

### Structs

#### StakeRequest

Request to stake kTokens in a vault.

```solidity
struct StakeRequest {
    address user;           // User address
    uint48 nonce;           // User's current nonce
    uint48 deadline;        // Request expiration timestamp
    address vault;          // Target kStakingVault
    uint48 maxFee;          // Maximum fee user accepts
    uint48 kTokenAmount;    // Amount of kTokens to stake
    address recipient;      // Recipient of stkTokens
}
```

#### UnstakeRequest

Request to unstake stkTokens from a vault.

```solidity
struct UnstakeRequest {
    address user;           // User address
    uint48 nonce;           // User's current nonce
    uint48 deadline;        // Request expiration timestamp
    address vault;          // Target kStakingVault (also the stkToken)
    uint48 maxFee;          // Maximum fee user accepts
    uint48 stkTokenAmount;  // Amount of stkTokens to unstake
    address recipient;      // Recipient of kTokens after claim
}
```

#### ClaimRequest

Request to claim staked shares or unstaked assets.

```solidity
struct ClaimRequest {
    address user;           // User address
    uint48 nonce;           // User's current nonce
    uint48 deadline;        // Request expiration timestamp
    address vault;          // Target kStakingVault
    uint48 maxFee;          // Maximum fee user accepts
    bytes32 requestId;      // Request ID from stake/unstake
}
```

#### PermitSignature

EIP-2612 permit signature data.

```solidity
struct PermitSignature {
    uint48 value;           // Amount to approve
    uint48 deadline;        // Permit expiration timestamp
    uint8 v;                // Signature v
    bytes32 r;              // Signature r
    bytes32 s;              // Signature s
}
```

### Functions

#### Execute Functions (With Permit)

```solidity
function executeRequestStakeWithPermit(
    StakeRequest calldata request,
    PermitSignature calldata permitForForwarder,
    PermitSignature calldata permitForVault,
    bytes calldata requestSig,
    uint48 fee
) external returns (bytes32 requestId);

function executeRequestUnstakeWithPermit(
    UnstakeRequest calldata request,
    PermitSignature calldata permitSig,
    bytes calldata requestSig,
    uint48 fee
) external returns (bytes32 requestId);

function executeClaimStakedSharesWithPermit(
    ClaimRequest calldata request,
    PermitSignature calldata permitSig,
    bytes calldata requestSig,
    uint48 fee
) external;

function executeClaimUnstakedAssetsWithPermit(
    ClaimRequest calldata request,
    PermitSignature calldata permitSig,
    bytes calldata requestSig,
    uint48 fee
) external;
```

#### Execute Functions (Without Permit)

```solidity
function executeRequestStake(
    StakeRequest calldata request,
    bytes calldata requestSig,
    uint48 fee
) external returns (bytes32 requestId);

function executeRequestUnstake(
    UnstakeRequest calldata request,
    bytes calldata requestSig,
    uint48 fee
) external returns (bytes32 requestId);

function executeClaimStakedShares(
    ClaimRequest calldata request,
    bytes calldata requestSig,
    uint48 fee
) external;

function executeClaimUnstakedAssets(
    ClaimRequest calldata request,
    bytes calldata requestSig,
    uint48 fee
) external;
```

#### Batch Functions

```solidity
function executeRequestStakeWithPermitBatch(
    StakeRequest[] calldata requests,
    PermitSignature[] calldata permitsForForwarder,
    PermitSignature[] calldata permitsForVault,
    bytes[] calldata requestSigs,
    uint48[] calldata fees
) external returns (bytes32[] memory requestIds);

function executeRequestUnstakeWithPermitBatch(
    UnstakeRequest[] calldata requests,
    PermitSignature[] calldata permitSigs,
    bytes[] calldata requestSigs,
    uint48[] calldata fees
) external returns (bytes32[] memory requestIds);

function executeRequestStakeBatch(
    StakeRequest[] calldata requests,
    bytes[] calldata requestSigs,
    uint48[] calldata fees
) external returns (bytes32[] memory requestIds);

function executeRequestUnstakeBatch(
    UnstakeRequest[] calldata requests,
    bytes[] calldata requestSigs,
    uint48[] calldata fees
) external returns (bytes32[] memory requestIds);
```

#### View Functions

```solidity
function nonces(address user) external view returns (uint256);
function DOMAIN_SEPARATOR() external view returns (bytes32);
function isTrustedExecutor(address executor) external view returns (bool);
function treasury() external view returns (address);
function owner() external view returns (address);
```

#### Admin Functions

```solidity
function setTrustedExecutor(address executor, bool trusted) external;
function setTreasury(address _treasury) external;
function rescueTokens(address token, address to, uint256 amount) external;
function transferOwnership(address newOwner) external;
```

### Events

```solidity
event GaslessStakeRequested(
    address indexed user,
    address indexed vault,
    uint256 kTokenAmount,
    uint256 fee,
    bytes32 requestId
);

event GaslessUnstakeRequested(
    address indexed user,
    address indexed vault,
    uint256 stkTokenAmount,
    uint256 fee,
    bytes32 requestId
);

event GaslessStakedSharesClaimed(
    address indexed user,
    address indexed vault,
    bytes32 requestId,
    uint256 fee
);

event GaslessUnstakedAssetsClaimed(
    address indexed user,
    address indexed vault,
    bytes32 requestId,
    uint256 fee
);

event TrustedExecutorUpdated(address indexed executor, bool trusted);
event TreasuryUpdated(address indexed treasury);
```

### Errors

```solidity
error NotTrustedExecutor();      // Caller is not a trusted executor
error RequestExpired();          // Request deadline has passed
error InvalidSignature();        // EIP-712 signature is invalid
error InvalidNonce();            // Nonce doesn't match user's current nonce
error ZeroAmount();              // Amount is zero
error ZeroAddress();             // Address is zero
error FeeExceedsMax();           // Fee > maxFee in signed request
error InsufficientAmountForFee(); // Amount <= fee
error PermitExpired();           // Permit deadline has passed
error PermitFailed();            // Permit call failed
error StakeRequestFailed();      // Vault stake call failed
error UnstakeRequestFailed();    // Vault unstake call failed
error ClaimStakedSharesFailed(); // Vault claim shares call failed
error ClaimUnstakedAssetsFailed(); // Vault claim assets call failed
error ArrayLengthMismatch();     // Batch array lengths don't match
```

## EIP-712 Type Hashes

```solidity
bytes32 constant STAKE_REQUEST_TYPEHASH = keccak256(
    "StakeRequest(address user,uint48 nonce,uint48 deadline,address vault,uint48 maxFee,uint48 kTokenAmount,address recipient)"
);

bytes32 constant UNSTAKE_REQUEST_TYPEHASH = keccak256(
    "UnstakeRequest(address user,uint48 nonce,uint48 deadline,address vault,uint48 maxFee,uint48 stkTokenAmount,address recipient)"
);

bytes32 constant CLAIM_REQUEST_TYPEHASH = keccak256(
    "ClaimRequest(address user,uint48 nonce,uint48 deadline,address vault,uint48 maxFee,bytes32 requestId)"
);
```

## EIP-712 Domain

```solidity
{
    name: "KamPaymaster",
    version: "1",
    chainId: <network chain id>,
    verifyingContract: <paymaster address>
}
```

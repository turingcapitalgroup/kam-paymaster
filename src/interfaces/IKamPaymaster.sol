// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IKamPaymaster
/// @notice Interface for the KamPaymaster gasless forwarder contract
/// @dev Enables gasless interactions with kStakingVaults using permit signatures, ERC2771 meta-transactions,
/// and Chainlink oracle price feeds for accurate fee calculation in token terms
interface IKamPaymaster {
    /* //////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a gasless stake request is executed
    /// @param user The user who initiated the stake
    /// @param vault The vault where stake was requested
    /// @param amount The gross kToken amount (before fee deduction)
    /// @param fee The fee deducted in kTokens
    /// @param requestId The resulting stake request ID
    event GaslessStakeRequested(
        address indexed user, address indexed vault, uint256 amount, uint256 fee, bytes32 requestId
    );

    /// @notice Emitted when a gasless unstake request is executed
    /// @param user The user who initiated the unstake
    /// @param vault The vault where unstake was requested
    /// @param stkAmount The stkToken amount being unstaked
    /// @param fee The fee deducted in stkTokens
    /// @param requestId The resulting unstake request ID
    event GaslessUnstakeRequested(
        address indexed user, address indexed vault, uint256 stkAmount, uint256 fee, bytes32 requestId
    );

    /// @notice Emitted when a gasless claim of staked shares is executed
    /// @param user The user claiming shares
    /// @param vault The vault from which shares are claimed
    /// @param requestId The stake request ID being claimed
    /// @param fee The fee deducted in stkTokens
    event GaslessStakedSharesClaimed(address indexed user, address indexed vault, bytes32 requestId, uint256 fee);

    /// @notice Emitted when a gasless claim of unstaked assets is executed
    /// @param user The user claiming assets
    /// @param vault The vault from which assets are claimed
    /// @param requestId The unstake request ID being claimed
    /// @param fee The fee deducted in kTokens
    event GaslessUnstakedAssetsClaimed(address indexed user, address indexed vault, bytes32 requestId, uint256 fee);

    /// @notice Emitted when fee configuration is updated
    /// @param baseFee New base fee in basis points
    /// @param gasMultiplier New gas cost multiplier
    event FeeConfigUpdated(uint256 baseFee, uint256 gasMultiplier);

    /// @notice Emitted when a trusted executor is updated
    /// @param executor The executor address
    /// @param isTrusted Whether the executor is trusted
    event TrustedExecutorUpdated(address indexed executor, bool isTrusted);

    /// @notice Emitted when the treasury is updated
    /// @param treasury The new treasury address
    event TreasuryUpdated(address indexed treasury);

    /// @notice Emitted when a price feed is set for an asset
    /// @param asset The underlying asset address
    /// @param priceFeed The Chainlink price feed address (asset/ETH)
    event PriceFeedSet(address indexed asset, address indexed priceFeed);

    /* //////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an invalid signature is provided
    error InvalidSignature();

    /// @notice Thrown when the request deadline has expired
    error RequestExpired();

    /// @notice Thrown when the nonce doesn't match expected value
    error InvalidNonce();

    /// @notice Thrown when caller is not a trusted executor
    error NotTrustedExecutor();

    /// @notice Thrown when zero address is provided
    error ZeroAddress();

    /// @notice Thrown when zero amount is provided
    error ZeroAmount();

    /// @notice Thrown when the vault is not registered
    error VaultNotRegistered();

    /// @notice Thrown when insufficient amount for fee coverage
    error InsufficientAmountForFee();

    /// @notice Thrown when the permit deadline has expired
    error PermitExpired();

    /// @notice Thrown when fee exceeds maximum allowed percentage
    error FeeExceedsMaximum();

    /// @notice Thrown when the price feed returns stale or invalid data
    error InvalidPriceFeed();

    /// @notice Thrown when no price feed is configured for an asset
    error NoPriceFeedConfigured();

    /* //////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Request structure for gasless stake operations
    /// @param user The address of the user initiating the stake
    /// @param vault The kStakingVault address
    /// @param kTokenAmount The gross amount of kTokens (including fee)
    /// @param recipient The address to receive stkTokens
    /// @param deadline The expiration timestamp for this request
    /// @param nonce The user's current nonce
    struct StakeRequest {
        address user;
        address vault;
        uint256 kTokenAmount;
        address recipient;
        uint256 deadline;
        uint256 nonce;
    }

    /// @notice Request structure for gasless unstake operations
    /// @param user The address of the user initiating the unstake
    /// @param vault The kStakingVault address
    /// @param stkTokenAmount The gross amount of stkTokens (including fee)
    /// @param recipient The address to receive kTokens
    /// @param deadline The expiration timestamp for this request
    /// @param nonce The user's current nonce
    struct UnstakeRequest {
        address user;
        address vault;
        uint256 stkTokenAmount;
        address recipient;
        uint256 deadline;
        uint256 nonce;
    }

    /// @notice Request structure for gasless claim operations
    /// @param user The address of the user claiming
    /// @param vault The kStakingVault address
    /// @param requestId The stake/unstake request ID to claim
    /// @param deadline The expiration timestamp for this request
    /// @param nonce The user's current nonce
    struct ClaimRequest {
        address user;
        address vault;
        bytes32 requestId;
        uint256 deadline;
        uint256 nonce;
    }

    /// @notice Permit signature parameters for EIP-2612
    /// @param value The permit value (allowance amount)
    /// @param deadline The permit deadline
    /// @param v The recovery byte of the signature
    /// @param r Half of the ECDSA signature pair
    /// @param s Half of the ECDSA signature pair
    struct PermitSignature {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /* //////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request with permit
    /// @dev Combines permit + requestStake in a single meta-transaction
    /// @param request The stake request parameters
    /// @param permitSig The permit signature for kToken approval
    /// @param requestSig The signature for the meta-transaction
    /// @return requestId The resulting stake request ID
    function executeStakeWithPermit(
        StakeRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    ) external returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request with permit
    /// @dev Combines permit + requestUnstake in a single meta-transaction
    /// @param request The unstake request parameters
    /// @param permitSig The permit signature for stkToken approval
    /// @param requestSig The signature for the meta-transaction
    /// @return requestId The resulting unstake request ID
    function executeUnstakeWithPermit(
        UnstakeRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    ) external returns (bytes32 requestId);

    /// @notice Execute a gasless claim of staked shares with fee deduction
    /// @dev Claims stkTokens and deducts fee in stkTokens (converted from kToken gas cost)
    /// @param request The claim request parameters
    /// @param permitSig The permit signature to allow fee deduction from received stkTokens
    /// @param requestSig The signature for the meta-transaction
    function executeClaimStakedShares(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    ) external;

    /// @notice Execute a gasless claim of unstaked assets with fee deduction
    /// @dev Claims kTokens and deducts fee in kTokens
    /// @param request The claim request parameters
    /// @param permitSig The permit signature to allow fee deduction from received kTokens
    /// @param requestSig The signature for the meta-transaction
    function executeClaimUnstakedAssets(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    ) external;

    /// @notice Get the current nonce for a user
    /// @param user The user address
    /// @return The current nonce
    function nonces(address user) external view returns (uint256);

    /// @notice Get the EIP-712 domain separator
    /// @return The domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Calculate the fee for a kToken using Chainlink oracle
    /// @param gasEstimate The estimated gas cost
    /// @param kToken The kToken address
    /// @return fee The calculated fee in kToken units
    function calculateFeeForKToken(uint256 gasEstimate, address kToken) external view returns (uint256 fee);

    /// @notice Calculate the fee for stkTokens based on their underlying kToken value
    /// @dev Uses vault's convertToAssets() to determine kToken equivalent
    /// @param gasEstimate The estimated gas cost
    /// @param vault The vault address (stkToken)
    /// @return fee The calculated fee in stkToken units
    function calculateFeeForStkToken(uint256 gasEstimate, address vault) external view returns (uint256 fee);

    /// @notice Check if an address is a trusted executor
    /// @param executor The address to check
    /// @return True if the executor is trusted
    function isTrustedExecutor(address executor) external view returns (bool);

    /// @notice Get the treasury address
    /// @return The treasury address that receives fees
    function treasury() external view returns (address);

    /// @notice Get the base fee in basis points
    /// @return The base fee (10000 = 100%)
    function baseFee() external view returns (uint256);

    /// @notice Get the gas cost multiplier for fee calculations
    /// @return The gas multiplier
    function gasMultiplier() external view returns (uint256);

    /// @notice Get the price feed address for an underlying asset
    /// @param asset The underlying asset address (e.g., USDC, WBTC)
    /// @return The Chainlink price feed address (asset/ETH)
    function assetPriceFeeds(address asset) external view returns (address);
}

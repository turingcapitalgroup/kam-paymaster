// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IKamPaymaster
/// @notice Interface for the KamPaymaster gasless forwarder contract
/// @dev Enables gasless interactions with kStakingVaults using permit signatures and ERC2771 meta-transactions.
/// Fees are passed directly by the trusted executor for simplicity and gas efficiency.
/// Users sign a maxFee parameter to cap the fee that can be charged.
/// Structs are tightly packed for gas optimization.
interface IKamPaymaster {
    /*//////////////////////////////////////////////////////////////
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

    /// @notice Emitted when a trusted executor is updated
    /// @param executor The executor address
    /// @param isTrusted Whether the executor is trusted
    event TrustedExecutorUpdated(address indexed executor, bool isTrusted);

    /// @notice Emitted when the treasury is updated
    /// @param treasury The new treasury address
    event TreasuryUpdated(address indexed treasury);

    /// @notice Emitted when tokens are rescued from the contract
    /// @param token The token address (address(0) for ETH)
    /// @param to The recipient address
    /// @param amount The amount rescued
    event TokensRescued(address indexed token, address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
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

    /// @notice Thrown when fee exceeds user's signed maxFee
    error FeeExceedsMax();

    /// @notice Thrown when stake request to vault fails
    error StakeRequestFailed();

    /// @notice Thrown when unstake request to vault fails
    error UnstakeRequestFailed();

    /// @notice Thrown when claim staked shares fails
    error ClaimStakedSharesFailed();

    /// @notice Thrown when claim unstaked assets fails
    error ClaimUnstakedAssetsFailed();

    /// @notice Thrown when permit call fails
    error PermitFailed();

    /// @notice Thrown when array lengths mismatch in batch operations
    error ArrayLengthMismatch();

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Request structure for gasless stake operations
    /// @dev Packed into 3 storage slots for gas efficiency:
    ///      Slot 1: user (20) + nonce (12) = 32 bytes
    ///      Slot 2: vault (20) + deadline (12) = 32 bytes
    ///      Slot 3: recipient (20) + maxFee (12) = 32 bytes
    ///      Slot 4: kTokenAmount (32) = 32 bytes
    /// @param user The address of the user initiating the stake
    /// @param nonce The user's current nonce (uint96 max ~79 septillion)
    /// @param vault The kStakingVault address
    /// @param deadline The expiration timestamp (uint96 max ~2.5 quadrillion seconds)
    /// @param recipient The address to receive stkTokens
    /// @param maxFee The maximum fee the user agrees to pay (uint96 max ~79B tokens at 18 decimals)
    /// @param kTokenAmount The gross amount of kTokens including fee
    struct StakeRequest {
        address user;
        uint96 nonce;
        address vault;
        uint96 deadline;
        address recipient;
        uint96 maxFee;
        uint256 kTokenAmount;
    }

    /// @notice Request structure for gasless unstake operations
    /// @dev Packed into 4 storage slots for gas efficiency:
    ///      Slot 1: user (20) + nonce (12) = 32 bytes
    ///      Slot 2: vault (20) + deadline (12) = 32 bytes
    ///      Slot 3: recipient (20) + maxFee (12) = 32 bytes
    ///      Slot 4: stkTokenAmount (32) = 32 bytes
    /// @param user The address of the user initiating the unstake
    /// @param nonce The user's current nonce (uint96 max ~79 septillion)
    /// @param vault The kStakingVault address
    /// @param deadline The expiration timestamp (uint96 max ~2.5 quadrillion seconds)
    /// @param recipient The address to receive kTokens
    /// @param maxFee The maximum fee the user agrees to pay (uint96 max ~79B tokens at 18 decimals)
    /// @param stkTokenAmount The gross amount of stkTokens including fee
    struct UnstakeRequest {
        address user;
        uint96 nonce;
        address vault;
        uint96 deadline;
        address recipient;
        uint96 maxFee;
        uint256 stkTokenAmount;
    }

    /// @notice Request structure for gasless claim operations
    /// @dev Packed into 4 storage slots for gas efficiency:
    ///      Slot 1: user (20) + nonce (12) = 32 bytes
    ///      Slot 2: vault (20) + deadline (12) = 32 bytes
    ///      Slot 3: maxFee (12) + 20 bytes padding = 32 bytes
    ///      Slot 4: requestId (32) = 32 bytes
    /// @param user The address of the user claiming
    /// @param nonce The user's current nonce (uint96 max ~79 septillion)
    /// @param vault The kStakingVault address
    /// @param deadline The expiration timestamp (uint96 max ~2.5 quadrillion seconds)
    /// @param maxFee The maximum fee the user agrees to pay (uint96 max ~79B tokens at 18 decimals)
    /// @param requestId The stake/unstake request ID to claim
    struct ClaimRequest {
        address user;
        uint96 nonce;
        address vault;
        uint96 deadline;
        uint96 maxFee;
        bytes32 requestId;
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

    /*//////////////////////////////////////////////////////////////
                    EXTERNAL FUNCTIONS (WITH PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request with permit
    /// @dev Combines permits + requestStake in a single meta-transaction
    /// @param request The stake request parameters
    /// @param permitForForwarder The permit signature for kToken approval to forwarder (for fee)
    /// @param permitForVault The permit signature for kToken approval to vault (for staking)
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    /// @return requestId The resulting stake request ID
    function executeRequestStakeWithPermit(
        StakeRequest calldata request,
        PermitSignature calldata permitForForwarder,
        PermitSignature calldata permitForVault,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request with permit
    /// @dev Combines permit + requestUnstake in a single meta-transaction
    /// @param request The unstake request parameters
    /// @param permitSig The permit signature for stkToken approval
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    /// @return requestId The resulting unstake request ID
    function executeRequestUnstakeWithPermit(
        UnstakeRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless claim of staked shares with permit
    /// @dev Combines permit + claimStakedShares in a single meta-transaction
    /// @param request The claim request parameters
    /// @param permitSig The permit signature for stkToken approval (for fee)
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    function executeClaimStakedSharesWithPermit(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig,
        uint96 fee
    )
        external;

    /// @notice Execute a gasless claim of unstaked assets with permit
    /// @dev Combines permit + claimUnstakedAssets in a single meta-transaction
    /// @param request The claim request parameters
    /// @param permitSig The permit signature for kToken approval (for fee)
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    function executeClaimUnstakedAssetsWithPermit(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig,
        uint96 fee
    )
        external;

    /*//////////////////////////////////////////////////////////////
                  EXTERNAL FUNCTIONS (WITHOUT PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request (assumes allowance already set)
    /// @param request The stake request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    /// @return requestId The resulting stake request ID
    function executeRequestStake(
        StakeRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request (assumes allowance already set)
    /// @param request The unstake request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    /// @return requestId The resulting unstake request ID
    function executeRequestUnstake(
        UnstakeRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless claim of staked shares (assumes allowance already set for fee)
    /// @param request The claim request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    function executeClaimStakedShares(ClaimRequest calldata request, bytes calldata requestSig, uint96 fee) external;

    /// @notice Execute a gasless claim of unstaked assets (assumes allowance already set for fee)
    /// @param request The claim request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    function executeClaimUnstakedAssets(ClaimRequest calldata request, bytes calldata requestSig, uint96 fee) external;

    /*//////////////////////////////////////////////////////////////
                          BATCH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute multiple gasless stake requests in a single transaction
    /// @param requests Array of stake request parameters
    /// @param permitsForForwarder Array of permit signatures for forwarder (for fees)
    /// @param permitsForVault Array of permit signatures for vault (for staking)
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting stake request IDs
    function executeRequestStakeWithPermitBatch(
        StakeRequest[] calldata requests,
        PermitSignature[] calldata permitsForForwarder,
        PermitSignature[] calldata permitsForVault,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless unstake requests in a single transaction
    /// @param requests Array of unstake request parameters
    /// @param permitSigs Array of permit signatures
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting unstake request IDs
    function executeRequestUnstakeWithPermitBatch(
        UnstakeRequest[] calldata requests,
        PermitSignature[] calldata permitSigs,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless stake requests without permits
    /// @param requests Array of stake request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting stake request IDs
    function executeRequestStakeBatch(
        StakeRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless unstake requests without permits
    /// @param requests Array of unstake request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting unstake request IDs
    function executeRequestUnstakeBatch(
        UnstakeRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a user
    /// @param user The user address
    /// @return The current nonce
    function nonces(address user) external view returns (uint256);

    /// @notice Get the EIP-712 domain separator
    /// @return The domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Check if an address is a trusted executor
    /// @param executor The address to check
    /// @return True if the executor is trusted
    function isTrustedExecutor(address executor) external view returns (bool);

    /// @notice Get the treasury address
    /// @return The treasury address that receives fees
    function treasury() external view returns (address);
}

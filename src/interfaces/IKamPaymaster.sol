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

    /// @notice Emitted when autoclaim is registered for a request
    /// @param user The user who authorized autoclaim
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID
    /// @param isStake True if stake request, false if unstake
    event AutoclaimRegistered(address indexed user, address indexed vault, bytes32 indexed requestId, bool isStake);

    /// @notice Emitted when autoclaim is executed
    /// @param user The user whose claim was executed
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID
    /// @param isStake True if stake claim, false if unstake claim
    event AutoclaimExecuted(address indexed user, address indexed vault, bytes32 indexed requestId, bool isStake);

    /// @notice Emitted when a batch autoclaim fails for a specific request
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID that failed
    /// @param isStake True if stake claim, false if unstake claim
    event AutoclaimFailed(address indexed vault, bytes32 indexed requestId, bool isStake);

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

    /// @notice Thrown when autoclaim is not registered for the request
    error AutoclaimNotRegistered();

    /// @notice Thrown when autoclaim has already been executed
    error AutoclaimAlreadyExecuted();

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Request structure for gasless stake operations
    /// @dev Packed into 4 storage slots for gas efficiency:
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

    /// @notice Request structure for gasless stake operations with autoclaim
    /// @dev Packed into 4 storage slots for gas efficiency:
    ///      Slot 1: user (20) + nonce (12) = 32 bytes
    ///      Slot 2: vault (20) + deadline (12) = 32 bytes
    ///      Slot 3: recipient (20) + maxFee (12) = 32 bytes
    ///      Slot 4: kTokenAmount (32) = 32 bytes
    /// @param user The address of the user initiating the stake
    /// @param nonce The user's current nonce
    /// @param vault The kStakingVault address
    /// @param deadline The expiration timestamp
    /// @param recipient The address to receive stkTokens
    /// @param maxFee The maximum total fee (covers both request + claim)
    /// @param kTokenAmount The gross amount of kTokens including fee + netStakeAmount
    struct StakeWithAutoclaimRequest {
        address user;
        uint96 nonce;
        address vault;
        uint96 deadline;
        address recipient;
        uint96 maxFee;
        uint256 kTokenAmount;
    }

    /// @notice Request structure for gasless unstake operations with autoclaim
    /// @dev Packed into 4 storage slots for gas efficiency:
    ///      Slot 1: user (20) + nonce (12) = 32 bytes
    ///      Slot 2: vault (20) + deadline (12) = 32 bytes
    ///      Slot 3: recipient (20) + maxFee (12) = 32 bytes
    ///      Slot 4: stkTokenAmount (32) = 32 bytes
    /// @param user The address of the user initiating the unstake
    /// @param nonce The user's current nonce
    /// @param vault The kStakingVault address
    /// @param deadline The expiration timestamp
    /// @param recipient The address to receive kTokens
    /// @param maxFee The maximum total fee (covers both request + claim)
    /// @param stkTokenAmount The gross amount of stkTokens including fee + netUnstakeAmount
    struct UnstakeWithAutoclaimRequest {
        address user;
        uint96 nonce;
        address vault;
        uint96 deadline;
        address recipient;
        uint96 maxFee;
        uint256 stkTokenAmount;
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

    /// @notice Autoclaim authorization data
    /// @dev Stored when user requests stake/unstake with autoclaim.
    ///      User is fetched from vault's request data. No deadline - can be claimed anytime.
    ///      Claim fee is paid upfront during request, so no fee collection at claim time.
    ///      Packed into 1 storage slot:
    ///      Slot 1: vault (20) + isStake (1) + executed (1) + padding (10) = 32 bytes
    /// @param vault The vault address
    /// @param isStake True if claiming staked shares, false if claiming unstaked assets
    /// @param executed True if autoclaim has been executed
    struct AutoclaimAuth {
        address vault;
        bool isStake;
        bool executed;
    }

    /*//////////////////////////////////////////////////////////////
                    EXTERNAL FUNCTIONS (WITH PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request with permit
    /// @dev Combines permit + requestStake in a single meta-transaction.
    ///      User permits paymaster for full kTokenAmount. Paymaster pulls tokens,
    ///      sends fee to treasury, and forwards netAmount to vault.
    /// @param request The stake request parameters
    /// @param permit The permit signature for kToken approval to paymaster (for full amount)
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    /// @return requestId The resulting stake request ID
    function executeRequestStakeWithPermit(
        StakeRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request with permit
    /// @dev Combines permit + requestUnstake in a single meta-transaction.
    ///      User permits paymaster for full stkTokenAmount. Paymaster pulls tokens,
    ///      sends fee to treasury, and forwards netAmount to vault.
    /// @param request The unstake request parameters
    /// @param permit The permit signature for stkToken approval to paymaster (for full amount)
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    /// @return requestId The resulting unstake request ID
    function executeRequestUnstakeWithPermit(
        UnstakeRequest calldata request,
        PermitSignature calldata permit,
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
    /// @param permits Array of permit signatures for paymaster (for full amounts)
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting stake request IDs
    function executeRequestStakeWithPermitBatch(
        StakeRequest[] calldata requests,
        PermitSignature[] calldata permits,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless unstake requests in a single transaction
    /// @param requests Array of unstake request parameters
    /// @param permits Array of permit signatures for paymaster (for full amounts)
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting unstake request IDs
    function executeRequestUnstakeWithPermitBatch(
        UnstakeRequest[] calldata requests,
        PermitSignature[] calldata permits,
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

    /// @notice Execute multiple gasless claims of staked shares with permits
    /// @param requests Array of claim request parameters
    /// @param permitSigs Array of permit signatures for stkToken approval (for fees)
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    function executeClaimStakedSharesWithPermitBatch(
        ClaimRequest[] calldata requests,
        PermitSignature[] calldata permitSigs,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external;

    /// @notice Execute multiple gasless claims of unstaked assets with permits
    /// @param requests Array of claim request parameters
    /// @param permitSigs Array of permit signatures for kToken approval (for fees)
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    function executeClaimUnstakedAssetsWithPermitBatch(
        ClaimRequest[] calldata requests,
        PermitSignature[] calldata permitSigs,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external;

    /// @notice Execute multiple gasless claims of staked shares without permits
    /// @param requests Array of claim request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    function executeClaimStakedSharesBatch(
        ClaimRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external;

    /// @notice Execute multiple gasless claims of unstaked assets without permits
    /// @param requests Array of claim request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    function executeClaimUnstakedAssetsBatch(
        ClaimRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external;

    /*//////////////////////////////////////////////////////////////
                          AUTOCLAIM FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request with autoclaim enabled (with permit)
    /// @dev Same as executeRequestStakeWithPermit but registers autoclaim for later execution.
    ///      User signs once, executor can claim on their behalf after settlement.
    /// @param request The stake with autoclaim request parameters
    /// @param permit The permit signature for kToken approval to paymaster
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    /// @return requestId The resulting stake request ID (used for autoclaim)
    function executeRequestStakeWithAutoclaimWithPermit(
        StakeWithAutoclaimRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request with autoclaim enabled (with permit)
    /// @dev Same as executeRequestUnstakeWithPermit but registers autoclaim for later execution.
    ///      User signs once, executor can claim on their behalf after settlement.
    /// @param request The unstake with autoclaim request parameters
    /// @param permit The permit signature for stkToken approval to paymaster
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    /// @return requestId The resulting unstake request ID (used for autoclaim)
    function executeRequestUnstakeWithAutoclaimWithPermit(
        UnstakeWithAutoclaimRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless stake request with autoclaim (assumes allowance already set)
    /// @dev Same as executeRequestStake but registers autoclaim for later execution.
    /// @param request The stake with autoclaim request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in kTokens (must be <= request.maxFee)
    /// @return requestId The resulting stake request ID (used for autoclaim)
    function executeRequestStakeWithAutoclaim(
        StakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute a gasless unstake request with autoclaim (assumes allowance already set)
    /// @dev Same as executeRequestUnstake but registers autoclaim for later execution.
    /// @param request The unstake with autoclaim request parameters
    /// @param requestSig The signature for the meta-transaction
    /// @param fee The fee amount in stkTokens (must be <= request.maxFee)
    /// @return requestId The resulting unstake request ID (used for autoclaim)
    function executeRequestUnstakeWithAutoclaim(
        UnstakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        returns (bytes32 requestId);

    /// @notice Execute multiple gasless stake requests with autoclaim (with permits)
    /// @param requests Array of stake with autoclaim request parameters
    /// @param permits Array of permit signatures for kToken approval to paymaster
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting stake request IDs
    function executeRequestStakeWithAutoclaimWithPermitBatch(
        StakeWithAutoclaimRequest[] calldata requests,
        PermitSignature[] calldata permits,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless unstake requests with autoclaim (with permits)
    /// @param requests Array of unstake with autoclaim request parameters
    /// @param permits Array of permit signatures for stkToken approval to paymaster
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting unstake request IDs
    function executeRequestUnstakeWithAutoclaimWithPermitBatch(
        UnstakeWithAutoclaimRequest[] calldata requests,
        PermitSignature[] calldata permits,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless stake requests with autoclaim (without permits)
    /// @param requests Array of stake with autoclaim request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting stake request IDs
    function executeRequestStakeWithAutoclaimBatch(
        StakeWithAutoclaimRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute multiple gasless unstake requests with autoclaim (without permits)
    /// @param requests Array of unstake with autoclaim request parameters
    /// @param requestSigs Array of signatures for the meta-transactions
    /// @param fees Array of fee amounts
    /// @return requestIds Array of resulting unstake request IDs
    function executeRequestUnstakeWithAutoclaimBatch(
        UnstakeWithAutoclaimRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        returns (bytes32[] memory requestIds);

    /// @notice Execute autoclaim for staked shares (no user signature required)
    /// @dev Can only be called if user used executeRequestStakeWithAutoclaim.
    ///      Claim fee was already paid upfront during the request.
    /// @param requestId The stake request ID to claim
    function executeAutoclaimStakedShares(bytes32 requestId) external;

    /// @notice Execute autoclaim for unstaked assets (no user signature required)
    /// @dev Can only be called if user used executeRequestUnstakeWithAutoclaim.
    ///      Claim fee was already paid upfront during the request.
    /// @param requestId The unstake request ID to claim
    function executeAutoclaimUnstakedAssets(bytes32 requestId) external;

    /// @notice Execute batch autoclaim for staked shares (no user signature required)
    /// @dev Executes multiple autoclaims in a single transaction. Skips invalid/already executed requests.
    /// @param requestIds Array of stake request IDs to claim
    function executeAutoclaimStakedSharesBatch(bytes32[] calldata requestIds) external;

    /// @notice Execute batch autoclaim for unstaked assets (no user signature required)
    /// @dev Executes multiple autoclaims in a single transaction. Skips invalid/already executed requests.
    /// @param requestIds Array of unstake request IDs to claim
    function executeAutoclaimUnstakedAssetsBatch(bytes32[] calldata requestIds) external;

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

    /// @notice Get autoclaim authorization for a request
    /// @param requestId The stake/unstake request ID
    /// @return The autoclaim authorization data
    function getAutoclaimAuth(bytes32 requestId) external view returns (AutoclaimAuth memory);

    /// @notice Check if autoclaim can be executed for a request
    /// @param requestId The stake/unstake request ID
    /// @return True if autoclaim is registered, not executed, and not expired
    function canAutoclaim(bytes32 requestId) external view returns (bool);
}

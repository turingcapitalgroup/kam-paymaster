// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IkPaymaster
/// @notice Interface for the kPaymaster gasless forwarder contract
/// @dev Enables gasless interactions with kStakingVaults using permit signatures and ERC2771 meta-transactions.
/// Fees are passed directly by the trusted executor for simplicity and gas efficiency.
/// Users sign a maxFee parameter to cap the fee that can be charged.
/// Structs are tightly packed for gas optimization.
interface IkPaymaster {
    /* //////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Discriminator for the four autoclaim flows that previously had separate entry points
    /// @dev `StakedShares` claims fulfilled stake requests via `claimStakedShares`.
    ///      `UnstakedAssets` claims fulfilled unstake requests via `claimUnstakedAssets`.
    enum AutoclaimType {
        StakedShares,
        UnstakedAssets
    }

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

    /// @notice Emitted when a user increments their nonce to invalidate outstanding signatures
    /// @param user The user who incremented their nonce
    /// @param newNonce The new nonce value
    event NonceIncremented(address indexed user, uint256 newNonce);

    /// @notice Emitted when autoclaim is registered for a request
    /// @param user The user who authorized autoclaim
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID
    /// @param claimType Whether the registration is for a staked-shares or unstaked-assets claim
    event AutoclaimRegistered(
        address indexed user, address indexed vault, bytes32 indexed requestId, AutoclaimType claimType
    );

    /// @notice Emitted when autoclaim is executed
    /// @param user The user whose claim was executed
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID
    /// @param claimType Whether the executed claim was for staked shares or unstaked assets
    event AutoclaimExecuted(
        address indexed user, address indexed vault, bytes32 indexed requestId, AutoclaimType claimType
    );

    /// @notice Emitted when a batch autoclaim fails for a specific request
    /// @param vault The vault address
    /// @param requestId The stake/unstake request ID that failed
    /// @param claimType Whether the failed claim was for staked shares or unstaked assets
    event AutoclaimFailed(address indexed vault, bytes32 indexed requestId, AutoclaimType claimType);

    /* //////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an invalid signature is provided
    error kPaymaster_InvalidSignature();

    /// @notice Thrown when the request deadline has expired
    error kPaymaster_RequestExpired();

    /// @notice Thrown when the nonce doesn't match expected value
    error kPaymaster_InvalidNonce();

    /// @notice Thrown when caller is not a trusted executor
    error kPaymaster_NotTrustedExecutor();

    /// @notice Thrown when zero address is provided
    error kPaymaster_ZeroAddress();

    /// @notice Thrown when zero amount is provided
    error kPaymaster_ZeroAmount();

    /// @notice Thrown when the vault is not registered
    error kPaymaster_VaultNotRegistered();

    /// @notice Thrown when insufficient amount for fee coverage
    error kPaymaster_InsufficientAmountForFee();

    /// @notice Thrown when the permit deadline has expired
    error kPaymaster_PermitExpired();

    /// @notice Thrown when fee exceeds user's signed maxFee
    error kPaymaster_FeeExceedsMax();

    /// @notice Thrown when stake request to vault fails
    error kPaymaster_StakeRequestFailed();

    /// @notice Thrown when unstake request to vault fails
    error kPaymaster_UnstakeRequestFailed();

    /// @notice Thrown when a single autoclaim fails (validation or downstream call).
    ///         Batch autoclaim does not revert on per-request failure — it emits `AutoclaimFailed` instead.
    error kPaymaster_AutoclaimRevert();

    /// @notice Thrown when permit call fails
    error kPaymaster_PermitFailed();

    /// @notice Thrown when array lengths mismatch in batch operations
    error kPaymaster_ArrayLengthMismatch();

    /// @notice Thrown when autoclaim is not registered for the request
    error kPaymaster_AutoclaimNotRegistered();

    /// @notice Thrown when autoclaim has already been executed
    error kPaymaster_AutoclaimAlreadyExecuted();

    /// @notice Thrown when batch size exceeds maximum or is zero
    error kPaymaster_BatchTooLarge();

    /// @notice Thrown when the paymaster is not the vault's trusted forwarder
    error kPaymaster_NotTrustedForwarder();

    /* //////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

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

    /* //////////////////////////////////////////////////////////////
                          AUTOCLAIM FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a gasless stake request with autoclaim enabled (with permit)
    /// @dev User signs once, executor can claim on their behalf after settlement.
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
    /// @dev User signs once, executor can claim on their behalf after settlement.
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
    /// @dev Processes each request sequentially in a single transaction
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
    /// @dev Processes each request sequentially in a single transaction
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
    /// @dev Processes each request sequentially in a single transaction
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
    /// @dev Processes each request sequentially in a single transaction
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
    /// @notice Execute a single autoclaim (no user signature required)
    /// @dev Granular reverts on precondition failure:
    ///        - `kPaymaster_AutoclaimNotRegistered` — no entry, or entry's `isStake` does not match
    ///          the requested `claimType`
    ///        - `kPaymaster_AutoclaimAlreadyExecuted` — entry was already claimed
    ///        - `kPaymaster_VaultNotRegistered` — vault was deregistered after autoclaim auth
    ///        - `kPaymaster_AutoclaimRevert` — downstream vault call reverted (auth.executed is
    ///          rolled back so the request can be retried)
    /// @param requestId The stake or unstake request ID to claim
    /// @param claimType `StakedShares` for stake-claim, `UnstakedAssets` for unstake-claim
    function executeAutoclaim(bytes32 requestId, AutoclaimType claimType) external;

    /// @notice Execute a batch of autoclaims (no user signature required)
    /// @dev Skips per-request failures and emits `AutoclaimFailed` for each one. Reverts
    ///      only on `kPaymaster_BatchTooLarge` (size guard).
    /// @param requestIds Array of stake or unstake request IDs to claim
    /// @param claimType `StakedShares` for stake-claim, `UnstakedAssets` for unstake-claim
    function executeAutoclaimBatch(bytes32[] calldata requestIds, AutoclaimType claimType) external;

    /* //////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a user
    /// @dev Returns the nonce from the internal mapping
    /// @param user The user address
    /// @return The current nonce
    function nonces(address user) external view returns (uint256);

    /// @notice Get the EIP-712 domain separator
    /// @dev Computes the EIP-712 domain separator from the contract's EIP712 override
    /// @return The domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Check if an address is a trusted executor
    /// @dev Returns the executor's trust status from the internal mapping
    /// @param executor The address to check
    /// @return True if the executor is trusted
    function isTrustedExecutor(address executor) external view returns (bool);

    /// @notice Get the treasury address
    /// @dev Returns the current treasury address that receives fees
    /// @return The treasury address that receives fees
    function treasury() external view returns (address);

    /// @notice Get autoclaim authorization for a request
    /// @dev Returns the autoclaim authorization from the internal registry mapping
    /// @param requestId The stake/unstake request ID
    /// @return The autoclaim authorization data
    function getAutoclaimAuth(bytes32 requestId) external view returns (AutoclaimAuth memory);

    /// @notice Check if autoclaim can be executed for a request
    /// @dev Checks vault != address(0) and !executed in the authorization
    /// @param requestId The stake/unstake request ID
    /// @return True if autoclaim is registered, not executed, and not expired
    function canAutoclaim(bytes32 requestId) external view returns (bool);

    /* //////////////////////////////////////////////////////////////
                          USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Increment the caller's nonce to invalidate all outstanding signed requests
    /// @dev Allows users to cancel pending meta-transactions by bumping their nonce
    function incrementNonce() external;

    /* //////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set a trusted executor
    /// @param executor The executor address
    /// @param trusted Whether the executor is trusted
    function setTrustedExecutor(address executor, bool trusted) external;

    /// @notice Set the treasury address
    /// @param _treasury The new treasury address
    function setTreasury(address _treasury) external;

    /// @notice Rescue stuck tokens from the contract
    /// @param token The token address (address(0) for ETH)
    /// @param to The recipient address
    /// @param amount The amount to rescue
    function rescueTokens(address token, address to, uint256 amount) external;
}

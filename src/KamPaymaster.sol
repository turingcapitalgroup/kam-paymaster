// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IKamPaymaster } from "./interfaces/IKamPaymaster.sol";
import { Ownable } from "./vendor/solady/auth/Ownable.sol";
import { EIP712 } from "./vendor/solady/utils/EIP712.sol";
import { SafeTransferLib } from "./vendor/solady/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "./vendor/solady/utils/SignatureCheckerLib.sol";
import { IRegistry } from "kam/src/interfaces/IRegistry.sol";
import { IVault } from "kam/src/interfaces/IVault.sol";
import { IVaultClaim } from "kam/src/interfaces/IVaultClaim.sol";
import { IkStakingVault } from "kam/src/interfaces/IkStakingVault.sol";
import { IVaultReader } from "kam/src/interfaces/modules/IVaultReader.sol";
import { BaseVaultTypes } from "kam/src/kStakingVault/types/BaseVaultTypes.sol";

/// @title KamPaymaster
/// @notice Gasless forwarder for kStakingVault interactions using permit signatures
/// @dev This contract acts as an ERC2771-style trusted forwarder that enables users to perform gasless
/// operations on kStakingVaults. Users sign meta-transactions which are executed by trusted relayers,
/// with gas costs covered by fee deduction from the tokens being transferred.
///
/// Key features:
/// - EIP-712 typed signatures for secure meta-transactions
/// - EIP-2612 permit integration for gasless token approvals
/// - Support for requestStake, requestUnstake, claimStakedShares, claimUnstakedAssets
/// - Both permit and non-permit versions of all functions
/// - Batch operations for gas efficiency
/// - maxFee parameter in signatures to protect users from excessive fees
/// - Packed structs for reduced calldata costs
contract KamPaymaster is IKamPaymaster, EIP712, Ownable {
    using SafeTransferLib for address;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev EIP-712 typehash for StakeRequest
    bytes32 public constant STAKE_REQUEST_TYPEHASH = keccak256(
        "StakeRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 kTokenAmount)"
    );

    /// @dev EIP-712 typehash for UnstakeRequest
    bytes32 public constant UNSTAKE_REQUEST_TYPEHASH = keccak256(
        "UnstakeRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 stkTokenAmount)"
    );

    /// @dev EIP-712 typehash for ClaimRequest
    bytes32 public constant CLAIM_REQUEST_TYPEHASH = keccak256(
        "ClaimRequest(address user,uint96 nonce,address vault,uint96 deadline,uint96 maxFee,bytes32 requestId)"
    );

    /// @dev EIP-712 typehash for StakeWithAutoclaimRequest
    bytes32 public constant STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH = keccak256(
        "StakeWithAutoclaimRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 kTokenAmount,uint96 claimFee)"
    );

    /// @dev EIP-712 typehash for UnstakeWithAutoclaimRequest
    bytes32 public constant UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH = keccak256(
        "UnstakeWithAutoclaimRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 stkTokenAmount,uint96 claimFee)"
    );

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Protocol registry for vault validation
    IRegistry public registry;

    /// @dev Protocol treasury to receive fees
    address public treasury;

    /// @dev Mapping of user address to nonce
    mapping(address user => uint256 nonce) private _nonces;

    /// @dev Mapping of trusted executor addresses
    mapping(address executor => bool isTrusted) private _trustedExecutors;

    /// @dev Mapping of requestId to autoclaim authorization
    mapping(bytes32 requestId => AutoclaimAuth) private _autoclaimRegistry;

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyTrustedExecutor() {
        if (!_trustedExecutors[msg.sender]) revert NotTrustedExecutor();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the KamPaymaster contract
    /// @param _owner The owner address with admin privileges
    /// @param _treasury The treasury address to receive fees
    /// @param _registry The registry address for vault validation
    constructor(address _owner, address _treasury, address _registry) {
        if (_owner == address(0)) revert ZeroAddress();
        if (_treasury == address(0)) revert ZeroAddress();
        if (_registry == address(0)) revert ZeroAddress();

        _initializeOwner(_owner);
        treasury = _treasury;
        registry = IRegistry(_registry);
        _trustedExecutors[_owner] = true;

        emit TrustedExecutorUpdated(_owner, true);
        emit TreasuryUpdated(_treasury);
    }

    /*//////////////////////////////////////////////////////////////
                      EXTERNAL FUNCTIONS (WITH PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function executeRequestStakeWithPermit(
        StakeRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address kToken = _getAsset(request.vault);

        _executePermit(kToken, request.user, address(this), permit);

        requestId = _executeStake(request, requestSig, kToken, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstakeWithPermit(
        UnstakeRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address stkToken = request.vault;

        _executePermit(stkToken, request.user, address(this), permit);

        requestId = _executeUnstake(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimStakedSharesWithPermit(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
    {
        address stkToken = request.vault;

        if (fee > 0) {
            _executePermit(stkToken, request.user, address(this), permitSig);
        }

        _executeClaimStakedShares(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimUnstakedAssetsWithPermit(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
    {
        address kToken = _getAsset(request.vault);

        if (fee > 0) {
            _executePermit(kToken, request.user, address(this), permitSig);
        }

        _executeClaimUnstakedAssets(request, requestSig, kToken, fee);
    }

    /*//////////////////////////////////////////////////////////////
                      EXTERNAL FUNCTIONS (WITHOUT PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function executeRequestStake(
        StakeRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address kToken = _getAsset(request.vault);
        requestId = _executeStake(request, requestSig, kToken, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstake(
        UnstakeRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        requestId = _executeUnstake(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimStakedShares(
        ClaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
    {
        _executeClaimStakedShares(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimUnstakedAssets(
        ClaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
    {
        address kToken = _getAsset(request.vault);
        _executeClaimUnstakedAssets(request, requestSig, kToken, fee);
    }

    /*//////////////////////////////////////////////////////////////
                            BATCH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function executeRequestStakeWithPermitBatch(
        StakeRequest[] calldata requests,
        PermitSignature[] calldata permits,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory requestIds)
    {
        uint256 len = requests.length;
        if (len != permits.length || len != requestSigs.length || len != fees.length) {
            revert ArrayLengthMismatch();
        }

        requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            requestIds[i] = _executeStakeWithPermitAtIndex(requests[i], permits[i], requestSigs[i], fees[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstakeWithPermitBatch(
        UnstakeRequest[] calldata requests,
        PermitSignature[] calldata permits,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory requestIds)
    {
        uint256 len = requests.length;
        if (len != permits.length || len != requestSigs.length || len != fees.length) {
            revert ArrayLengthMismatch();
        }

        requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            requestIds[i] = _executeUnstakeWithPermitAtIndex(requests[i], permits[i], requestSigs[i], fees[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestStakeBatch(
        StakeRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory requestIds)
    {
        uint256 len = requests.length;
        if (len != requestSigs.length || len != fees.length) {
            revert ArrayLengthMismatch();
        }

        requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            address kToken = _getAsset(requests[i].vault);
            requestIds[i] = _executeStake(requests[i], requestSigs[i], kToken, fees[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstakeBatch(
        UnstakeRequest[] calldata requests,
        bytes[] calldata requestSigs,
        uint96[] calldata fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory requestIds)
    {
        uint256 len = requests.length;
        if (len != requestSigs.length || len != fees.length) {
            revert ArrayLengthMismatch();
        }

        requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            requestIds[i] = _executeUnstake(requests[i], requestSigs[i], fees[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          AUTOCLAIM FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function executeRequestStakeWithAutoclaimWithPermit(
        StakeWithAutoclaimRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address kToken = _getAsset(request.vault);

        _executePermit(kToken, request.user, address(this), permit);

        requestId = _executeStakeWithAutoclaim(request, requestSig, kToken, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstakeWithAutoclaimWithPermit(
        UnstakeWithAutoclaimRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address stkToken = request.vault;

        _executePermit(stkToken, request.user, address(this), permit);

        requestId = _executeUnstakeWithAutoclaim(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestStakeWithAutoclaim(
        StakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        address kToken = _getAsset(request.vault);

        requestId = _executeStakeWithAutoclaim(request, requestSig, kToken, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeRequestUnstakeWithAutoclaim(
        UnstakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        requestId = _executeUnstakeWithAutoclaim(request, requestSig, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeAutoclaimStakedShares(bytes32 requestId) external onlyTrustedExecutor {
        AutoclaimAuth storage auth = _autoclaimRegistry[requestId];

        if (auth.vault == address(0)) revert AutoclaimNotRegistered();
        if (!auth.isStake) revert AutoclaimNotRegistered();
        if (auth.executed) revert AutoclaimAlreadyExecuted();
        if (!registry.isVault(auth.vault)) revert VaultNotRegistered();

        auth.executed = true;

        // Fetch user from vault's stake request
        BaseVaultTypes.StakeRequest memory stakeRequest = IVaultReader(auth.vault).getStakeRequest(requestId);
        address user = stakeRequest.user;

        // Forward claim to vault (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(abi.encodeCall(IVaultClaim.claimStakedShares, (requestId)), user);

        (bool success,) = auth.vault.call(forwardData);
        if (!success) revert ClaimStakedSharesFailed();

        // No fee collection - claim fee was paid upfront during request

        emit AutoclaimExecuted(user, auth.vault, requestId, true);
        emit GaslessStakedSharesClaimed(user, auth.vault, requestId, 0);
    }

    /// @inheritdoc IKamPaymaster
    function executeAutoclaimUnstakedAssets(bytes32 requestId) external onlyTrustedExecutor {
        AutoclaimAuth storage auth = _autoclaimRegistry[requestId];

        if (auth.vault == address(0)) revert AutoclaimNotRegistered();
        if (auth.isStake) revert AutoclaimNotRegistered();
        if (auth.executed) revert AutoclaimAlreadyExecuted();
        if (!registry.isVault(auth.vault)) revert VaultNotRegistered();

        auth.executed = true;

        // Fetch user from vault's unstake request
        BaseVaultTypes.UnstakeRequest memory unstakeRequest = IVaultReader(auth.vault).getUnstakeRequest(requestId);
        address user = unstakeRequest.user;

        // Forward claim to vault (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(abi.encodeCall(IVaultClaim.claimUnstakedAssets, (requestId)), user);

        (bool success,) = auth.vault.call(forwardData);
        if (!success) revert ClaimUnstakedAssetsFailed();

        // No fee collection - claim fee was paid upfront during request

        emit AutoclaimExecuted(user, auth.vault, requestId, false);
        emit GaslessUnstakedAssetsClaimed(user, auth.vault, requestId, 0);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function nonces(address user) external view returns (uint256) {
        return _nonces[user];
    }

    /// @inheritdoc IKamPaymaster
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @inheritdoc IKamPaymaster
    function isTrustedExecutor(address executor) external view returns (bool) {
        return _trustedExecutors[executor];
    }

    /// @inheritdoc IKamPaymaster
    function getAutoclaimAuth(bytes32 requestId) external view returns (AutoclaimAuth memory) {
        return _autoclaimRegistry[requestId];
    }

    /// @inheritdoc IKamPaymaster
    function canAutoclaim(bytes32 requestId) external view returns (bool) {
        AutoclaimAuth storage auth = _autoclaimRegistry[requestId];
        return auth.vault != address(0) && !auth.executed;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set a trusted executor
    /// @param executor The executor address
    /// @param trusted Whether the executor is trusted
    function setTrustedExecutor(address executor, bool trusted) external onlyOwner {
        if (executor == address(0)) revert ZeroAddress();
        _trustedExecutors[executor] = trusted;
        emit TrustedExecutorUpdated(executor, trusted);
    }

    /// @notice Set the treasury address
    /// @param _treasury The new treasury address
    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /// @notice Rescue stuck tokens from the contract
    /// @param token The token address (address(0) for ETH)
    /// @param to The recipient address
    /// @param amount The amount to rescue
    function rescueTokens(address token, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (token == address(0)) {
            SafeTransferLib.safeTransferETH(to, amount);
        } else {
            token.safeTransfer(to, amount);
        }
        emit TokensRescued(token, to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Get the underlying asset for a vault
    function _getAsset(address vault) internal view returns (address) {
        return IkStakingVault(vault).asset();
    }

    /// @dev Execute stake with permit at a specific index (for batch operations)
    function _executeStakeWithPermitAtIndex(
        StakeRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        address kToken = _getAsset(request.vault);

        _executePermit(kToken, request.user, address(this), permit);

        requestId = _executeStake(request, requestSig, kToken, fee);
    }

    /// @dev Execute unstake with permit at a specific index (for batch operations)
    function _executeUnstakeWithPermitAtIndex(
        UnstakeRequest calldata request,
        PermitSignature calldata permit,
        bytes calldata requestSig,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        address stkToken = request.vault;

        _executePermit(stkToken, request.user, address(this), permit);

        requestId = _executeUnstake(request, requestSig, fee);
    }

    /// @dev Execute stake logic
    /// @dev Single permit model: paymaster pulls full amount, sends fee to treasury, approves vault for netAmount
    function _executeStake(
        StakeRequest calldata request,
        bytes calldata requestSig,
        address kToken,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        _validateStakeRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        if (request.kTokenAmount <= fee) revert InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = request.kTokenAmount - fee;
        }

        unchecked {
            ++_nonces[request.user];
        }

        // Pull full amount from user to paymaster
        kToken.safeTransferFrom(request.user, address(this), request.kTokenAmount);

        // Send fee to treasury
        if (fee > 0) {
            kToken.safeTransfer(treasury, fee);
        }

        // Approve vault to pull netAmount
        kToken.safeApprove(request.vault, netAmount);

        // Forward requestStake call with paymaster as msg.sender (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestStake, (request.user, request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        if (!success) revert StakeRequestFailed();

        requestId = abi.decode(returnData, (bytes32));

        emit GaslessStakeRequested(request.user, request.vault, request.kTokenAmount, fee, requestId);
    }

    /// @dev Execute unstake logic
    /// @dev Single permit model: paymaster pulls full amount, sends fee to treasury, approves vault for netAmount
    function _executeUnstake(
        UnstakeRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        _validateUnstakeRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        address stkToken = request.vault;

        if (request.stkTokenAmount <= fee) revert InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = request.stkTokenAmount - fee;
        }

        unchecked {
            ++_nonces[request.user];
        }

        // Pull full amount from user to paymaster
        stkToken.safeTransferFrom(request.user, address(this), request.stkTokenAmount);

        // Send fee to treasury
        if (fee > 0) {
            stkToken.safeTransfer(treasury, fee);
        }

        // Approve vault to pull netAmount
        stkToken.safeApprove(request.vault, netAmount);

        // Forward requestUnstake call (ERC2771 pattern)
        // requestUnstake uses _msgSender() as owner, so we append request.user
        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVault.requestUnstake, (request.recipient, netAmount)), request.user);

        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        if (!success) revert UnstakeRequestFailed();

        requestId = abi.decode(returnData, (bytes32));

        emit GaslessUnstakeRequested(request.user, request.vault, request.stkTokenAmount, fee, requestId);
    }

    /// @dev Execute claim staked shares logic
    function _executeClaimStakedShares(ClaimRequest calldata request, bytes calldata requestSig, uint96 fee) internal {
        _validateClaimRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        address stkToken = request.vault;

        unchecked {
            ++_nonces[request.user];
        }

        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVaultClaim.claimStakedShares, (request.requestId)), request.user);

        (bool success,) = request.vault.call(forwardData);
        if (!success) revert ClaimStakedSharesFailed();

        if (fee > 0) {
            stkToken.safeTransferFrom(request.user, treasury, fee);
        }

        emit GaslessStakedSharesClaimed(request.user, request.vault, request.requestId, fee);
    }

    /// @dev Execute claim unstaked assets logic
    function _executeClaimUnstakedAssets(
        ClaimRequest calldata request,
        bytes calldata requestSig,
        address kToken,
        uint96 fee
    )
        internal
    {
        _validateClaimRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        unchecked {
            ++_nonces[request.user];
        }

        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVaultClaim.claimUnstakedAssets, (request.requestId)), request.user);

        (bool success,) = request.vault.call(forwardData);
        if (!success) revert ClaimUnstakedAssetsFailed();

        if (fee > 0) {
            kToken.safeTransferFrom(request.user, treasury, fee);
        }

        emit GaslessUnstakedAssetsClaimed(request.user, request.vault, request.requestId, fee);
    }

    /// @dev Execute stake with autoclaim logic
    /// @dev User pays requestFee + claimFee upfront. kTokenAmount = requestFee + claimFee + netStakeAmount
    function _executeStakeWithAutoclaim(
        StakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        address kToken,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        _validateStakeWithAutoclaimRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        // Total fees = requestFee + claimFee
        uint256 totalFees = uint256(fee) + uint256(request.claimFee);
        if (request.kTokenAmount <= totalFees) revert InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = request.kTokenAmount - totalFees;
        }

        unchecked {
            ++_nonces[request.user];
        }

        // Pull full amount from user to paymaster
        kToken.safeTransferFrom(request.user, address(this), request.kTokenAmount);

        // Send total fees (requestFee + claimFee) to treasury
        if (totalFees > 0) {
            kToken.safeTransfer(treasury, totalFees);
        }

        // Approve vault to pull netAmount
        kToken.safeApprove(request.vault, netAmount);

        // Forward requestStake call with paymaster as msg.sender (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestStake, (request.user, request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        if (!success) revert StakeRequestFailed();

        requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[requestId] = AutoclaimAuth({ vault: request.vault, isStake: true, executed: false });

        emit GaslessStakeRequested(request.user, request.vault, request.kTokenAmount, fee, requestId);
        emit AutoclaimRegistered(request.user, request.vault, requestId, true, request.claimFee);
    }

    /// @dev Execute unstake with autoclaim logic
    /// @dev User pays requestFee + claimFee upfront. stkTokenAmount = requestFee + claimFee + netUnstakeAmount
    function _executeUnstakeWithAutoclaim(
        UnstakeWithAutoclaimRequest calldata request,
        bytes calldata requestSig,
        uint96 fee
    )
        internal
        returns (bytes32 requestId)
    {
        _validateUnstakeWithAutoclaimRequest(request, requestSig, fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(request.vault)) revert VaultNotRegistered();

        address stkToken = request.vault;

        // Total fees = requestFee + claimFee
        uint256 totalFees = uint256(fee) + uint256(request.claimFee);
        if (request.stkTokenAmount <= totalFees) revert InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = request.stkTokenAmount - totalFees;
        }

        unchecked {
            ++_nonces[request.user];
        }

        // Pull full amount from user to paymaster
        stkToken.safeTransferFrom(request.user, address(this), request.stkTokenAmount);

        // Send total fees (requestFee + claimFee) to treasury
        if (totalFees > 0) {
            stkToken.safeTransfer(treasury, totalFees);
        }

        // Approve vault to pull netAmount
        stkToken.safeApprove(request.vault, netAmount);

        // Forward requestUnstake call (ERC2771 pattern)
        // requestUnstake uses _msgSender() as owner, so we append request.user
        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVault.requestUnstake, (request.recipient, netAmount)), request.user);

        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        if (!success) revert UnstakeRequestFailed();

        requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[requestId] = AutoclaimAuth({ vault: request.vault, isStake: false, executed: false });

        emit GaslessUnstakeRequested(request.user, request.vault, request.stkTokenAmount, fee, requestId);
        emit AutoclaimRegistered(request.user, request.vault, requestId, false, request.claimFee);
    }

    /// @dev Validate a stake request
    function _validateStakeRequest(StakeRequest calldata request, bytes calldata sig, uint96 fee) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.kTokenAmount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroAddress();
        if (fee > request.maxFee) revert FeeExceedsMax();

        bytes32 structHash = keccak256(
            abi.encode(
                STAKE_REQUEST_TYPEHASH,
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.kTokenAmount
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate an unstake request
    function _validateUnstakeRequest(UnstakeRequest calldata request, bytes calldata sig, uint96 fee) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.stkTokenAmount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroAddress();
        if (fee > request.maxFee) revert FeeExceedsMax();

        bytes32 structHash = keccak256(
            abi.encode(
                UNSTAKE_REQUEST_TYPEHASH,
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.stkTokenAmount
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate a claim request
    function _validateClaimRequest(ClaimRequest calldata request, bytes calldata sig, uint96 fee) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (fee > request.maxFee) revert FeeExceedsMax();

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_REQUEST_TYPEHASH,
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.maxFee,
                request.requestId
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate a stake with autoclaim request
    function _validateStakeWithAutoclaimRequest(
        StakeWithAutoclaimRequest calldata request,
        bytes calldata sig,
        uint96 fee
    )
        internal
        view
    {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.kTokenAmount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroAddress();
        if (fee > request.maxFee) revert FeeExceedsMax();

        bytes32 structHash = keccak256(
            abi.encode(
                STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH,
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.kTokenAmount,
                request.claimFee
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate an unstake with autoclaim request
    function _validateUnstakeWithAutoclaimRequest(
        UnstakeWithAutoclaimRequest calldata request,
        bytes calldata sig,
        uint96 fee
    )
        internal
        view
    {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.stkTokenAmount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroAddress();
        if (fee > request.maxFee) revert FeeExceedsMax();

        bytes32 structHash = keccak256(
            abi.encode(
                UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH,
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.stkTokenAmount,
                request.claimFee
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate an EIP-712 signature using Solady's SignatureCheckerLib
    function _validateSignature(address signer, bytes32 structHash, bytes calldata sig) internal view {
        bytes32 digest = _hashTypedData(structHash);
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(signer, digest, sig)) {
            revert InvalidSignature();
        }
    }

    /// @dev Execute EIP-2612 permit
    /// @dev Skips permit if allowance is already sufficient to prevent front-running failures
    function _executePermit(address token, address owner_, address spender, PermitSignature calldata sig) internal {
        // Skip permit if allowance is already sufficient (handles front-running/replay scenarios)
        (bool allowanceSuccess, bytes memory allowanceData) =
            token.staticcall(abi.encodeWithSignature("allowance(address,address)", owner_, spender));
        if (allowanceSuccess && allowanceData.length >= 32) {
            uint256 currentAllowance = abi.decode(allowanceData, (uint256));
            if (currentAllowance >= sig.value) return;
        }

        if (sig.deadline < block.timestamp) revert PermitExpired();

        (bool success,) = token.call(
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                owner_,
                spender,
                sig.value,
                sig.deadline,
                sig.v,
                sig.r,
                sig.s
            )
        );

        if (!success) revert PermitFailed();
    }

    /// @dev EIP712 domain name
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "KamPaymaster";
        version = "1";
    }

    /// @notice Receive ETH
    receive() external payable { }
}

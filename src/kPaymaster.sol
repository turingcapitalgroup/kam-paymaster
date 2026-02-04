// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IkPaymaster } from "./interfaces/IkPaymaster.sol";
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
import { OptimizedReentrancyGuardTransient } from "solady/utils/OptimizedReentrancyGuardTransient.sol";

/// @title kPaymaster
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
contract kPaymaster is IkPaymaster, EIP712, Ownable, OptimizedReentrancyGuardTransient {
    using SafeTransferLib for address;

    /* //////////////////////////////////////////////////////////////
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
        "StakeWithAutoclaimRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 kTokenAmount)"
    );

    /// @dev EIP-712 typehash for UnstakeWithAutoclaimRequest
    bytes32 public constant UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH = keccak256(
        "UnstakeWithAutoclaimRequest(address user,uint96 nonce,address vault,uint96 deadline,address recipient,uint96 maxFee,uint256 stkTokenAmount)"
    );

    /// @dev Maximum number of requests in a batch operation
    uint256 public constant MAX_BATCH_SIZE = 200;

    /* //////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Protocol registry for vault validation
    IRegistry public immutable registry;

    /// @dev Protocol treasury to receive fees
    address public treasury;

    /// @dev Mapping of user address to nonce
    mapping(address user => uint256 nonce) private _nonces;

    /// @dev Mapping of trusted executor addresses
    mapping(address executor => bool isTrusted) private _trustedExecutors;

    /// @dev Mapping of requestId to autoclaim authorization
    mapping(bytes32 requestId => AutoclaimAuth) private _autoclaimRegistry;

    /* //////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Restricts function access to trusted executor addresses only
    modifier onlyTrustedExecutor() {
        _onlyTrustedExecutor();
        _;
    }

    function _onlyTrustedExecutor() internal view {
        if (!_trustedExecutors[msg.sender]) revert kPaymaster_NotTrustedExecutor();
    }

    /* //////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the kPaymaster contract
    /// @dev Sets owner, treasury, and registry. Registers owner as initial trusted executor.
    /// @param _owner The owner address with admin privileges
    /// @param _treasury The treasury address to receive fees
    /// @param _registry The registry address for vault validation
    constructor(address _owner, address _treasury, address _registry) {
        if (_owner == address(0)) revert kPaymaster_ZeroAddress();
        if (_treasury == address(0)) revert kPaymaster_ZeroAddress();
        if (_registry == address(0)) revert kPaymaster_ZeroAddress();

        _initializeOwner(_owner);
        treasury = _treasury;
        registry = IRegistry(_registry);
        _trustedExecutors[_owner] = true;

        emit TrustedExecutorUpdated(_owner, true);
        emit TreasuryUpdated(_treasury);
    }

    /* //////////////////////////////////////////////////////////////
                      EXTERNAL FUNCTIONS (WITH PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithPermit(
        StakeRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);

        _executePermit(kToken, _request.user, address(this), _permit);

        _requestId = _executeStake(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithPermit(
        UnstakeRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address stkToken = _request.vault;

        _executePermit(stkToken, _request.user, address(this), _permit);

        _requestId = _executeUnstake(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimStakedSharesWithPermit(
        ClaimRequest calldata _request,
        PermitSignature calldata _permitSig,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        address stkToken = _request.vault;

        if (_fee > 0) {
            _executePermit(stkToken, _request.user, address(this), _permitSig);
        }

        _executeClaimStakedShares(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimUnstakedAssetsWithPermit(
        ClaimRequest calldata _request,
        PermitSignature calldata _permitSig,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);

        if (_fee > 0) {
            _executePermit(kToken, _request.user, address(this), _permitSig);
        }

        _executeClaimUnstakedAssets(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /* //////////////////////////////////////////////////////////////
                      EXTERNAL FUNCTIONS (WITHOUT PERMIT)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function executeRequestStake(
        StakeRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);
        _requestId = _executeStake(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstake(
        UnstakeRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        _requestId = _executeUnstake(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimStakedShares(
        ClaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        _executeClaimStakedShares(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimUnstakedAssets(
        ClaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);
        _executeClaimUnstakedAssets(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /* //////////////////////////////////////////////////////////////
                            BATCH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithPermitBatch(
        StakeRequest[] calldata _requests,
        PermitSignature[] calldata _permits,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permits.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            _requestIds[i] = _executeStakeWithPermitAtIndex(_requests[i], _permits[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithPermitBatch(
        UnstakeRequest[] calldata _requests,
        PermitSignature[] calldata _permits,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permits.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            _requestIds[i] = _executeUnstakeWithPermitAtIndex(_requests[i], _permits[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestStakeBatch(
        StakeRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            address kToken = _getAsset(_requests[i].vault);
            _requestIds[i] = _executeStake(_requests[i], _requestSigs[i], kToken, _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeBatch(
        UnstakeRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            _requestIds[i] = _executeUnstake(_requests[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimStakedSharesWithPermitBatch(
        ClaimRequest[] calldata _requests,
        PermitSignature[] calldata _permitSigs,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permitSigs.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        for (uint256 i; i < len;) {
            address stkToken = _requests[i].vault;

            if (_fees[i] > 0) {
                _executePermit(stkToken, _requests[i].user, address(this), _permitSigs[i]);
            }

            _executeClaimStakedShares(_requests[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimUnstakedAssetsWithPermitBatch(
        ClaimRequest[] calldata _requests,
        PermitSignature[] calldata _permitSigs,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permitSigs.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        for (uint256 i; i < len;) {
            address kToken = _getAsset(_requests[i].vault);

            if (_fees[i] > 0) {
                _executePermit(kToken, _requests[i].user, address(this), _permitSigs[i]);
            }

            _executeClaimUnstakedAssets(_requests[i], _requestSigs[i], kToken, _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimStakedSharesBatch(
        ClaimRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        for (uint256 i; i < len;) {
            _executeClaimStakedShares(_requests[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeClaimUnstakedAssetsBatch(
        ClaimRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        for (uint256 i; i < len;) {
            address kToken = _getAsset(_requests[i].vault);
            _executeClaimUnstakedAssets(_requests[i], _requestSigs[i], kToken, _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /* //////////////////////////////////////////////////////////////
                          AUTOCLAIM FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithAutoclaimWithPermit(
        StakeWithAutoclaimRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);

        _executePermit(kToken, _request.user, address(this), _permit);

        _requestId = _executeStakeWithAutoclaim(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithAutoclaimWithPermit(
        UnstakeWithAutoclaimRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address stkToken = _request.vault;

        _executePermit(stkToken, _request.user, address(this), _permit);

        _requestId = _executeUnstakeWithAutoclaim(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithAutoclaim(
        StakeWithAutoclaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        address kToken = _getAsset(_request.vault);

        _requestId = _executeStakeWithAutoclaim(_request, _requestSig, kToken, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithAutoclaim(
        UnstakeWithAutoclaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        external
        onlyTrustedExecutor
        returns (bytes32 _requestId)
    {
        _lockReentrant();

        _requestId = _executeUnstakeWithAutoclaim(_request, _requestSig, _fee);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithAutoclaimWithPermitBatch(
        StakeWithAutoclaimRequest[] calldata _requests,
        PermitSignature[] calldata _permits,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permits.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            address kToken = _getAsset(_requests[i].vault);
            _executePermit(kToken, _requests[i].user, address(this), _permits[i]);
            _requestIds[i] = _executeStakeWithAutoclaim(_requests[i], _requestSigs[i], kToken, _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithAutoclaimWithPermitBatch(
        UnstakeWithAutoclaimRequest[] calldata _requests,
        PermitSignature[] calldata _permits,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _permits.length || len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            address stkToken = _requests[i].vault;
            _executePermit(stkToken, _requests[i].user, address(this), _permits[i]);
            _requestIds[i] = _executeUnstakeWithAutoclaim(_requests[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestStakeWithAutoclaimBatch(
        StakeWithAutoclaimRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            address kToken = _getAsset(_requests[i].vault);
            _requestIds[i] = _executeStakeWithAutoclaim(_requests[i], _requestSigs[i], kToken, _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeRequestUnstakeWithAutoclaimBatch(
        UnstakeWithAutoclaimRequest[] calldata _requests,
        bytes[] calldata _requestSigs,
        uint96[] calldata _fees
    )
        external
        onlyTrustedExecutor
        returns (bytes32[] memory _requestIds)
    {
        _lockReentrant();

        uint256 len = _requests.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        if (len != _requestSigs.length || len != _fees.length) {
            revert kPaymaster_ArrayLengthMismatch();
        }

        _requestIds = new bytes32[](len);

        for (uint256 i; i < len;) {
            _requestIds[i] = _executeUnstakeWithAutoclaim(_requests[i], _requestSigs[i], _fees[i]);
            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaimStakedShares(bytes32 _requestId) external onlyTrustedExecutor {
        _lockReentrant();

        AutoclaimAuth storage auth = _autoclaimRegistry[_requestId];

        if (auth.vault == address(0)) revert kPaymaster_AutoclaimNotRegistered();
        if (!auth.isStake) revert kPaymaster_AutoclaimNotRegistered();
        if (auth.executed) revert kPaymaster_AutoclaimAlreadyExecuted();
        if (!registry.isVault(auth.vault)) revert kPaymaster_VaultNotRegistered();
        // Note: If vault is deregistered after autoclaim registration, user must claim directly from vault

        auth.executed = true;

        // Fetch user from vault's stake request
        BaseVaultTypes.StakeRequest memory stakeRequest = IVaultReader(auth.vault).getStakeRequest(_requestId);
        address user = stakeRequest.user;

        // Forward claim to vault (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(abi.encodeCall(IVaultClaim.claimStakedShares, (_requestId)), user);

        (bool success,) = auth.vault.call(forwardData);
        if (!success) revert kPaymaster_ClaimStakedSharesFailed();

        // No fee collection - claim fee was paid upfront during request

        emit AutoclaimExecuted(user, auth.vault, _requestId, true);
        emit GaslessStakedSharesClaimed(user, auth.vault, _requestId, 0);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaimUnstakedAssets(bytes32 _requestId) external onlyTrustedExecutor {
        _lockReentrant();

        AutoclaimAuth storage auth = _autoclaimRegistry[_requestId];

        if (auth.vault == address(0)) revert kPaymaster_AutoclaimNotRegistered();
        if (auth.isStake) revert kPaymaster_AutoclaimNotRegistered();
        if (auth.executed) revert kPaymaster_AutoclaimAlreadyExecuted();
        if (!registry.isVault(auth.vault)) revert kPaymaster_VaultNotRegistered();
        // Note: If vault is deregistered after autoclaim registration, user must claim directly from vault

        auth.executed = true;

        // Fetch user from vault's unstake request
        BaseVaultTypes.UnstakeRequest memory unstakeRequest = IVaultReader(auth.vault).getUnstakeRequest(_requestId);
        address user = unstakeRequest.user;

        // Forward claim to vault (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(abi.encodeCall(IVaultClaim.claimUnstakedAssets, (_requestId)), user);

        (bool success,) = auth.vault.call(forwardData);
        if (!success) revert kPaymaster_ClaimUnstakedAssetsFailed();

        // No fee collection - claim fee was paid upfront during request
        emit AutoclaimExecuted(user, auth.vault, _requestId, false);
        emit GaslessUnstakedAssetsClaimed(user, auth.vault, _requestId, 0);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaimStakedSharesBatch(bytes32[] calldata _requestIds) external onlyTrustedExecutor {
        _lockReentrant();

        uint256 len = _requestIds.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        for (uint256 i; i < len;) {
            bytes32 requestId = _requestIds[i];
            AutoclaimAuth storage auth = _autoclaimRegistry[requestId];

            // Skip invalid or already executed requests
            if (auth.vault == address(0) || !auth.isStake || auth.executed || !registry.isVault(auth.vault)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Fetch user from vault's stake request
            BaseVaultTypes.StakeRequest memory stakeRequest = IVaultReader(auth.vault).getStakeRequest(requestId);
            address user = stakeRequest.user;

            // Forward claim to vault (ERC2771 pattern)
            bytes memory forwardData =
                abi.encodePacked(abi.encodeCall(IVaultClaim.claimStakedShares, (requestId)), user);

            auth.executed = true;

            (bool success,) = auth.vault.call(forwardData);
            if (success) {
                emit AutoclaimExecuted(user, auth.vault, requestId, true);
                emit GaslessStakedSharesClaimed(user, auth.vault, requestId, 0);
            } else {
                auth.executed = false;
                emit AutoclaimFailed(auth.vault, requestId, true);
            }

            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaimUnstakedAssetsBatch(bytes32[] calldata _requestIds) external onlyTrustedExecutor {
        _lockReentrant();

        uint256 len = _requestIds.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        for (uint256 i; i < len;) {
            bytes32 requestId = _requestIds[i];
            AutoclaimAuth storage auth = _autoclaimRegistry[requestId];

            // Skip invalid or already executed requests
            if (auth.vault == address(0) || auth.isStake || auth.executed || !registry.isVault(auth.vault)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Fetch user from vault's unstake request
            BaseVaultTypes.UnstakeRequest memory unstakeRequest = IVaultReader(auth.vault).getUnstakeRequest(requestId);
            address user = unstakeRequest.user;

            // Forward claim to vault (ERC2771 pattern)
            bytes memory forwardData =
                abi.encodePacked(abi.encodeCall(IVaultClaim.claimUnstakedAssets, (requestId)), user);

            auth.executed = true;

            (bool success,) = auth.vault.call(forwardData);
            if (success) {
                emit AutoclaimExecuted(user, auth.vault, requestId, false);
                emit GaslessUnstakedAssetsClaimed(user, auth.vault, requestId, 0);
            } else {
                auth.executed = false;
                emit AutoclaimFailed(auth.vault, requestId, false);
            }

            unchecked {
                ++i;
            }
        }

        _unlockReentrant();
    }

    /* //////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function nonces(address _user) external view returns (uint256) {
        return _nonces[_user];
    }

    /// @inheritdoc IkPaymaster
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @inheritdoc IkPaymaster
    function isTrustedExecutor(address _executor) external view returns (bool) {
        return _trustedExecutors[_executor];
    }

    /// @inheritdoc IkPaymaster
    function getAutoclaimAuth(bytes32 _requestId) external view returns (AutoclaimAuth memory) {
        return _autoclaimRegistry[_requestId];
    }

    /// @inheritdoc IkPaymaster
    function canAutoclaim(bytes32 _requestId) external view returns (bool) {
        AutoclaimAuth storage auth = _autoclaimRegistry[_requestId];
        return auth.vault != address(0) && !auth.executed;
    }

    /* //////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function setTrustedExecutor(address _executor, bool _trusted) external onlyOwner {
        if (_executor == address(0)) revert kPaymaster_ZeroAddress();
        _trustedExecutors[_executor] = _trusted;
        emit TrustedExecutorUpdated(_executor, _trusted);
    }

    /// @inheritdoc IkPaymaster
    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert kPaymaster_ZeroAddress();
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /// @inheritdoc IkPaymaster
    function rescueTokens(address _token, address _to, uint256 _amount) external onlyOwner {
        _lockReentrant();

        if (_to == address(0)) revert kPaymaster_ZeroAddress();
        if (_token == address(0)) {
            SafeTransferLib.safeTransferETH(_to, _amount);
        } else {
            _token.safeTransfer(_to, _amount);
        }
        emit TokensRescued(_token, _to, _amount);

        _unlockReentrant();
    }

    /* //////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Get the underlying asset for a vault
    /// @param _vault The vault address
    /// @return The underlying kToken address
    function _getAsset(address _vault) internal view returns (address) {
        return IkStakingVault(_vault).asset();
    }

    /// @dev Execute stake with permit at a specific index (for batch operations)
    /// @param _request The stake request parameters
    /// @param _permit The permit signature
    /// @param _requestSig The meta-transaction signature
    /// @param _fee The fee amount
    /// @return _requestId The resulting stake request ID
    function _executeStakeWithPermitAtIndex(
        StakeRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        address kToken = _getAsset(_request.vault);

        _executePermit(kToken, _request.user, address(this), _permit);

        _requestId = _executeStake(_request, _requestSig, kToken, _fee);
    }

    /// @dev Execute unstake with permit at a specific index (for batch operations)
    /// @param _request The unstake request parameters
    /// @param _permit The permit signature
    /// @param _requestSig The meta-transaction signature
    /// @param _fee The fee amount
    /// @return _requestId The resulting unstake request ID
    function _executeUnstakeWithPermitAtIndex(
        UnstakeRequest calldata _request,
        PermitSignature calldata _permit,
        bytes calldata _requestSig,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        address stkToken = _request.vault;

        _executePermit(stkToken, _request.user, address(this), _permit);

        _requestId = _executeUnstake(_request, _requestSig, _fee);
    }

    /// @dev Execute stake logic
    /// @dev Single permit model: paymaster pulls full amount, sends fee to treasury, approves vault for netAmount
    /// @param _request The stake request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _kToken The underlying asset address
    /// @param _fee The fee amount in kTokens
    /// @return _requestId The resulting stake request ID
    function _executeStake(
        StakeRequest calldata _request,
        bytes calldata _requestSig,
        address _kToken,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        _validateStakeRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        if (_request.kTokenAmount <= _fee) revert kPaymaster_InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = _request.kTokenAmount - _fee;
        }

        unchecked {
            ++_nonces[_request.user];
        }

        // Pull full amount from user to paymaster
        _kToken.safeTransferFrom(_request.user, address(this), _request.kTokenAmount);

        // Send fee to treasury
        if (_fee > 0) {
            _kToken.safeTransfer(treasury, _fee);
        }

        // Approve vault to pull netAmount
        _kToken.safeApproveWithRetry(_request.vault, netAmount);

        // Forward requestStake call with paymaster as msg.sender (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestStake, (_request.user, _request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_StakeRequestFailed();
        _kToken.safeApproveWithRetry(_request.vault, 0);

        _requestId = abi.decode(returnData, (bytes32));

        emit GaslessStakeRequested(_request.user, _request.vault, _request.kTokenAmount, _fee, _requestId);
    }

    /// @dev Execute unstake logic
    /// @dev Single permit model: paymaster pulls full amount, sends fee to treasury, approves vault for netAmount
    /// @param _request The unstake request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _fee The fee amount in stkTokens
    /// @return _requestId The resulting unstake request ID
    function _executeUnstake(
        UnstakeRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        _validateUnstakeRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        address stkToken = _request.vault;

        if (_request.stkTokenAmount <= _fee) revert kPaymaster_InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = _request.stkTokenAmount - _fee;
        }

        unchecked {
            ++_nonces[_request.user];
        }

        // Pull full amount from user to paymaster
        stkToken.safeTransferFrom(_request.user, address(this), _request.stkTokenAmount);

        // Send fee to treasury
        if (_fee > 0) {
            stkToken.safeTransfer(treasury, _fee);
        }

        // Approve vault to pull netAmount
        stkToken.safeApproveWithRetry(_request.vault, netAmount);

        // Forward requestUnstake call (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestUnstake, (_request.user, _request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_UnstakeRequestFailed();
        stkToken.safeApproveWithRetry(_request.vault, 0);

        _requestId = abi.decode(returnData, (bytes32));

        emit GaslessUnstakeRequested(_request.user, _request.vault, _request.stkTokenAmount, _fee, _requestId);
    }

    /// @dev Execute claim staked shares logic
    /// @dev Fee is collected AFTER vault claim by design -- user needs claim proceeds (stkTokens)
    ///      to pay the fee. Reentrancy protection is provided by onlyTrustedExecutor + incremented nonce.
    /// @param _request The claim request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _fee The fee amount in stkTokens
    function _executeClaimStakedShares(
        ClaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        internal
    {
        _validateClaimRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        address stkToken = _request.vault;

        unchecked {
            ++_nonces[_request.user];
        }

        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVaultClaim.claimStakedShares, (_request.requestId)), _request.user);

        (bool success,) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_ClaimStakedSharesFailed();

        // Fee collected after vault claim -- user receives stkTokens from the claim first
        if (_fee > 0) {
            stkToken.safeTransferFrom(_request.user, treasury, _fee);
        }

        emit GaslessStakedSharesClaimed(_request.user, _request.vault, _request.requestId, _fee);
    }

    /// @dev Execute claim unstaked assets logic
    /// @dev Fee is collected AFTER vault claim by design -- user needs claim proceeds (kTokens)
    ///      to pay the fee. Reentrancy protection is provided by onlyTrustedExecutor + incremented nonce.
    /// @param _request The claim request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _kToken The underlying asset address
    /// @param _fee The fee amount in kTokens
    function _executeClaimUnstakedAssets(
        ClaimRequest calldata _request,
        bytes calldata _requestSig,
        address _kToken,
        uint96 _fee
    )
        internal
    {
        _validateClaimRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        unchecked {
            ++_nonces[_request.user];
        }

        bytes memory forwardData =
            abi.encodePacked(abi.encodeCall(IVaultClaim.claimUnstakedAssets, (_request.requestId)), _request.user);

        (bool success,) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_ClaimUnstakedAssetsFailed();

        // Fee collected after vault claim -- user receives kTokens from the claim first
        if (_fee > 0) {
            _kToken.safeTransferFrom(_request.user, treasury, _fee);
        }

        emit GaslessUnstakedAssetsClaimed(_request.user, _request.vault, _request.requestId, _fee);
    }

    /// @dev Execute stake with autoclaim logic
    /// @dev User pays fee upfront (covers both request + claim). kTokenAmount = fee + netStakeAmount
    /// @param _request The stake with autoclaim request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _kToken The underlying asset address
    /// @param _fee The fee amount in kTokens
    /// @return _requestId The resulting stake request ID
    function _executeStakeWithAutoclaim(
        StakeWithAutoclaimRequest calldata _request,
        bytes calldata _requestSig,
        address _kToken,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        _validateStakeWithAutoclaimRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        if (_request.kTokenAmount <= _fee) revert kPaymaster_InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = _request.kTokenAmount - _fee;
        }

        unchecked {
            ++_nonces[_request.user];
        }

        // Pull full amount from user to paymaster
        _kToken.safeTransferFrom(_request.user, address(this), _request.kTokenAmount);

        // Send fee to treasury
        if (_fee > 0) {
            _kToken.safeTransfer(treasury, _fee);
        }

        // Approve vault to pull netAmount
        _kToken.safeApproveWithRetry(_request.vault, netAmount);

        // Forward requestStake call with paymaster as msg.sender (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestStake, (_request.user, _request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_StakeRequestFailed();
        _kToken.safeApproveWithRetry(_request.vault, 0);

        _requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[_requestId] = AutoclaimAuth({ vault: _request.vault, isStake: true, executed: false });

        emit GaslessStakeRequested(_request.user, _request.vault, _request.kTokenAmount, _fee, _requestId);
        emit AutoclaimRegistered(_request.user, _request.vault, _requestId, true);
    }

    /// @dev Execute unstake with autoclaim logic
    /// @dev User pays fee upfront (covers both request + claim). stkTokenAmount = fee + netUnstakeAmount
    /// @param _request The unstake with autoclaim request parameters
    /// @param _requestSig The meta-transaction signature
    /// @param _fee The fee amount in stkTokens
    /// @return _requestId The resulting unstake request ID
    function _executeUnstakeWithAutoclaim(
        UnstakeWithAutoclaimRequest calldata _request,
        bytes calldata _requestSig,
        uint96 _fee
    )
        internal
        returns (bytes32 _requestId)
    {
        _validateUnstakeWithAutoclaimRequest(_request, _requestSig, _fee);

        // Validate vault is registered in the protocol
        if (!registry.isVault(_request.vault)) revert kPaymaster_VaultNotRegistered();

        address stkToken = _request.vault;

        if (_request.stkTokenAmount <= _fee) revert kPaymaster_InsufficientAmountForFee();

        uint256 netAmount;
        unchecked {
            netAmount = _request.stkTokenAmount - _fee;
        }

        unchecked {
            ++_nonces[_request.user];
        }

        // Pull full amount from user to paymaster
        stkToken.safeTransferFrom(_request.user, address(this), _request.stkTokenAmount);

        // Send fee to treasury
        if (_fee > 0) {
            stkToken.safeTransfer(treasury, _fee);
        }

        // Approve vault to pull netAmount
        stkToken.safeApproveWithRetry(_request.vault, netAmount);

        // Forward requestUnstake call (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestUnstake, (_request.user, _request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_UnstakeRequestFailed();
        stkToken.safeApproveWithRetry(_request.vault, 0);

        _requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[_requestId] = AutoclaimAuth({ vault: _request.vault, isStake: false, executed: false });

        emit GaslessUnstakeRequested(_request.user, _request.vault, _request.stkTokenAmount, _fee, _requestId);
        emit AutoclaimRegistered(_request.user, _request.vault, _requestId, false);
    }

    /// @dev Validate a stake request
    /// @param _request The stake request to validate
    /// @param _sig The EIP-712 signature
    /// @param _fee The fee amount
    function _validateStakeRequest(StakeRequest calldata _request, bytes calldata _sig, uint96 _fee) internal view {
        if (_request.deadline < block.timestamp) revert kPaymaster_RequestExpired();
        if (_request.vault == address(0)) revert kPaymaster_ZeroAddress();
        if (_request.nonce != _nonces[_request.user]) revert kPaymaster_InvalidNonce();
        if (_request.kTokenAmount == 0) revert kPaymaster_ZeroAmount();
        if (_request.recipient == address(0)) revert kPaymaster_ZeroAddress();
        if (_fee > _request.maxFee) revert kPaymaster_FeeExceedsMax();

        bytes32 typehash = STAKE_REQUEST_TYPEHASH;
        bytes32 structHash;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, typehash)
            calldatacopy(add(m, 0x20), _request, 0xe0)
            structHash := keccak256(m, 0x100)
        }

        _validateSignature(_request.user, structHash, _sig);
    }

    /// @dev Validate an unstake request
    /// @param _request The unstake request to validate
    /// @param _sig The EIP-712 signature
    /// @param _fee The fee amount
    function _validateUnstakeRequest(UnstakeRequest calldata _request, bytes calldata _sig, uint96 _fee) internal view {
        if (_request.deadline < block.timestamp) revert kPaymaster_RequestExpired();
        if (_request.vault == address(0)) revert kPaymaster_ZeroAddress();
        if (_request.nonce != _nonces[_request.user]) revert kPaymaster_InvalidNonce();
        if (_request.stkTokenAmount == 0) revert kPaymaster_ZeroAmount();
        if (_request.recipient == address(0)) revert kPaymaster_ZeroAddress();
        if (_fee > _request.maxFee) revert kPaymaster_FeeExceedsMax();

        bytes32 typehash = UNSTAKE_REQUEST_TYPEHASH;
        bytes32 structHash;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, typehash)
            calldatacopy(add(m, 0x20), _request, 0xe0)
            structHash := keccak256(m, 0x100)
        }

        _validateSignature(_request.user, structHash, _sig);
    }

    /// @dev Validate a claim request
    /// @param _request The claim request to validate
    /// @param _sig The EIP-712 signature
    /// @param _fee The fee amount
    function _validateClaimRequest(ClaimRequest calldata _request, bytes calldata _sig, uint96 _fee) internal view {
        if (_request.deadline < block.timestamp) revert kPaymaster_RequestExpired();
        if (_request.vault == address(0)) revert kPaymaster_ZeroAddress();
        if (_request.nonce != _nonces[_request.user]) revert kPaymaster_InvalidNonce();
        if (_fee > _request.maxFee) revert kPaymaster_FeeExceedsMax();

        bytes32 typehash = CLAIM_REQUEST_TYPEHASH;
        bytes32 structHash;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, typehash)
            calldatacopy(add(m, 0x20), _request, 0xc0)
            structHash := keccak256(m, 0xe0)
        }

        _validateSignature(_request.user, structHash, _sig);
    }

    /// @dev Validate a stake with autoclaim request
    /// @param _request The stake with autoclaim request to validate
    /// @param _sig The EIP-712 signature
    /// @param _fee The fee amount
    function _validateStakeWithAutoclaimRequest(
        StakeWithAutoclaimRequest calldata _request,
        bytes calldata _sig,
        uint96 _fee
    )
        internal
        view
    {
        if (_request.deadline < block.timestamp) revert kPaymaster_RequestExpired();
        if (_request.vault == address(0)) revert kPaymaster_ZeroAddress();
        if (_request.nonce != _nonces[_request.user]) revert kPaymaster_InvalidNonce();
        if (_request.kTokenAmount == 0) revert kPaymaster_ZeroAmount();
        if (_request.recipient == address(0)) revert kPaymaster_ZeroAddress();
        if (_fee > _request.maxFee) revert kPaymaster_FeeExceedsMax();

        bytes32 typehash = STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH;
        bytes32 structHash;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, typehash)
            calldatacopy(add(m, 0x20), _request, 0xe0)
            structHash := keccak256(m, 0x100)
        }

        _validateSignature(_request.user, structHash, _sig);
    }

    /// @dev Validate an unstake with autoclaim request
    /// @param _request The unstake with autoclaim request to validate
    /// @param _sig The EIP-712 signature
    /// @param _fee The fee amount
    function _validateUnstakeWithAutoclaimRequest(
        UnstakeWithAutoclaimRequest calldata _request,
        bytes calldata _sig,
        uint96 _fee
    )
        internal
        view
    {
        if (_request.deadline < block.timestamp) revert kPaymaster_RequestExpired();
        if (_request.vault == address(0)) revert kPaymaster_ZeroAddress();
        if (_request.nonce != _nonces[_request.user]) revert kPaymaster_InvalidNonce();
        if (_request.stkTokenAmount == 0) revert kPaymaster_ZeroAmount();
        if (_request.recipient == address(0)) revert kPaymaster_ZeroAddress();
        if (_fee > _request.maxFee) revert kPaymaster_FeeExceedsMax();

        bytes32 typehash = UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH;
        bytes32 structHash;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, typehash)
            calldatacopy(add(m, 0x20), _request, 0xe0)
            structHash := keccak256(m, 0x100)
        }

        _validateSignature(_request.user, structHash, _sig);
    }

    /// @dev Validate an EIP-712 signature using Solady's SignatureCheckerLib
    /// @param _signer The expected signer address
    /// @param _structHash The EIP-712 struct hash
    /// @param _sig The signature bytes
    function _validateSignature(address _signer, bytes32 _structHash, bytes calldata _sig) internal view {
        bytes32 digest = _hashTypedData(_structHash);
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(_signer, digest, _sig)) {
            revert kPaymaster_InvalidSignature();
        }
    }

    /// @dev Execute EIP-2612 permit
    /// @dev Skips permit if allowance is already sufficient to prevent front-running failures
    /// @param _token The token address to permit
    /// @param _owner The token owner address
    /// @param _spender The spender address
    /// @param _sig The permit signature parameters
    function _executePermit(address _token, address _owner, address _spender, PermitSignature calldata _sig) internal {
        // Skip permit if allowance is already sufficient (handles front-running/replay scenarios)
        (bool allowanceSuccess, bytes memory allowanceData) =
            _token.staticcall(abi.encodeWithSignature("allowance(address,address)", _owner, _spender));
        if (allowanceSuccess && allowanceData.length >= 32) {
            uint256 currentAllowance = abi.decode(allowanceData, (uint256));
            if (currentAllowance >= _sig.value) return;
        }

        if (_sig.deadline < block.timestamp) revert kPaymaster_PermitExpired();

        (bool success,) = _token.call(
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                _owner,
                _spender,
                _sig.value,
                _sig.deadline,
                _sig.v,
                _sig.r,
                _sig.s
            )
        );

        if (!success) revert kPaymaster_PermitFailed();
    }

    /// @dev EIP712 domain name
    /// @return _name The EIP-712 domain name
    /// @return _version The EIP-712 domain version
    function _domainNameAndVersion() internal pure override returns (string memory _name, string memory _version) {
        _name = "kPaymaster";
        _version = "1";
    }

    /// @notice Receive ETH for rescue functionality
    /// @dev Allows the contract to receive ETH which can be rescued via rescueTokens
    receive() external payable { }
}

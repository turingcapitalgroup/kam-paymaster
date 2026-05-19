// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

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
/// - Support for stake/unstake with autoclaim
/// - Both permit and non-permit versions of all functions
/// - Batch operations for gas efficiency
/// - maxFee parameter in signatures to protect users from excessive fees
/// - Packed structs for reduced calldata costs
contract kPaymaster is IkPaymaster, EIP712, Ownable, OptimizedReentrancyGuardTransient {
    using SafeTransferLib for address;

    /* //////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

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
            ++i;
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
            ++i;
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
            ++i;
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
            ++i;
        }

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaim(bytes32 _requestId, AutoclaimType _claimType) external onlyTrustedExecutor {
        _lockReentrant();

        AutoclaimAuth storage auth = _autoclaimRegistry[_requestId];
        bool expectStake = (_claimType == AutoclaimType.StakedShares);

        // Granular reverts so callers know which precondition failed.
        if (auth.vault == address(0)) revert kPaymaster_AutoclaimNotRegistered();
        if (auth.isStake != expectStake) revert kPaymaster_AutoclaimNotRegistered();
        if (auth.executed) revert kPaymaster_AutoclaimAlreadyExecuted();
        if (!registry.isVault(auth.vault)) revert kPaymaster_VaultNotRegistered();

        (bool success, address user, address vault) = _doAutoclaim(_requestId, _claimType, auth);
        if (!success) revert kPaymaster_AutoclaimRevert();

        emit AutoclaimExecuted(user, vault, _requestId, _claimType);

        _unlockReentrant();
    }

    /// @inheritdoc IkPaymaster
    function executeAutoclaimBatch(
        bytes32[] calldata _requestIds,
        AutoclaimType _claimType
    )
        external
        onlyTrustedExecutor
    {
        _lockReentrant();

        uint256 len = _requestIds.length;
        if (len == 0 || len > MAX_BATCH_SIZE) revert kPaymaster_BatchTooLarge();
        bool expectStake = (_claimType == AutoclaimType.StakedShares);

        for (uint256 i; i < len;) {
            bytes32 requestId = _requestIds[i];
            AutoclaimAuth storage auth = _autoclaimRegistry[requestId];

            // Skip on validation failure (mirrors granular reverts in `executeAutoclaim`).
            if (
                auth.vault == address(0) || auth.isStake != expectStake || auth.executed
                    || !registry.isVault(auth.vault)
            ) {
                ++i;
                continue;
            }

            (bool success, address user, address vault) = _doAutoclaim(requestId, _claimType, auth);
            if (success) emit AutoclaimExecuted(user, vault, requestId, _claimType);
            else emit AutoclaimFailed(vault, requestId, _claimType);

            ++i;
        }

        _unlockReentrant();
    }

    /// @notice Performs the claim work after validation. Shared by single + batch entry points.
    /// @dev Validation is the caller's responsibility — single reverts on failure, batch skips.
    ///      Sets `auth.executed = true` before the call and rolls back to `false` if the
    ///      downstream vault call reverts so the request can be retried later.
    /// @param _requestId Stake or unstake request id
    /// @param _claimType Discriminator selecting the reader function and claim selector
    /// @param auth Storage pointer to the registry entry (already validated by caller)
    /// @return success True if the downstream vault call succeeded
    /// @return user The request owner read from the vault's reader
    /// @return vault The vault address from the registry entry
    function _doAutoclaim(
        bytes32 _requestId,
        AutoclaimType _claimType,
        AutoclaimAuth storage auth
    )
        internal
        returns (bool success, address user, address vault)
    {
        vault = auth.vault;
        auth.executed = true;

        // ERC2771 trailing-address pattern: append the request owner so the vault sees them.
        bytes4 claimSelector;
        if (_claimType == AutoclaimType.StakedShares) {
            user = IVaultReader(vault).getStakeRequest(_requestId).user;
            claimSelector = IVaultClaim.claimStakedShares.selector;
        } else {
            user = IVaultReader(vault).getUnstakeRequest(_requestId).user;
            claimSelector = IVaultClaim.claimUnstakedAssets.selector;
        }

        bytes memory forwardData = abi.encodePacked(abi.encodeWithSelector(claimSelector, _requestId), user);
        (success,) = vault.call(forwardData);
        if (!success) auth.executed = false; // rollback so the user / executor can retry later
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
                          USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IkPaymaster
    function incrementNonce() external {
        uint256 newNonce = ++_nonces[msg.sender];
        emit NonceIncremented(msg.sender, newNonce);
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

        if (!IVault(_request.vault).isTrustedForwarder(address(this))) revert kPaymaster_NotTrustedForwarder();

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
        _kToken.safeApprove(_request.vault, 0);

        _requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[_requestId] = AutoclaimAuth({ vault: _request.vault, isStake: true, executed: false });

        emit GaslessStakeRequested(_request.user, _request.vault, _request.kTokenAmount, _fee, _requestId);
        emit AutoclaimRegistered(_request.user, _request.vault, _requestId, AutoclaimType.StakedShares);
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

        if (!IVault(_request.vault).isTrustedForwarder(address(this))) revert kPaymaster_NotTrustedForwarder();

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

        // Forward requestUnstake call (ERC2771 pattern)
        bytes memory forwardData = abi.encodePacked(
            abi.encodeCall(IVault.requestUnstake, (_request.user, _request.recipient, netAmount)), address(this)
        );

        (bool success, bytes memory returnData) = _request.vault.call(forwardData);
        if (!success) revert kPaymaster_UnstakeRequestFailed();

        _requestId = abi.decode(returnData, (bytes32));

        // Register autoclaim (user is fetched from vault during claim, no fee needed at claim time)
        _autoclaimRegistry[_requestId] = AutoclaimAuth({ vault: _request.vault, isStake: false, executed: false });

        emit GaslessUnstakeRequested(_request.user, _request.vault, _request.stkTokenAmount, _fee, _requestId);
        emit AutoclaimRegistered(_request.user, _request.vault, _requestId, AutoclaimType.UnstakedAssets);
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
    /// @param _token The token address to permit
    /// @param _owner The token owner address
    /// @param _spender The spender address
    /// @param _sig The permit signature parameters
    function _executePermit(address _token, address _owner, address _spender, PermitSignature calldata _sig) internal {
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

        if (!success) {
            (bool allowanceSuccess, bytes memory allowanceData) =
                _token.staticcall(abi.encodeWithSignature("allowance(address,address)", _owner, _spender));
            if (!allowanceSuccess || allowanceData.length < 32 || abi.decode(allowanceData, (uint256)) < _sig.value) {
                revert kPaymaster_PermitFailed();
            }
        }
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

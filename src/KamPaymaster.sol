// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IKamPaymaster } from "./interfaces/IKamPaymaster.sol";
import { IChainlinkAggregator } from "./interfaces/IChainlinkAggregator.sol";

/// @title KamPaymaster
/// @notice Gasless forwarder for kStakingVault interactions using permit signatures and Chainlink oracles
/// @dev This contract acts as an ERC2771-style trusted forwarder that enables users to perform gasless
/// operations on kStakingVaults. Users sign meta-transactions which are executed by trusted relayers,
/// with gas costs covered by fee deduction from the tokens being transferred.
///
/// Key features:
/// - EIP-712 typed signatures for secure meta-transactions
/// - EIP-2612 permit integration for gasless token approvals
/// - Chainlink oracle integration for accurate token/ETH price feeds
/// - Support for requestStake, requestUnstake, claimStakedShares, claimUnstakedAssets
/// - Fee deduction on all operations including claims
///
/// Fee model:
/// - Fees are calculated using Chainlink asset/ETH price feeds
/// - For kTokens: uses underlying asset price feed (e.g., USDC/ETH for kUSD)
/// - For stkTokens: converts to kTokens via convertToAssets(), then uses kToken's price feed
/// - Fee = (gasEstimate * gasPrice * gasMultiplier) / tokenPriceInEth + baseFee%
contract KamPaymaster is IKamPaymaster {
    using SafeTransferLib for address;

    /* //////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Maximum fee in basis points (50% = 5000 bps)
    uint256 public constant MAX_FEE_BPS = 5000;

    /// @dev Basis points denominator
    uint256 public constant BPS_DENOMINATOR = 10000;

    /// @dev Gas buffer for internal operations
    uint256 public constant GAS_BUFFER = 50000;

    /// @dev Maximum staleness for Chainlink price feeds (1 hour)
    uint256 public constant MAX_PRICE_STALENESS = 3600;

    /// @dev EIP-712 typehash for StakeRequest
    bytes32 public constant STAKE_REQUEST_TYPEHASH = keccak256(
        "StakeRequest(address user,address vault,uint256 kTokenAmount,address recipient,uint256 deadline,uint256 nonce)"
    );

    /// @dev EIP-712 typehash for UnstakeRequest
    bytes32 public constant UNSTAKE_REQUEST_TYPEHASH = keccak256(
        "UnstakeRequest(address user,address vault,uint256 stkTokenAmount,address recipient,uint256 deadline,uint256 nonce)"
    );

    /// @dev EIP-712 typehash for ClaimRequest
    bytes32 public constant CLAIM_REQUEST_TYPEHASH =
        keccak256("ClaimRequest(address user,address vault,bytes32 requestId,uint256 deadline,uint256 nonce)");

    /// @dev EIP-712 domain separator typehash
    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Contract name for EIP-712
    string public constant NAME = "KamPaymaster";

    /// @dev Contract version for EIP-712
    string public constant VERSION = "1";

    /* //////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Owner of the contract
    address public owner;

    /// @dev Protocol treasury to receive fees
    address public treasury;

    /// @dev KAM Registry address for vault validation
    address public registry;

    /// @dev Base fee in basis points (100 = 1%)
    uint256 public baseFee;

    /// @dev Multiplier for gas cost calculation (scaled to 1e18, e.g., 1.2e18 = 1.2x)
    uint256 public gasMultiplier;

    /// @dev Mapping of underlying asset address to Chainlink price feed (asset/ETH)
    /// @notice Use the underlying asset address (USDC, WBTC, etc.), not the kToken address
    mapping(address asset => address priceFeed) public assetPriceFeeds;

    /// @dev Mapping of user address to nonce
    mapping(address user => uint256 nonce) private _nonces;

    /// @dev Mapping of trusted executor addresses
    mapping(address executor => bool isTrusted) private _trustedExecutors;

    /// @dev Cached domain separator
    bytes32 private immutable _cachedDomainSeparator;

    /// @dev Cached chain ID for domain separator validation
    uint256 private immutable _cachedChainId;

    /* //////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        require(msg.sender == owner, "KamPaymaster: not owner");
        _;
    }

    modifier onlyTrustedExecutor() {
        if (!_trustedExecutors[msg.sender]) revert NotTrustedExecutor();
        _;
    }

    /* //////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the KamPaymaster contract
    /// @param _owner The owner address with admin privileges
    /// @param _treasury The treasury address to receive fees
    /// @param _registry The KAM registry address for vault validation
    /// @param _baseFee Initial base fee in basis points
    /// @param _gasMultiplier Initial gas cost multiplier (scaled to 1e18)
    constructor(address _owner, address _treasury, address _registry, uint256 _baseFee, uint256 _gasMultiplier) {
        if (_owner == address(0)) revert ZeroAddress();
        if (_treasury == address(0)) revert ZeroAddress();
        if (_registry == address(0)) revert ZeroAddress();

        owner = _owner;
        treasury = _treasury;
        registry = _registry;
        baseFee = _baseFee;
        gasMultiplier = _gasMultiplier;

        // Set owner as trusted executor by default
        _trustedExecutors[_owner] = true;

        // Cache domain separator
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _computeDomainSeparator();
    }

    /* //////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function executeStakeWithPermit(
        StakeRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        // Validate request
        _validateStakeRequest(request, requestSig);

        // Get vault's kToken address
        address kToken = _getVaultKToken(request.vault);

        // Execute permit to approve this contract to spend user's kTokens
        _executePermit(kToken, request.user, address(this), permitSig);

        // Calculate fee in kTokens using Chainlink oracle
        uint256 fee = _calculateFeeForKToken(kToken, GAS_BUFFER + 150000); // ~150k gas for requestStake

        // Validate amount covers fee
        if (request.kTokenAmount <= fee) revert InsufficientAmountForFee();

        uint256 netAmount = request.kTokenAmount - fee;

        // Transfer kTokens from user to this contract
        kToken.safeTransferFrom(request.user, address(this), request.kTokenAmount);

        // Send fee to treasury
        if (fee > 0) {
            kToken.safeTransfer(treasury, fee);
        }

        // Approve vault to spend net kTokens
        kToken.safeApprove(request.vault, netAmount);

        // Forward the request to the vault with user's address appended (ERC2771 style)
        bytes memory callData =
            abi.encodeWithSignature("requestStake(address,uint256)", request.recipient, netAmount);

        // Append user address for ERC2771 context
        bytes memory forwardData = abi.encodePacked(callData, request.user);

        // Execute the forwarded call
        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        require(success, "KamPaymaster: stake request failed");

        // Decode request ID from return data
        requestId = abi.decode(returnData, (bytes32));

        // Increment nonce
        _nonces[request.user]++;

        emit GaslessStakeRequested(request.user, request.vault, request.kTokenAmount, fee, requestId);
    }

    /// @inheritdoc IKamPaymaster
    function executeUnstakeWithPermit(
        UnstakeRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    )
        external
        onlyTrustedExecutor
        returns (bytes32 requestId)
    {
        // Validate request
        _validateUnstakeRequest(request, requestSig);

        // stkToken is the vault itself (it's an ERC20)
        address stkToken = request.vault;

        // Execute permit to approve this contract to spend user's stkTokens
        _executePermit(stkToken, request.user, address(this), permitSig);

        // Calculate fee in stkTokens using Chainlink oracle + convertToAssets
        uint256 fee = _calculateFeeForStkToken(request.vault, GAS_BUFFER + 180000); // ~180k gas for requestUnstake

        // Validate amount covers fee
        if (request.stkTokenAmount <= fee) revert InsufficientAmountForFee();

        uint256 netAmount = request.stkTokenAmount - fee;

        // Take ONLY the fee from user and send directly to treasury
        // The vault will transfer the remaining netAmount from user via _msgSender() internally
        if (fee > 0) {
            stkToken.safeTransferFrom(request.user, treasury, fee);
        }

        // Forward the request to the vault with user's address appended (ERC2771 style)
        // Note: The vault extracts user from calldata suffix and transfers netAmount from user
        bytes memory callData =
            abi.encodeWithSignature("requestUnstake(address,uint256)", request.recipient, netAmount);

        // Append user address for ERC2771 context
        bytes memory forwardData = abi.encodePacked(callData, request.user);

        // Execute the forwarded call
        (bool success, bytes memory returnData) = request.vault.call(forwardData);
        require(success, "KamPaymaster: unstake request failed");

        // Decode request ID from return data
        requestId = abi.decode(returnData, (bytes32));

        // Increment nonce
        _nonces[request.user]++;

        emit GaslessUnstakeRequested(request.user, request.vault, request.stkTokenAmount, fee, requestId);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimStakedShares(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    )
        external
        onlyTrustedExecutor
    {
        // Validate request
        _validateClaimRequest(request, requestSig);

        // stkToken is the vault itself
        address stkToken = request.vault;

        // Get user's stkToken balance before claim
        uint256 balanceBefore = _getTokenBalance(stkToken, request.user);

        // Forward the claim to the vault with user's address appended (ERC2771 style)
        bytes memory callData = abi.encodeWithSignature("claimStakedShares(bytes32)", request.requestId);

        // Append user address for ERC2771 context
        bytes memory forwardData = abi.encodePacked(callData, request.user);

        // Execute the forwarded call
        (bool success,) = request.vault.call(forwardData);
        require(success, "KamPaymaster: claim staked shares failed");

        // Get user's stkToken balance after claim
        uint256 balanceAfter = _getTokenBalance(stkToken, request.user);

        // Calculate received stkTokens
        uint256 receivedStkTokens = balanceAfter - balanceBefore;

        // Calculate fee in stkTokens using Chainlink oracle + convertToAssets
        uint256 fee = _calculateFeeForStkToken(request.vault, GAS_BUFFER + 120000); // ~120k gas for claim

        // Only take fee if user received tokens and fee is within bounds
        if (receivedStkTokens > 0 && fee > 0 && fee < receivedStkTokens) {
            // Execute permit to transfer fee from user
            _executePermit(stkToken, request.user, address(this), permitSig);

            // Transfer fee from user to treasury
            stkToken.safeTransferFrom(request.user, treasury, fee);
        } else {
            fee = 0;
        }

        // Increment nonce
        _nonces[request.user]++;

        emit GaslessStakedSharesClaimed(request.user, request.vault, request.requestId, fee);
    }

    /// @inheritdoc IKamPaymaster
    function executeClaimUnstakedAssets(
        ClaimRequest calldata request,
        PermitSignature calldata permitSig,
        bytes calldata requestSig
    )
        external
        onlyTrustedExecutor
    {
        // Validate request
        _validateClaimRequest(request, requestSig);

        // Get vault's kToken address
        address kToken = _getVaultKToken(request.vault);

        // Get user's kToken balance before claim
        uint256 balanceBefore = _getTokenBalance(kToken, request.user);

        // Forward the claim to the vault with user's address appended (ERC2771 style)
        bytes memory callData = abi.encodeWithSignature("claimUnstakedAssets(bytes32)", request.requestId);

        // Append user address for ERC2771 context
        bytes memory forwardData = abi.encodePacked(callData, request.user);

        // Execute the forwarded call
        (bool success,) = request.vault.call(forwardData);
        require(success, "KamPaymaster: claim unstaked assets failed");

        // Get user's kToken balance after claim
        uint256 balanceAfter = _getTokenBalance(kToken, request.user);

        // Calculate received kTokens
        uint256 receivedKTokens = balanceAfter - balanceBefore;

        // Calculate fee in kTokens using Chainlink oracle
        uint256 fee = _calculateFeeForKToken(kToken, GAS_BUFFER + 120000); // ~120k gas for claim

        // Only take fee if user received tokens and fee is within bounds
        if (receivedKTokens > 0 && fee > 0 && fee < receivedKTokens) {
            // Execute permit to transfer fee from user
            _executePermit(kToken, request.user, address(this), permitSig);

            // Transfer fee from user to treasury
            kToken.safeTransferFrom(request.user, treasury, fee);
        } else {
            fee = 0;
        }

        // Increment nonce
        _nonces[request.user]++;

        emit GaslessUnstakedAssetsClaimed(request.user, request.vault, request.requestId, fee);
    }

    /* //////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IKamPaymaster
    function nonces(address user) external view returns (uint256) {
        return _nonces[user];
    }

    /// @inheritdoc IKamPaymaster
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        }
        return _computeDomainSeparator();
    }

    /// @inheritdoc IKamPaymaster
    function calculateFeeForKToken(uint256 gasEstimate, address kToken) external view returns (uint256 fee) {
        return _calculateFeeForKToken(kToken, gasEstimate);
    }

    /// @inheritdoc IKamPaymaster
    function calculateFeeForStkToken(uint256 gasEstimate, address vault) external view returns (uint256 fee) {
        return _calculateFeeForStkToken(vault, gasEstimate);
    }

    /// @inheritdoc IKamPaymaster
    function isTrustedExecutor(address executor) external view returns (bool) {
        return _trustedExecutors[executor];
    }

    /* //////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the fee configuration
    /// @param _baseFee New base fee in basis points
    /// @param _gasMultiplier New gas cost multiplier (scaled to 1e18)
    function setFeeConfig(uint256 _baseFee, uint256 _gasMultiplier) external onlyOwner {
        if (_baseFee > MAX_FEE_BPS) revert FeeExceedsMaximum();
        baseFee = _baseFee;
        gasMultiplier = _gasMultiplier;
        emit FeeConfigUpdated(_baseFee, _gasMultiplier);
    }

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

    /// @notice Set the Chainlink price feed for an underlying asset
    /// @dev The price feed should return asset/ETH price (e.g., USDC/ETH, WBTC/ETH)
    /// @param asset The underlying asset address (e.g., USDC, WBTC)
    /// @param priceFeed The Chainlink aggregator address for asset/ETH
    function setAssetPriceFeed(address asset, address priceFeed) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        assetPriceFeeds[asset] = priceFeed;
        emit PriceFeedSet(asset, priceFeed);
    }

    /// @notice Transfer ownership of the contract
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
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
    }

    /* //////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Compute the EIP-712 domain separator
    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH, keccak256(bytes(NAME)), keccak256(bytes(VERSION)), block.chainid, address(this)
            )
        );
    }

    /// @dev Validate a stake request signature
    function _validateStakeRequest(StakeRequest calldata request, bytes calldata sig) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.kTokenAmount == 0) revert ZeroAmount();

        bytes32 structHash = keccak256(
            abi.encode(
                STAKE_REQUEST_TYPEHASH,
                request.user,
                request.vault,
                request.kTokenAmount,
                request.recipient,
                request.deadline,
                request.nonce
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate an unstake request signature
    function _validateUnstakeRequest(UnstakeRequest calldata request, bytes calldata sig) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();
        if (request.stkTokenAmount == 0) revert ZeroAmount();

        bytes32 structHash = keccak256(
            abi.encode(
                UNSTAKE_REQUEST_TYPEHASH,
                request.user,
                request.vault,
                request.stkTokenAmount,
                request.recipient,
                request.deadline,
                request.nonce
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate a claim request signature
    function _validateClaimRequest(ClaimRequest calldata request, bytes calldata sig) internal view {
        if (request.deadline < block.timestamp) revert RequestExpired();
        if (request.nonce != _nonces[request.user]) revert InvalidNonce();

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_REQUEST_TYPEHASH, request.user, request.vault, request.requestId, request.deadline, request.nonce
            )
        );

        _validateSignature(request.user, structHash, sig);
    }

    /// @dev Validate an EIP-712 signature
    function _validateSignature(address signer, bytes32 structHash, bytes calldata sig) internal view {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        address recovered;
        if (sig.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(sig.offset)
                s := calldataload(add(sig.offset, 0x20))
                v := byte(0, calldataload(add(sig.offset, 0x40)))
            }
            recovered = ecrecover(digest, v, r, s);
        } else if (sig.length == 64) {
            // EIP-2098 compact signature
            bytes32 r;
            bytes32 vs;
            assembly {
                r := calldataload(sig.offset)
                vs := calldataload(add(sig.offset, 0x20))
            }
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            uint8 v = uint8(uint256(vs >> 255)) + 27;
            recovered = ecrecover(digest, v, r, s);
        }

        if (recovered == address(0) || recovered != signer) revert InvalidSignature();
    }

    /// @dev Execute EIP-2612 permit
    function _executePermit(
        address token,
        address owner_,
        address spender,
        PermitSignature calldata sig
    )
        internal
    {
        if (sig.deadline < block.timestamp) revert PermitExpired();

        // Call permit on the token - use the value from the signature
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
        require(success, "KamPaymaster: permit failed");
    }

    /// @dev Get the kToken address for a vault
    function _getVaultKToken(address vault) internal view returns (address) {
        // Call the vault to get its underlying kToken
        (bool success, bytes memory data) = vault.staticcall(abi.encodeWithSignature("kToken()"));
        if (!success || data.length < 32) {
            // Try alternative method through registry
            (success, data) = vault.staticcall(abi.encodeWithSignature("asset()"));
            if (!success) revert VaultNotRegistered();

            address asset = abi.decode(data, (address));
            // Get kToken from registry
            (success, data) = registry.staticcall(abi.encodeWithSignature("assetToKToken(address)", asset));
            if (!success) revert VaultNotRegistered();
        }
        return abi.decode(data, (address));
    }

    /// @dev Get the underlying asset address for a kToken
    function _getUnderlyingAsset(address kToken) internal view returns (address) {
        // Try to get asset directly from kToken (if it has such function)
        (bool success, bytes memory data) = kToken.staticcall(abi.encodeWithSignature("asset()"));
        if (success && data.length >= 32) {
            return abi.decode(data, (address));
        }

        // Try to get from registry by reverse lookup
        (success, data) = registry.staticcall(abi.encodeWithSignature("kTokenToAsset(address)", kToken));
        if (success && data.length >= 32) {
            return abi.decode(data, (address));
        }

        // If no explicit asset mapping, use the kToken itself as key for price feed lookup
        return kToken;
    }

    /// @dev Get token balance for an account
    function _getTokenBalance(address token, address account) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", account));
        if (success && data.length >= 32) {
            return abi.decode(data, (uint256));
        }
        return 0;
    }

    /// @dev Get token decimals
    function _getTokenDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("decimals()"));
        if (success && data.length >= 32) {
            return abi.decode(data, (uint8));
        }
        return 18; // Default to 18 decimals
    }

    /// @dev Get the asset/ETH price from Chainlink oracle
    /// @param asset The underlying asset address
    /// @return price The asset price in ETH (scaled to 1e18)
    function _getAssetPriceInEth(address asset) internal view returns (uint256 price) {
        address priceFeed = assetPriceFeeds[asset];
        if (priceFeed == address(0)) revert NoPriceFeedConfigured();

        IChainlinkAggregator aggregator = IChainlinkAggregator(priceFeed);

        (, int256 answer,, uint256 updatedAt,) = aggregator.latestRoundData();

        // Validate price is positive and not stale
        if (answer <= 0) revert InvalidPriceFeed();
        if (block.timestamp - updatedAt > MAX_PRICE_STALENESS) revert InvalidPriceFeed();

        // Get decimals and normalize to 1e18
        uint8 feedDecimals = aggregator.decimals();
        if (feedDecimals < 18) {
            price = uint256(answer) * 10 ** (18 - feedDecimals);
        } else if (feedDecimals > 18) {
            price = uint256(answer) / 10 ** (feedDecimals - 18);
        } else {
            price = uint256(answer);
        }
    }

    /// @dev Calculate fee for kToken using Chainlink oracle
    /// @param kToken The kToken address
    /// @param gasEstimate The estimated gas cost
    /// @return fee The fee in kToken units
    function _calculateFeeForKToken(address kToken, uint256 gasEstimate) internal view returns (uint256 fee) {
        // Get underlying asset for price lookup
        address asset = _getUnderlyingAsset(kToken);

        // Get asset price in ETH from Chainlink
        uint256 assetPriceInEth = _getAssetPriceInEth(asset);

        // Get token decimals
        uint8 tokenDecimals = _getTokenDecimals(kToken);

        // Calculate gas cost in wei (ETH)
        // gasCostWei = gasEstimate * gasPrice * gasMultiplier / 1e18
        uint256 gasCostWei = gasEstimate * tx.gasprice * gasMultiplier / 1e18;

        // Convert ETH cost to token units
        // fee = gasCostWei * 1e18 / assetPriceInEth * 10^tokenDecimals / 1e18
        // Simplified: fee = gasCostWei * 10^tokenDecimals / assetPriceInEth
        fee = gasCostWei * (10 ** tokenDecimals) / assetPriceInEth;

        // Add base fee percentage
        fee = fee + (fee * baseFee / BPS_DENOMINATOR);
    }

    /// @dev Calculate fee for stkToken using vault's convertToAssets and Chainlink oracle
    /// @param vault The vault address (which is also the stkToken)
    /// @param gasEstimate The estimated gas cost
    /// @return fee The fee in stkToken units
    function _calculateFeeForStkToken(address vault, uint256 gasEstimate) internal view returns (uint256 fee) {
        // Get the kToken for this vault
        address kToken = _getVaultKToken(vault);

        // Calculate what the fee would be in kTokens
        uint256 feeInKTokens = _calculateFeeForKToken(kToken, gasEstimate);

        // Convert kToken fee to stkToken fee using vault's convertToShares
        // convertToShares tells us how many stkTokens equal a given amount of kTokens
        (bool success, bytes memory data) =
            vault.staticcall(abi.encodeWithSignature("convertToShares(uint256)", feeInKTokens));

        if (success && data.length >= 32) {
            fee = abi.decode(data, (uint256));
        } else {
            // Fallback: try previewDeposit (ERC4626 standard)
            (success, data) = vault.staticcall(abi.encodeWithSignature("previewDeposit(uint256)", feeInKTokens));
            if (success && data.length >= 32) {
                fee = abi.decode(data, (uint256));
            } else {
                // If no conversion available, assume 1:1 ratio
                fee = feeInKTokens;
            }
        }
    }

    /// @notice Receive ETH
    receive() external payable { }
}

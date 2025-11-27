// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";
import { KamPaymaster } from "../src/KamPaymaster.sol";
import { IKamPaymaster } from "../src/interfaces/IKamPaymaster.sol";
import { IChainlinkAggregator } from "../src/interfaces/IChainlinkAggregator.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
    function mint(address, uint256) external;
}

contract MockERC20Permit {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(_name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(deadline >= block.timestamp, "permit expired");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "invalid signature");

        allowance[owner][spender] = value;
    }
}

contract MockChainlinkAggregator is IChainlinkAggregator {
    int256 public price;
    uint8 public decimals_;
    uint256 public updatedAt;

    constructor(int256 _price, uint8 _decimals) {
        price = _price;
        decimals_ = _decimals;
        updatedAt = block.timestamp;
    }

    function setPrice(int256 _price) external {
        price = _price;
        updatedAt = block.timestamp;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 _updatedAt, uint80 answeredInRound)
    {
        return (1, price, block.timestamp, updatedAt, 1);
    }

    function decimals() external view override returns (uint8) {
        return decimals_;
    }
}

contract MockKStakingVault is MockERC20Permit {
    address public kToken;
    address public trustedForwarder;

    struct StakeRequest {
        address user;
        uint256 amount;
        address recipient;
        bool claimed;
    }

    struct UnstakeRequest {
        address user;
        uint256 stkAmount;
        address recipient;
        bool claimed;
    }

    mapping(bytes32 => StakeRequest) public stakeRequests;
    mapping(bytes32 => UnstakeRequest) public unstakeRequests;

    bytes32 public currentBatchId;
    bool public batchSettled;
    uint256 public sharePrice = 1e6;
    uint256 private _requestCounter;

    constructor(address _kToken) MockERC20Permit("Staked kUSDC", "stkUSDC", 6) {
        kToken = _kToken;
        currentBatchId = keccak256(abi.encode(block.timestamp, address(this), 0));
    }

    function setTrustedForwarder(address _forwarder) external {
        trustedForwarder = _forwarder;
    }

    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    function _msgSender() internal view returns (address sender) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function getBatchId() external view returns (bytes32) {
        return currentBatchId;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets * 1e6 / sharePrice;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return shares * sharePrice / 1e6;
    }

    function requestStake(address recipient, uint256 amount) external payable returns (bytes32 requestId) {
        address sender = _msgSender();
        MockERC20Permit(kToken).transferFrom(msg.sender, address(this), amount);
        requestId = keccak256(abi.encode(sender, amount, block.timestamp, ++_requestCounter));
        stakeRequests[requestId] = StakeRequest({ user: sender, amount: amount, recipient: recipient, claimed: false });
    }

    function requestUnstake(address recipient, uint256 stkAmount) external payable returns (bytes32 requestId) {
        address sender = _msgSender();
        require(balanceOf[sender] >= stkAmount, "insufficient balance");
        balanceOf[sender] -= stkAmount;
        balanceOf[address(this)] += stkAmount;
        requestId = keccak256(abi.encode(sender, stkAmount, block.timestamp, ++_requestCounter));
        unstakeRequests[requestId] = UnstakeRequest({ user: sender, stkAmount: stkAmount, recipient: recipient, claimed: false });
    }

    function claimStakedShares(bytes32 requestId) external payable {
        address sender = _msgSender();
        StakeRequest storage request = stakeRequests[requestId];
        require(request.user == sender, "not request owner");
        require(!request.claimed, "already claimed");
        require(batchSettled, "batch not settled");

        request.claimed = true;
        uint256 shares = request.amount * 1e6 / sharePrice;
        balanceOf[request.recipient] += shares;
        totalSupply += shares;
    }

    function claimUnstakedAssets(bytes32 requestId) external payable {
        address sender = _msgSender();
        UnstakeRequest storage request = unstakeRequests[requestId];
        require(request.user == sender, "not request owner");
        require(!request.claimed, "already claimed");
        require(batchSettled, "batch not settled");

        request.claimed = true;
        uint256 assets = request.stkAmount * sharePrice / 1e6;
        MockERC20Permit(kToken).transfer(request.recipient, assets);
    }

    function closeBatch(bytes32, bool createNew) external {
        if (createNew) {
            currentBatchId = keccak256(abi.encode(block.timestamp, address(this), ++_requestCounter));
        }
    }

    function settleBatch() external {
        batchSettled = true;
    }

    function setSharePrice(uint256 _price) external {
        sharePrice = _price;
    }
}

contract MockRegistry {
    mapping(address => address) public assetToKToken;
    mapping(address => address) public kTokenToAsset;

    function setAssetToKToken(address asset, address _kToken) external {
        assetToKToken[asset] = _kToken;
        kTokenToAsset[_kToken] = asset;
    }
}

contract KamPaymasterIntegrationTest is Test {
    KamPaymaster public paymaster;
    MockERC20Permit public underlyingAsset;
    MockERC20Permit public kToken;
    MockKStakingVault public vault;
    MockRegistry public registry;
    MockChainlinkAggregator public priceFeed;

    address public owner;
    address public treasury;
    address public executor;

    uint256 public constant USER_PRIVATE_KEY = 0xA11CE;
    address public testUser;

    uint256 constant BASE_FEE = 100;
    uint256 constant GAS_MULTIPLIER = 1e18;
    uint256 constant _1_USDC = 1e6;
    int256 constant USDC_ETH_PRICE = 5e14;

    function setUp() public {
        owner = makeAddr("owner");
        treasury = makeAddr("treasury");
        executor = makeAddr("executor");
        testUser = vm.addr(USER_PRIVATE_KEY);

        underlyingAsset = new MockERC20Permit("USD Coin", "USDC", 6);
        kToken = new MockERC20Permit("KAM USDC", "kUSD", 6);
        vault = new MockKStakingVault(address(kToken));
        registry = new MockRegistry();
        registry.setAssetToKToken(address(underlyingAsset), address(kToken));

        priceFeed = new MockChainlinkAggregator(USDC_ETH_PRICE, 18);
        paymaster = new KamPaymaster(owner, treasury, address(registry), BASE_FEE, GAS_MULTIPLIER);

        vm.startPrank(owner);
        paymaster.setAssetPriceFeed(address(underlyingAsset), address(priceFeed));
        paymaster.setAssetPriceFeed(address(kToken), address(priceFeed));
        paymaster.setTrustedExecutor(executor, true);
        vm.stopPrank();

        vault.setTrustedForwarder(address(paymaster));
        kToken.mint(testUser, 100_000 * _1_USDC);
        kToken.mint(address(vault), 1_000_000 * _1_USDC);
    }

    function _createPermitSignature(
        address token,
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (IKamPaymaster.PermitSignature memory) {
        MockERC20Permit t = MockERC20Permit(token);

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner_,
                spender,
                value,
                t.nonces(owner_),
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", t.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return IKamPaymaster.PermitSignature({ value: value, deadline: deadline, v: v, r: r, s: s });
    }

    function _createStakeRequestSignature(
        IKamPaymaster.StakeRequest memory request,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.STAKE_REQUEST_TYPEHASH(),
                request.user,
                request.vault,
                request.kTokenAmount,
                request.recipient,
                request.deadline,
                request.nonce
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createUnstakeRequestSignature(
        IKamPaymaster.UnstakeRequest memory request,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.UNSTAKE_REQUEST_TYPEHASH(),
                request.user,
                request.vault,
                request.stkTokenAmount,
                request.recipient,
                request.deadline,
                request.nonce
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createClaimRequestSignature(
        IKamPaymaster.ClaimRequest memory request,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.CLAIM_REQUEST_TYPEHASH(),
                request.user,
                request.vault,
                request.requestId,
                request.deadline,
                request.nonce
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function test_setUp() public view {
        assertEq(paymaster.owner(), owner);
        assertEq(paymaster.treasury(), treasury);
        assertEq(paymaster.baseFee(), BASE_FEE);
        assertTrue(paymaster.isTrustedExecutor(executor));
        assertEq(kToken.balanceOf(testUser), 100_000 * _1_USDC);
    }

    function test_fullGaslessStakeFlow() public {
        vm.txGasPrice(50 gwei);

        bytes32 requestId = _executeGaslessStake(10_000 * _1_USDC);

        vault.settleBatch();

        _executeGaslessClaimStakedShares(requestId);
    }

    function _executeGaslessStake(uint256 stakeAmount) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory stakeRequest = IKamPaymaster.StakeRequest({
            user: testUser,
            vault: address(vault),
            kTokenAmount: stakeAmount,
            recipient: testUser,
            deadline: deadline,
            nonce: paymaster.nonces(testUser)
        });

        IKamPaymaster.PermitSignature memory permitSig =
            _createPermitSignature(address(kToken), testUser, address(paymaster), stakeAmount, deadline, USER_PRIVATE_KEY);

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kToken.balanceOf(testUser);
        uint256 treasuryBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        requestId = paymaster.executeStakeWithPermit(stakeRequest, permitSig, requestSig);

        uint256 feeCollected = kToken.balanceOf(treasury) - treasuryBefore;

        assertEq(kToken.balanceOf(testUser), userKTokenBefore - stakeAmount);
        assertGt(feeCollected, 0);
    }

    function _executeGaslessClaimStakedShares(bytes32 requestId) internal {
        uint256 claimDeadline = block.timestamp + 1 hours;

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
            user: testUser,
            vault: address(vault),
            requestId: requestId,
            deadline: claimDeadline,
            nonce: paymaster.nonces(testUser)
        });

        IKamPaymaster.PermitSignature memory claimPermitSig =
            _createPermitSignature(address(vault), testUser, address(paymaster), 100_000 * _1_USDC, claimDeadline, USER_PRIVATE_KEY);

        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        uint256 userStkBefore = vault.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeClaimStakedShares(claimRequest, claimPermitSig, claimSig);

        assertGt(vault.balanceOf(testUser), userStkBefore);
    }

    function test_fullGaslessUnstakeFlow() public {
        vm.txGasPrice(50 gwei);

        _performDirectStake(testUser, 20_000 * _1_USDC);

        uint256 userStkBalance = vault.balanceOf(testUser);
        require(userStkBalance > 0, "No stkTokens to unstake");

        bytes32 requestId = _executeGaslessUnstake(userStkBalance / 2);

        vault.settleBatch();

        _executeGaslessClaimUnstakedAssets(requestId);
    }

    function _executeGaslessUnstake(uint256 unstakeAmount) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.UnstakeRequest memory unstakeRequest = IKamPaymaster.UnstakeRequest({
            user: testUser,
            vault: address(vault),
            stkTokenAmount: unstakeAmount,
            recipient: testUser,
            deadline: deadline,
            nonce: paymaster.nonces(testUser)
        });

        IKamPaymaster.PermitSignature memory permitSig =
            _createPermitSignature(address(vault), testUser, address(paymaster), unstakeAmount, deadline, USER_PRIVATE_KEY);

        bytes memory requestSig = _createUnstakeRequestSignature(unstakeRequest, USER_PRIVATE_KEY);

        uint256 userStkBefore = vault.balanceOf(testUser);
        uint256 treasuryBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        requestId = paymaster.executeUnstakeWithPermit(unstakeRequest, permitSig, requestSig);

        uint256 feeCollected = vault.balanceOf(treasury) - treasuryBefore;

        assertEq(vault.balanceOf(testUser), userStkBefore - unstakeAmount);
        assertGt(feeCollected, 0);
    }

    function _executeGaslessClaimUnstakedAssets(bytes32 requestId) internal {
        uint256 claimDeadline = block.timestamp + 1 hours;

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
            user: testUser,
            vault: address(vault),
            requestId: requestId,
            deadline: claimDeadline,
            nonce: paymaster.nonces(testUser)
        });

        IKamPaymaster.PermitSignature memory claimPermitSig =
            _createPermitSignature(address(kToken), testUser, address(paymaster), 100_000 * _1_USDC, claimDeadline, USER_PRIVATE_KEY);

        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kToken.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssets(claimRequest, claimPermitSig, claimSig);

        assertGt(kToken.balanceOf(testUser), userKTokenBefore);
    }

    function test_revert_expiredDeadline() public {
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            vault: address(vault),
            kTokenAmount: 1000 * _1_USDC,
            recipient: testUser,
            deadline: block.timestamp - 1,
            nonce: 0
        });

        IKamPaymaster.PermitSignature memory permitSig =
            IKamPaymaster.PermitSignature({ value: 1000 * _1_USDC, deadline: block.timestamp - 1, v: 27, r: bytes32(0), s: bytes32(0) });

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.RequestExpired.selector);
        paymaster.executeStakeWithPermit(request, permitSig, requestSig);
    }

    function test_revert_invalidNonce() public {
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            vault: address(vault),
            kTokenAmount: 1000 * _1_USDC,
            recipient: testUser,
            deadline: deadline,
            nonce: 999
        });

        IKamPaymaster.PermitSignature memory permitSig =
            _createPermitSignature(address(kToken), testUser, address(paymaster), 1000 * _1_USDC, deadline, USER_PRIVATE_KEY);

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InvalidNonce.selector);
        paymaster.executeStakeWithPermit(request, permitSig, requestSig);
    }

    function test_revert_notTrustedExecutor() public {
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            vault: address(vault),
            kTokenAmount: 1000 * _1_USDC,
            recipient: testUser,
            deadline: block.timestamp + 1 hours,
            nonce: 0
        });

        IKamPaymaster.PermitSignature memory permitSig =
            IKamPaymaster.PermitSignature({ value: 1000 * _1_USDC, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0) });

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeStakeWithPermit(request, permitSig, "");
    }

    function test_revert_insufficientAmountForFee() public {
        vm.txGasPrice(1000 gwei);

        uint256 tinyAmount = 1;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            vault: address(vault),
            kTokenAmount: tinyAmount,
            recipient: testUser,
            deadline: deadline,
            nonce: 0
        });

        IKamPaymaster.PermitSignature memory permitSig =
            _createPermitSignature(address(kToken), testUser, address(paymaster), tinyAmount, deadline, USER_PRIVATE_KEY);

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InsufficientAmountForFee.selector);
        paymaster.executeStakeWithPermit(request, permitSig, requestSig);
    }

    function test_nonceIncrementsAfterEachOperation() public {
        vm.txGasPrice(50 gwei);

        assertEq(paymaster.nonces(testUser), 0);

        _executeGaslessStakeSimple(testUser, 1000 * _1_USDC);
        assertEq(paymaster.nonces(testUser), 1);

        _executeGaslessStakeSimple(testUser, 1000 * _1_USDC);
        assertEq(paymaster.nonces(testUser), 2);
    }

    function test_feeCalculationWithDifferentGasPrices() public {
        uint256 lowGasPrice = 10 gwei;
        uint256 highGasPrice = 100 gwei;

        vm.txGasPrice(lowGasPrice);
        uint256 lowFee = paymaster.calculateFeeForKToken(200_000, address(kToken));

        vm.txGasPrice(highGasPrice);
        uint256 highFee = paymaster.calculateFeeForKToken(200_000, address(kToken));

        assertGt(highFee, lowFee);
        assertEq(highFee / lowFee, highGasPrice / lowGasPrice);
    }

    function _performDirectStake(address user, uint256 amount) internal {
        vm.startPrank(user);
        kToken.approve(address(vault), amount);
        bytes32 requestId = vault.requestStake(user, amount);
        vm.stopPrank();

        vault.settleBatch();

        vm.prank(user);
        vault.claimStakedShares(requestId);
    }

    function _executeGaslessStakeSimple(address user, uint256 amount) internal returns (bytes32) {
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            vault: address(vault),
            kTokenAmount: amount,
            recipient: user,
            deadline: deadline,
            nonce: paymaster.nonces(user)
        });

        IKamPaymaster.PermitSignature memory permitSig =
            _createPermitSignature(address(kToken), user, address(paymaster), amount, deadline, USER_PRIVATE_KEY);

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        return paymaster.executeStakeWithPermit(request, permitSig, requestSig);
    }
}
